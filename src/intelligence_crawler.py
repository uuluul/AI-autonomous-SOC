import os
import time
import schedule
import feedparser
import logging
import re
import hashlib
import json
import requests
import pika
from bs4 import BeautifulSoup
from datetime import datetime
from dotenv import load_dotenv
from OTXv2 import OTXv2

# ================= 系統設定與日誌初始化 =================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [Intelligence Crawler] - %(message)s')
logger = logging.getLogger(__name__)

# 載入 .env 檔案中的環境變數
load_dotenv()
OTX_API_KEY = os.getenv("OTX_API_KEY")

# 資料夾與檔案設定
INPUT_DIR = "data/input"
HISTORY_FILE = "data/rss_history.json" 

# RSS 來源清單
RSS_FEEDS = {
    "CISA_Alerts": "https://www.cisa.gov/uscert/ncas/alerts.xml",
    "TheHackerNews": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/"
}

# ================= 共用工具函式 =================

def clean_filename(title):
    """將標題轉為合法的檔名 (Remove invalid characters for filenames)"""
    clean = re.sub(r'[\\/*?:"<>|]', "", title)
    return clean.replace(" ", "_")[:100]

def clean_html(html_content):
    """移除 HTML 標籤，只保留純文字 (Remove HTML tags)"""
    soup = BeautifulSoup(html_content, "html.parser")
    return soup.get_text()

def get_content_hash(text):
    """對文字內容進行 MD5 編碼 (Generate MD5 hash)"""
    return hashlib.md5(text.strip().encode('utf-8')).hexdigest()

def load_history():
    """載入已抓取過的 Hash 清單 (Load history for deduplication)"""
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                return set(json.load(f))
        except:
            return set()
    return set()

def save_history(history_set):
    """儲存最新的 Hash 清單 (Save history)"""
    with open(HISTORY_FILE, "w") as f:
        json.dump(list(history_set), f)

def save_to_input_folder(source_name, title, content):
    """將抓取到的非 RSS 情資儲存為 .txt 檔案 (Save premium CTI feeds)"""
    os.makedirs(INPUT_DIR, exist_ok=True)
    
    content_hash = get_content_hash(content)[:8]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    filename = f"{source_name}_CTI_{timestamp}_{content_hash}.txt"
    filepath = os.path.join(INPUT_DIR, filename)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(f"Source: {source_name}\n")
        f.write(f"Scraped At: {datetime.now().isoformat()}\n")
        f.write(f"Title: {title}\n")
        f.write("-" * 50 + "\n")
        f.write(content)
    
    logger.info(f"  Successfully saved CTI: [{source_name}] {title[:30]}... -> {filepath}")

# ================= Phase 1: Zero-Log Event Emission =================
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "rabbitmq")

_URGENCY_KEYWORDS = [
    "actively exploited", "in the wild", "zero-day", "0-day",
    "critical vulnerability", "emergency patch", "mass exploitation",
    "remote code execution", "pre-auth", "unauthenticated",
]

def _emit_zero_log_event(title: str, content: str, source: str = "crawler"):
    """
    If the crawled article mentions a CVE with urgency keywords,
    publish a zero_log_event so the Adversarial Engine can cross-
    reference against local assets — even with ZERO local logs.
    """
    cves = re.findall(r"CVE-\d{4}-\d{4,7}", content, re.IGNORECASE)
    if not cves:
        return

    combined = (title + " " + content).lower()
    is_urgent = any(kw in combined for kw in _URGENCY_KEYWORDS)
    if not is_urgent:
        return

    try:
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(
                host=RABBITMQ_HOST, connection_attempts=2, retry_delay=1
            )
        )
        channel = connection.channel()
        channel.queue_declare(queue="zero_log_events", durable=True)

        for cve_id in list(set(cves))[:3]:  # Max 3 CVEs per article
            event = {
                "cve_id": cve_id.upper(),
                "severity": "CRITICAL",
                "affected_software": title,
                "source": source,
                "source_article": title[:200],
                "timestamp": datetime.now().isoformat(),
            }
            channel.basic_publish(
                exchange="",
                routing_key="zero_log_events",
                body=json.dumps(event),
                properties=pika.BasicProperties(delivery_mode=2),
            )
            logger.info(f" Zero-Log Event emitted: {cve_id} from '{title[:50]}...'")

        connection.close()
    except Exception as exc:
        logger.warning(f" Failed to emit zero-log event (non-critical): {exc}")

# ================= 爬蟲 1: RSS Feeds =================

def fetch_rss():
    """抓取 RSS 新聞 (Fetch RSS feeds)"""
    logger.info("🕷️ Starting RSS fetch cycle...")
    history = load_history()
    new_hashes_found = False
    
    for source_name, url in RSS_FEEDS.items():
        try:
            logger.info(f"Checking RSS feed: {source_name}...")
            feed = feedparser.parse(url)
            
            for entry in feed.entries[:10]:
                title = entry.title
                link = entry.link
                content_raw = entry.get('summary', entry.get('description', ''))
                content = clean_html(content_raw)
                published = entry.get('published', datetime.now().strftime('%Y-%m-%d'))
                
                content_hash = get_content_hash(content)
                
                if content_hash in history:
                    continue

                safe_title = clean_filename(title)
                filename = f"RSS_{source_name}_{safe_title}.txt"
                filepath = os.path.join(INPUT_DIR, filename)
                processed_path = os.path.join("data/processed", filename)
                
                if os.path.exists(filepath) or os.path.exists(processed_path):
                    continue
                
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(f"Title: {title}\n")
                    f.write(f"Source: {source_name}\n")
                    f.write(f"Date: {published}\n")
                    f.write(f"Link: {link}\n")
                    f.write(f"Content_Hash: {content_hash}\n")
                    f.write(f"\n[Content]\n{content}\n")
                
                history.add(content_hash)
                new_hashes_found = True
                _emit_zero_log_event(title, content, source=source_name)
                logger.info(f"  New RSS Report Fetched: {filename}")
                
        except Exception as e:
            logger.error(f"  Error fetching RSS {source_name}: {e}")

    if new_hashes_found:
        save_history(history)

# ================= 爬蟲 2: AlienVault OTX =================

def fetch_otx_pulses(limit=5):
    """抓取 AlienVault OTX (Fetch AlienVault OTX)"""
    if not OTX_API_KEY:
        logger.warning("  OTX_API_KEY is missing. Skipping AlienVault OTX fetch.")
        return 0

    logger.info("  Connecting to AlienVault OTX API...")
    otx = OTXv2(OTX_API_KEY)
    saved_count = 0
    
    try:
        pulses = otx.getall() 
        logger.info(f"  Successfully fetched OTX Pulses. Processing the latest {limit} entries...")
        
        for pulse in pulses[:limit]:
            title = pulse.get('name', 'Unknown Pulse')
            description = pulse.get('description', 'No description available.')
            tags = pulse.get('tags', [])
            indicators = pulse.get('indicators', [])
            
            content = f"Description: {description}\n"
            content += f"Tags: {', '.join(tags)}\n\n"
            content += "Indicators (IoCs):\n"
            
            for ind in indicators[:20]:
                content += f"- Type: {ind.get('type')}, Indicator: {ind.get('indicator')}\n"
            
            save_to_input_folder("OTX", title, content)
            saved_count += 1
            time.sleep(1) 

    except Exception as e:
        logger.error(f"  OTX fetch failed: {e}")
        
    return saved_count

# ================= 爬蟲 3: Abuse.ch URLhaus =================

def fetch_abusech_threatfox(limit=10):
    """抓取 Abuse.ch ThreatFox 綜合威脅指標 (Fetch Abuse.ch ThreatFox IoCs)"""
    logger.info("  Connecting to Abuse.ch ThreatFox API...")
    # ThreatFox API 網址
    threatfox_api = "https://threatfox-api.abuse.ch/api/v1/"
    saved_count = 0

    try:
        # ThreatFox API 要求使用 POST 請求，查詢最近 1 天的最新 IoC
        payload = {"query": "get_iocs", "days": 1}
        response = requests.post(threatfox_api, json=payload)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("query_status") == "ok":
                iocs = data.get("data", [])
                logger.info(f"  Successfully fetched ThreatFox data. Processing top {limit} entries...")
                
                for item in iocs[:limit]:
                    ioc_value = item.get('ioc_value')
                    ioc_type = item.get('ioc_type')
                    threat_type = item.get('threat_type')
                    malware = item.get('malware_printable')
                    tags = item.get('tags', [])
                    
                    title = f"Abuse.ch ThreatFox - {malware} ({ioc_type})"
                    content = f"A new ThreatFox IoC has been reported associated with {malware}.\n"
                    content += f"Threat Type: {threat_type}\n"
                    content += f"Tags: {', '.join(tags) if tags else 'None'}\n\n"
                    content += "Indicators (IoCs):\n"
                    content += f"- Type: {ioc_type}, Indicator: {ioc_value}\n"
                    
                    # 使用 ABUSECH 前綴，維持和 run_pipeline.py 的相容性
                    save_to_input_folder("ABUSECH", title, content)
                    saved_count += 1
            else:
                logger.warning(f"  ThreatFox API returned no data: {data.get('query_status')}")
                
        else:
             logger.error(f"  ThreatFox API returned error status code: {response.status_code}")
             
    except Exception as e:
         logger.error(f"  Abuse.ch ThreatFox fetch failed: {e}")

    return saved_count

# ================= 爬蟲 4: GitHub Security Advisories =================

def fetch_github_advisories(limit=5):
    """抓取 GitHub 最新漏洞 (Fetch GitHub Security Advisories)"""
    logger.info("  Connecting to GitHub Security Advisories API...")
    github_api = "https://api.github.com/advisories" 
    headers = {"Accept": "application/vnd.github.v3+json"}
    saved_count = 0

    try:
        response = requests.get(github_api, headers=headers)
        if response.status_code == 200:
            advisories = response.json()
            logger.info(f"  Successfully fetched GitHub Advisories. Processing top {limit} entries...")
            
            for adv in advisories[:limit]:
                ghsa_id = adv.get('ghsa_id', 'Unknown GHSA')
                cve_id = adv.get('cve_id', 'No CVE')
                summary = adv.get('summary', 'Unknown Vulnerability')
                description = adv.get('description', 'No description provided.')
                severity = adv.get('severity', 'Unknown Severity')
                
                title = f"GitHub Advisory - {summary}"
                content = f"Vulnerability Summary: {summary}\n"
                content += f"Severity: {severity.upper()}\n"
                content += f"Identifiers: {ghsa_id}, {cve_id}\n\n"
                content += "Description and Impact:\n"
                content += f"{description}\n"
                
                save_to_input_folder("GITHUB", title, content)
                saved_count += 1
                _emit_zero_log_event(title, content, source="GitHub_Advisory")
                
        else:
             logger.error(f"  GitHub API returned error status code: {response.status_code}")
             
    except Exception as e:
         logger.error(f"  GitHub Advisory fetch failed: {e}")

    return saved_count

# ================= 主排程邏輯 =================

def job_run_all_crawlers():
    """執行所有爬蟲任務的排程函數 (Main job function to run all crawlers)"""
    logger.info(f"=== Starting Comprehensive CTI Crawl Task ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ===")
    
    # 1. RSS
    fetch_rss()
    
    # 2. OTX
    otx_count = fetch_otx_pulses(limit=5)
    
    # 3. Abuse.ch
    abusech_count = fetch_abusech_threatfox(limit=10) 
       
    # 4. GitHub Advisories
    github_count = fetch_github_advisories(limit=5)
    
    total_premium = otx_count + abusech_count + github_count
    logger.info(f"  Crawl task completed! Total {total_premium} new premium CTI feeds imported.")
    logger.info("=== Waiting for the next scheduled cycle ===")

def main():
    os.makedirs(INPUT_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
    
    logger.info("=====================================================")
    logger.info("  Unified Intelligence Crawler Service Started")
    logger.info("  Sources: RSS, OTX, Abuse.ch, GitHub Advisories")
    logger.info(f"  Fingerprint database: {HISTORY_FILE}")
    logger.info("=====================================================")
    
    # 啟動時先執行一次完整抓取
    job_run_all_crawlers()
    
    # 設定排程：每 30 分鐘自動執行一次所有任務
    schedule.every(30).minutes.do(job_run_all_crawlers)
    
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == "__main__":
    main()