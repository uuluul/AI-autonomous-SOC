import os
import time
import schedule
import feedparser
import logging
import re
import hashlib
import json
from bs4 import BeautifulSoup
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [RSS Crawler] - %(message)s')
logger = logging.getLogger(__name__)

# 資料夾與檔案設定
INPUT_DIR = "data/input"
HISTORY_FILE = "data/rss_history.json" 

# RSS 來源清單
RSS_FEEDS = {
    "CISA_Alerts": "https://www.cisa.gov/uscert/ncas/alerts.xml",
    "TheHackerNews": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/"
}

def clean_filename(title):
    """將標題轉為合法的檔名"""
    clean = re.sub(r'[\\/*?:"<>|]', "", title)
    return clean.replace(" ", "_")[:100]

def clean_html(html_content):
    """移除 HTML 標籤，只保留純文字"""
    soup = BeautifulSoup(html_content, "html.parser")
    return soup.get_text()

# === MD5 校驗邏輯 ===

def get_content_hash(text):
    """對文字內容進行 MD5 編碼"""
    return hashlib.md5(text.strip().encode('utf-8')).hexdigest()

def load_history():
    """載入已抓取過的 Hash 清單"""
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                return set(json.load(f))
        except:
            return set()
    return set()

def save_history(history_set):
    """儲存最新的 Hash 清單"""
    with open(HISTORY_FILE, "w") as f:
        json.dump(list(history_set), f)

def fetch_rss():
    logger.info("🕷️ Starting RSS fetch cycle...")
    
    # 載入歷史紀錄
    history = load_history()
    new_hashes_found = False
    
    for source_name, url in RSS_FEEDS.items():
        try:
            logger.info(f"Checking feed: {source_name}...")
            feed = feedparser.parse(url)
            
            for entry in feed.entries[:10]: # 擴大範圍，增加命中機會
                title = entry.title
                link = entry.link
                content_raw = entry.get('summary', entry.get('description', ''))
                content = clean_html(content_raw)
                published = entry.get('published', datetime.now().strftime('%Y-%m-%d'))
                
                # --- 內容校驗 ---
                # 只針對內容做 Hash，如果內容一模一樣，即便標題變了也會被跳過
                content_hash = get_content_hash(content)
                
                if content_hash in history:
                    logger.debug(f"  Skipping (Content Duplicate): {title[:30]}...")
                    continue

                # 組合檔名
                safe_title = clean_filename(title)
                filename = f"RSS_{source_name}_{safe_title}.txt"
                filepath = os.path.join(INPUT_DIR, filename)
                
                # 額外檢查檔案是否存在 (雙重保險)
                processed_path = os.path.join("data/processed", filename)
                if os.path.exists(filepath) or os.path.exists(processed_path):
                    continue
                
                # 寫入檔案
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(f"Title: {title}\n")
                    f.write(f"Source: {source_name}\n")
                    f.write(f"Date: {published}\n")
                    f.write(f"Link: {link}\n")
                    f.write(f"Content_Hash: {content_hash}\n") # 紀錄在檔案內方便溯源
                    f.write(f"\n[Content]\n{content}\n")
                
                # 更新歷史紀錄
                history.add(content_hash)
                new_hashes_found = True
                logger.info(f"  New Report Fetched: {filename}")
                
        except Exception as e:
            logger.error(f"  Error fetching {source_name}: {e}")

    # 只有在有新文章時才更新 history 檔案，減少 IO 負擔
    if new_hashes_found:
        save_history(history)

def main():
    
    os.makedirs(INPUT_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
    
    logger.info("  RSS Crawler Service Started with MD5 Deduplication.")
    logger.info(f"   Fingerprint database: {HISTORY_FILE}")
    
    fetch_rss()
    
    # 設定排程
    schedule.every(30).minutes.do(fetch_rss)
    
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == "__main__":
    main()