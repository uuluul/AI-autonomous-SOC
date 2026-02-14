import os
import time
import json
import logging
import glob
import pika
import requests
from datetime import datetime, timedelta
from llm_client import LLMClient
from to_stix import build_stix_bundle
from to_pdf import generate_pdf_report
from extract_schema import DEFAULT_SYSTEM_PROMPT, EXTRACTION_SCHEMA_DESCRIPTION
from validate_stix import validate_stix_json
from utils import chunk_text, merge_extractions
from database import insert_task
from pii_masker import PIIMasker
from src.setup_opensearch import upsert_indicator, upload_to_opensearch as upload_to_os_lib, get_opensearch_client
from src.enrichment import EnrichmentEngine
from src.cve_enrichment import CVEEnricher
import schedule
import threading
import subprocess

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

# 環境變數
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_QUEUE = "cti_tasks"
ROLE = os.getenv("ROLE", "master")  # 'master' or 'worker'

# 資料夾設定
INPUT_DIR = "data/input"
PROCESSED_DIR = "data/processed"
OUTPUT_DIR = "out"

# OpenSearch 設定 (用於 RAG 檢索)
OS_HOST = os.getenv("OPENSEARCH_HOST", "opensearch-node")
OS_PORT = os.getenv("OPENSEARCH_PORT", "9200")
OS_USER = os.getenv("OPENSEARCH_USER", "admin")
OS_PASS = os.getenv("OPENSEARCH_PASSWORD", "admin")
OS_AUTH = (OS_USER, OS_PASS)
BASE_URL = f"http://{OS_HOST}:{OS_PORT}"
INDEX_KB = "cti-reports"

def ensure_dirs():
    """確保必要的資料夾存在"""
    for d in [INPUT_DIR, PROCESSED_DIR, OUTPUT_DIR]:
        os.makedirs(d, exist_ok=True)

# --- RabbitMQ 連線 Helper ---
def get_rabbitmq_connection():
    """建立 RabbitMQ 連線與 Channel"""
    credentials = pika.PlainCredentials('user', 'password')
    parameters = pika.ConnectionParameters(RABBITMQ_HOST, 5672, '/', credentials, heartbeat=600)
    
    while True:
        try:
            connection = pika.BlockingConnection(parameters)
            channel = connection.channel()
            channel.queue_declare(queue=RABBITMQ_QUEUE, durable=True)
            return connection, channel
        except pika.exceptions.AMQPConnectionError:
            logger.warning("  Waiting for RabbitMQ...")
            time.sleep(5)

# --- RAG 檢索函式 ---
def retrieve_context(text_content: str, top_k: int = 3) -> str:
    """
    RAG 核心：同時查詢「外部專家知識 (MITRE/AI Defense)」與「內部歷史案例 (Reports)」
    """
    if not text_content: 
        return ""
    
    client = get_opensearch_client()
    context_parts = []
    
    # 搜尋內容截斷，避免 Token 過長，但保留足夠語意
    search_query = text_content[:1000]

    # =========================================================
    # 查詢 cti-knowledge-base (外部知識)
    # 目的：找出這段文字涉及什麼「攻擊手法」或「防禦建議」
    # =========================================================
    try:
        kb_response = client.search(
            index="cti-knowledge-base",
            body={
                "size": top_k,
                "query": {
                    "multi_match": {
                        "query": search_query,
                        # 標題 (name) 權重 x3，描述 (description) 權重 x1
                        "fields": ["name^3", "description"], 
                        "type": "best_fields"
                    }
                }
            }
        )
        
        hits = kb_response.get("hits", {}).get("hits", [])
        if hits:
            attacks = []
            defenses = []
            
            for hit in hits:
                src = hit["_source"]
                # 格式：[來源] ID 名稱: 描述片段
                info = f"- [{src.get('source', 'UNK').upper()}] {src.get('name', '')} ({src.get('external_id', 'N/A')}): {src.get('description', '')[:200]}..."
                
                if src.get("type") == "defense":
                    defenses.append(info)
                else:
                    attacks.append(info)
            
            # 組裝知識庫 Context
            if attacks:
                context_parts.append("  [Known Attack Patterns (MITRE ATT&CK)]:")
                context_parts.extend(attacks)
            if defenses:
                context_parts.append("  [Recommended Defenses (AI Defense)]:")
                context_parts.extend(defenses)
                
    except Exception as e:
        logger.warning(f"  Knowledge Base search failed: {e}")

    # =========================================================
    # 查詢 cti-reports (內部歷史)
    # 目的：找出「以前遇過這件事嗎？」
    # =========================================================
    try:
        report_response = client.search(
            index="cti-reports",
            body={
                "size": top_k,
                "query": {
                    "more_like_this": {
                        # 在這些欄位中尋找相似內容
                        "fields": ["content", "analysis_summary", "log_text"],
                        "like": search_query,
                        "min_term_freq": 1,
                        "max_query_terms": 12
                    }
                }
            }
        )
        
        hits = report_response.get("hits", {}).get("hits", [])
        if hits:
            history = []
            for hit in hits:
                src = hit["_source"]
                # 排除自己 (如果是重跑的話)
                if src.get("content") == text_content: continue
                
                # 格式：日期 | 檔名 | 摘要
                info = f"- {src.get('timestamp', 'Unknown Date')[:10]} | {src.get('filename', 'Unknown')}: {src.get('analysis_summary', 'No summary')[:150]}..."
                history.append(info)
            
            if history:
                context_parts.append("\n  [Similar Past Internal Incidents]:")
                context_parts.extend(history)

    except Exception as e:
        logger.warning(f"  Historical Report search failed: {e}")

    # =========================================================
    # 回傳最終組合文字
    # =========================================================
    if not context_parts:
        return ""
        
    return "\n".join(context_parts)


# ================= 🧹 自動清理舊檔案邏輯 =================
def cleanup_old_files():
    """
    定期任務：刪除 processed 資料夾中超過 RETENTION_DAYS 的舊檔案
    """
    RETENTION_DAYS = 30  #  設定保留幾天
    cutoff_time = time.time() - (RETENTION_DAYS * 86400) # 計算截止時間戳
    
    logger.info(f"🧹 [Cleanup] Starting cleanup of files older than {RETENTION_DAYS} days...")
    
    deleted_count = 0
    try:
        # 掃描 processed 資料夾
        for filename in os.listdir(PROCESSED_DIR):
            file_path = os.path.join(PROCESSED_DIR, filename)
            
            # 只處理檔案，不處理資料夾
            if os.path.isfile(file_path):
                file_mtime = os.path.getmtime(file_path)
                
                # 如果檔案修改時間早於截止時間，就刪除
                if file_mtime < cutoff_time:
                    try:
                        os.remove(file_path)
                        deleted_count += 1
                    except OSError as e:
                        logger.error(f"  Failed to delete {filename}: {e}")
                        
        if deleted_count > 0:
            logger.info(f"  [Cleanup] Deleted {deleted_count} old files.")
        else:
            logger.info("  [Cleanup] No files needed deletion.")
            
    except Exception as e:
        logger.error(f"  [Cleanup] Error during cleanup: {e}")

# ================= 自動更新排程 =================

def update_knowledge_base_job():
    """
    定期任務：執行 setup_knowledge_base.py 以更新 MITRE / AI Defense 資料
    """
    logger.info("  [CronJob] Starting scheduled Knowledge Base update (AI Defense/MITRE)...")
    try:
        # 呼叫另外一支 Python 腳本來執行下載與更新
        result = subprocess.run(
            ["python", "/app/src/setup_knowledge_base.py"], 
            capture_output=True, 
            text=True
        )
        
        if result.returncode == 0:
            logger.info("  [CronJob] Knowledge Base updated successfully.")
            # logger.info(result.stdout) # 如果要看詳細輸出可以取消註解
        else:
            logger.error(f"  [CronJob] Update script failed:\n{result.stderr}")
            
    except Exception as e:
        logger.error(f"  [CronJob] Execution error: {e}")

def run_scheduler_thread():
    """背景排程執行緒"""
    logger.info("  Scheduler initialized. AI Defense will update periodically.")
    
    # 設定排程：預設 每 12 小時更新一次
    schedule.every(12).hours.do(update_knowledge_base_job)
    # 每天凌晨 03:00 執行硬碟大掃除
    schedule.every().day.at("03:00").do(cleanup_old_files)

    # 啟動時先立即跑一次，確保資料庫有最新資料
    update_knowledge_base_job()

    while True:
        schedule.run_pending()
        time.sleep(60) # 每分鐘檢查一次是否有任務要跑

# ============================================================

def move_to_processed(file_path, filename):
    """將處理完的檔案移至 processed 資料夾"""
    # 產生時間戳記，避免檔名重複
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    processed_dest = os.path.join(PROCESSED_DIR, f"{timestamp}_{filename}")
    
    try:
        if os.path.exists(file_path):
            os.rename(file_path, processed_dest)
            logger.info(f"  File archived to: {processed_dest}")
        else:
            logger.warning(f"  File not found during archive: {file_path}")
    except OSError as e:
        logger.error(f"  Error archiving file: {e}")


def process_task(task_payload: dict, llm: LLMClient):
    """
    Worker 邏輯：支援「檔案模式」與「串流模式」的通用處理器
    Payload 格式範例：
      1. 檔案: {"file_path": "/app/data/input/LOG.txt", "filename": "LOG.txt"}
      2. 串流: {"timestamp": "...", "source_ip": "...", "message": "..."}
    """
    
    # --- 判斷來源並取得內容 ---
    file_path = None
    
    if "file_path" in task_payload:
        # [方法 A: 檔案處理] Master 的任務
        filename = task_payload.get("filename", "unknown.txt")
        file_path = task_payload["file_path"]
        logger.info(f"  [File Mode] Processing: {filename}")
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                raw_content = f.read()
        except Exception as e:
            logger.error(f"  Failed to read file: {e}")
            return
            
    else:
        # [方法 B: 串流處理] Fluent Bit 的即時 Log
        logger.info(f"⚡ [Stream Mode] Processing live log event")
        
        # 自動生成一個虛擬檔名，方便後續邏輯識別
        # 格式: LOG_STREAM_{timestamp}_{source_ip}
        ts = int(time.time())
        src_ip = task_payload.get('source_ip', 'unknown_ip')
        filename = f"LOG_STREAM_{ts}_{src_ip}"
        
        # 將 JSON 物件轉回字串，因為後面的 PII Masker 和切片器吃的是字串
        raw_content = json.dumps(task_payload, ensure_ascii=False)

    # ================= PII 遮罩 (隱私保護) =================
    masker = PIIMasker()
    safe_content = masker.mask(raw_content) 
    
    if safe_content != raw_content:
        logger.info("  PII Masking applied (Emails/Phones redacted).")

    is_log = filename.startswith("LOG_")
    normalized_data = {} # 存放結構化資料

    # ================ AI 自適應正規化  =================
    if is_log:
        try:
            # 嘗試直接解析 (如果 Fluent Bit 已經送來 JSON，這裡會成功)
            normalized_data = json.loads(safe_content)
            logger.info(f"  {filename} is valid JSON. Using natively.")
        except json.JSONDecodeError:
            # 如果是 Raw Text，呼叫 AI 進行正規化
            logger.info(f"  {filename} is raw text. Starting AI Adaptive Normalization...")
            normalized_data = llm.normalize_log(safe_content)
            
            if not normalized_data:
                normalized_data = {}
            
            # 更新 safe_content 為標準化後的 JSON 字串
            safe_content = json.dumps(normalized_data, ensure_ascii=False)
            logger.info(f"  AI Normalized Data: {safe_content}")

    # ================= 長文本切片與 AI 分析 =================
    chunks = chunk_text(safe_content)
    if len(chunks) > 1:
        logger.info(f"  Large document detected! Split into {len(chunks)} chunks.")

    chunk_results = []
    has_rag_context = False

    for i, chunk in enumerate(chunks):
        # RAG: 同時查詢知識庫與歷史報告
        rag_context = retrieve_context(chunk)
        if rag_context:
            has_rag_context = True

        enhanced_chunk = f"{rag_context}\n\n[Report Segment {i+1}]:\n{chunk}"

        try:
            chunk_extraction = llm.get_extraction(enhanced_chunk)
            if chunk_extraction:
                chunk_results.append(chunk_extraction)
        except Exception as e:
            logger.error(f"  Error analyzing chunk {i+1}: {e}")
            continue

    # ================= 合併分析結果 =================
    if not chunk_results:
        logger.warning("  LLM returned empty result for all chunks.")
        if file_path: move_to_processed(file_path, filename)
        return

    extracted = merge_extractions(chunk_results)

    # 合併正規化資料 (補齊 IP 等欄位)
    if is_log and normalized_data:
        if "source_ip" in normalized_data:
            if "indicators" not in extracted: extracted["indicators"] = {}
            if "ipv4" not in extracted["indicators"]: extracted["indicators"]["ipv4"] = []
            
            ip = normalized_data["source_ip"]
            if ip and ip not in extracted["indicators"]["ipv4"]:
                extracted["indicators"]["ipv4"].append(ip)
        
        extracted.update(normalized_data)

    logger.info(f"  Analysis Complete. Merged {len(chunk_results)} chunks.")

    # 統一欄位名稱
    if "confidence" not in extracted and "confidence_score" in extracted:
        extracted["confidence"] = extracted["confidence_score"]

    # 關鍵字強制補分
    current_score = extracted.get("confidence", 0)
    critical_keywords = [
        "CRITICAL", "RANSOMWARE", "MALWARE", "ATTACK", "BLOCKED", "CISA", 
        "JNDI", "EXPLOIT", "UNAUTHORIZED", "DENIED", "FAILED LOGIN", "ROOT", "SQL INJECTION"
    ]    
    if current_score < 50:
        content_upper = safe_content.upper()
        if any(k in content_upper for k in critical_keywords):
            logger.warning(f"  LLM gave low score ({current_score}), but found CRITICAL keywords. Overriding to 95!")
            extracted["confidence"] = 95
    
    if extracted.get("confidence") is None:
        extracted["confidence"] = 0

    # ================= 豐富化 (Enrichment) =================
    try:
        enricher = EnrichmentEngine()
        enriched_data = {}
        indicators = extracted.get("indicators", {})
        
        for ip in indicators.get("ipv4", []):
            info = enricher.enrich_ip(ip)
            if info["geo"] or info["asset"]:
                enriched_data[ip] = info
        
        extracted["enrichment"] = enriched_data
        enricher.close()
        
    except Exception as e:
        logger.error(f"  Enrichment failed: {e}")

    # ================= 1.6 CVE 漏洞關聯 =================
    try:
        cve_enricher = CVEEnricher()
        vulnerability_results = []

        ai_cve_ids = extracted.get("cve_ids", [])
        regex_cve_ids = cve_enricher.extract_cve_ids(raw_content)
        all_cve_ids = list(set(ai_cve_ids + regex_cve_ids))
        
        if all_cve_ids:
            logger.info(f"  Identifed CVEs (AI + Regex): {all_cve_ids}")

        for cid in all_cve_ids:
            if not any(v["id"] == cid for v in vulnerability_results):
                details = cve_enricher.get_cve_details(cid)
                if details:
                    vulnerability_results.append(details)

        extracted["vulnerabilities"] = vulnerability_results
        
        if any(isinstance(v.get("score"), (int, float)) and v.get("score") >= 7.0 for v in vulnerability_results):
            if extracted.get("confidence", 0) < 90:
                extracted["confidence"] = 95
                logger.warning("  Critical Vulnerability Detected! Confidence boosted to 95.")

    except Exception as e:
        logger.error(f"  CVE Enrichment Failed: {e}")

    # ================= 建立 STIX Bundle =================
    stix_bundle = build_stix_bundle(extracted)
    stix_json_str = json.dumps(stix_bundle, indent=4, ensure_ascii=False)
        
    static_out_path = os.path.join(OUTPUT_DIR, "bundle_stix21.json")
    with open(static_out_path, "w", encoding="utf-8") as f:
        f.write(stix_json_str)

    # ================= 智慧分流路由邏輯 ===================
    is_log = filename.startswith("LOG_")               # 確保 is_log 定義清晰
    is_rss = filename.startswith("RSS_")
    is_otx = filename.startswith("OTX_CTI_")           # 辨識 OTX 來源
    is_abusech = filename.startswith("ABUSECH_CTI_")   # 辨識 Abuse.ch 來源
    is_github = filename.startswith("GITHUB_CTI_")     # 辨識 GitHub 來源
    is_premium_feed = is_otx or is_abusech or is_github # 統稱為專業威脅情資

    confidence = extracted.get("confidence", 0)
    threat_matched = has_rag_context 

    # 定義「有實質指標」的情報：包含 ipv4, domains, urls, cve_ids
    has_indicators = bool(extracted.get("indicators", {}).get("ipv4") or 
                          extracted.get("indicators", {}).get("domains") or 
                          extracted.get("indicators", {}).get("urls") or 
                          extracted.get("cve_ids"))

    # 定義自動通關條件 (Auto-Pilot Condition)
    auto_pilot_condition = (
        is_rss or 
        (is_log and (confidence >= 80 or threat_matched)) or
        (is_premium_feed and confidence >= 70 and has_indicators)
    )

    # 1. 自動化通道 (Auto-Pilot)
    if auto_pilot_condition:
        
        # 依據不同來源給予不同的觸發原因日誌
        if is_rss:
            trigger_reason = "RSS Feed"
        elif is_otx:
            trigger_reason = f"AlienVault OTX Pulse ({confidence}%)"
        elif is_abusech:
            trigger_reason = f"Abuse.ch Malware IoC ({confidence}%)"
        elif is_github:
            trigger_reason = f"GitHub Security Advisory ({confidence}%)"
        else:
            trigger_reason = f"High Confidence Log ({confidence}%)"
            
        logger.info(f"  Automated Pipeline Triggered [{trigger_reason}]. Blocking & Reporting...")

        pdf_filename = f"{os.path.splitext(filename)[0]}.pdf"
        pdf_path = os.path.join("data/reports", pdf_filename)
        generate_pdf_report(extracted, pdf_path)
        
        indicators = extracted.get("indicators", {})
        report_info = {"filename": filename, "confidence": confidence}
        
        for ip in indicators.get("ipv4", []):
            upsert_indicator(ip, "ipv4", report_info)
        for domain in indicators.get("domains", []):
            upsert_indicator(domain, "domain", report_info)

        doc = extracted.copy()
        
        # 依據來源設定資料庫中的 source_type 標籤
        if is_rss:
            src_type = "rss"
        elif is_premium_feed:
            src_type = "premium_cti_feed"
        else:
            src_type = "log_automation"

        doc.update({
            "filename": filename,
            "timestamp": datetime.now().isoformat(),
            "expiration_date": (datetime.now() + timedelta(days=30)).isoformat(),
            "pdf_path": pdf_path,
            "source_type": src_type,
            "threat_matched": threat_matched
        })
        
        report_id = os.path.splitext(filename)[0] 
        upload_to_os_lib(doc, report_id, "cti-reports")

        # 同步寫入 SOC Dashboard (只處理 is_log)
        if is_log:
            soc_doc = doc.copy()
            first_ip = indicators.get("ipv4", [None])[0]
            soc_doc["source_ip"] = first_ip if first_ip else "Unknown"
            soc_doc["log_text"] = raw_content
            soc_doc["message"] = raw_content
            soc_doc["threat_matched"] = True 
            soc_doc["attack_type"] = extracted.get("attack_type", "High Confidence Threat")
            soc_doc["severity"] = "Critical" if confidence >= 90 else "High"
            soc_doc["mitigation_status"] = "Blocked  "
            
            upload_to_os_lib(soc_doc, f"log_{report_id}", "security-logs-knn")
            logger.info(f"  Synced to SOC Dashboard (security-logs-knn)")

    # 2. 噪音過濾通道 (直接丟棄/不處理)
    elif (is_log and confidence < 40) or (is_premium_feed and confidence < 50):
        # 如果情報解析失敗或被 AI 判定為無用雜訊，則過濾掉
        logger.info(f"  Low confidence data ({confidence}%). Archiving without review.")

    # 3. 人工審核通道 (Human-in-the-Loop)
    else:
        # 邊緣案例，例如有情報但 AI 不太確定，丟給人工審核
        if is_log:
            source_type = "suspicious_log"
            log_msg = f"🤔 Suspicious Log ({confidence}%). Sending to Human Review..."
        elif is_premium_feed:
            source_type = "unverified_cti_feed"
            log_msg = f"🤔 Unverified Premium CTI ({confidence}%). Sending to Human Review..."
        else:
            source_type = "manual"
            log_msg = f"🤔 Ambiguous Manual Upload ({confidence}%). Sending to Human Review..."
            
        logger.info(log_msg)
        
        insert_task(
            filename=filename,
            source_type=source_type,
            raw_content=safe_content,
            analysis_json=extracted,
            confidence=confidence
        )
    # ================= 將分析結果存為 JSON 備份 =================
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # 如果是串流模式，filename 已經包含時間戳，這裡再加一次前綴或是可以簡化
        json_filename = f"{timestamp}_{os.path.splitext(filename)[0]}.json"
        json_path = os.path.join(PROCESSED_DIR, json_filename)
        
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(extracted, f, indent=4, ensure_ascii=False)
            
        logger.info(f"  Analysis JSON saved to: {json_path}")
    except Exception as e:
        logger.error(f"  Failed to save JSON file: {e}")

    # ================= 歸檔 (只針對檔案模式) =================
    if file_path:
        move_to_processed(file_path, filename)


# --- Master: 監控檔案並發送任務 ---
def run_master():
    logger.info("  CTI Master Started. Monitoring data/input/ ...")
    
    # 啟動背景更新執行緒 (排程器)
    updater_thread = threading.Thread(target=run_scheduler_thread, daemon=True)
    updater_thread.start()
    
    while True: # 第一層：連線重試
        connection = None
        try:
            connection, channel = get_rabbitmq_connection()
            
            # 宣告 Exchange 和 Queue 拓樸
            # 為了確保 Master 發出去的任務，跟 Fluent Bit 發出去的 Log，都走同一條路
            channel.exchange_declare(exchange='cti_exchange', exchange_type='direct')
            channel.queue_declare(queue=RABBITMQ_QUEUE, durable=True)
            channel.queue_bind(exchange='cti_exchange', queue=RABBITMQ_QUEUE, routing_key='cti_queue')
            
            logger.info("  Master connected to RabbitMQ (Binding: cti_exchange -> cti_queue).")

            while True: # 第二層：監控迴圈
                # 檢查連線
                if connection.is_closed:
                    raise pika.exceptions.AMQPConnectionError("Connection closed")

                # 掃描 txt 檔案
                files = glob.glob(os.path.join(INPUT_DIR, "*.txt"))
                for file_path in files:
                    filename = os.path.basename(file_path)
                    
                    # 跳過已經被鎖定的檔案
                    if filename.endswith(".processing"):
                        continue

                    logger.info(f"📂 Found new file: {filename}")
                    
                    # 鎖定檔案 (改名)
                    processing_path = file_path + ".processing"
                    try:
                        os.rename(file_path, processing_path)
                    except OSError:
                        continue # 可能被其他 process 搶走了

                    # 發送任務
                    task_payload = json.dumps({
                        "file_path": processing_path,
                        "filename": filename
                    })
                    
                    try:
                        # 發送至指定的 Exchange 和 Routing Key
                        channel.basic_publish(
                            exchange='cti_exchange',  # 指定交換機
                            routing_key='cti_queue',  # 指定路由鍵 (跟 Fluent Bit 一樣)
                            body=task_payload,
                            properties=pika.BasicProperties(delivery_mode=2) 
                        )
                        logger.info(f"  Task queued: {filename}")
                        
                    except (pika.exceptions.AMQPError, pika.exceptions.StreamLostError) as e:
                        # 這是連線問題，需要讓外層迴圈重連
                        logger.error(f"  RabbitMQ Error during publish: {e}")
                        os.rename(processing_path, file_path) # 復原檔案
                        raise e # 拋出錯誤讓外層 while True 重連
                    except Exception as e:
                        # 這是程式邏輯或其他問題 (例如 JSON 錯誤)，不要讓 Master 崩潰重啟
                        logger.error(f"  Logical Error during publish: {e}")
                        os.rename(processing_path, file_path)
                        # 不要 raise，讓它繼續處理下一個檔案，避免卡死

                time.sleep(2) # 輪詢間隔

        except (pika.exceptions.AMQPError, pika.exceptions.AMQPConnectionError) as e:
            logger.error(f"  Master connection lost: {e}. Retrying in 5s...")
            time.sleep(5)
        except Exception as e:
            logger.error(f"  Master unexpected error: {e}. Restarting in 10s...")
            time.sleep(10)

# --- Worker: 從 Queue 領任務 ---
def run_worker():
    logger.info("  CTI Worker Started. Waiting for tasks...")
    llm = LLMClient()
    
    while True:
        try:
            connection, channel = get_rabbitmq_connection()
            
            # 宣告 Exchange 與 Queue 綁定 (跟 Master/Fluent Bit 一致)
            channel.exchange_declare(exchange='cti_exchange', exchange_type='direct')
            channel.queue_declare(queue=RABBITMQ_QUEUE, durable=True)
            channel.queue_bind(exchange='cti_exchange', queue=RABBITMQ_QUEUE, routing_key='cti_queue')
            
            channel.basic_qos(prefetch_count=1)
            logger.info("  Worker connected & listening on 'cti_queue'...")

            def callback(ch, method, properties, body):
                try:
                    # 解析訊息 (可能是 Master 的檔案路徑，也可能是 Fluent Bit 的 JSON)
                    task_payload = json.loads(body)
                    
                    # 呼叫通用的處理函式
                    process_task(task_payload, llm)
                    
                    # 任務成功，發送 ACK
                    ch.basic_ack(delivery_tag=method.delivery_tag)
                    
                except Exception as e:
                    logger.error(f"  Worker task error: {e}")
                    # 避免毒藥訊息卡死，選擇 ACK 並記錄錯誤 (也可以不 ACK 直接重試)
                    ch.basic_ack(delivery_tag=method.delivery_tag)

            channel.basic_consume(queue=RABBITMQ_QUEUE, on_message_callback=callback)
            channel.start_consuming()

        except Exception as e:
            logger.error(f"  Worker error: {e}. Restarting in 5s...")
            time.sleep(5)

if __name__ == "__main__":
    ensure_dirs()
    if ROLE == 'master':
        run_master()
    else:
        run_worker()