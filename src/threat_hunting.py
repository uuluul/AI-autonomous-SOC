import os
import time
import json
import logging
from datetime import datetime, timedelta
from opensearchpy import OpenSearch
from to_pdf import generate_pdf_report
from src.utils import send_webhook_notification
from pii_masker import PIIMasker
from firewall_mock import FirewallClient

# 設定 Log
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [Hunter] - %(message)s')
logger = logging.getLogger(__name__)

# 初始化防火牆
fw_client = FirewallClient(vendor="PaloAlto-NGFW")

# OpenSearch 連線設定
HOST = os.getenv("OPENSEARCH_HOST", "opensearch-node")
PORT = os.getenv("OPENSEARCH_PORT", "9200")
USER = os.getenv("OPENSEARCH_USER", "admin")
PASS = os.getenv("OPENSEARCH_PASSWORD", "admin")
AUTH = (USER, PASS)

# 建立 OpenSearch 客戶端物件，不然 client.update 會報錯
client = OpenSearch(
    hosts=[{'host': HOST, 'port': PORT}],
    http_auth=AUTH,
    use_ssl=False,
    verify_certs=False,
    ssl_show_warn=False
)

# 定義索引名稱
INDEX_LOGS = "security-logs-knn"
INDEX_CTI = "cti-reports"
INDEX_MATCHES = "threat-matches"

# 輸出資料夾
OUTPUT_DIR = "data/reports"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def get_active_indicators():
    """
    從去重後的指標索引 (cti-indicators) 中提取惡意 IP
    """
    # 定義查詢：只抓去重指標索引中，尚未過期的資料
    query = {
        "size": 5000,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"expiration_date": {"gte": "now"}}}, # 只抓尚未過期的
                    {"term": {"type": "ipv4"}} # 只抓 IPv4，避免抓到 Domain 導致 Log 比對不到
                ]
            }
        }
    }
    
    try:
        # 從 cti-indicators 索引讀取
        resp = client.search(index="cti-indicators", body=query)
        active_threats = {}
        
        for hit in resp["hits"]["hits"]:
            src = hit["_source"]
            indicator_val = src.get("value")
            
            # 取得該指標關聯的所有報告中，最近的一份
            # reports[-1] 代表最新的那一份
            reports = src.get("related_reports", ["Unknown"])
            
            if indicator_val:
                active_threats[indicator_val] = reports[-1]
            
        logger.info(f"  [Hunter] Loaded {len(active_threats)} UNIQUE indicators (Deduplicated)")
        return active_threats
        
    except Exception as e:
        logger.error(f"  Error fetching unique indicators: {e}")
        return {}
    
def hunt_in_logs(active_threats):
    """
    在 Log 中搜尋這些惡意 IP
    """
    if not active_threats:
        return

    malicious_ips = list(active_threats.keys())
    
    # 搜尋條件：Source IP 在惡意名單內，且是過去 1 小時的 Log
    query = {
        "size": 100,
        "query": {
            "bool": {
                "must": [
                    {"terms": {"source_ip.keyword": malicious_ips}}, 
                    {"range": {"timestamp": {"gte": "now-1h"}}} 
                ]
            }
        }
    }

    try:
        resp = client.search(index=INDEX_LOGS, body=query) # 改用 client
        hits = resp["hits"]["hits"]
        
        if hits:
            logger.warning(f"  [Hunter] MATCH FOUND! Found {len(hits)} suspicious logs.")
            detected_map = {}

            for hit in hits:
                log_data = hit["_source"]
                doc_id = hit["_id"]
                index_name = hit["_index"]
                ip = log_data.get("source_ip")
                
                if ip and ip in active_threats:
                    detected_map[ip] = log_data
                    
                    # 記錄命中
                    record_match(log_data, active_threats[ip])

                    # 自動封鎖邏輯 (SOAR)
                    logger.info(f"⚡ Triggering SOAR Playbook for {ip}...")
                    success = fw_client.block_ip(ip)
                    
                    if success:
                        logger.info(f"  Firewall Blocked {ip}. Updating DB record...")
                        try:
                            client.update(
                                index=index_name,
                                id=doc_id,
                                body={
                                    "doc": {
                                        "threat_matched": True,
                                        "mitigation_status": "Blocked  ",
                                        "mitigation_time": datetime.now().isoformat(),
                                        "firewall_rule_id": f"FW-AUTO-{int(datetime.now().timestamp())}"
                                    }
                                }
                            )
                            logger.info("  DB Record Updated successfully.")
                        except Exception as e:
                            logger.error(f"  Failed to update DB: {e}")
                    else:
                        try:
                            client.update(
                                index=index_name,
                                id=doc_id,
                                body={"doc": {"mitigation_status": "Failed  "}}
                            )
                        except: pass

            # --- 發送報告與通知 ---
            if detected_map:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                pdf_filename = f"CRITICAL_ALERT_{timestamp}.pdf"
                pdf_path = os.path.join(OUTPUT_DIR, pdf_filename)
                
                incident_data = {
                    "filename": f"INCIDENT-{timestamp}",
                    "confidence": 100,
                    "indicators": {"ipv4": list(detected_map.keys()), "domains": [], "hashes": {}},
                    "ttps": [{"mitre_technique_id": "T1071", "name": "C2 Traffic", "description": "Internal host communicating with CTI threat."}],
                    "mitigation": ["Isolate host", "Block IP on Firewall", "Full Scan"]
                }
                
                generate_pdf_report(incident_data, pdf_path)
                
                # 發送 Webhook
                alert_msg = (
                    f"  *CRITICAL THREAT DETECTED*\n"
                    f"  *IPs*: `{', '.join(detected_map.keys())}`\n"
                    f"  *Source*: `{list(active_threats.values())[0]}`\n"
                    f"  *Action*: Firewall Block Rule Applied"
                )
                send_webhook_notification(alert_msg)

        else:
            logger.info(f"  [Hunter] No threats found in last hour.")
            
    except Exception as e:
        logger.error(f"  Error hunting logs: {e}")

def record_match(log_data, report_name):
    """
    將命中結果寫入 threat-matches 索引
    """
    match_id = f"match_{int(time.time())}_{log_data.get('source_ip')}"
    
    match_doc = {
        "timestamp": datetime.now().isoformat(),
        "source_ip": log_data.get("source_ip"),
        "dest_ip": log_data.get("dest_ip", "Unknown"),
        "related_report": report_name,
        "action": "Alert",
        "severity": "Critical",
        "mitigation": "Blocked  ", # 預設寫入已封鎖
        "description": f"Matched malicious IP from report: {report_name}"
    }
    
    try:
        client.index(index=INDEX_MATCHES, id=match_id, body=match_doc)
    except Exception as e:
        logger.error(f"  Failed to save match record: {e}")

if __name__ == "__main__":
    logger.info("  Threat Hunter Service Started...")
    time.sleep(10) 
    
    while True:
        active_threats = get_active_indicators()
        hunt_in_logs(active_threats)
        time.sleep(60)