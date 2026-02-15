import json
import os
import yaml
import re 
from datetime import datetime, timezone
from opensearchpy import OpenSearch
from dotenv import load_dotenv
# 從 cmdb_mock 引入查詢函式
try:
    from .cmdb_mock import get_asset_context
except ImportError:
    from cmdb_mock import get_asset_context

load_dotenv()

# --- 設定區 ---
STIX_FILE = "out/bundle_stix21.json" 
LOG_INDEX = "security-logs-knn" 
ALERT_INDEX = "security-alerts"  # 儲存警報的索引

client = OpenSearch(
    hosts=[{'host': os.getenv("OPENSEARCH_HOST", "localhost"), 'port': int(os.getenv("OPENSEARCH_PORT", 9200))}],
    http_compress=True,
    use_ssl=False
)

def save_alert_to_db(rule_name, log_content, asset_info):
    """
    將豐富化後的警報資料存入 OpenSearch 供 UI 顯示
    """
    alert_doc = {
        "timestamp": datetime.now(timezone.utc).isoformat(), # 警報產生的時間
        "rule_name": rule_name,
        "log_excerpt": log_content[:500], # 紀錄部分原始 Log 作為證據
        "asset_hostname": asset_info['hostname'],
        "asset_owner": asset_info['owner'],
        "asset_department": asset_info['department'],
        "asset_criticality": asset_info['criticality'],
        "status": "New" # 狀態標記：New, Investigating, Resolved
    }
    
    try:
        res = client.index(index=ALERT_INDEX, body=alert_doc)
        print(f"     [DB SAVE] Alert saved to index {ALERT_INDEX} (ID: {res['_id']})")
    except Exception as e:
        print(f"     [DB SAVE] Failed to save alert: {e}")

def load_sigma_rules_from_stix(filepath):
    if not os.path.exists(filepath):
        print(f"    STIX file not found: {filepath}")
        return []
    with open(filepath, 'r', encoding='utf-8') as f:
        bundle = json.load(f)
    sigma_rules = []
    for obj in bundle.get("objects", []):
        if obj.get("type") == "indicator":
            print(f"    Found indicator: {obj.get('name')} | Type: {obj.get('pattern_type')}")
        if obj.get("type") == "indicator" and obj.get("pattern_type") == "sigma":
            try:
                rule_content = yaml.safe_load(obj.get("pattern", ""))
                sigma_rules.append({"name": obj.get("name"), "rule": rule_content})
            except yaml.YAMLError as e:
                print(f"    Failed to parse Sigma YAML: {e}")
    print(f"    Loaded {len(sigma_rules)} Sigma detection rules from STIX")
    return sigma_rules

def convert_sigma_to_query(sigma_rule):
    detection = sigma_rule.get("detection", {})
    keywords = detection.get("keywords", [])
    if not keywords: return None
    should_clauses = []
    for k in keywords:
        should_clauses.append({"match_phrase": {"log_text": k}})
        should_clauses.append({"match_phrase": {"message": k}})
    return {"query": {"bool": {"should": should_clauses, "minimum_should_match": 1}}}

def extract_ip_from_text(text):
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    match = re.search(ip_pattern, text)
    return match.group(0) if match else None

def run_sigma_detection(sigma_rules):
    """
    執行偵測、CMDB 豐富化、並存入資料庫
    """
    print(f"\n  [AUTO DEFENSE] Scanning OpenSearch index: {LOG_INDEX}")
    
    for rule_entry in sigma_rules:
        name = rule_entry["name"]
        query = convert_sigma_to_query(rule_entry["rule"])
        if not query: continue
            
        print(f"  Executing rule: {name}...")
        
        try:
            response = client.search(body=query, index=LOG_INDEX)
            hits = response['hits']['total']['value']
            
            if hits > 0:
                print(f"\n  [ALERT] Rule matched! Found {hits} suspicious events.")
                
                for hit in response['hits']['hits']:
                    source_log = hit['_source']
                    log_content = source_log.get('message') or source_log.get('log_text') or "No content"                    
                    # 豐富化：向 CMDB 查詢
                    target_ip = extract_ip_from_text(log_content)
                    asset_info = get_asset_context(target_ip)
                    
                    # 顯示資訊
                    print(f"     Matched log: {log_content[:100]}...")
                    print(f"     Impacted asset: {asset_info['hostname']} | Department: {asset_info['department']}")
                    
                    # 將豐富化後的警報存回資料庫
                    save_alert_to_db(name, log_content, asset_info)
                    
                    # 如果等級是最高，可以額外標記
                    if asset_info['criticality'] == "CRITICAL":
                        print(f"     [AUTOMATED RESPONSE] Critical asset appears to be under threat!")
            else:
                print(f"  No matches. No relevant threats detected.")
        except Exception as e:
            print(f"  Detection execution error: {e}")

def main():
    sigma_rules = load_sigma_rules_from_stix(STIX_FILE)
    if not sigma_rules:
        print("  No valid rules to execute. Please verify the CTI pipeline has produced the STIX output.")
        return
    run_sigma_detection(sigma_rules)

if __name__ == "__main__":
    main()