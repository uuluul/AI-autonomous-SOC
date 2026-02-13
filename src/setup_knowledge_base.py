import requests
import json
import os
import time

# OpenSearch 連線設定
HOST = os.getenv("OPENSEARCH_HOST", "opensearch-node")
PORT = os.getenv("OPENSEARCH_PORT", "9200")
USER = os.getenv("OPENSEARCH_USER", "admin")
PASS = os.getenv("OPENSEARCH_PASSWORD", "admin")
AUTH = (USER, PASS)
BASE_URL = f"http://{HOST}:{PORT}"
INDEX_NAME = "cti-knowledge-base"

# 資料來源
MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
AIDEFEND_URL = "https://raw.githubusercontent.com/edward-playground/aidefense-framework/main/data/data.json"

def find_aidefend_nodes(node):
    """遞迴搜尋 JSON 中所有是 AIDEFEND 防禦建議的物件"""
    items = []
    if isinstance(node, dict):
        # 特徵識別：如果有 'id' 且開頭是 'AID'，或者 'key' 開頭是 'AID'
        oid = node.get("id") or node.get("key")
        name = node.get("title") or node.get("name") or node.get("label")
        
        if oid and isinstance(oid, str) and oid.startswith("AID") and name:
            items.append(node)
        
        # 繼續往下層找
        for value in node.values():
            items.extend(find_aidefend_nodes(value))
            
    elif isinstance(node, list):
        for item in node:
            items.extend(find_aidefend_nodes(item))
            
    return items

def recreate_index():
    url = f"{BASE_URL}/{INDEX_NAME}"
    try:
        requests.delete(url, auth=AUTH) # 清除舊的
    except:
        pass

    payload = {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "external_id": {"type": "keyword"},
                "name": {"type": "text"},
                "description": {"type": "text"},
                "source": {"type": "keyword"},
                "type": {"type": "keyword"}
            }
        }
    }
    requests.put(url, json=payload, auth=AUTH, headers={"Content-Type": "application/json"})
    print(f"  Index {INDEX_NAME} has been recreated.")

def download_mitre():
    print(f"  [1/2] Downloading MITRE ATT&CK...")
    try:
        data = requests.get(MITRE_URL).json()
        bulk_data = ""
        count = 0
        for obj in data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                ext_id = next((r['external_id'] for r in obj.get('external_references', []) if r['source_name'] == 'mitre-attack'), None)
                if ext_id:
                    doc = {
                        "external_id": ext_id,
                        "name": obj.get("name"),
                        "description": obj.get("description"),
                        "source": "mitre",
                        "type": "attack"
                    }
                    bulk_data += json.dumps({"index": {"_index": INDEX_NAME}}) + "\n" + json.dumps(doc) + "\n"
                    count += 1
                    if count % 500 == 0:
                        upload_bulk(bulk_data)
                        bulk_data = ""
        if bulk_data: upload_bulk(bulk_data)
        print(f"  MITRE import completed: {count} documents.")
    except Exception as e:
        print(f"  MITRE import failed: {e}")

def ensure_index_exists():
    url = f"{BASE_URL}/{INDEX_NAME}"
    
    # 檢查是否存在
    if requests.head(url, auth=AUTH).status_code == 200:
        print(f"  Index {INDEX_NAME} already exists. Ready for incremental upsert.")
        return

    # 建立索引 (對知識庫優化的 Mapping)
    payload = {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "external_id": {"type": "keyword"}, # 例如 T1059
                "name": {"type": "text", "analyzer": "standard"}, # 標題
                "description": {"type": "text", "analyzer": "english"}, # 內文
                "source": {"type": "keyword"}, # mitre 或 aidefend
                "type": {"type": "keyword"}, # attack 或 defense
                "last_updated": {"type": "date"}
            }
        }
    }
    resp = requests.put(url, json=payload, auth=AUTH, headers={"Content-Type": "application/json"})
    if resp.status_code in [200, 201]:
        print(f"  Index {INDEX_NAME} created successfully.")
    else:
        print(f"  Failed to create index: {resp.text}")


def download_aidefend():
    print(f"  [2/2] Downloading AIDEFEND defense matrix...")
    try:
        resp = requests.get(AIDEFEND_URL)
        if resp.status_code != 200:
            print(f"  Download failed. HTTP status: {resp.status_code}")
            return
        
        data = resp.json()
        
        # 使用暴力搜尋法
        items = find_aidefend_nodes(data)
        
        if not items:
            print("  Warning: Download succeeded but no AID-prefixed items were found. Please verify the JSON structure.")
            # Debug: 印出最上層的 keys 確認發生什麼事
            if isinstance(data, dict):
                print(f"Debug - Top keys: {list(data.keys())}")
            return

        bulk_data = ""
        count = 0
        for item in items:
            aid_id = item.get("id") or item.get("key")
            name = item.get("title") or item.get("name") or item.get("label")
            desc = item.get("description") or item.get("summary") or ""
            
            # 處理關聯威脅 (Mappings)
            mappings = item.get("mappings", [])
            mapped_threats = [m for m in mappings if isinstance(m, str)]
            full_desc = f"{desc} \n[Related Threats]: {', '.join(mapped_threats)}"

            doc = {
                "external_id": aid_id,
                "name": name,
                "description": full_desc,
                "source": "aidefend",
                "type": "defense"
            }
            
            bulk_data += json.dumps({"index": {"_index": INDEX_NAME}}) + "\n" + json.dumps(doc) + "\n"
            count += 1
            if count % 200 == 0:
                upload_bulk(bulk_data)
                bulk_data = ""

        if bulk_data: upload_bulk(bulk_data)
        print(f"  AIDEFEND import completed: {count} documents.")
        
    except Exception as e:
        print(f"  AIDEFEND import error: {e}")

def upload_bulk(payload):
    requests.post(f"{BASE_URL}/_bulk", data=payload, auth=AUTH, headers={"Content-Type": "application/json"})

if __name__ == "__main__":
    recreate_index()
    download_mitre()
    download_aidefend()