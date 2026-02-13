import os
import requests
import json
import time
from dotenv import load_dotenv

load_dotenv()

# 設定 (改回 HTTP)
HOST = os.getenv("OPENSEARCH_HOST", "localhost")
PORT = os.getenv("OPENSEARCH_PORT", "9200")
AUTH = (os.getenv("OPENSEARCH_USER", "admin"), os.getenv("OPENSEARCH_PASSWORD", "admin"))
API_BASE = f"http://{HOST}:{PORT}/_plugins/_anomaly_detection/detectors"

def delete_existing_detector(name_pattern="layer6"):
    """
    先找出舊的偵測器並刪除，確保設定能更新
    """
    search_url = f"{API_BASE}/_search"
    query = {
        "query": {
            "wildcard": {"name": f"*{name_pattern}*"}
        }
    }
    try:
        resp = requests.post(search_url, auth=AUTH, json=query)
        if resp.status_code == 200:
            hits = resp.json().get("hits", {}).get("hits", [])
            for hit in hits:
                det_id = hit["_id"]
                det_name = hit["_source"]["name"]
                print(f"🗑️ Deleting old detector: {det_name} ({det_id})...")
                requests.delete(f"{API_BASE}/{det_id}", auth=AUTH)
    except Exception as e:
        print(f"  Error checking existing detectors: {e}")

def create_detector():
    headers = {"Content-Type": "application/json"}
    
    detector_config = {
        "name": "layer6-high-traffic-detector-v2", # 改個名字確保是新的
        "description": "Detects unusual spikes (DDoS/Brute Force)",
        "time_field": "timestamp", # 這裡確認是用 timestamp (沒有 @)
        "indices": ["security-logs*"],
        "feature_attributes": [
            {
                "feature_name": "log_volume", # 改個名字
                "feature_enabled": True,
                "aggregation_query": {
                    "log_volume": {
                        "value_count": {
                            "field": "timestamp"
                        }
                    }
                }
            }
        ],
        "detection_interval": {
            "period": {"interval": 1, "unit": "Minutes"}
        },
        "window_delay": {
            "period": {"interval": 1, "unit": "Minutes"}
        }
    }

    print(f"  Creating RCF Detector on {API_BASE}...")
    response = requests.post(API_BASE, auth=AUTH, json=detector_config, headers=headers)

    if response.status_code in [201, 200]:
        det_id = response.json()["_id"]
        print(f"  Detector Created Successfully! ID: {det_id}")
        return det_id
    else:
        print(f"  Error creating detector: {response.text}")
        return None

def start_detector(detector_id):
    if not detector_id: return
    url = f"{API_BASE}/{detector_id}/_start"
    response = requests.post(url, auth=AUTH)
    if response.status_code == 200:
        print("  Detector Started! RCF is now learning...")
    else:
        print(f"  Failed to start: {response.text}")

if __name__ == "__main__":
    # 先清乾淨
    delete_existing_detector()
    # 建立新的
    new_id = create_detector()
    # 啟動
    start_detector(new_id)