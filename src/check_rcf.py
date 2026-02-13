import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()

HOST = os.getenv("OPENSEARCH_HOST", "localhost")
PORT = os.getenv("OPENSEARCH_PORT", "9200")
AUTH = (os.getenv("OPENSEARCH_USER", "admin"), os.getenv("OPENSEARCH_PASSWORD", "admin"))

# 這是查詢「異常結果」的 API
RESULT_URL = f"http://{HOST}:{PORT}/_plugins/_anomaly_detection/detectors/results/_search" # <-- 正確

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_anomalies():
    print("  Checking for RCF Anomalies in the last 10 minutes...")
    
    query = {
        "size": 5,
        "sort": [{"data_start_time": "desc"}], # 抓最新的結果
        "query": {
            "bool": {
                "filter": [
                    {"range": {"anomaly_grade": {"gt": 0}}} # 只找有異常分數的 (Grade > 0)
                ]
            }
        }
    }

    response = requests.post(RESULT_URL, auth=AUTH, json=query, verify=False)
    
    if response.status_code == 200:
        hits = response.json().get("hits", {}).get("hits", [])
        if not hits:
            print("  No anomalies detected (System is stable).")
        else:
            print(f"  Found {len(hits)} Anomalies!")
            for hit in hits:
                source = hit["_source"]
                grade = source["anomaly_grade"]
                confidence = source["confidence"]
                time_start = source["data_start_time"]
                print(f"     [Time: {time_start}] Grade: {grade:.2f} (Confidence: {confidence:.2f})")
                if grade > 0.8:
                    print("        CRITICAL ALERT: High probability of Attack!")
    else:
        print(f"  Error querying results: {response.text}")

if __name__ == "__main__":
    check_anomalies()