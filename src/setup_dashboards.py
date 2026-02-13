import requests
import time
import os

# Dashboards 的 API 通常在 5601
DASHBOARD_HOST = "opensearch-dashboards"
DASHBOARD_PORT = "5601"
BASE_URL = f"http://{DASHBOARD_HOST}:{DASHBOARD_PORT}/api/saved_objects"

# Header 設定 (OpenSearch Dashboards 要求)
HEADERS = {
    "osd-xsrf": "true",
    "Content-Type": "application/json"
}

def wait_for_dashboards():
    print("  Waiting for OpenSearch Dashboards...")
    for _ in range(30):
        try:
            resp = requests.get(f"http://{DASHBOARD_HOST}:{DASHBOARD_PORT}/api/status")
            if resp.status_code == 200:
                print("  Dashboards is UP!")
                return True
        except:
            pass
        time.sleep(5)
    return False

def create_index_pattern(pattern_name, time_field="@timestamp"):
    """自動建立 Index Pattern"""
    payload = {
        "attributes": {
            "title": pattern_name,
            "timeFieldName": time_field
        }
    }
    
    try:
        # 檢查是否已存在
        check_url = f"{BASE_URL}/index-pattern/{pattern_name}"
        if requests.get(check_url).status_code == 200:
            print(f"  Index Pattern {pattern_name} already exists.")
            return

        # 建立新的
        resp = requests.post(f"{BASE_URL}/index-pattern/{pattern_name}", json=payload, headers=HEADERS)
        if resp.status_code == 200:
            print(f"  Created Index Pattern: {pattern_name}")
        else:
            print(f"  Failed to create {pattern_name}: {resp.text}")
            
    except Exception as e:
        print(f"  Error: {e}")

if __name__ == "__main__":
    if wait_for_dashboards():
        # 建立需要的兩個主要 Pattern
        create_index_pattern("fluent-bit-logs*", "timestamp")
        create_index_pattern("threat-matches*", "timestamp")
        create_index_pattern("stix-data*", "timestamp")