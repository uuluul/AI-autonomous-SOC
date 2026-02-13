import requests
import json
import sys
import time
import os

# 設定 OpenSearch 連線
HOST = "opensearch-node" 
PORT = "9200"

# API 端點
NOTIFICATIONS_API = f"http://{HOST}:{PORT}/_plugins/_notifications/configs"
ALERTING_API = f"http://{HOST}:{PORT}/_plugins/_alerting/monitors"

def create_channel():
    """
    建立通知通道 (Channel) - 修正 JSON 結構 加上 config 封裝
    """
    print(f"  Connecting to Notifications API: {NOTIFICATIONS_API}")
    
    payload = {
        "config": {
            "name": "SOAR Webhook Channel",
            "description": "Channel for SOAR Integration",
            "config_type": "webhook",
            "is_enabled": True,
            "webhook": {
                "url": "http://soar-server:5000/webhook",
                "method": "POST",
                "header_params": {
                    "Content-Type": "application/json"
                }
            }
        }
    }
    
    try:
        resp = requests.post(NOTIFICATIONS_API, json=payload)
        
        if resp.status_code not in [200, 201]:
            print(f"  Failed to create channel. Status: {resp.status_code}")
            print(f"Response: {resp.text}")
            return None
            
        config_id = resp.json().get("config_id")
        print(f"  Channel Created! ID: {config_id}")
        return config_id
        
    except Exception as e:
        print(f"  Error creating channel: {e}")
        return None

def create_monitor(channel_id):
    """
    建立監控器
    """
    if not channel_id:
        return

    print(f"  Creating Monitor on: {ALERTING_API}")
        
    payload = {
        "type": "monitor",
        "name": "High Severity Threat Monitor",
        "monitor_type": "query_level_monitor",
        "enabled": True,
        "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
        "inputs": [{
            "search": {
                "indices": ["fluent-bit-logs"],
                "query": {
                    "query": {
                        "match": {"action": "malicious_script_execution"}
                    }
                }
            }
        }],
        "triggers": [{
            "name": "Malicious Action Detected",
            "severity": "1",
            "condition": {
                "script": {
                    "source": "ctx.results[0].hits.total.value > 0",
                    "lang": "painless"
                }
            },
            "actions": [{
                "name": "Notify SOAR",
                "destination_id": channel_id,
                "message_template": {
                    "source": """{
                        "text": "Threat Detected!",
                        "count": "{{ctx.results.0.hits.total.value}}",
                        "timestamp": "{{ctx.periodStart}}"
                    }"""
                }
            }]
        }],
        # 防止重複建立的簡單機制
        # "ui_metadata": {"schedule": {"timezone": None, "frequency": "minutes", "period": 1}} 
    }
    
    try:
        resp = requests.post(ALERTING_API, json=payload)
        if resp.status_code in [200, 201]:
            print(f"  Monitor Created Successfully! ID: {resp.json().get('_id')}")
        else:
            print(f"  Failed to create monitor. Status: {resp.status_code}")
            print(resp.text)
    except Exception as e:
        print(f"  Error creating monitor: {e}")

def wait_for_opensearch():
    print("⏳ Waiting for OpenSearch to be ready...")
    retries = 0
    while retries < 30: # 3 分鐘
        try:
            resp = requests.get(f"http://{HOST}:{PORT}")
            if resp.status_code == 200:
                print("  OpenSearch is UP!")
                return True
        except requests.exceptions.ConnectionError:
            pass
        
        print(".", end="", flush=True)
        time.sleep(5)
        retries += 1
    print("\n  OpenSearch timeout!")
    return False

if __name__ == "__main__":
    print("  Starting SOAR Integration Setup...", flush=True)
    
    # 先等待資料庫啟動
    if wait_for_opensearch():
        # 給 Fluent Bit 一點時間建立 Index
        time.sleep(10) 
        
        channel_id = create_channel()
        if channel_id:
            create_monitor(channel_id)
    else:
        sys.exit(1)