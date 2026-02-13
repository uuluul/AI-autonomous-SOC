import time
import json
import random
import os
from datetime import datetime
import sys

LOG_DIR = "/var/log/apps"

if not os.path.exists(LOG_DIR):
    try:
        os.makedirs(LOG_DIR)
    except PermissionError:
        print(f"  Warning: Cannot create {LOG_DIR}, assuming it exists.")

LOG_FILE = os.path.join(LOG_DIR, "app.log")

def generate_log():
    """產生一筆 JSON 格式的 Log"""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "ip": f"192.168.1.{random.randint(1, 255)}",
        "action": random.choice(["login_success", "login_failed", "file_access", "process_start"]),
        "user": random.choice(["admin", "guest", "root", "unknown"]),
        "message": "System activity detected"
    }
    
    # 模擬攻擊
    if random.random() < 0.1: # 10% 機率產生攻擊
        log_entry["ip"] = "203.0.113.10"
        log_entry["action"] = "malicious_script_execution"
        log_entry["message"] = "Possible webshell detected via CMD"
        print(f"  Generating ATTACK log: {log_entry}")
    else:
        print(f"  Generating normal log")

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

if __name__ == "__main__":
    print(f"  Starting File Log Simulation -> {LOG_FILE}", flush=True)
    try:
        while True:
            generate_log()
            time.sleep(1) # 控制產生速度
    except KeyboardInterrupt:
        print("Stopped.")