import time
import random
from datetime import datetime, timezone
from opensearchpy import OpenSearch
from dotenv import load_dotenv
import os

load_dotenv()

# Client Setup (關閉 SSL)
client = OpenSearch(
    hosts=[{'host': os.getenv("OPENSEARCH_HOST", "localhost"), 'port': int(os.getenv("OPENSEARCH_PORT", 9200))}],
    http_auth=(os.getenv("OPENSEARCH_USER", "admin"), os.getenv("OPENSEARCH_PASSWORD", "admin")),
    use_ssl=False,
    verify_certs=False,
    ssl_show_warn=False
)

INDEX_NAME = "security-logs-knn"

def generate_log(message, vector_placeholder):
    doc = {
        "log_text": message,
        "log_vector": vector_placeholder,
        # 確認時間和opensearch一致
        "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    }
    client.index(index=INDEX_NAME, body=doc)

def run_simulation():
    dummy_vector = [0.1] * 1536 

    print("  Phase 1: Generating Normal Traffic (Training RCF)...")
    end_time = time.time() + 100 
    while time.time() < end_time:
        num_logs = random.randint(2, 5)
        for _ in range(num_logs):
            generate_log(f"User login success ip={random.randint(1,255)}.1.1.1", dummy_vector)
        time.sleep(1)
        print(".", end="", flush=True)
    
    print("\n\n  Phase 2: Simulating ATTACK (Anomaly)!")
    print("   (Sending 500 logs in 5 seconds - Brute Force)")
    
    for i in range(500):
        generate_log(f"User login failed password error ip=192.168.1.100", dummy_vector)
        if i % 100 == 0:
            print("!", end="", flush=True)
    
    print("\n\n  Simulation Complete.") 
    print("  PLEASE WAIT 2 MINUTES before checking results (RCF Window Delay).")

if __name__ == "__main__":
    run_simulation()