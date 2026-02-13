import time
import os
from datetime import datetime, timezone
from dotenv import load_dotenv
load_dotenv()
from opensearchpy import OpenSearch
from .llm_client import LLMClient

llm = LLMClient()
client = OpenSearch(
    hosts=[{'host': 'localhost', 'port': 9200}],
    http_compress=True,
    use_ssl=False
)
index_name = "security-logs-knn"

# 這邊是預設的白名單
normal_logs = [
    # SSH / Login 類
    "User admin logged in successfully from IP 192.168.1.5 via SSH.",
    "User alice logged in successfully from IP 192.168.1.6 via SSH.",
    "User bob logged in successfully from IP 10.0.0.12 via VPN.",
    "Accepted password for root from 192.168.1.200 port 22 ssh2.",
    "Accepted publickey for user ubuntu from 192.168.1.15 port 54321.",
    
    # System / Service 類
    "System scheduled backup started at 02:00 AM.",
    "System backup completed successfully. Duration: 15 mins.",
    "Cron job /etc/cron.daily/logrotate executed.",
    "Service docker restarted successfully.",
    "Web server apache2 restarted successfully.",
    "Service nginx status: active (running).",
    
    # File / Database 類
    "File server synced 500 files to cloud storage.",
    "File server synced 120 files to backup drive.",
    "Database connection pool initialized with 10 connections.",
    "PostgreSQL vacuum process completed on DB_MAIN.",
    "User alice access HR database for payroll report.",
    "User bob queried inventory database for stock check.",
    
    # Network 類
    "Network interface eth0 up, speed 1000Mbps.",
    "Network interface wlan0 connected to SSID 'Office_WiFi'.",
    "Firewall allowed outgoing traffic to 8.8.8.8 on port 53.",
    "DHCP request from 00:11:22:33:44:55, assigned IP 192.168.1.101.",
    
    # Antivirus / Security 類
    "Antivirus scan completed. No threats found.",
    "Windows Defender signature updated to version 1.2.3.",
    "System integrity check passed. No changes detected.",
] * 2

def ingest_data():
    print(f"  Starting ingestion of {len(normal_logs)} baseline logs...")
    
    for log_text in normal_logs:
        try:
            print(f"Vectorizing log: {log_text[:30]}...")
            embedding = llm.get_embedding(log_text)

            doc = {
                "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                "log_text": log_text,
                "log_vector": embedding
            }
            
            client.index(index=index_name, body=doc)
            
        except Exception as e:
            print(f"  Error occurred: {e}")
            
    client.indices.refresh(index=index_name)
    print("  All baseline logs successfully ingested!")

if __name__ == "__main__":
    ingest_data()