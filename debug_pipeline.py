#!/usr/bin/env python3
"""
Diagnostic script to check RabbitMQ queue depths and OpenSearch index counts.
"""
import os
import sys
import json
import time

try:
    import pika
    from opensearchpy import OpenSearch
except ImportError:
    print("Missing dependencies. Run: pip install pika opensearch-py")
    sys.exit(1)

# Config
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "localhost")
RABBITMQ_PORT = int(os.getenv("RABBITMQ_PORT", "5672"))
RABBITMQ_USER = os.getenv("RABBITMQ_USER", "user")
RABBITMQ_PASS = os.getenv("RABBITMQ_PASS", "password")

OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", "admin")
OPENSEARCH_PASS = os.getenv("OPENSEARCH_PASS", "admin")

QUEUES = ["cti_queue", "honeypot_events", "mtd_action_queue", "mtd_approval_queue", "prediction_tasks"]
INDICES = ["security-logs-knn", "security-alerts", "attack-path-predictions", "mtd-audit-log", "cti-reports", "honeypot-telemetry"]

def check_rabbitmq():
    print(f"\n--- Checking RabbitMQ ({RABBITMQ_HOST}:{RABBITMQ_PORT}) ---")
    try:
        creds = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
        conn = pika.BlockingConnection(pika.ConnectionParameters(
            host=RABBITMQ_HOST, port=RABBITMQ_PORT, credentials=creds
        ))
        ch = conn.channel()
        
        for q in QUEUES:
            try:
                # Passive declare checks if queue exists and returns message count
                q_state = ch.queue_declare(queue=q, passive=True)
                count = q_state.method.message_count
                status = "✅ OK" if count < 100 else "⚠️ BACKLOG"
                print(f"  Queue '{q}': {count} messages ({status})")
            except pika.exceptions.ChannelClosedByBroker:
                print(f"  Queue '{q}': ❌ Not Found")
                # Re-open channel if closed
                ch = conn.channel()
            except Exception as e:
                print(f"  Queue '{q}': ❌ Error ({e})")
        conn.close()
    except Exception as e:
        print(f"  ❌ Connection Failed: {e}")

def check_opensearch():
    print(f"\n--- Checking OpenSearch ({OPENSEARCH_HOST}:{OPENSEARCH_PORT}) ---")
    try:
        client = OpenSearch(
            hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
            http_auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
            use_ssl=False, verify_certs=False, ssl_show_warn=False
        )
        
        if not client.ping():
            print("  ❌ Ping Failed")
            return

        for idx in INDICES:
            if client.indices.exists(index=idx):
                count = client.count(index=idx)['count']
                print(f"  Index '{idx}': {count} docs")
                
                # Check for tenant_id in a sample doc
                try:
                    res = client.search(index=idx, body={"size": 1})
                    if res['hits']['hits']:
                        src = res['hits']['hits'][0]['_source']
                        tid = src.get('tenant_id', 'MISSING')
                        print(f"    sample tenant_id: {tid}")
                except:
                    pass
            else:
                print(f"  Index '{idx}': ❌ Not Found")
                
    except Exception as e:
        print(f"  ❌ Connection Failed: {e}")

if __name__ == "__main__":
    print("🔍 Starting Pipeline Diagnosis...")
    check_rabbitmq()
    check_opensearch()
    print("\nDone.")
