import os
import json
import pika
import uuid
from datetime import datetime
from opensearchpy import OpenSearch

# Config
# When running inside Docker, use service names. When running locally, use localhost.
# But since we are running via docker exec, we should use service names or ENV.
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "rabbitmq") 
RABBITMQ_PORT = 5672
OS_HOST = os.getenv("OPENSEARCH_HOST", "opensearch-node")
OS_PORT = 9200
OS_AUTH = ("admin", "admin")

def get_os_client():
    return OpenSearch(
        hosts=[{'host': OS_HOST, 'port': OS_PORT}],
        http_compress=True,
        http_auth=OS_AUTH,
        use_ssl=False,
        verify_certs=False,
        ssl_assert_hostname=False,
        ssl_show_warn=False
    )

def seed_rabbitmq():
    try:
        credentials = pika.PlainCredentials('user', 'password')
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=RABBITMQ_HOST, port=RABBITMQ_PORT, credentials=credentials)
        )
        channel = connection.channel()
        channel.queue_declare(queue='cti_tasks', durable=True)

        # 1. Tenant Alpha - Critical Attack
        payload_1 = {
            "source_ip": "192.168.1.100",
            "message": "Failed password for root from 192.168.1.100 port 22 ssh2",
            "tenant_id": "tenant_alpha",
            "timestamp": datetime.now().isoformat()
        }
        channel.basic_publish(
            exchange='',
            routing_key='cti_tasks',
            body=json.dumps(payload_1)
        )
        print("✅ Sent Tenant Alpha Task")

        # 2. Tenant Beta - Normal Traffic
        payload_2 = {
            "source_ip": "10.0.0.5",
            "message": "Accepted password for user admin",
            "tenant_id": "tenant_beta",
            "timestamp": datetime.now().isoformat()
        }
        channel.basic_publish(
            exchange='',
            routing_key='cti_tasks',
            body=json.dumps(payload_2)
        )
        print("✅ Sent Tenant Beta Task")

        connection.close()
    except Exception as e:
        print(f"❌ RabbitMQ Error: {e}")

def seed_opensearch():
    client = get_os_client()
    
    # 1. Audit Logs (RBAC)
    audit_doc = {
        "timestamp": datetime.now().isoformat(),
        "actor": "admin",
        "action": "ROLLBACK_BLOCK",
        "target": "185.156.72.11",
        "status": "SUCCESS",
        "justification": "False Positive confirmed by CTI.",
        "role": "Tier2_Analyst",
        "session_id": str(uuid.uuid4()),
        "tenant_id": "tenant_alpha"
    }
    client.index(index="soc-audit-logs", body=audit_doc)
    print("✅ Indexed Audit Log")

    # 2. CTI Report (Knowledge Base)
    report_doc = {
        "filename": "APT29_Analysis.pdf",
        "timestamp": datetime.now().isoformat(),
        "source_type": "External CTI",
        "confidence": 95,
        "indicators": {"ipv4": ["185.156.72.11"], "domains": ["evil-corp.com"]},
        "ttps": [{"id": "T1110", "name": "Brute Force"}],
        "threat_matched": True,
        "tenant_id": "tenant_alpha"
    }
    client.index(index="cti-reports", body=report_doc)
    print("✅ Indexed CTI Report")
    
    # 3. Security Alerts (Enriched)
    alert_doc = {
        "timestamp": datetime.now().isoformat(),
        "rule_name": "Suspicious RDP Activity",
        "source_ip": "45.1.2.3",
        "asset_hostname": "finance-server-01",
        "asset_department": "Finance",
        "asset_criticality": "CRITICAL",
        "asset_owner": "John Doe",
        "status": "New",
        "log_excerpt": "RDP Login Failed 50 times in 1 minute.",
        "tenant_id": "tenant_alpha"
    }
    client.index(index="security-alerts", body=alert_doc)
    print("✅ Indexed Security Alert")

if __name__ == "__main__":
    seed_rabbitmq()
    seed_opensearch()
