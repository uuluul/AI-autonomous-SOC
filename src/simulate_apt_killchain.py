
import pika
import json
import time
import uuid
import os
import random

# RabbitMQ Config
RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'localhost')
RABBITMQ_QUEUE = 'cti_queue'
RABBITMQ_USER = os.getenv('RABBITMQ_DEFAULT_USER', 'user')
RABBITMQ_PASS = os.getenv('RABBITMQ_DEFAULT_PASS', 'password')

def send_apt_signals():
    print(f"Initiating APT-29 Kill Chain Simulation...")
    print(f"Connecting to RabbitMQ at {RABBITMQ_HOST}...")

    try:
        credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials)
        )
        channel = connection.channel()
        channel.queue_declare(queue=RABBITMQ_QUEUE, durable=True)

        # 1. Initial Access (Phishing / Spearphishing)
        msg_1 = {
            "id": str(uuid.uuid4()),
            "type": "cti_report",
            "source": "RecordedFuture",
            "message": "Detected spearphishing campaign targeting HR department with subject 'Q3 Bonus Plan'. Malicious attachment 'bonus_plan.xlsm' contains macros executng PowerShell.",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tenant_id": "default",
            "indicators": ["192.168.1.105", "10.0.0.15"],
            "confidence": 95,
            "attack_type": "Phishing"
        }
        
        # 2. Lateral Movement (RDP / SMB)
        msg_2 = {
            "id": str(uuid.uuid4()),
            "type": "cti_report",
            "source": "CrowdStrike",
            "message": "Lateral movement detected from 10.0.0.15 to 10.0.0.20 via SMB. T1021.002. Suspicious service installation 'svc_updater'.",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tenant_id": "default",
            "indicators": ["10.0.0.15", "10.0.0.20"],
            "confidence": 90,
            "attack_type": "Lateral Movement"
        }

        # 3. Credential Access (LSASS Dump) - Trigger Red Team
        msg_3 = {
            "id": str(uuid.uuid4()),
            "type": "cti_report",
            "source": "DarkTrace",
            "message": "CRITICAL: LSASS memory dump attempt detected on DC-01 (10.0.0.5). T1003.001. User 'svc_backup' compromised. Potential Golden Ticket attack.",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tenant_id": "default",
            "indicators": ["10.0.0.5", "svc_backup"],
            "confidence": 99,
            "attack_type": "Credential Dumping"
        }

        kill_chain = [msg_1, msg_2, msg_3]

        for i, msg in enumerate(kill_chain):
            channel.basic_publish(
                exchange='',
                routing_key=RABBITMQ_QUEUE,
                body=json.dumps(msg),
                properties=pika.BasicProperties(delivery_mode=2)
            )
            print(f"  [Step {i+1}/3] Sent CTI Report: {msg['source']}")
            time.sleep(1) # Pace the attack

        connection.close()
        print("APT Simulation Complete. Indicators injected into pipeline.")
        return True

    except Exception as e:
        print(f"[ERROR] Failed to send APT signals: {e}")
        return False

if __name__ == "__main__":
    if send_apt_signals():
        exit(0)
    else:
        exit(1)
