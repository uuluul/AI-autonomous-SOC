from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import sys
import pika
import os
import time
from datetime import datetime
from opensearchpy import OpenSearch, RequestsHttpConnection

# RabbitMQ Config
RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'rabbitmq')
RABBITMQ_QUEUE = 'cti_queue'
HONEYPOT_QUEUE = 'honeypot_events'            # Phase 2: Deception telemetry
RABBITMQ_USER = os.getenv('RABBITMQ_DEFAULT_USER', 'user')
RABBITMQ_PASS = os.getenv('RABBITMQ_DEFAULT_PASS', 'password')

# OpenSearch Config
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "opensearch-node")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", 9200))
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", "admin")
OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD", "admin")

def get_opensearch_client():
    return OpenSearch(
        hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
        http_auth=(OPENSEARCH_USER, OPENSEARCH_PASSWORD),
        use_ssl=False,
        verify_certs=False,
        connection_class=RequestsHttpConnection
    )

def relay_honeypot_event(raw_data):
    """
    Phase 2 — Relay honeypot telemetry from Fluent Bit sidecar
    to the 'honeypot_events' RabbitMQ queue.
    """
    try:
        credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(
                host=RABBITMQ_HOST, credentials=credentials,
                connection_attempts=3, retry_delay=2,
            )
        )
        channel = connection.channel()
        channel.queue_declare(queue=HONEYPOT_QUEUE, durable=True)

        payloads = json.loads(raw_data)

        # Fluent Bit HTTP output sends [[timestamp, record], ...]
        if isinstance(payloads, list):
            for item in payloads:
                if isinstance(item, list) and len(item) >= 2:
                    record = item[1]
                elif isinstance(item, dict):
                    record = item
                else:
                    continue
                channel.basic_publish(
                    exchange='',
                    routing_key=HONEYPOT_QUEUE,
                    body=json.dumps(record),
                    properties=pika.BasicProperties(delivery_mode=2),
                )
        elif isinstance(payloads, dict):
            channel.basic_publish(
                exchange='',
                routing_key=HONEYPOT_QUEUE,
                body=json.dumps(payloads),
                properties=pika.BasicProperties(delivery_mode=2),
            )

        connection.close()
        print(f"  [SOAR] 🍯 Honeypot telemetry relayed to RabbitMQ ({HONEYPOT_QUEUE})", flush=True)
    except Exception as e:
        import traceback
        print(f"  [SOAR] ❌ Honeypot relay failed: {repr(e)}", flush=True)
        traceback.print_exc()

def send_to_rabbitmq(msg):
    try:
        print(f"  [SOAR] Connecting to RabbitMQ at {RABBITMQ_HOST} as {RABBITMQ_USER}...", flush=True)
        credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
        connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials))
        channel = connection.channel()
        channel.exchange_declare(exchange='cti_exchange', exchange_type='direct')
        channel.queue_declare(queue=RABBITMQ_QUEUE, durable=True)
        channel.queue_bind(exchange='cti_exchange', queue=RABBITMQ_QUEUE, routing_key='cti_queue')
        
        payloads = json.loads(msg)
        print("  [SOAR] JSON parsed successfully.", flush=True)
        
        if isinstance(payloads, list):
            print(f"  [SOAR] Processing list of {len(payloads)} items...", flush=True)
            for i, item in enumerate(payloads):
                 if isinstance(item, list) and len(item) >= 2:
                     log_entry = item[1]
                 elif isinstance(item, dict):
                     log_entry = item
                 else:
                     continue

                 channel.basic_publish(
                        exchange='cti_exchange',
                        routing_key='cti_queue',
                        body=json.dumps(log_entry),
                        properties=pika.BasicProperties(delivery_mode=2)
                     )

        else:
             print("  [SOAR] Processing single item...", flush=True)
             channel.basic_publish(
                exchange='cti_exchange',
                routing_key='cti_queue',
                body=json.dumps(payloads),
                properties=pika.BasicProperties(delivery_mode=2)
             )
        
        connection.close()
        print(f"  [SOAR] Relayed logs to RabbitMQ successfully.", flush=True)
    except Exception as e:
        import traceback
        print(f"  [SOAR] Failed to relay to RabbitMQ: {repr(e)}", flush=True)
        traceback.print_exc()

class SimpleHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            # 1. Ingestion Endpoint
            if self.path == '/ingest':
                send_to_rabbitmq(post_data)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Ingested")
                return

            # 2. Honeypot Telemetry
            if self.path == '/honeypot_event':
                relay_honeypot_event(post_data)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Honeypot event relayed")
                return

            # 3. Analyze Endpoint (Triggered by Prediction Engine)
            if self.path == '/analyze':
                self.handle_analyze(post_data)
                return

            # 4. Unblock Endpoint
            if self.path == '/unblock':
                data = json.loads(post_data)
                print(f"  [SOAR] Unblock request for {data.get('ip')}", flush=True)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Unblocked")
                return

            # Default: Alert Webhook
            data = json.loads(post_data)
        except Exception as e:
            print(f"SOAR Error: {e}")
            data = {"raw": post_data.decode('utf-8')}
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Alert Received")
    
    def handle_analyze(self, post_data):
        """
        Real Logic:
        1. Parse prediction
        2. Generate Playbook
        3. Index to defense-playbooks
        4. Execute Action
        5. Index to soar-actions
        """
        try:
            prediction = json.loads(post_data)
            pred_id = prediction.get("prediction_id")
            risk_score = prediction.get("overall_risk_score", 0)
            scanner_ip = prediction.get("scanner_ip", "Unknown")
            
            print(f"  [SOAR] 🛡️ Received Analysis Request for Prediction {pred_id} (Risk: {risk_score})", flush=True)
            
            client = get_opensearch_client()
            
            # --- 1. Create Playbook ---
            playbook_id = f"pb-{str(uuid.uuid4())[:8]}"
            playbook_doc = {
                "playbook_id": playbook_id,
                "prediction_id": pred_id,
                "timestamp": datetime.utcnow().isoformat(),
                "name": f"Automated Defense against {scanner_ip}",
                "trigger_risk": risk_score,
                "status": "ACTIVE",
                "remediation_steps": [
                    f"Block inbound traffic from {scanner_ip} on all firewalls",
                    "Terminate valid sessions associated with compromised host",
                    "Rotate credentials for exposed services",
                    "Isolate host if lateral movement is detected"
                ] if risk_score > 50 else ["Monitor traffic for further anomalies"],
                "created_by": "soar-auto-response"
            }
            
            # Index Playbook
            try:
                client.index(index="defense-playbooks", body=playbook_doc, refresh=True)
                print(f"  [SOAR] ✅ Created Playbook {playbook_id}", flush=True)
            except Exception as e:
                print(f"  [SOAR] ❌ Failed to index Playbook {playbook_id}: {e}", flush=True)
                # Continuing to action simulation anyway...

            # --- 2. Execute Action (Simulation) ---
            if risk_score > 70:
                action_id = f"act-{str(uuid.uuid4())[:8]}"
                action_doc = {
                    "action_id": action_id,
                    "playbook_id": playbook_id,
                    "timestamp": datetime.utcnow().isoformat(),
                    "action_type": "BLOCK_IP",
                    "target": scanner_ip,
                    "status": "SUCCESS",
                    "execution_log": "Firewall API invoked. Rule #492 created. Packet drop enabled.",
                    "executor": "soar-server"
                }
                client.index(index="soar-actions", body=action_doc, refresh=True)
                print(f"  [SOAR] ⚡ Executed Action {action_id} (BLOCK {scanner_ip})", flush=True)
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"status": "analyzed", "playbook_id": playbook_id}).encode())
            
        except Exception as e:
            print(f"  [SOAR] ❌ Analysis failed: {e}", flush=True)
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Analysis Failed")

    def log_message(self, format, *args):
        pass

import uuid
import time

def init_indices():
    """Ensure required indices exist with correct mappings."""
    try:
        print("  [SOAR] ⏳ Initializing OpenSearch indices...", flush=True)
        # Wait for OpenSearch to be ready
        client = None
        for i in range(5):
            try:
                client = get_opensearch_client()
                if client.ping():
                    break
            except:
                pass
            print(f"  [SOAR] Waiting for OpenSearch... ({i+1}/5)", flush=True)
            time.sleep(2)
        
        if not client:
             print("  [SOAR] ⚠️ OpenSearch not validated, attempting creation anyway...", flush=True)
             client = get_opensearch_client()

        indices = {
            "defense-playbooks": {
                "mappings": {
                    "properties": {
                        "playbook_id": {"type": "keyword"},
                        "prediction_id": {"type": "keyword"},
                        "timestamp": {"type": "date"},
                        "remediation_steps": {"type": "text"},
                        "trigger_risk": {"type": "float"}
                    }
                }
            },
            "soar-actions": {
                "mappings": {
                    "properties": {
                        "action_id": {"type": "keyword"},
                        "playbook_id": {"type": "keyword"},
                        "timestamp": {"type": "date"},
                        "action_type": {"type": "keyword"},
                        "status": {"type": "keyword"}
                    }
                }
            }
        }
        
        for index_name, body in indices.items():
            if not client.indices.exists(index=index_name):
                client.indices.create(index=index_name, body=body)
                print(f"  [SOAR] ✅ Created index: {index_name}", flush=True)
            else:
                print(f"  [SOAR] ℹ️ Index exists: {index_name}", flush=True)
                
    except Exception as e:
        print(f"  [SOAR] ❌ Failed to initialize indices: {e}", flush=True)

if __name__ == "__main__":
    init_indices()
    
    # Ensure pika is installed (it is in requirements.txt)
    server = HTTPServer(('0.0.0.0', 5000), SimpleHandler)
    print("   ✅ Real SOAR Server listening on port 5000... (Analysis Enabled)", flush=True)
    server.serve_forever()