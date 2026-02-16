from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import sys
import pika
import os

# RabbitMQ Config
RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'rabbitmq')
RABBITMQ_QUEUE = 'cti_queue'
HONEYPOT_QUEUE = 'honeypot_events'            # Phase 2: Deception telemetry
RABBITMQ_USER = os.getenv('RABBITMQ_DEFAULT_USER', 'user')
RABBITMQ_PASS = os.getenv('RABBITMQ_DEFAULT_PASS', 'password')


def relay_honeypot_event(raw_data):
    """
    Phase 2 — Relay honeypot telemetry from Fluent Bit sidecar
    to the 'honeypot_events' RabbitMQ queue.

    Path:  Fluent Bit sidecar (honeypot-net)
           → HTTP POST /honeypot_event (this endpoint)
           → RabbitMQ honeypot_events queue
           → Validation Engine
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
             # Fluent Bit HTTP format: [[timestamp, {"key": "val"}], ...]
             for i, item in enumerate(payloads):
                 print(f"  [SOAR] Item {i} type: {type(item)}, content: {item}", flush=True)
                 if isinstance(item, list) and len(item) >= 2:
                     log_entry = item[1]
                 elif isinstance(item, dict):
                     # Maybe format is different?
                     log_entry = item
                 else:
                     print(f"  [SOAR] Skipping unknown item format: {item}", flush=True)
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
            # Check path to distinguish ingestion vs alert webhook
            if self.path == '/ingest':
                # This is log ingestion from Fluent Bit
                send_to_rabbitmq(post_data)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Ingested")
                self.wfile.write(b"Ingested")
                return

            # ─── Phase 2: Honeypot Telemetry Relay ────────
            if self.path == '/honeypot_event':
                relay_honeypot_event(post_data)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Honeypot event relayed")
                return

            if self.path == '/unblock':
                data = json.loads(post_data)
                print("\n\n" + "="*50, flush=True)
                print("  [SOAR SYSTEM] RECEIVED ROLLBACK REQUEST!  ", flush=True)
                print(f"  Target IP: {data.get('ip', 'Unknown')}", flush=True)
                print("  Action: Removing Firewall Rules & Unblocking Credential...", flush=True)
                print("="*50 + "\n", flush=True)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Unblocked")
                return

            # Default: Alert Webhook (from Master/Worker)
            data = json.loads(post_data)
        except:
            data = {"raw": post_data.decode('utf-8')}
        
        print("\n\n" + "="*50, flush=True)
        print("  [SOAR SYSTEM] RECEIVED ALERT FROM OPENSEARCH!  ", flush=True)
        print(f"  Payload Received: {json.dumps(data, indent=2)}", flush=True)
        print("  Action: Blocking IP address via Firewall API...", flush=True)
        print("="*50 + "\n", flush=True)
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Alert Received")
        
        sys.stdout.flush()

    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    # Ensure pika is installed (it is in requirements.txt)
    server = HTTPServer(('0.0.0.0', 5000), SimpleHandler)
    print("   Mock SOAR Server listening on port 5000... (Unbuffered Mode)", flush=True)
    server.serve_forever()