import pytest
import pika
import json
import time
import uuid
import os
from opensearchpy import OpenSearch

# Configuration consistent with integration test
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "localhost")
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = 9200
OPENSEARCH_AUTH = ("admin", "admin")
QUEUE_NAME = "cti_queue"
INDEX_NAME = "security-logs-knn"

def get_opensearch_client():
    return OpenSearch(
        hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
        http_compress=True,
        http_auth=OPENSEARCH_AUTH,
        use_ssl=False,
        verify_certs=False,
        ssl_assert_hostname=False,
        ssl_show_warn=False
    )

@pytest.mark.e2e
def test_pipeline_flow():
    print(f"DEBUG: Starting E2E Clone Test. Queue: {QUEUE_NAME}, Host: {RABBITMQ_HOST}")
    
    # 1. Generate Unique Test Message mimicking the Integration Test structure
    test_id = str(uuid.uuid4())
    test_message = {
        "id": test_id,
        "type": "integration_test",
        "message": f"CRITICAL: Detected malware beaconing {test_id} to malicious C2 server.",
        "tenant_id": "default",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    
    # 2. Publish to RabbitMQ
    try:
        user = os.getenv("RABBITMQ_DEFAULT_USER", "user")
        password = os.getenv("RABBITMQ_DEFAULT_PASS", "password")
        credentials = pika.PlainCredentials(user, password)
        
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials)
        )
        channel = connection.channel()
        channel.queue_declare(queue=QUEUE_NAME, durable=True)
        
        channel.basic_publish(
            exchange='',
            routing_key=QUEUE_NAME,
            body=json.dumps(test_message),
            properties=pika.BasicProperties(
                delivery_mode=2,
            ))
        print(f"[E2E] Published message ID {test_id} to RabbitMQ")
        connection.close()
    except Exception as e:
        if os.getenv("CI") == "true":
             pytest.fail(f"RabbitMQ connection failed: {e}")
        pytest.skip(f"RabbitMQ unreachable: {e}")

    # 3. Wait for Processing
    wait_time = 20
    print(f"[E2E] Waiting {wait_time}s for worker processing...")
    time.sleep(wait_time)

    # 4. Verify in OpenSearch
    try:
        client = get_opensearch_client()
        client.indices.refresh(index=INDEX_NAME)
        
        # Search for the unique ID in the message field
        query = {
            "query": {
                "match_phrase": {
                    "message": f"CRITICAL: Detected malware beaconing {test_id} to malicious C2 server."
                }
            }
        }
        
        response = client.search(body=query, index=INDEX_NAME)
        hits = response['hits']['total']['value']
        
        if hits > 0:
            print(f"[E2E] Success! Found document: {response['hits']['hits'][0]['_id']}")
        else:
            pytest.fail("Pipeline E2E failed: Document not found in OpenSearch")
            
    except Exception as e:
        pytest.fail(f"OpenSearch query failed: {e}")