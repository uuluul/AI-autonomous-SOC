
import pika
import json
import time
import uuid
from opensearchpy import OpenSearch

# Configuration - Host is localhost for tests running outside containers
RABBITMQ_HOST = "localhost"
OPENSEARCH_HOST = "localhost"
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

def test_pipeline_integration():
    """
    Integration Test:
    1. Publish a unique CTI message to RabbitMQ 'cti_queue'.
    2. Wait for cti-pipeline-worker to consume it.
    3. Query OpenSearch 'security-logs-knn' to verify it was indexed.
    """
    print(f"Starting Integration Test: {QUEUE_NAME} -> Worker -> {INDEX_NAME}")

    # 1. Generate Unique Test Message
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
        credentials = pika.PlainCredentials("user", "password")
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
                delivery_mode=2,  # make message persistent
            ))
        print(f"[1/3] Published message ID {test_id} to RabbitMQ")
        connection.close()
    except Exception as e:
        print(f"Failed to publish to RabbitMQ: {e}")
        return False

    # 3. Wait for Processing (Allow worker time to pick up and index)
    wait_time = 15
    print(f"[2/3] Waiting {wait_time}s for worker processing...")
    time.sleep(wait_time)

    # 4. Verify in OpenSearch
    try:
        client = get_opensearch_client()
        # Refresh index to ensure search visibility
        client.indices.refresh(index=INDEX_NAME)
        
        # Search for the unique ID (Assuming pipeline maps input 'id' to something searchable or retains content)
        # Note: The pipeline might transform the message. We search for the unique content string.
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
            print(f"[3/3] Success! Found document in OpenSearch: {response['hits']['hits'][0]['_id']}")
            return True
        else:
            print(f"[3/3] Failed. Document not found in OpenSearch after wait.")
            # Debug: Print recent logs?
            return False

    except Exception as e:
        print(f"[ERROR] Failed to query OpenSearch: {e}")
        return False

if __name__ == "__main__":
    if test_pipeline_integration():
        exit(0)
    else:
        exit(1)
