import os
import json
import uuid
import time
import pytest
import pika
from opensearchpy import OpenSearch

# Config
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "localhost")
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
INDEX_NAME = os.getenv("E2E_INDEX_NAME", "cti-reports")
QUEUE_NAME = os.getenv("RABBITMQ_QUEUE", "cti_queue")  # 對齊 worker

TENANT_ID = "tenant_e2e"


@pytest.fixture(scope="module")
def os_client():
    return OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": 9200}],
        http_compress=True,
        use_ssl=False,
        verify_certs=False,
        ssl_assert_hostname=False,
        ssl_show_warn=False,
    )


def publish_task(payload: dict):
    """Publish a single task to RabbitMQ queue (default exchange)."""
    credentials = pika.PlainCredentials("user", "password")
    connection = pika.BlockingConnection(
        pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials)
    )
    channel = connection.channel()
    channel.queue_declare(queue=QUEUE_NAME, durable=True)
    channel.basic_publish(
        exchange="",
        routing_key=QUEUE_NAME,
        body=json.dumps(payload),
        properties=pika.BasicProperties(delivery_mode=2),
    )
    connection.close()


@pytest.mark.e2e
def test_pipeline_flow(os_client):
    """
    E2E:
    1) Publish event to RabbitMQ
    2) Poll OpenSearch until the processed document appears
    3) Validate expected AI fields
    """
    test_id = str(uuid.uuid4())
    now = time.time()
    trace = f"e2e={test_id}"  # 唯一 token，避免撞到舊資料

    payload = {
        "event_id": test_id,
        "tenant_id": TENANT_ID,
        "session_id": "e2e",
        "source": "e2e_fixture",
        "raw_log": (
            "Feb 16 07:40:00 host sshd[123]: Failed password for invalid user root "
            f"from 1.2.3.4 port 4444 ssh2 ({trace})"
        ),
        "@timestamp": now,
        "timestamp": now,
        "source_ip": "1.2.3.4",
    }

    # 1) Publish
    try:
        publish_task(payload)
    except Exception as e:
        if os.getenv("CI") == "true":
            pytest.fail(f"Failed to publish to RabbitMQ: {e}")
        pytest.skip("RabbitMQ unreachable")

    # 2) Poll OpenSearch
    query = {
        "size": 1,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"term": {"tenant_id": TENANT_ID}},
                    {
                        "query_string": {
                            "query": trace,
                            "fields": ["raw_log", "message", "raw_content", "*"],
                        }
                    },
                ]
            }
        },
    }

    found_doc = None
    last_err = None

    for _ in range(30):  # up to 30s
        time.sleep(1)
        try:
            # 先 refresh，降低 “剛寫入但搜不到” 的 flake
            try:
                os_client.indices.refresh(index=INDEX_NAME)
            except Exception:
                pass

            resp = os_client.search(index=INDEX_NAME, body=query)
            total = resp.get("hits", {}).get("total", {}).get("value", 0)
            if total > 0:
                found_doc = resp["hits"]["hits"][0]["_source"]
                break
        except Exception as e:
            last_err = e
            continue

    if not found_doc:
        extra = f" (last_err={last_err})" if last_err else ""
        pytest.fail(f"Pipeline E2E failed: Document not found after 30s{extra}")

    # 3) Validations
    doc = found_doc
    assert doc.get("tenant_id") == TENANT_ID
    assert "risk_level" in doc
    assert "ai_confidence" in doc
    assert "mitre_ttps" in doc

    if "event_id" in doc:
        assert isinstance(doc["event_id"], str)
    if "source_ip" in doc:
        assert doc["source_ip"] == "1.2.3.4"

