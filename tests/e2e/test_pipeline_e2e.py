import json
import os
import time
from pathlib import Path

import pika
import pytest
from opensearchpy import OpenSearch


RABBITMQ_HOST = os.getenv("E2E_RABBITMQ_HOST", "localhost")
RABBITMQ_PORT = int(os.getenv("E2E_RABBITMQ_PORT", "5672"))
RABBITMQ_USER = os.getenv("RABBITMQ_USER", "user")
RABBITMQ_PASS = os.getenv("RABBITMQ_PASS", "password")
RABBITMQ_QUEUE = os.getenv("E2E_RABBITMQ_QUEUE", "cti_tasks")
RABBITMQ_EXCHANGE = os.getenv("E2E_RABBITMQ_EXCHANGE", "cti_exchange")
RABBITMQ_ROUTING_KEY = os.getenv("E2E_RABBITMQ_ROUTING_KEY", "cti_queue")

OPENSEARCH_HOST = os.getenv("E2E_OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.getenv("E2E_OPENSEARCH_PORT", "9200"))
OPENSEARCH_INDEX = os.getenv("E2E_OPENSEARCH_INDEX", "security-logs-knn")

FIXTURE_PATH = Path("tests/fixtures/event_fixture.json")


def _opensearch_client() -> OpenSearch:
    return OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        use_ssl=False,
        verify_certs=False,
        ssl_show_warn=False,
        http_auth=("admin", "admin"),
    )


def _publish_event(payload: dict):
    credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
    params = pika.ConnectionParameters(
        host=RABBITMQ_HOST,
        port=RABBITMQ_PORT,
        virtual_host="/",
        credentials=credentials,
        heartbeat=60,
    )
    connection = pika.BlockingConnection(params)
    channel = connection.channel()
    channel.exchange_declare(exchange=RABBITMQ_EXCHANGE, exchange_type="direct", durable=False)
    channel.queue_declare(queue=RABBITMQ_QUEUE, durable=True)
    channel.queue_bind(exchange=RABBITMQ_EXCHANGE, queue=RABBITMQ_QUEUE, routing_key=RABBITMQ_ROUTING_KEY)
    channel.basic_publish(
        exchange=RABBITMQ_EXCHANGE,
        routing_key=RABBITMQ_ROUTING_KEY,
        body=json.dumps(payload),
        properties=pika.BasicProperties(delivery_mode=2),
    )
    connection.close()


@pytest.mark.e2e
def test_pipeline_event_to_opensearch_e2e():
    payload = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    marker = f"e2e-{int(time.time())}"
    payload["message"] = f"{payload['message']} [{marker}]"

    try:
        _publish_event(payload)
    except pika.exceptions.AMQPError as exc:
        pytest.skip(f"RabbitMQ is not reachable in current environment: {exc}")

    client = _opensearch_client()
    try:
        client.info()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"OpenSearch is not reachable in current environment: {exc}")

    deadline = time.time() + 90
    found_doc = None

    while time.time() < deadline:
        result = client.search(
            index=OPENSEARCH_INDEX,
            body={
                "size": 1,
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {"match_phrase": {"message": marker}},
            },
        )
        hits = result.get("hits", {}).get("hits", [])
        if hits:
            found_doc = hits[0].get("_source", {})
            break
        time.sleep(3)

    assert found_doc is not None, "Timed out waiting for indexed document in OpenSearch"
    assert "risk_level" in found_doc
    assert "mitre_ttps" in found_doc
    assert "ai_confidence" in found_doc
