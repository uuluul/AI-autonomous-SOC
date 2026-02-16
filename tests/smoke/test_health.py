import os
import pytest
import requests
import pika

@pytest.mark.smoke
def test_opensearch_reachability():
    """Verify OpenSearch is reachable."""
    host = os.getenv("OPENSEARCH_HOST", "localhost")
    url = f"http://{host}:9200"
    try:
        resp = requests.get(url, timeout=5)
        assert resp.status_code == 200
    except requests.exceptions.ConnectionError:
        if os.getenv("CI") == "true":
            pytest.fail("OpenSearch is unreachable in CI environment!")
        else:
            pytest.skip("OpenSearch unreachable locally, skipping.")

@pytest.mark.smoke
def test_rabbitmq_reachability():
    """Verify RabbitMQ is reachable."""
    host = os.getenv("RABBITMQ_HOST", "localhost")
    credentials = pika.PlainCredentials('user', 'password')
    try:
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=host, port=5672, credentials=credentials, connection_attempts=3, retry_delay=2)
        )
        assert connection.is_open
        connection.close()
    except pika.exceptions.AMQPConnectionError:
        if os.getenv("CI") == "true":
            pytest.fail("RabbitMQ is unreachable in CI environment!")
        else:
            pytest.skip("RabbitMQ unreachable locally, skipping.")
