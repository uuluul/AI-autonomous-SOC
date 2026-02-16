import os

import pytest
import requests


OPENSEARCH_URL = os.getenv("SMOKE_OPENSEARCH_URL", "http://localhost:9200")
RABBITMQ_URL = os.getenv("SMOKE_RABBITMQ_URL", "http://localhost:15672/api/overview")
RABBITMQ_USER = os.getenv("RABBITMQ_USER", "user")
RABBITMQ_PASS = os.getenv("RABBITMQ_PASS", "password")


def test_opensearch_health():
    try:
        response = requests.get(OPENSEARCH_URL, timeout=10)
    except requests.RequestException as exc:
        pytest.skip(f"OpenSearch is not reachable in current environment: {exc}")

    response.raise_for_status()
    payload = response.json()
    assert "cluster_name" in payload


def test_rabbitmq_health():
    try:
        response = requests.get(
            RABBITMQ_URL,
            auth=(RABBITMQ_USER, RABBITMQ_PASS),
            timeout=10,
        )
    except requests.RequestException as exc:
        pytest.skip(f"RabbitMQ API is not reachable in current environment: {exc}")

    response.raise_for_status()
    payload = response.json()
    assert payload.get("rabbitmq_version")
