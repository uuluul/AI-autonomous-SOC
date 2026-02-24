"""
NeoVigil AI Worker Edge Filtering -- Layer 2
==============================================
Lightweight domain-specific AI workers that pre-filter logs before
they reach the Commander AI pipeline. Drops normal traffic entirely,
escalating only anomalies as alert.critical to RabbitMQ.

Workers:
  - NetworkAIWorker:  log.network  -> port scans, C2 beaconing, bad IPs
  - EndpointAIWorker: log.endpoint -> LOLBins, process anomalies
  - IdentityAIWorker: log.identity -> brute force, kerberoasting

Consumes:  ai_worker_{network,endpoint,identity}  (RabbitMQ)
Produces:  alert_critical                          (RabbitMQ priority queue)

Usage:
    AI_WORKER_DOMAIN=network python src/ai_worker.py
"""

import json
import logging
import os
import re
import sys
import time
import uuid
from datetime import datetime

import pika

# ─── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [AIWorker] %(levelname)s -- %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ─── OpenSearch client ────────────────────────────────────────
try:
    from src.setup_opensearch import get_opensearch_client, upload_to_opensearch
except ImportError:
    try:
        from setup_opensearch import get_opensearch_client, upload_to_opensearch
    except ImportError:
        logger.error("Cannot import get_opensearch_client")
        sys.exit(1)

# ─── Configuration ────────────────────────────────────────────
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_USER = os.getenv("RABBITMQ_DEFAULT_USER", "user")
RABBITMQ_PASS = os.getenv("RABBITMQ_DEFAULT_PASS", "password")
OPENSEARCH_INDEX = "security-logs-knn"
ALERT_CRITICAL_QUEUE = "alert_critical"

# Domain-specific thresholds (configurable via env)
NETWORK_THRESHOLD = float(os.getenv("AI_WORKER_NETWORK_THRESHOLD", "0.65"))
ENDPOINT_THRESHOLD = float(os.getenv("AI_WORKER_ENDPOINT_THRESHOLD", "0.60"))
IDENTITY_THRESHOLD = float(os.getenv("AI_WORKER_IDENTITY_THRESHOLD", "0.55"))

# ─── Known-Bad Patterns (lightweight, no LLM needed) ─────────

NETWORK_SUSPICIOUS_PATTERNS = [
    r"port\s*scan",
    r"nmap",
    r"syn\s*flood",
    r"c2\s*beacon",
    r"command.and.control",
    r"reverse.shell",
    r"exfiltration",
    r"dns\s*tunnel",
    r"cobalt\s*strike",
    r"metasploit",
]

ENDPOINT_SUSPICIOUS_PATTERNS = [
    r"mimikatz",
    r"lsass",
    r"credential.dump",
    r"powershell.*-enc",
    r"certutil.*urlcache",
    r"bitsadmin.*transfer",
    r"rundll32.*javascript",
    r"mshta.*vbscript",
    r"wmic.*process.*call",
    r"psexec",
]

IDENTITY_SUSPICIOUS_PATTERNS = [
    r"brute.force",
    r"failed.login.*(\d{3,})",
    r"kerberoast",
    r"golden.ticket",
    r"pass.the.hash",
    r"privilege.escalation",
    r"impossible.travel",
    r"account.lockout",
    r"new.admin.*created",
    r"service.account.*login",
]


# ─── Base Worker ──────────────────────────────────────────────

class AIWorker:
    """Base class for domain-specific AI edge filtering workers."""

    DOMAIN = "base"
    INPUT_QUEUE = "ai_worker_base"
    PATTERNS = []
    THRESHOLD = 0.65

    def __init__(self):
        self.os_client = get_opensearch_client()
        self.stats = {"processed": 0, "escalated": 0, "dropped": 0}
        logger.info(
            f"[{self.DOMAIN.upper()}] Worker initialized | "
            f"queue={self.INPUT_QUEUE} threshold={self.THRESHOLD}"
        )

    def classify(self, log_record: dict) -> dict:
        """
        Lightweight anomaly classification using pattern matching
        and optional KNN similarity scoring.
        Returns: {"is_anomaly": bool, "score": float, "reason": str}
        """
        log_text = self._extract_text(log_record)
        if not log_text:
            return {"is_anomaly": False, "score": 0.0, "reason": "empty_log"}

        # Stage 1: Fast regex pattern matching
        for pattern in self.PATTERNS:
            match = re.search(pattern, log_text, re.IGNORECASE)
            if match:
                return {
                    "is_anomaly": True,
                    "score": 0.95,
                    "reason": f"pattern_match:{pattern}",
                    "matched_text": match.group()[:100],
                }

        # Stage 2: KNN anomaly scoring against baseline
        knn_score = self._knn_anomaly_score(log_text)
        if knn_score is not None and knn_score >= self.THRESHOLD:
            return {
                "is_anomaly": True,
                "score": knn_score,
                "reason": "knn_anomaly",
            }

        return {"is_anomaly": False, "score": knn_score or 0.0, "reason": "benign"}

    def _extract_text(self, log_record: dict) -> str:
        """Extract searchable text from various log formats."""
        if isinstance(log_record, str):
            return log_record

        # Try common log field names
        for field in ["message", "log", "log_text", "raw", "data", "event_data"]:
            val = log_record.get(field)
            if val and isinstance(val, str):
                return val

        # Fallback: serialize entire record
        return json.dumps(log_record, default=str)[:2000]

    def _knn_anomaly_score(self, log_text: str) -> float:
        """
        Query KNN index for similarity scoring.
        Returns anomaly score (0-1, higher = more anomalous).
        Falls back to None if index is empty or unavailable.
        """
        try:
            # Use keyword search as lightweight proxy for KNN
            # (avoids requiring embedding generation at edge)
            query = {
                "size": 5,
                "query": {
                    "bool": {
                        "must": [
                            {"match": {"log_text": log_text[:500]}},
                            {"term": {"source_type": self.DOMAIN}},
                        ]
                    }
                },
            }
            resp = self.os_client.search(index=OPENSEARCH_INDEX, body=query)
            hits = resp.get("hits", {}).get("hits", [])

            if not hits:
                # No baseline data -> conservatively flag as anomaly
                return 0.70

            # Higher max_score = more similar to known logs = less anomalous
            max_score = max(h["_score"] for h in hits) if hits else 0
            # Normalize: OpenSearch BM25 scores vary; cap at 20 for normalization
            normalized = min(max_score / 20.0, 1.0)
            return 1.0 - normalized

        except Exception as exc:
            logger.debug(f"[{self.DOMAIN}] KNN scoring failed (non-critical): {exc}")
            return None

    def should_escalate(self, classification: dict) -> bool:
        """Determine if anomaly should be escalated to Commander AI."""
        return classification.get("is_anomaly", False)

    def escalate(self, log_record: dict, classification: dict, channel):
        """Publish anomaly to alert_critical priority queue."""
        enriched = {
            "alert_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "domain": self.DOMAIN,
            "anomaly_score": classification.get("score", 0),
            "anomaly_reason": classification.get("reason", "unknown"),
            "original_log": log_record,
            "escalated_by": f"ai_worker_{self.DOMAIN}",
        }

        channel.basic_publish(
            exchange="",
            routing_key=ALERT_CRITICAL_QUEUE,
            body=json.dumps(enriched, default=str),
            properties=pika.BasicProperties(
                delivery_mode=2,
                priority=5,
            ),
        )
        self.stats["escalated"] += 1
        logger.info(
            f"[{self.DOMAIN.upper()}] ESCALATED alert "
            f"(score={classification['score']:.2f}, "
            f"reason={classification['reason']})"
        )

    def process_message(self, ch, method, properties, body):
        """RabbitMQ callback: classify and optionally escalate."""
        try:
            log_record = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            log_record = {"raw": body.decode("utf-8", errors="replace")}

        self.stats["processed"] += 1
        classification = self.classify(log_record)

        if self.should_escalate(classification):
            self.escalate(log_record, classification, ch)
        else:
            self.stats["dropped"] += 1

        ch.basic_ack(delivery_tag=method.delivery_tag)

        # Periodic stats logging
        if self.stats["processed"] % 100 == 0:
            logger.info(
                f"[{self.DOMAIN.upper()}] Stats: "
                f"processed={self.stats['processed']} "
                f"escalated={self.stats['escalated']} "
                f"dropped={self.stats['dropped']}"
            )

    def run(self):
        """Start consuming from domain queue with auto-reconnect."""
        while True:
            try:
                credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
                connection = pika.BlockingConnection(
                    pika.ConnectionParameters(
                        host=RABBITMQ_HOST,
                        credentials=credentials,
                        connection_attempts=5,
                        retry_delay=3,
                        heartbeat=60,
                    )
                )
                channel = connection.channel()
                channel.queue_declare(queue=self.INPUT_QUEUE, durable=True)
                channel.queue_declare(
                    queue=ALERT_CRITICAL_QUEUE,
                    durable=True,
                    arguments={"x-max-priority": 10},
                )
                channel.basic_qos(prefetch_count=10)
                channel.basic_consume(
                    queue=self.INPUT_QUEUE,
                    on_message_callback=self.process_message,
                )
                logger.info(
                    f"[{self.DOMAIN.upper()}] Consuming from {self.INPUT_QUEUE}..."
                )
                channel.start_consuming()

            except pika.exceptions.AMQPConnectionError as exc:
                logger.warning(
                    f"[{self.DOMAIN.upper()}] RabbitMQ connection lost: {exc}. "
                    f"Reconnecting in 5s..."
                )
                time.sleep(5)
            except KeyboardInterrupt:
                logger.info(f"[{self.DOMAIN.upper()}] Shutting down.")
                break
            except Exception as exc:
                logger.error(
                    f"[{self.DOMAIN.upper()}] Unexpected error: {exc}. "
                    f"Restarting in 10s..."
                )
                time.sleep(10)


# ─── Domain-Specific Workers ─────────────────────────────────

class NetworkAIWorker(AIWorker):
    """Processes log.network telemetry: Suricata, firewall, IDS/IPS."""
    DOMAIN = "network"
    INPUT_QUEUE = "ai_worker_network"
    PATTERNS = NETWORK_SUSPICIOUS_PATTERNS
    THRESHOLD = NETWORK_THRESHOLD


class EndpointAIWorker(AIWorker):
    """Processes log.endpoint telemetry: Sysmon, EDR, process events."""
    DOMAIN = "endpoint"
    INPUT_QUEUE = "ai_worker_endpoint"
    PATTERNS = ENDPOINT_SUSPICIOUS_PATTERNS
    THRESHOLD = ENDPOINT_THRESHOLD


class IdentityAIWorker(AIWorker):
    """Processes log.identity telemetry: AD events, auth failures."""
    DOMAIN = "identity"
    INPUT_QUEUE = "ai_worker_identity"
    PATTERNS = IDENTITY_SUSPICIOUS_PATTERNS
    THRESHOLD = IDENTITY_THRESHOLD


# ─── Entry Point ──────────────────────────────────────────────

WORKER_MAP = {
    "network": NetworkAIWorker,
    "endpoint": EndpointAIWorker,
    "identity": IdentityAIWorker,
}

if __name__ == "__main__":
    domain = os.getenv("AI_WORKER_DOMAIN", "network").lower()

    if domain not in WORKER_MAP:
        logger.error(
            f"Unknown AI_WORKER_DOMAIN: {domain}. "
            f"Valid: {list(WORKER_MAP.keys())}"
        )
        sys.exit(1)

    worker = WORKER_MAP[domain]()
    worker.run()
