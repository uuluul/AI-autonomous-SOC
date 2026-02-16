"""
NeoVigil Validation Engine — Phase 2
=====================================
Closes the self-evolving feedback loop by:

  1. **Consuming** honeypot telemetry from the 'honeypot_events' queue
  2. **Validating** Phase 1 predictions against actual attacker behaviour
  3. **Detecting** novel / zero-day payloads via hash-based deduplication
  4. **Feeding back** captured techniques into the RAG index so Phase 1
     becomes smarter with every capture

Consumes:  honeypot_events              (RabbitMQ)
Produces:  honeypot-telemetry           (OpenSearch)
           prediction-accuracy          (OpenSearch)
           security-logs-knn            (OpenSearch — RAG feedback)
           cti-reports                  (OpenSearch — zero-day captures)

Updates:   attack-path-predictions      (status → VALIDATED)
"""

import hashlib
import json
import logging
import os
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import pika

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)

# ─── Lazy imports ────────────────────────────────────────────
try:
    from src.setup_opensearch import get_opensearch_client
except ImportError:
    from setup_opensearch import get_opensearch_client

# ─── Configuration ───────────────────────────────────────────
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "rabbitmq")
HONEYPOT_QUEUE = "honeypot_events"

# OpenSearch indices
TELEMETRY_INDEX = "honeypot-telemetry"
ACCURACY_INDEX = "prediction-accuracy"
PREDICTION_INDEX = "attack-path-predictions"
RAG_INDEX = "security-logs-knn"
CTI_INDEX = "cti-reports"
DECOY_STATE_INDEX = "decoy-state"

# ─── MITRE ATT&CK Technique Classification ───────────────────
_PORT_TECHNIQUE_MAP = {
    22:   "T1021.004",      # Remote Services: SSH
    445:  "T1021.002",      # Remote Services: SMB/Windows Admin Shares
    139:  "T1021.002",
    3389: "T1021.001",      # Remote Desktop Protocol
    5432: "T1190",          # Exploit Public-Facing Application
    3306: "T1190",
    80:   "T1190",
    443:  "T1190",
    389:  "T1087.002",      # Account Discovery: Domain Account
    636:  "T1087.002",
    8080: "T1190",
    8443: "T1190",
}

# Payload indicators for technique refinement
_PAYLOAD_TECHNIQUE_HINTS = [
    (["passwd", "shadow", "/etc/", "cat /"],       "T1003"),     # Credential Dumping
    (["powershell", "invoke-", "iex("],             "T1059.001"), # PowerShell
    (["cmd.exe", "whoami", "net user", "ipconfig"], "T1059.003"), # Windows Command Shell
    (["wget", "curl", "python -c", "bash -i"],     "T1059.004"), # Unix Shell
    (["mimikatz", "sekurlsa", "lsadump"],           "T1003.001"), # LSASS Memory
    (["dcsync", "drsuapi", "ntds.dit"],             "T1003.006"), # DCSync
    (["select * from", "union select", "1=1"],      "T1190"),     # SQL Injection
    (["<script>", "javascript:", "onerror="],       "T1189"),     # Drive-by Compromise
]


# ════════════════════════════════════════════════════════════
#  Validation Engine
# ════════════════════════════════════════════════════════════

class ValidationEngine:
    """
    Processes honeypot telemetry, validates Phase 1 predictions,
    and closes the self-evolving feedback loop.

    The feedback loop:
      Honeypot capture → validate prediction → index to RAG
      → Phase 1 retrieves for future predictions → better predictions
      → better honeypot placement → more captures → ∞
    """

    def __init__(self):
        logger.info("⚖️  Initialising Validation Engine …")
        self.os = get_opensearch_client()
        logger.info("✅ Validation Engine initialised")

    # ─── Main Entry Point ──────────────────────────────────

    def process_honeypot_event(self, event: dict) -> dict:
        """
        Process a single honeypot telemetry event through the
        full validation pipeline:

          1. Parse & enrich telemetry
          2. Classify MITRE technique
          3. Look up linked prediction
          4. Validate prediction accuracy
          5. Check payload novelty
          6. Index telemetry
          7. Feed back into RAG (THE KEY STEP)
        """
        decoy_id = event.get("decoy_id", "unknown")
        attacker_ip = event.get("attacker_ip") or event.get("source_ip", "0.0.0.0")
        payload = event.get("payload_raw", event.get("payload", ""))
        service = event.get("service_targeted", event.get("service", "unknown"))
        port = event.get("port", 0)

        logger.info(
            f"📨 Processing honeypot event: decoy={decoy_id[:8]}, "
            f"attacker={attacker_ip}, service={service}, port={port}"
        )

        # ─── Step 1: Build telemetry document ─────────────
        payload_str = str(payload)[:2000]  # Cap payload size
        payload_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()

        telemetry_doc = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "decoy_id": decoy_id,
            "linked_prediction": None,
            "attacker_ip": attacker_ip,
            "service_targeted": service,
            "protocol": event.get("protocol", "tcp"),
            "port": port,
            "payload_raw": payload_str,
            "payload_hash": payload_hash,
            "technique_detected": self._classify_technique(service, port, payload_str),
            "is_novel_payload": False,
            "severity": "High",
        }

        # ─── Step 2: Look up linked prediction ────────────
        prediction = self._get_linked_prediction(decoy_id)
        if prediction:
            telemetry_doc["linked_prediction"] = prediction.get("prediction_id")

            # ─── Step 3: Validate prediction ──────────────
            accuracy_record = self._validate_prediction(prediction, telemetry_doc)

            # ─── Step 4: Update prediction status ─────────
            self._mark_prediction_validated(prediction, telemetry_doc)

        # ─── Step 5: Check payload novelty ────────────────
        telemetry_doc["is_novel_payload"] = self._is_novel_payload(payload_hash)

        # ─── Step 6: Index telemetry ──────────────────────
        self._index_telemetry(telemetry_doc)

        # ─── Step 7: Feed back into RAG ───────────────────
        self._feed_to_rag(telemetry_doc, prediction)

        # ─── Step 8: Trigger Phase 3 MTD evaluation ───────
        if prediction:
            self._trigger_mtd_evaluation(telemetry_doc, prediction)

        logger.info(
            f"✅ Event processed: {telemetry_doc['event_id'][:8]} "
            f"(technique={telemetry_doc['technique_detected']}, "
            f"novel={telemetry_doc['is_novel_payload']}, "
            f"validated={'✅' if prediction else '⏭️'})"
        )

        return telemetry_doc

    # ─── Prediction Lookup ─────────────────────────────────

    def _get_linked_prediction(self, decoy_id: str) -> Optional[dict]:
        """
        Find the Phase 1 prediction linked to this decoy by looking
        up the decoy-state index → prediction_id → prediction doc.
        """
        try:
            # Step 1: Find the decoy state entry
            state_query = {
                "query": {"term": {"decoy_id": decoy_id}},
                "size": 1,
            }
            state_resp = self.os.search(index=DECOY_STATE_INDEX, body=state_query)
            state_hits = state_resp.get("hits", {}).get("hits", [])

            if not state_hits:
                logger.debug(f"  No decoy state found for {decoy_id[:8]}")
                return None

            prediction_id = state_hits[0]["_source"].get("prediction_id")
            if not prediction_id:
                return None

            # Step 2: Fetch the original prediction
            pred_resp = self.os.get(index=PREDICTION_INDEX, id=prediction_id)
            return pred_resp.get("_source")

        except Exception as exc:
            logger.warning(f"⚠️  Prediction lookup failed for decoy {decoy_id[:8]}: {exc}")
            return None

    # ─── Prediction Validation ─────────────────────────────

    def _validate_prediction(self, prediction: dict, telemetry: dict) -> dict:
        """
        Compare the predicted kill chain step against actual attacker
        behaviour and generate an accuracy record.

        Matching logic:
          - Port match:      predicted target_port == actual port
          - Technique match:  predicted technique_id == actual technique
          - Both must match for was_correct = True
        """
        predicted_technique = None
        predicted_target = None
        predicted_confidence = 0.0

        # Find the kill chain step that matches the port
        for step in prediction.get("predicted_kill_chain", []):
            step_port = step.get("target_port")
            if step_port and str(step_port) == str(telemetry.get("port")):
                predicted_technique = step.get("technique_id")
                predicted_target = step.get("target_host")
                predicted_confidence = step.get("confidence", 0)
                break

        actual_technique = telemetry.get("technique_detected")
        was_correct = (
            predicted_technique is not None
            and actual_technique is not None
            and predicted_technique == actual_technique
        )

        accuracy_record = {
            "prediction_id": prediction.get("prediction_id"),
            "prediction_date": prediction.get("timestamp"),
            "validation_date": datetime.utcnow().isoformat(),
            "predicted_target": predicted_target,
            "actual_target": telemetry.get("service_targeted"),
            "was_correct": was_correct,
            "confidence_at_prediction": predicted_confidence,
            "attack_technique": actual_technique,
            "decoy_id": telemetry["decoy_id"],
            "feedback_indexed": True,
            "time_to_capture_sec": self._calc_time_delta(
                prediction.get("timestamp"),
                telemetry.get("timestamp"),
            ),
        }

        # Index accuracy record
        try:
            self.os.index(
                index=ACCURACY_INDEX,
                body=accuracy_record,
                refresh=True,
            )
        except Exception as exc:
            logger.error(f"❌ Failed to index accuracy record: {exc}")

        status_emoji = "✅ CORRECT" if was_correct else "❌ MISS"
        logger.info(
            f"⚖️  Prediction {prediction.get('prediction_id', '?')[:8]}: "
            f"{status_emoji} — predicted {predicted_technique}, "
            f"actual {actual_technique} "
            f"(confidence={predicted_confidence:.0%})"
        )

        return accuracy_record

    # ─── Mark Prediction as Validated ──────────────────────

    def _mark_prediction_validated(self, prediction: dict, telemetry: dict):
        """Update the Phase 1 prediction status to VALIDATED."""
        pred_id = prediction.get("prediction_id")
        if not pred_id:
            return

        try:
            self.os.update(
                index=PREDICTION_INDEX,
                id=pred_id,
                body={"doc": {
                    "status": "VALIDATED",
                    "validated_at": datetime.utcnow().isoformat(),
                    "validated_by_decoy": telemetry["decoy_id"],
                    "actual_attacker_ip": telemetry["attacker_ip"],
                    "actual_technique": telemetry["technique_detected"],
                }},
                refresh=True,
            )
            logger.info(f"📝 Prediction {pred_id[:8]} marked as VALIDATED")
        except Exception as exc:
            logger.warning(f"⚠️  Failed to update prediction status: {exc}")

    # ─── Payload Novelty Detection ─────────────────────────

    def _is_novel_payload(self, payload_hash: str) -> bool:
        """
        Check if this payload hash has EVER been seen before in our
        telemetry index. A novel hash = potentially zero-day.
        """
        try:
            query = {
                "query": {"term": {"payload_hash": payload_hash}},
                "size": 0,
            }
            resp = self.os.search(index=TELEMETRY_INDEX, body=query)
            count = resp.get("hits", {}).get("total", {}).get("value", 0)
            return count == 0
        except Exception:
            return False  # Err on side of caution

    # ─── Telemetry Indexing ────────────────────────────────

    def _index_telemetry(self, telemetry_doc: dict):
        """Index the raw telemetry event to honeypot-telemetry."""
        try:
            self.os.index(
                index=TELEMETRY_INDEX,
                id=telemetry_doc["event_id"],
                body=telemetry_doc,
                refresh=True,
            )
        except Exception as exc:
            logger.error(f"❌ Failed to index telemetry: {exc}")

    # ─── RAG Feedback (THE SELF-EVOLUTION STEP) ────────────

    def _feed_to_rag(self, telemetry: dict, prediction: Optional[dict]):
        """
        THE KEY STEP that makes the system smarter.

        Index the captured attack telemetry as a new document in
        the RAG knowledge base (security-logs-knn). Phase 1's
        retrieve_context() will now find this pattern when future
        similar alerts arrive — giving REDSPEC more accurate
        historical intelligence.

        For novel payloads, also index to cti-reports so humans
        can review and officially inoculate the network.
        """
        technique = telemetry.get("technique_detected", "Unknown")
        is_novel = telemetry.get("is_novel_payload", False)
        novelty_flag = "🆕 NOVEL ZERO-DAY PAYLOAD" if is_novel else ""

        # ─── Build RAG document ───────────────────────────
        rag_document = {
            "title": (
                f"Honeypot Capture: {technique} attack from "
                f"{telemetry['attacker_ip']} on {telemetry['service_targeted']}"
            ),
            "summary": (
                f"Attacker {telemetry['attacker_ip']} targeted decoy "
                f"{telemetry['service_targeted']} on port {telemetry['port']}. "
                f"Technique: {technique}. "
                f"Payload hash: {telemetry['payload_hash'][:16]}…  {novelty_flag}"
            ),
            "attack_type": technique,
            "source_ip": telemetry["attacker_ip"],
            "timestamp": telemetry["timestamp"],
            "indicators": {
                "ipv4": [telemetry["attacker_ip"]],
                "payload_hash": [telemetry["payload_hash"]],
            },
            "payload_hash": telemetry["payload_hash"],
            "source_type": "honeypot_capture",
            "threat_matched": True,
            "severity": telemetry.get("severity", "High"),
            "confidence": 95,  # Honeypot captures are high-confidence intel
            "message": telemetry.get("payload_raw", "")[:500],
            "deception_metadata": {
                "decoy_id": telemetry["decoy_id"],
                "is_novel": is_novel,
                "prediction_validated": prediction is not None,
                "prediction_id": (
                    prediction.get("prediction_id") if prediction else None
                ),
                "capture_type": "zero_day" if is_novel else "known_technique",
            },
        }

        # ─── Index to RAG (security-logs-knn) ─────────────
        doc_id = f"honeypot_{telemetry['event_id']}"
        try:
            self.os.index(
                index=RAG_INDEX,
                id=doc_id,
                body=rag_document,
                refresh=True,
            )
            logger.info(
                f"🧬 RAG feedback indexed: {doc_id[:20]}… "
                f"(novel={is_novel})"
            )
        except Exception as exc:
            logger.error(f"❌ Failed to index RAG feedback: {exc}")

        # ─── Novel payloads → CTI Reports for human review ─
        if is_novel:
            try:
                cti_doc = {
                    **rag_document,
                    "source_type": "zero_day_capture",
                    "inoculation_status": "PENDING_REVIEW",
                    "review_notes": (
                        "⚠️ This payload was captured in a honeypot and has "
                        "NEVER been seen before. Tier 2+ analyst review required "
                        "before inoculation rules are deployed."
                    ),
                }
                self.os.index(
                    index=CTI_INDEX,
                    id=f"zerodaywatch_{telemetry['event_id']}",
                    body=cti_doc,
                    refresh=True,
                )
                logger.warning(
                    f"🚨 ZERO-DAY PAYLOAD CAPTURED & INDEXED: "
                    f"hash={telemetry['payload_hash'][:16]}… "
                    f"from {telemetry['attacker_ip']} "
                    f"→ inoculation_status=PENDING_REVIEW"
                )
            except Exception as exc:
                logger.error(f"❌ Failed to index zero-day capture: {exc}")

    # ─── Technique Classification ──────────────────────────

    def _classify_technique(
        self, service: str, port: int, payload: str
    ) -> str:
        """
        Classify the MITRE ATT&CK technique from telemetry.

        Priority:
          1. Payload content indicators (most specific)
          2. Port-based mapping (fallback)
          3. Default: T1595 (Active Scanning)
        """
        payload_lower = payload.lower() if payload else ""

        # Priority 1: Payload-based classification
        for keywords, technique in _PAYLOAD_TECHNIQUE_HINTS:
            if any(kw in payload_lower for kw in keywords):
                return technique

        # Priority 2: Port-based classification
        if port in _PORT_TECHNIQUE_MAP:
            return _PORT_TECHNIQUE_MAP[port]

        # Default: Active Scanning
        return "T1595"

    # ─── Phase 3: MTD Trigger ──────────────────────────────

    def _trigger_mtd_evaluation(self, telemetry: dict, prediction: dict):
        """
        Phase 3 — Notify the MTD Controller that a honeypot capture
        has validated a prediction. The MTD Controller uses this as
        one signal in its composite scoring.
        """
        try:
            mtd_payload = {
                "trigger_id": str(uuid.uuid4()),
                "trigger_source": "phase2_honeypot_capture",
                "prediction_id": prediction.get("prediction_id"),
                "target_ip": telemetry.get("decoy_id", ""),
                "scanner_ip": telemetry.get("attacker_ip", ""),
                "source_ip": telemetry.get("attacker_ip", ""),
                "risk_score": prediction.get("overall_risk_score", 70),
                "technique_detected": telemetry.get("technique_detected"),
                "is_novel_payload": telemetry.get("is_novel_payload", False),
                "timestamp": datetime.utcnow().isoformat(),
            }
            connection = pika.BlockingConnection(
                pika.ConnectionParameters(
                    host=RABBITMQ_HOST,
                    connection_attempts=2,
                    retry_delay=1,
                )
            )
            channel = connection.channel()
            channel.queue_declare(queue="mtd_action_queue", durable=True)
            channel.basic_publish(
                exchange="",
                routing_key="mtd_action_queue",
                body=json.dumps(mtd_payload),
                properties=pika.BasicProperties(delivery_mode=2),
            )
            connection.close()
            logger.info(
                f"🛡️ MTD trigger dispatched for capture "
                f"from {telemetry.get('attacker_ip')}"
            )
        except Exception as exc:
            logger.warning(
                f"⚠️  Failed to dispatch MTD trigger (non-critical): {exc}"
            )

    # ─── Utility ───────────────────────────────────────────

    @staticmethod
    def _calc_time_delta(ts1: Optional[str], ts2: Optional[str]) -> int:
        """Calculate seconds between two ISO timestamps."""
        if not ts1 or not ts2:
            return 0
        try:
            t1 = datetime.fromisoformat(ts1.replace("Z", "+00:00"))
            t2 = datetime.fromisoformat(ts2.replace("Z", "+00:00"))
            return abs(int((t2 - t1).total_seconds()))
        except (ValueError, TypeError):
            return 0

    # ─── Accuracy Statistics ───────────────────────────────

    def get_accuracy_stats(self) -> dict:
        """
        Query prediction-accuracy index and compute aggregate
        accuracy metrics for the Streamlit dashboard.
        """
        try:
            aggs_query = {
                "size": 0,
                "aggs": {
                    "total_validations": {"value_count": {"field": "prediction_id"}},
                    "correct_predictions": {
                        "filter": {"term": {"was_correct": True}},
                    },
                    "avg_confidence": {
                        "avg": {"field": "confidence_at_prediction"},
                    },
                    "avg_capture_time": {
                        "avg": {"field": "time_to_capture_sec"},
                    },
                    "by_technique": {
                        "terms": {"field": "attack_technique", "size": 20},
                    },
                },
            }
            resp = self.os.search(index=ACCURACY_INDEX, body=aggs_query)
            aggs = resp.get("aggregations", {})

            total = aggs.get("total_validations", {}).get("value", 0)
            correct = aggs.get("correct_predictions", {}).get("doc_count", 0)

            return {
                "total_validations": total,
                "correct_predictions": correct,
                "accuracy_rate": (correct / total * 100) if total > 0 else 0,
                "avg_confidence": aggs.get("avg_confidence", {}).get("value", 0),
                "avg_capture_time_sec": aggs.get("avg_capture_time", {}).get("value", 0),
                "top_techniques": [
                    {"technique": b["key"], "count": b["doc_count"]}
                    for b in aggs.get("by_technique", {}).get("buckets", [])
                ],
            }
        except Exception as exc:
            logger.warning(f"⚠️  Accuracy stats query failed: {exc}")
            return {
                "total_validations": 0,
                "correct_predictions": 0,
                "accuracy_rate": 0,
                "avg_confidence": 0,
                "avg_capture_time_sec": 0,
                "top_techniques": [],
            }

    # ─── RabbitMQ Consumer Loop ────────────────────────────

    def run(self):
        """Main event loop — consume honeypot_events from RabbitMQ."""
        logger.info("⚖️  Validation Engine online — starting RabbitMQ consumer …")

        while True:
            try:
                connection = pika.BlockingConnection(
                    pika.ConnectionParameters(
                        host=RABBITMQ_HOST,
                        heartbeat=600,
                        blocked_connection_timeout=300,
                        connection_attempts=10,
                        retry_delay=5,
                    )
                )
                channel = connection.channel()
                channel.queue_declare(queue=HONEYPOT_QUEUE, durable=True)
                channel.basic_qos(prefetch_count=1)

                def on_honeypot_event(ch, method, _props, body):
                    try:
                        event = json.loads(body)
                        self.process_honeypot_event(event)
                    except json.JSONDecodeError as exc:
                        logger.error(f"❌ Invalid JSON in honeypot event: {exc}")
                    except Exception as exc:
                        logger.error(
                            f"❌ Honeypot event processing error: {exc}",
                            exc_info=True,
                        )
                    finally:
                        ch.basic_ack(delivery_tag=method.delivery_tag)

                channel.basic_consume(
                    queue=HONEYPOT_QUEUE,
                    on_message_callback=on_honeypot_event,
                )

                logger.info(f"⚖️  Listening on '{HONEYPOT_QUEUE}' …")
                channel.start_consuming()

            except pika.exceptions.AMQPConnectionError as exc:
                logger.warning(f"⚠️  RabbitMQ lost: {exc}. Reconnecting in 10s …")
                time.sleep(10)
            except KeyboardInterrupt:
                logger.info("🛑 Validation Engine shutting down (KeyboardInterrupt)")
                break
            except Exception as exc:
                logger.error(
                    f"❌ Unexpected consumer error: {exc}",
                    exc_info=True,
                )
                time.sleep(10)


# ════════════════════════════════════════════════════════════
#  Entrypoint
# ════════════════════════════════════════════════════════════
if __name__ == "__main__":
    engine = ValidationEngine()
    engine.run()
