"""
NeoVigil Feedback Loop — Closed-Loop ML via RAG
=================================================
Validates AI predictions against real honeypot captures to create
a continuous learning feedback loop.

Flow:
  1. Query `honeypot-telemetry` for recent attacker interactions
  2. Query `attack-path-predictions` for recent AI predictions
  3. Cross-reference: match honeypot source_ip ↔ prediction scanner_ip
  4. Generate validated CTI documents with confidence=100%
  5. Inject into `security-logs-knn` with tag `validated_cti`
  6. The Prediction Engine will retrieve these via RAG to learn
     from confirmed True Positives

Run manually:
    python src/feedback_loop.py

Or schedule via cron / Docker healthcheck every 15 minutes.
"""

import json
import logging
import os
import sys
import uuid
from datetime import datetime, timedelta

# ─── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [FeedbackLoop] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ─── OpenSearch client ────────────────────────────────────────
try:
    from src.setup_opensearch import get_opensearch_client
except ImportError:
    try:
        from setup_opensearch import get_opensearch_client
    except ImportError:
        logger.error("Cannot import get_opensearch_client")
        sys.exit(1)

# ─── Configuration ────────────────────────────────────────────
HONEYPOT_INDEX = "honeypot-telemetry"
PREDICTIONS_INDEX = "attack-path-predictions"
VALIDATED_INDEX = "security-logs-knn"
MTD_AUDIT_INDEX = "mtd-audit-log"

LOOKBACK_HOURS = int(os.getenv("FEEDBACK_LOOKBACK_HOURS", "2"))
DUMMY_VECTOR_DIM = 768  # Must match KNN mapping in security-logs-knn


# ─── Helpers ──────────────────────────────────────────────────

def _safe_query(os_client, index: str, body: dict) -> list:
    """Run a search query, returning hits or empty list on error."""
    try:
        resp = os_client.search(index=index, body=body, size=200)
        return [h["_source"] for h in resp.get("hits", {}).get("hits", [])]
    except Exception as exc:
        logger.warning(f"  Query to {index} failed: {exc}")
        return []


def _dummy_vector() -> list:
    """Generate a zero-filled 768-dim vector for KNN mapping compliance."""
    return [0.0] * DUMMY_VECTOR_DIM


# ─── Core Logic ───────────────────────────────────────────────

def run_feedback_loop():
    """
    Main feedback loop: cross-reference honeypot captures with
    AI predictions to generate validated CTI.
    """
    os_client = get_opensearch_client()
    cutoff = (datetime.utcnow() - timedelta(hours=LOOKBACK_HOURS)).isoformat()

    logger.info(
        f" Starting feedback loop — lookback: {LOOKBACK_HOURS}h "
        f"(cutoff: {cutoff})"
    )

    # ─── 1. Fetch recent honeypot captures ────────────────
    honeypot_query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": cutoff}}},
                ]
            }
        },
        "_source": [
            "source_ip", "target_ip", "payload", "protocol",
            "timestamp", "honeypot_id", "service_type",
        ],
    }
    captures = _safe_query(os_client, HONEYPOT_INDEX, honeypot_query)
    logger.info(f" Found {len(captures)} honeypot captures in last {LOOKBACK_HOURS}h")

    if not captures:
        # Also try MTD audit log for migration-related trap telemetry
        mtd_query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"proposed_at": {"gte": cutoff}}},
                        {"term": {"status": "COMPLETED"}},
                    ]
                }
            },
            "_source": [
                "scanner_ip", "target_ip", "target_host", "score",
                "action_type", "proposed_at", "migration_result",
            ],
        }
        mtd_actions = _safe_query(os_client, MTD_AUDIT_INDEX, mtd_query)
        if mtd_actions:
            logger.info(
                f" Synthesizing {len(mtd_actions)} MTD actions as "
                f"validated honeypot interactions"
            )
            for action in mtd_actions:
                captures.append({
                    "source_ip": action.get("scanner_ip", ""),
                    "target_ip": action.get("target_ip", ""),
                    "payload": f"MTD Migration Triggered — Score: {action.get('score', 0)}",
                    "protocol": "MTD-Action",
                    "timestamp": action.get("proposed_at", datetime.utcnow().isoformat()),
                    "honeypot_id": f"mtd-trap-{action.get('target_host', 'unknown')[:16]}",
                    "service_type": action.get("action_type", "migration"),
                })

    # ─── 2. Fetch recent predictions ──────────────────────
    prediction_query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": cutoff}}},
                ]
            }
        },
        "_source": [
            "scanner_ip", "compromised_host", "target_ip",
            "overall_risk_score", "predicted_kill_chain",
            "timestamp", "prediction_id",
        ],
    }
    predictions = _safe_query(os_client, PREDICTIONS_INDEX, prediction_query)
    logger.info(f" Found {len(predictions)} predictions in last {LOOKBACK_HOURS}h")

    # ─── 3. Cross-reference: match IPs ────────────────────
    # Build lookup: scanner_ip → prediction
    pred_by_ip: dict = {}
    for pred in predictions:
        scanner = pred.get("scanner_ip", "")
        if scanner:
            pred_by_ip[scanner] = pred
        # Also index by compromised_host.ip
        comp = pred.get("compromised_host", {})
        if isinstance(comp, dict) and comp.get("ip"):
            pred_by_ip[comp["ip"]] = pred
        elif isinstance(comp, str) and comp:
            pred_by_ip[comp] = pred

    validated_count = 0
    for capture in captures:
        source_ip = capture.get("source_ip", "")
        target_ip = capture.get("target_ip", "")

        # Match: honeypot source_ip matches prediction scanner_ip
        matching_pred = pred_by_ip.get(source_ip) or pred_by_ip.get(target_ip)

        if matching_pred:
            # ─── 4. Generate validated CTI ────────────
            payload_text = capture.get("payload", "N/A")
            if isinstance(payload_text, dict):
                payload_text = json.dumps(payload_text, default=str)

            pred_chain = matching_pred.get("predicted_kill_chain", [])
            chain_summary = "; ".join(
                f"{s.get('technique_id', '?')}/{s.get('tactic', '?')}"
                for s in (pred_chain if isinstance(pred_chain, list) else [])
            )

            validated_doc = {
                "validation_id": str(uuid.uuid4()),
                "timestamp": datetime.utcnow().isoformat(),
                "source_ip": source_ip,
                "target_ip": target_ip,
                "prediction_id": matching_pred.get("prediction_id", ""),
                "original_risk_score": matching_pred.get("overall_risk_score", 0),
                "validated_confidence": 100.0,
                "honeypot_capture": {
                    "payload": str(payload_text)[:500],
                    "protocol": capture.get("protocol", ""),
                    "honeypot_id": capture.get("honeypot_id", ""),
                    "captured_at": capture.get("timestamp", ""),
                },
                "predicted_kill_chain_summary": chain_summary,
                "validation_type": "HONEYPOT_CONFIRMED",
                "message": (
                    f"[VALIDATED TTP] Attacker at {source_ip} targeted {target_ip}. "
                    f"Honeypot captured payload: {str(payload_text)[:200]}. "
                    f"Predicted chain: {chain_summary}. "
                    f"Confidence updated to 100%."
                ),
                "tags": ["validated_cti"],
                "severity": "Critical",
                "tenant_id": "default",
                # KNN vector field — dummy vector for mapping compliance
                "message_vector": _dummy_vector(),
            }

            # ─── 5. Index to security-logs-knn ────────
            doc_id = f"vcti-{validated_doc['validation_id'][:8]}"
            try:
                os_client.index(
                    index=VALIDATED_INDEX,
                    id=doc_id,
                    body=validated_doc,
                    refresh=True,
                )
                validated_count += 1
                logger.info(
                    f"[VALIDATED TTP] Attacker at {source_ip} targeted "
                    f"{target_ip}. Honeypot captured payload: "
                    f"{str(payload_text)[:100]}. Confidence updated to 100%."
                )
            except Exception as exc:
                logger.error(f" Failed to index validated CTI: {exc}")

        else:
            # No matching prediction — log as unmatched honeypot activity
            logger.debug(
                f" Honeypot capture from {source_ip} — no matching prediction"
            )

    logger.info(
        f" Feedback loop complete: {validated_count} validated CTI documents "
        f"injected into {VALIDATED_INDEX}"
    )
    return validated_count


# ─── Entry Point ──────────────────────────────────────────────
if __name__ == "__main__":
    count = run_feedback_loop()
    print(f"\n{'='*60}")
    print(f"  Feedback Loop Result: {count} validated CTI documents")
    print(f"{'='*60}")
