"""
NeoVigil Adaptation Engine -- Phase 5
=======================================
Closes the defense lifecycle loop with quality assurance and learning:

  1. **STIX Quality Control** -- Validate all STIX 2.1 bundles produced
  2. **Knowledge Base Population** -- Store attacker TTPs for semantic recall
  3. **Reinforcement Learning** -- RLHF-based weight adjustment recommendations
  4. **Executive Reporting** -- Auto-generated PDF with Phase 1-4 timeline

Consumes:  adapt_tasks             (RabbitMQ)
Produces:  adapt-cycles            (OpenSearch)
           incident-timeline       (OpenSearch)
           PDF reports             (out/ directory)
"""

import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime

import pika

# ─── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [AdaptEngine] %(levelname)s -- %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ─── Imports ──────────────────────────────────────────────────
try:
    from src.setup_opensearch import get_opensearch_client, upload_to_opensearch
    from src.audit_logger import AuditLogger
except ImportError:
    try:
        from setup_opensearch import get_opensearch_client, upload_to_opensearch
        from audit_logger import AuditLogger
    except ImportError:
        get_opensearch_client = None
        upload_to_opensearch = None
        AuditLogger = None

try:
    from src.validate_stix import validate_stix_json
except ImportError:
    try:
        from validate_stix import validate_stix_json
    except ImportError:
        validate_stix_json = None

try:
    from src.feedback_loop import run_feedback_loop
except ImportError:
    try:
        from feedback_loop import run_feedback_loop
    except ImportError:
        run_feedback_loop = None

try:
    from src.to_pdf import generate_pdf_report
except ImportError:
    try:
        from to_pdf import generate_pdf_report
    except ImportError:
        generate_pdf_report = None

# ─── Configuration ────────────────────────────────────────────
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_USER = os.getenv("RABBITMQ_DEFAULT_USER", "user")
RABBITMQ_PASS = os.getenv("RABBITMQ_DEFAULT_PASS", "password")

ADAPT_QUEUE = "adapt_tasks"
ADAPT_CYCLES_INDEX = "adapt-cycles"
INCIDENT_TIMELINE_INDEX = "incident-timeline"
KB_INDEX = "cti-knowledge-base"
PREDICTIONS_INDEX = "attack-path-predictions"
HONEYPOT_INDEX = "honeypot-telemetry"
MTD_AUDIT_INDEX = "mtd-audit-log"
CONTAIN_ACTIONS_INDEX = "contain-actions"
CONTAIN_PLAYBOOKS_INDEX = "contain-playbooks"

OUTPUT_DIR = os.getenv("REPORT_OUTPUT_DIR", "out")


class AdaptEngine:
    """Phase 5 adaptation and learning orchestrator."""

    def __init__(self):
        self.os_client = get_opensearch_client() if get_opensearch_client else None
        self.audit = AuditLogger() if AuditLogger else None
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        logger.info("AdaptEngine initialized.")

    # ─── Main Entry Point ────────────────────────────────────

    def process_adaptation(self, trigger: dict):
        """
        Main entry: process adaptation trigger from Phase 4.

        trigger = {
            "incident_id": str,
            "trigger_source": "phase4_contain_complete",
            "prediction_id": str,
            "playbook_id": str,
            "firewall_blocks": [...],
            "iac_patches": [...],
            "risk_score": float,
            "kill_chain": [...],
            "attacker_ips": [...],
            "target_ips": [...],
            "timestamp": str,
        }
        """
        incident_id = trigger.get("incident_id", str(uuid.uuid4()))
        cycle_id = f"adapt-{str(uuid.uuid4())[:8]}"

        logger.info(
            f"[{cycle_id}] Processing adaptation for incident {incident_id}"
        )

        # 1. STIX Quality Control
        stix_validation = self.validate_stix_quality(trigger)
        logger.info(
            f"[{cycle_id}] STIX validation: "
            f"{'PASS' if stix_validation.get('valid') else 'SKIP/FAIL'}"
        )

        # 2. Knowledge Base Population
        kb_count = self.populate_knowledge_base(trigger)
        logger.info(f"[{cycle_id}] Knowledge base entries added: {kb_count}")

        # 3. Reinforcement Learning Weight Adjustment
        rl_adjustments = self.run_feedback_adjustment(trigger)
        logger.info(
            f"[{cycle_id}] RL adjustments: "
            f"validated={rl_adjustments.get('validated_count', 0)}"
        )

        # 4. Build Incident Timeline
        timeline = self.build_incident_timeline(trigger)
        logger.info(
            f"[{cycle_id}] Incident timeline built: "
            f"{len(timeline.get('phases', {}))} phases"
        )

        # 5. Generate Executive PDF Report
        report_path = self.generate_executive_report(trigger, timeline)
        logger.info(f"[{cycle_id}] Report: {report_path or 'skipped'}")

        # 6. Record adaptation cycle
        cycle_doc = {
            "cycle_id": cycle_id,
            "incident_id": incident_id,
            "timestamp": datetime.utcnow().isoformat(),
            "stix_validation": stix_validation,
            "knowledge_base_entries": kb_count,
            "rl_adjustments": rl_adjustments,
            "report_path": report_path,
            "status": "COMPLETED",
            "tenant_id": trigger.get("tenant_id", "default"),
        }
        if upload_to_opensearch:
            upload_to_opensearch(
                cycle_doc, doc_id=cycle_id, index_name=ADAPT_CYCLES_INDEX
            )

        # Audit log
        if self.audit:
            self.audit.log_event(
                actor="AdaptEngine",
                action="ADAPT_CYCLE_COMPLETE",
                target=incident_id,
                status="SUCCESS",
                justification=f"Phase 5 adaptation cycle {cycle_id} completed",
            )

        logger.info(f"[{cycle_id}] Phase 5 ADAPT complete.")
        return cycle_doc

    # ─── Sub-Engine 1: STIX Quality Control ──────────────────

    def validate_stix_quality(self, trigger: dict) -> dict:
        """Validate STIX bundles associated with this incident."""
        if not validate_stix_json:
            return {"valid": None, "reason": "validator_unavailable"}

        playbook_id = trigger.get("playbook_id")
        if not playbook_id or not self.os_client:
            return {"valid": None, "reason": "no_playbook"}

        try:
            resp = self.os_client.get(
                index=CONTAIN_PLAYBOOKS_INDEX, id=playbook_id
            )
            playbook = resp.get("_source", {})
            stix_bundle_id = playbook.get("stix_bundle_id")

            if not stix_bundle_id:
                return {"valid": None, "reason": "no_stix_bundle"}

            # For now, validate the playbook structure as a proxy
            # Full STIX validation requires the actual bundle document
            playbook_json = json.dumps(playbook, default=str)
            is_valid, details = validate_stix_json(playbook_json)

            return {
                "valid": is_valid,
                "errors": details.get("counts", {}).get("errors", 0),
                "warnings": details.get("counts", {}).get("warnings", 0),
            }
        except Exception as exc:
            logger.debug(f"STIX validation skipped: {exc}")
            return {"valid": None, "reason": str(exc)}

    # ─── Sub-Engine 2: Knowledge Base Population ─────────────

    def populate_knowledge_base(self, trigger: dict) -> int:
        """
        Extract attacker TTPs from the incident and store in
        cti-knowledge-base for future semantic recall.
        """
        if not self.os_client:
            return 0

        entries_added = 0
        kill_chain = trigger.get("kill_chain", [])
        incident_id = trigger.get("incident_id", "unknown")

        for step in kill_chain:
            if not isinstance(step, dict):
                continue

            technique_id = step.get("technique_id", "UNKNOWN")
            doc_id = f"kb-{incident_id[:8]}-{technique_id}"

            doc = {
                "external_id": technique_id,
                "name": step.get("technique_name", step.get("tactic", "Unknown")),
                "description": (
                    f"Observed in incident {incident_id}. "
                    f"Attacker used {technique_id} targeting "
                    f"{step.get('target_host', 'unknown')}. "
                    f"Confidence: {step.get('confidence', 0)}. "
                    f"Risk score: {trigger.get('risk_score', 0)}."
                ),
                "source": "incident_learning",
                "type": "attack",
                "last_updated": datetime.utcnow().isoformat(),
                "incident_id": incident_id,
            }

            try:
                self.os_client.index(
                    index=KB_INDEX, id=doc_id, body=doc, refresh=True
                )
                entries_added += 1
            except Exception as exc:
                logger.warning(f"KB population failed for {technique_id}: {exc}")

        return entries_added

    # ─── Sub-Engine 3: Reinforcement Learning ────────────────

    def run_feedback_adjustment(self, trigger: dict) -> dict:
        """
        RLHF-based weight adjustment for prediction accuracy.
        Leverages existing feedback_loop.py + LLM weight recommendations.
        """
        result = {
            "validated_count": 0,
            "weight_recommendations": [],
        }

        # Run existing feedback loop
        if run_feedback_loop:
            try:
                validated = run_feedback_loop()
                result["validated_count"] = validated
            except Exception as exc:
                logger.warning(f"Feedback loop execution failed: {exc}")

        # Query prediction accuracy to compute adjustment recommendations
        if self.os_client:
            try:
                accuracy_data = self._compute_prediction_accuracy(trigger)
                result["accuracy"] = accuracy_data

                # Generate weight recommendations based on accuracy
                if accuracy_data.get("total_predictions", 0) > 0:
                    hit_rate = accuracy_data.get("hit_rate", 0)
                    if hit_rate < 0.5:
                        result["weight_recommendations"].append({
                            "parameter": "prediction_confidence_threshold",
                            "current": 70,
                            "recommended": 60,
                            "reason": f"Low hit rate ({hit_rate:.1%}), lower threshold to increase sensitivity",
                        })
                    elif hit_rate > 0.9:
                        result["weight_recommendations"].append({
                            "parameter": "prediction_confidence_threshold",
                            "current": 70,
                            "recommended": 80,
                            "reason": f"High hit rate ({hit_rate:.1%}), raise threshold to reduce false positives",
                        })
            except Exception as exc:
                logger.debug(f"Prediction accuracy computation failed: {exc}")

        return result

    def _compute_prediction_accuracy(self, trigger: dict) -> dict:
        """Compute prediction accuracy metrics from recent data."""
        try:
            # Count recent predictions
            pred_query = {
                "query": {"match_all": {}},
                "size": 0,
                "aggs": {"total": {"value_count": {"field": "prediction_id"}}},
            }
            pred_resp = self.os_client.search(
                index=PREDICTIONS_INDEX, body=pred_query
            )
            total_preds = (
                pred_resp.get("aggregations", {})
                .get("total", {})
                .get("value", 0)
            )

            # Count validated predictions (from prediction-accuracy index)
            val_query = {
                "query": {"match_all": {}},
                "size": 0,
                "aggs": {"total": {"value_count": {"field": "validation_id"}}},
            }
            val_resp = self.os_client.search(
                index="prediction-accuracy", body=val_query
            )
            total_validated = (
                val_resp.get("aggregations", {})
                .get("total", {})
                .get("value", 0)
            )

            hit_rate = total_validated / max(total_preds, 1)
            return {
                "total_predictions": total_preds,
                "total_validated": total_validated,
                "hit_rate": round(hit_rate, 4),
            }
        except Exception:
            return {"total_predictions": 0, "total_validated": 0, "hit_rate": 0}

    # ─── Sub-Engine 4: Incident Timeline ─────────────────────

    def build_incident_timeline(self, trigger: dict) -> dict:
        """
        Query all OpenSearch indices to build a complete Phase 1-4
        timeline for this incident.
        """
        incident_id = trigger.get("incident_id", "unknown")
        prediction_id = trigger.get("prediction_id")
        mtd_action_id = trigger.get("mtd_action_id")

        timeline = {
            "incident_id": incident_id,
            "timestamp": datetime.utcnow().isoformat(),
            "risk_score": trigger.get("risk_score", 0),
            "phases": {},
        }

        # Phase 1: PREDICT
        if prediction_id and self.os_client:
            timeline["phases"]["predict"] = self._query_phase(
                PREDICTIONS_INDEX, "prediction_id", prediction_id
            )

        # Phase 2: DECEIVE
        if prediction_id and self.os_client:
            timeline["phases"]["deceive"] = self._query_phase(
                HONEYPOT_INDEX, "prediction_id", prediction_id
            )

        # Phase 3: MUTATE
        if mtd_action_id and self.os_client:
            timeline["phases"]["mutate"] = self._query_phase(
                MTD_AUDIT_INDEX, "action_id", mtd_action_id
            )

        # Phase 4: CONTAIN
        if self.os_client:
            timeline["phases"]["contain"] = self._query_phase(
                CONTAIN_ACTIONS_INDEX, "incident_id", incident_id
            )

        # Store timeline
        if upload_to_opensearch:
            upload_to_opensearch(
                timeline, doc_id=incident_id, index_name=INCIDENT_TIMELINE_INDEX
            )

        return timeline

    def _query_phase(self, index: str, field: str, value: str) -> dict:
        """Query a phase index for related documents."""
        try:
            resp = self.os_client.search(
                index=index,
                body={"query": {"term": {field: value}}, "size": 10},
            )
            hits = resp.get("hits", {}).get("hits", [])
            return {
                "count": len(hits),
                "records": [h["_source"] for h in hits[:5]],
            }
        except Exception as exc:
            return {"count": 0, "error": str(exc)}

    # ─── Sub-Engine 5: Executive Reporting ───────────────────

    def generate_executive_report(self, trigger: dict, timeline: dict) -> str:
        """Auto-generate PDF report with full Phase 1-4 timeline."""
        if not generate_pdf_report:
            logger.debug("PDF generation unavailable")
            return None

        incident_id = trigger.get("incident_id", "unknown")[:8]
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(
            OUTPUT_DIR, f"incident_{incident_id}_{timestamp}.pdf"
        )

        # Build comprehensive report data
        report_data = {
            "filename": f"Incident-{incident_id}",
            "confidence": int(trigger.get("risk_score", 0)),
            "ttps": trigger.get("kill_chain", []),
            "indicators": {
                "ipv4": trigger.get("attacker_ips", []),
            },
            "courses_of_action": self._build_action_summary(trigger, timeline),
        }

        try:
            result_path = generate_pdf_report(report_data, output_path)
            return result_path
        except Exception as exc:
            logger.error(f"PDF report generation failed: {exc}")
            return None

    def _build_action_summary(self, trigger: dict, timeline: dict) -> list:
        """Build a summary of all containment actions for the report."""
        actions = []

        # Firewall blocks
        blocks = trigger.get("firewall_blocks", [])
        if blocks:
            blocked_ips = [b["ip"] for b in blocks if b.get("success")]
            actions.append({
                "name": "Firewall Containment",
                "description": f"Blocked {len(blocked_ips)} attacker IPs: "
                               f"{', '.join(blocked_ips[:5])}",
            })

        # Playbook
        playbook_id = trigger.get("playbook_id")
        if playbook_id:
            actions.append({
                "name": "SOAR Playbook Deployed",
                "description": f"Auto-generated containment playbook {playbook_id}",
            })

        # IaC patches
        patches = trigger.get("iac_patches", [])
        if patches:
            actions.append({
                "name": "Infrastructure Patches",
                "description": f"Generated {len(patches)} security patches for "
                               f"vulnerable configurations",
            })

        # Phase summary
        phases = timeline.get("phases", {})
        phase_summary = []
        for phase_name, phase_data in phases.items():
            count = phase_data.get("count", 0) if isinstance(phase_data, dict) else 0
            phase_summary.append(f"{phase_name.upper()}: {count} records")
        if phase_summary:
            actions.append({
                "name": "Incident Timeline",
                "description": " | ".join(phase_summary),
            })

        return actions

    # ─── RabbitMQ Consumer ───────────────────────────────────

    def _on_message(self, ch, method, properties, body):
        """RabbitMQ message callback."""
        try:
            trigger = json.loads(body)
            self.process_adaptation(trigger)
            ch.basic_ack(delivery_tag=method.delivery_tag)
        except Exception as exc:
            logger.error(f"Failed to process adaptation: {exc}")
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

    def run(self):
        """Start consuming from adapt_tasks queue with auto-reconnect."""
        logger.info("Phase 5 AdaptEngine starting...")
        while True:
            try:
                credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
                connection = pika.BlockingConnection(
                    pika.ConnectionParameters(
                        host=RABBITMQ_HOST,
                        credentials=credentials,
                        connection_attempts=5,
                        retry_delay=5,
                        heartbeat=60,
                    )
                )
                channel = connection.channel()
                dlq_args = {
                    "x-dead-letter-exchange": "",
                    "x-dead-letter-routing-key": "dlq_main",
                }
                channel.queue_declare(queue=ADAPT_QUEUE, durable=True, arguments=dlq_args)
                channel.basic_qos(prefetch_count=1)
                channel.basic_consume(
                    queue=ADAPT_QUEUE,
                    on_message_callback=self._on_message,
                )
                logger.info(f"Consuming from {ADAPT_QUEUE}...")
                channel.start_consuming()

            except pika.exceptions.AMQPConnectionError as exc:
                logger.warning(f"RabbitMQ connection lost: {exc}. Reconnecting in 5s...")
                time.sleep(5)
            except KeyboardInterrupt:
                logger.info("AdaptEngine shutting down.")
                break
            except Exception as exc:
                logger.error(f"Unexpected error: {exc}. Restarting in 10s...")
                time.sleep(10)


# ─── Entry Point ──────────────────────────────────────────────
if __name__ == "__main__":
    engine = AdaptEngine()
    engine.run()
