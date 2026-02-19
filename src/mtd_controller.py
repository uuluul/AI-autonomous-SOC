"""
NeoVigil MTD Controller — Phase 3
==================================
Central orchestrator for Moving Target Defense actions.

This service:
  1. Consumes trigger events from 'mtd_action_queue' (RabbitMQ)
  2. Gathers multi-signal intelligence from OpenSearch
  3. Computes composite MTD threat score
  4. Determines action tier (obfuscation / migration / lockdown)
  5. Enforces RBAC approval gates
  6. Dispatches to Obfuscation Engine or Migration Engine
  7. Maintains immutable audit trail

Trigger sources:
  - Phase 1: High-risk predictions (risk ≥ 85)
  - Phase 2: Validated honeypot captures
  - Scanner detection: Repeated probes from same IP
  - Manual: Analyst-initiated from the SOC dashboard
"""

import json
import logging
import os
import signal
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import pika

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [MTD-Controller] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# ─── Lazy imports ────────────────────────────────────────────
try:
    from src.obfuscation_engine import ObfuscationEngine
except ImportError:
    from obfuscation_engine import ObfuscationEngine

try:
    from src.migration_engine import MigrationEngine
except ImportError:
    from migration_engine import MigrationEngine

try:
    from src.setup_opensearch import get_opensearch_client
except ImportError:
    from setup_opensearch import get_opensearch_client

# ─── Configuration ───────────────────────────────────────────
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "rabbitmq")
MTD_ACTION_QUEUE = "mtd_action_queue"
MTD_APPROVAL_QUEUE = "mtd_approval_queue"
MTD_AUDIT_INDEX = "mtd-audit-log"
MTD_MUTATIONS_INDEX = "mtd-active-mutations"
PREDICTION_INDEX = "attack-path-predictions"
TELEMETRY_INDEX = "honeypot-telemetry"
ASSETS_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "data", "assets.json"
)

# ─── Scoring weights ─────────────────────────────────────────
WEIGHT_PRED_RISK = 0.40
WEIGHT_HP_CAPTURES = 0.30
WEIGHT_SCAN_FREQ = 0.20
WEIGHT_CRITICALITY = 0.10

# ─── Thresholds ──────────────────────────────────────────────
THRESHOLD_OBFUSCATION = 30
THRESHOLD_MIGRATION_PROPOSAL = 35
THRESHOLD_MIGRATION_EXECUTE = 40

# ─── Asset criticality mapping ───────────────────────────────
_CRIT_SCORE = {
    "Critical": 1.0, "High": 0.8, "Medium": 0.5, "Low": 0.3, "Unknown": 0.4,
}

# ─── Approval TTL ────────────────────────────────────────────
APPROVAL_TIMEOUT_MINUTES = int(os.getenv("MTD_APPROVAL_TIMEOUT", "15"))

# ─── RBAC Policy for MTD actions ─────────────────────────────
MTD_RBAC = {
    "obfuscation": {
        "auto_approve": True,
        "min_role": "Tier1_Analyst",
    },
    "migration": {
        "auto_approve": False,
        "min_role": "Tier2_Analyst",
    },
    "emergency_lockdown": {
        "auto_approve": False,
        "min_role": "Admin",
    },
}

# ─── Role hierarchy (lower number = higher privilege) ────────
_ROLE_LEVEL = {
    "System_Owner": 0,
    "Admin": 1,
    "Tier2_Analyst": 2,
    "Tier1_Analyst": 3,
    "Viewer": 4,
}


# ════════════════════════════════════════════════════════════
#  MTD Threat Scoring
# ════════════════════════════════════════════════════════════

def compute_mtd_score(signals: dict) -> float:
    """
    Composite MTD trigger score (0-100).

    Inputs (all normalized to 0-100 range):
      - prediction_risk:   Phase 1 risk score (direct)
      - captures:          Number of honeypot captures (× 25, capped at 100)
      - scan_count:        Scanner probe frequency (× 10, capped at 100)
      - criticality:       Target asset criticality string → weight

    Weights:
      Prediction   40%
      Captures     30%
      Scan freq    20%
      Criticality  10%
    """
    pred_risk = min(100, max(0, signals.get("prediction_risk", 0)))
    hp_captures = min(100, signals.get("captures", 0) * 25)
    scan_freq = min(100, signals.get("scan_count", 0) * 10)
    crit_str = signals.get("criticality", "Unknown")
    criticality = _CRIT_SCORE.get(crit_str, 0.4) * 100

    score = (
        pred_risk   * WEIGHT_PRED_RISK +
        hp_captures * WEIGHT_HP_CAPTURES +
        scan_freq   * WEIGHT_SCAN_FREQ +
        criticality * WEIGHT_CRITICALITY
    )

    # Demo override: high prediction risk guarantees aggressive response
    if pred_risk > 80:
        score = max(score, 85.0)

    return round(score, 2)


def determine_action(score: float) -> dict:
    """
    Determine the MTD action tier based on composite score.

    Returns
    -------
    dict with keys: action_type, requires_approval, min_role
    """
    if score >= THRESHOLD_MIGRATION_EXECUTE:
        return {
            "action_type": "obfuscation+migration",
            "obfuscate": True,
            "migrate": True,
            "requires_approval": True,
            "min_role": "Tier2_Analyst",
        }
    elif score >= THRESHOLD_MIGRATION_PROPOSAL:
        return {
            "action_type": "obfuscation+migration_proposed",
            "obfuscate": True,
            "migrate": False,  # Proposed only — not auto-executed
            "requires_approval": True,
            "min_role": "Tier2_Analyst",
        }
    elif score >= THRESHOLD_OBFUSCATION:
        return {
            "action_type": "obfuscation",
            "obfuscate": True,
            "migrate": False,
            "requires_approval": False,
            "min_role": "Tier1_Analyst",
        }
    else:
        return {
            "action_type": "none",
            "obfuscate": False,
            "migrate": False,
            "requires_approval": False,
            "min_role": "Viewer",
        }


def check_mtd_rbac(action: dict, user_role: str = "system") -> bool:
    """
    Verify the user role meets the minimum requirement for the action.
    """
    # System service always operates as Admin
    if user_role in ("system", "System_Owner", "Admin"):
        return True

    if not action.get("requires_approval"):
        return True

    min_role = action.get("min_role", "Admin")
    user_level = _ROLE_LEVEL.get(user_role, 99)
    min_level = _ROLE_LEVEL.get(min_role, 99)

    return user_level <= min_level


# ════════════════════════════════════════════════════════════
#  Signal Gathering
# ════════════════════════════════════════════════════════════

class SignalGatherer:
    """
    Gathers multi-source intelligence from OpenSearch indices
    to compute the MTD composite score.
    """

    def __init__(self, os_client=None):
        self.os_client = os_client or get_opensearch_client()
        self.assets: Dict[str, dict] = {}
        self._load_assets()

    def _load_assets(self):
        """Load CMDB asset data."""
        try:
            with open(ASSETS_PATH, "r", encoding="utf-8") as f:
                self.assets = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            logger.warning("⚠️  Could not load assets.json")

    def gather_signals(self, trigger: dict) -> dict:
        """
        Gather all signals for the target IP/host from trigger data
        and enrichment queries.
        """
        target_ip = trigger.get("target_ip", "")
        scanner_ip = trigger.get("scanner_ip", trigger.get("source_ip", ""))

        signals = {
            "prediction_risk": trigger.get("risk_score", 0),
            "captures": self._count_captures(scanner_ip),
            "scan_count": self._count_scanner_probes(scanner_ip),
            "criticality": self._get_criticality(target_ip),
            "target_ip": target_ip,
            "scanner_ip": scanner_ip,
            "target_host": self._get_hostname(target_ip),
            "target_software": self._get_software(target_ip),
        }

        return signals

    def _count_captures(self, scanner_ip: str) -> int:
        """Count honeypot captures attributed to the scanner IP."""
        if not scanner_ip:
            return 0
        try:
            resp = self.os_client.count(
                index=TELEMETRY_INDEX,
                body={"query": {"term": {"source_ip": scanner_ip}}},
            )
            return resp.get("count", 0)
        except Exception:
            return 0

    def _count_scanner_probes(self, scanner_ip: str) -> int:
        """Count recent scanner probes from this IP in the last 1 hour."""
        if not scanner_ip:
            return 0
        try:
            resp = self.os_client.count(
                index="security-logs-knn",
                body={
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"source_ip": scanner_ip}},
                                {"range": {
                                    "timestamp": {
                                        "gte": "now-1h",
                                    },
                                }},
                            ],
                        },
                    },
                },
            )
            return resp.get("count", 0)
        except Exception:
            return 0

    def _get_criticality(self, target_ip: str) -> str:
        """Get asset criticality from CMDB."""
        asset = self.assets.get(target_ip, {})
        return asset.get("criticality", "Unknown")

    def _get_hostname(self, target_ip: str) -> str:
        """Get hostname from CMDB."""
        asset = self.assets.get(target_ip, {})
        return asset.get("hostname", target_ip)

    def _get_software(self, target_ip: str) -> List[str]:
        """Get installed software from CMDB."""
        asset = self.assets.get(target_ip, {})
        return asset.get("software", [])


# ════════════════════════════════════════════════════════════
#  MTD Controller (Main Orchestrator)
# ════════════════════════════════════════════════════════════

class MTDController:
    """
    Central orchestrator for all MTD actions.

    Consumes from:
      - mtd_action_queue:   Trigger events from Phase 1/2/scanner
      - mtd_approval_queue: Approval decisions from analysts

    Dispatches to:
      - ObfuscationEngine:  For header/banner spoofing
      - MigrationEngine:    For Blue/Green container migration
    """

    def __init__(self):
        self.signal_gatherer = SignalGatherer()
        self.obfuscation = ObfuscationEngine()
        self.migration = MigrationEngine()
        self.os_client = get_opensearch_client()
        self.pending_approvals: Dict[str, dict] = {}
        self._ensure_indices()
        self._shutdown = threading.Event()

    def _ensure_indices(self):
        """Create OpenSearch indices if they don't exist."""
        for idx in [MTD_AUDIT_INDEX, MTD_MUTATIONS_INDEX]:
            try:
                if not self.os_client.indices.exists(index=idx):
                    self.os_client.indices.create(
                        index=idx,
                        body={
                            "settings": {
                                "number_of_shards": 1,
                                "number_of_replicas": 0,
                            },
                        },
                    )
                    logger.info(f"📁 Created index: {idx}")
            except Exception as exc:
                logger.warning(f"⚠️  Could not create index {idx}: {exc}")

    # ─── Main Trigger Processing ──────────────────────────

    def process_trigger(self, trigger: dict):
        """
        Process an incoming MTD trigger event.

        Steps:
          1. Gather intelligence signals
          2. Compute MTD composite score
          3. Determine action tier
          4. Check RBAC gate
          5. Execute or submit for approval
        """
        trigger_id = trigger.get("trigger_id", str(uuid.uuid4()))
        trigger_source = trigger.get("trigger_source", "unknown")

        logger.info(
            f"📨 [{trigger_id[:8]}] New MTD trigger from {trigger_source}"
        )

        # 1. Gather signals
        signals = self.signal_gatherer.gather_signals(trigger)

        # 2. Compute score
        score = compute_mtd_score(signals)

        logger.info(
            f"📊 [{trigger_id[:8]}] MTD Score: {score}\n"
            f"   Components: pred_risk={signals['prediction_risk']}, "
            f"captures={signals['captures']}, "
            f"scans={signals['scan_count']}, "
            f"criticality={signals['criticality']}"
        )

        # 3. Determine action
        action = determine_action(score)

        if action["action_type"] == "none":
            logger.info(
                f"⏭️  [{trigger_id[:8]}] Score {score} below threshold "
                f"({THRESHOLD_OBFUSCATION}). No action."
            )
            return

        # 4. Build action record
        action_record = {
            "action_id": f"mtd-{uuid.uuid4().hex[:8]}",
            "trigger_id": trigger_id,
            "trigger_source": trigger_source,
            "score": score,
            "signals": signals,
            "action_type": action["action_type"],
            "obfuscate": action["obfuscate"],
            "migrate": action["migrate"],
            "requires_approval": action["requires_approval"],
            "status": "PROPOSED",
            "proposed_at": datetime.utcnow().isoformat(),
            "target_ip": signals.get("target_ip", ""),
            "scanner_ip": signals.get("scanner_ip", ""),
            "target_host": signals.get("target_host", ""),
        }

        # 5. RBAC gate
        if action["requires_approval"]:
            # Submit for human approval
            self._submit_for_approval(action_record)
        else:
            # Auto-approved (obfuscation only)
            action_record["status"] = "AUTO_APPROVED"
            action_record["approved_by"] = "system"
            self._execute_action(action_record)

    # ─── Action Execution ─────────────────────────────────

    def _execute_action(self, action_record: dict):
        """Execute the MTD action (obfuscation and/or migration)."""
        action_id = action_record["action_id"]
        action_record["status"] = "EXECUTING"
        action_record["execution_started"] = datetime.utcnow().isoformat()

        logger.info(
            f"🚀 [{action_id}] Executing MTD action: "
            f"{action_record['action_type']}"
        )

        # ─── Obfuscation ─────────────────────────────
        if action_record.get("obfuscate"):
            try:
                scanner_ip = action_record.get("scanner_ip", "")
                target_host = action_record.get("target_host", "unknown")
                target_software = action_record.get("signals", {}).get(
                    "target_software", ["unknown"]
                )
                primary_software = (
                    target_software[0] if target_software else "unknown"
                )

                rule = self.obfuscation.generate_rule(
                    scanner_ip=scanner_ip,
                    target_service=primary_software,
                    target_host=target_host,
                    trigger_reason=(
                        f"MTD score {action_record['score']} "
                        f"from {action_record['trigger_source']}"
                    ),
                )

                if rule:
                    action_record["obfuscation_rule_id"] = rule.get("rule_id")
                    # Attempt Nginx reload
                    self.obfuscation.reload_nginx()

                logger.info(
                    f"🎭 [{action_id}] Obfuscation applied for "
                    f"{scanner_ip} → {rule.get('spoof_profile', 'N/A')}"
                )
            except Exception as exc:
                logger.error(f"❌ [{action_id}] Obfuscation failed: {exc}")

        # ─── Migration ────────────────────────────────
        if action_record.get("migrate"):
            try:
                target_host = action_record.get("target_host", "")
                result = self.migration.execute_migration(
                    target_container_name=target_host,
                    trigger_reason=(
                        f"MTD score {action_record['score']} — "
                        f"{action_record['action_type']}"
                    ),
                    approved_by=action_record.get("approved_by", "system"),
                )
                action_record["migration_result"] = result
                logger.info(
                    f"🔄 [{action_id}] Migration result: "
                    f"{result.get('status', 'unknown')}"
                )
            except Exception as exc:
                logger.error(f"❌ [{action_id}] Migration failed: {exc}")

        # ─── Finalize ─────────────────────────────────
        action_record["status"] = "COMPLETED"
        action_record["completed_at"] = datetime.utcnow().isoformat()
        self._index_audit(action_record)

        logger.info(
            f"✅ [{action_id}] MTD action completed: "
            f"{action_record['action_type']} (score={action_record['score']})"
        )

    # ─── Approval Queue ───────────────────────────────────

    def _submit_for_approval(self, action_record: dict):
        """Submit an MTD action for human approval via RabbitMQ.
        
        Hybrid Approval: Sets auto_execute_timestamp to now + 300s.
        If no human decision is received before then, the maintenance
        thread will force-execute the action.
        """
        action_id = action_record["action_id"]
        action_record["status"] = "PENDING_APPROVAL"
        action_record["approval_deadline"] = (
            datetime.utcnow() + timedelta(minutes=APPROVAL_TIMEOUT_MINUTES)
        ).isoformat()
        # Hybrid: auto-execute after 300 seconds if no human decision
        action_record["auto_execute_timestamp"] = (
            datetime.utcnow() + timedelta(seconds=300)
        ).isoformat()

        self.pending_approvals[action_id] = action_record

        # Notification mock: alert SOC analyst
        target_host = action_record.get('target_host', action_record.get('target_ip', 'unknown'))
        logger.info(
            f"[NOTIFICATION] Critical alert sent to SOC analyst. "
            f"Waiting 5 minutes for manual approval before initiating "
            f"autonomous defense for host {target_host}."
        )

        # Publish as PENDING — the approval handler or the maintenance
        # force-timeout will advance the state
        action_record["role"] = "Admin"
        action_record["decision"] = "PENDING"
        action_record["approved_by"] = "awaiting_analyst"

        try:
            _user = os.getenv("RABBITMQ_USER", "user")
            _pass = os.getenv("RABBITMQ_PASS", "password")
            _creds = pika.PlainCredentials(_user, _pass)
            connection = pika.BlockingConnection(
                pika.ConnectionParameters(
                    host=RABBITMQ_HOST,
                    credentials=_creds,
                    connection_attempts=3,
                    retry_delay=2,
                )
            )
            channel = connection.channel()
            channel.queue_declare(queue=MTD_APPROVAL_QUEUE, durable=True)
            channel.basic_publish(
                exchange="",
                routing_key=MTD_APPROVAL_QUEUE,
                body=json.dumps(action_record, default=str),
                properties=pika.BasicProperties(delivery_mode=2),
            )
            connection.close()

            logger.info(
                f"🔔 [{action_id}] Submitted for approval:\n"
                f"   Type:    {action_record['action_type']}\n"
                f"   Score:   {action_record['score']}\n"
                f"   Target:  {target_host}\n"
                f"   Scanner: {action_record.get('scanner_ip', 'N/A')}\n"
                f"   Deadline: {action_record['approval_deadline']}\n"
                f"   Auto-execute at: {action_record['auto_execute_timestamp']}"
            )
        except Exception as exc:
            logger.error(f"❌ Failed to submit for approval: {exc}")

        # Index as pending
        self._index_audit(action_record)

    def process_approval(self, approval: dict):
        """
        Process an approval/rejection decision from an analyst.

        Expected format:
          {
            "action_id": "mtd-...",
            "decision": "APPROVED" | "REJECTED",
            "approved_by": "analyst_username",
            "role": "Tier2_Analyst"
          }
        """
        action_id = approval.get("action_id", "")
        decision = approval.get("decision", "").upper()
        approved_by = approval.get("approved_by", "unknown")
        user_role = approval.get("role", "Admin")

        action_record = self.pending_approvals.get(action_id)
        if not action_record:
            logger.warning(
                f"⚠️  Approval for unknown action: {action_id}"
            )
            return

        # Verify RBAC
        action = determine_action(action_record.get("score", 0))
        if not check_mtd_rbac(action, user_role):
            logger.warning(
                f"🚫 [{action_id}] RBAC denied: role={user_role}, "
                f"required={action.get('min_role')}"
            )
            return

        if decision == "PENDING":
            # Self-published PENDING message — keep in pending_approvals
            # The maintenance thread will force-execute after 300s
            auto_ts = action_record.get("auto_execute_timestamp", "N/A")
            logger.info(
                f"⏳ [{action_id}] PENDING — awaiting analyst decision. "
                f"Auto-execute at: {auto_ts}"
            )
            return

        if decision == "APPROVED":
            logger.info(
                f"✅ [{action_id}] APPROVED by {approved_by} ({user_role})"
            )
            action_record["status"] = "APPROVED"
            action_record["approved_by"] = approved_by
            action_record["approved_at"] = datetime.utcnow().isoformat()
            # Remove from pending so maintenance won't also execute
            self.pending_approvals.pop(action_id, None)
            self._execute_action(action_record)
        elif decision == "REJECTED":
            logger.info(
                f"❌ [{action_id}] REJECTED by {approved_by} ({user_role})"
            )
            action_record["status"] = "REJECTED"
            action_record["rejected_by"] = approved_by
            action_record["rejected_at"] = datetime.utcnow().isoformat()
            self._index_audit(action_record)
        else:
            logger.warning(f"⚠️  Unknown decision: {decision}")

        # Remove from pending
        self.pending_approvals.pop(action_id, None)

    # ─── Approval Timeout Escalation ──────────────────────

    def check_approval_timeouts(self):
        """
        Escalate actions that have been pending approval for too long.
        Runs periodically in the background.
        """
        now = datetime.utcnow()
        stale_actions = []

        for action_id, record in self.pending_approvals.items():
            deadline = record.get("approval_deadline", "")
            if deadline:
                try:
                    dl = datetime.fromisoformat(deadline)
                    if now > dl:
                        stale_actions.append(action_id)
                except ValueError:
                    pass

        for action_id in stale_actions:
            record = self.pending_approvals.pop(action_id, {})
            if record:
                record["status"] = "ESCALATED"
                record["escalated_at"] = now.isoformat()
                record["escalation_reason"] = (
                    f"No approval received within {APPROVAL_TIMEOUT_MINUTES}min"
                )
                self._index_audit(record)
                logger.warning(
                    f"⏰ [{action_id}] ESCALATED: approval timed out "
                    f"after {APPROVAL_TIMEOUT_MINUTES}min"
                )

        # ─── Hybrid Wait-and-Force: auto-execute after timeout ─────
        force_actions = []
        for action_id, record in self.pending_approvals.items():
            auto_ts = record.get("auto_execute_timestamp", "")
            if auto_ts:
                try:
                    ts = datetime.fromisoformat(auto_ts)
                    if now > ts:
                        force_actions.append(action_id)
                except ValueError:
                    pass

        for action_id in force_actions:
            record = self.pending_approvals.pop(action_id, {})
            if record:
                record["status"] = "SYSTEM_FORCED_TIMEOUT"
                record["decision"] = "SYSTEM_FORCED_TIMEOUT"
                record["approved_by"] = "MTD-Auto-Force"
                record["forced_at"] = now.isoformat()
                logger.warning(
                    f"⚡ [{action_id}] FORCE-EXECUTING: No human decision "
                    f"within 300s timeout. Autonomous intervention activated."
                )
                self._execute_action(record)

    # ─── TTL Pruning ──────────────────────────────────────

    def run_maintenance(self):
        """Periodic maintenance: prune expired rules, check timeouts, force-execute."""
        pruned = self.obfuscation.prune_expired_rules()
        if pruned > 0:
            self.obfuscation.reload_nginx()
        self.check_approval_timeouts()
        logger.debug(
            f"🔧 Maintenance tick: {len(self.pending_approvals)} pending actions"
        )

    # ─── Rollback API ─────────────────────────────────────

    def rollback_migration(
        self,
        migration_id: str,
        rolled_back_by: str = "system",
    ) -> dict:
        """Rollback a completed migration."""
        return self.migration.execute_rollback(
            migration_id=migration_id,
            rolled_back_by=rolled_back_by,
        )

    # ─── Statistics ───────────────────────────────────────

    def get_statistics(self) -> dict:
        """Return current MTD operational statistics."""
        return {
            "active_obfuscation_rules": self.obfuscation.get_rule_count(),
            "pending_approvals": len(self.pending_approvals),
            "active_migrations": len(self.migration.active_migrations),
        }

    # ─── OpenSearch ───────────────────────────────────────

    @staticmethod
    def _clean_docker_metadata(data):
        """Deep-clean Docker container metadata to prevent OpenSearch mapping errors.
        
        Removes deeply nested keys (labels, Config, HostConfig, NetworkSettings,
        Mounts) that cause 'illegal_argument_exception' due to dynamic object
        mapping conflicts in OpenSearch.
        """
        BANNED_KEYS = {
            "labels", "Labels", "Config", "HostConfig",
            "NetworkSettings", "Mounts", "GraphDriver",
            "ExposedPorts", "Volumes", "Env",
        }
        if isinstance(data, dict):
            return {
                k: MTDController._clean_docker_metadata(v)
                for k, v in data.items()
                if k not in BANNED_KEYS
            }
        elif isinstance(data, list):
            return [
                MTDController._clean_docker_metadata(item)
                for item in data
            ]
        return data

    def _index_audit(self, record: dict):
        """Index to immutable audit log (with Docker metadata cleanup)."""
        doc_id = record.get("action_id", str(uuid.uuid4()))
        clean_record = self._clean_docker_metadata(record)
        try:
            self.os_client.index(
                index=MTD_AUDIT_INDEX,
                id=doc_id,
                body=clean_record,
                refresh=True,
            )
        except Exception as exc:
            logger.error(f"❌ Audit indexing failed: {exc}")


# ════════════════════════════════════════════════════════════
#  RabbitMQ Consumer Loop
# ════════════════════════════════════════════════════════════

def _connect_rabbitmq():
    """Robust RabbitMQ connection with retry."""
    retry = 0
    max_retries = 30
    
    user = os.getenv("RABBITMQ_USER", "user")
    password = os.getenv("RABBITMQ_PASS", "password")
    credentials = pika.PlainCredentials(user, password)

    while retry < max_retries:
        try:
            connection = pika.BlockingConnection(
                pika.ConnectionParameters(
                    host=RABBITMQ_HOST,
                    credentials=credentials,
                    heartbeat=600,
                    blocked_connection_timeout=300,
                    connection_attempts=3,
                    retry_delay=5,
                )
            )
            logger.info(f"✅ Connected to RabbitMQ at {RABBITMQ_HOST} as {user}")
            return connection
        except pika.exceptions.AMQPConnectionError as exc:
            retry += 1
            wait = min(2 ** retry, 30)
            logger.warning(
                f"⚠️  RabbitMQ connection failed (attempt {retry}/{max_retries}): "
                f"{exc}. Retrying in {wait}s…"
            )
            time.sleep(wait)

    logger.error("❌ Could not connect to RabbitMQ after all retries.")
    sys.exit(1)


def main():
    """Entry point — start the MTD Controller consumer loop."""
    logger.info("=" * 60)
    logger.info("  NeoVigil MTD Controller — Phase 3")
    logger.info("  Moving Target Defense Orchestrator")
    logger.info("=" * 60)

    controller = MTDController()

    # ─── Maintenance thread ───────────────────────────────
    maintenance_stop = threading.Event()

    def maintenance_loop():
        while not maintenance_stop.is_set():
            try:
                controller.run_maintenance()
            except Exception as exc:
                logger.error(f"Maintenance error: {exc}")
            maintenance_stop.wait(30)  # Run every 30s for hybrid approval

    maint_thread = threading.Thread(
        target=maintenance_loop, daemon=True, name="mtd-maintenance",
    )
    maint_thread.start()
    logger.info("🔧 Maintenance thread started (30s cycle — hybrid approval mode)")

    # ─── Signal handler ───────────────────────────────────
    def handle_shutdown(signum, frame):
        logger.info("🛑 Shutdown signal received — cleaning up…")
        maintenance_stop.set()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    # ─── Consumer loop with auto-reconnect ─────────────────
    while True:
        connection = None
        try:
            connection = _connect_rabbitmq()
            channel = connection.channel()
            channel.queue_declare(queue=MTD_ACTION_QUEUE, durable=True)
            channel.queue_declare(queue=MTD_APPROVAL_QUEUE, durable=True)
            channel.basic_qos(prefetch_count=1)

            def on_action(ch, method, properties, body):
                try:
                    trigger = json.loads(body)
                    controller.process_trigger(trigger)
                    ch.basic_ack(delivery_tag=method.delivery_tag)
                except json.JSONDecodeError:
                    logger.error(f"❌ Invalid JSON in action queue")
                    ch.basic_nack(
                        delivery_tag=method.delivery_tag, requeue=False,
                    )
                except Exception as exc:
                    logger.error(f"❌ Error processing trigger: {exc}")
                    ch.basic_nack(
                        delivery_tag=method.delivery_tag, requeue=True,
                    )

            def on_approval(ch, method, properties, body):
                try:
                    approval = json.loads(body)
                    controller.process_approval(approval)
                    ch.basic_ack(delivery_tag=method.delivery_tag)
                except json.JSONDecodeError:
                    logger.error(f"❌ Invalid JSON in approval queue")
                    ch.basic_nack(
                        delivery_tag=method.delivery_tag, requeue=False,
                    )
                except Exception as exc:
                    logger.error(f"❌ Error processing approval: {exc}")
                    ch.basic_nack(
                        delivery_tag=method.delivery_tag, requeue=True,
                    )

            channel.basic_consume(
                queue=MTD_ACTION_QUEUE, on_message_callback=on_action,
            )
            channel.basic_consume(
                queue=MTD_APPROVAL_QUEUE, on_message_callback=on_approval,
            )

            logger.info(
                f"👂 Listening on queues: "
                f"{MTD_ACTION_QUEUE}, {MTD_APPROVAL_QUEUE}"
            )
            logger.info(
                f"📊 Thresholds: "
                f"obfuscation={THRESHOLD_OBFUSCATION}, "
                f"migrate_propose={THRESHOLD_MIGRATION_PROPOSAL}, "
                f"migrate_execute={THRESHOLD_MIGRATION_EXECUTE}"
            )

            channel.start_consuming()

        except pika.exceptions.AMQPConnectionError:
            logger.warning("⚠️  RabbitMQ connection lost. Reconnecting…")
            time.sleep(5)
        except Exception as exc:
            logger.error(f"❌ Unexpected error: {exc}", exc_info=True)
            time.sleep(5)
        finally:
            if connection and not connection.is_closed:
                try:
                    connection.close()
                except Exception:
                    pass


if __name__ == "__main__":
    main()
