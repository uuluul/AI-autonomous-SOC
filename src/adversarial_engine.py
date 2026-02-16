"""
NeoVigil Adversarial Prediction Engine  —  Phase 1
===================================================
Orchestrates three sub-engines for proactive threat prediction:

  1. **Topology-Aware Path Simulator**
     – BFS from compromised host → rank reachable targets by criticality

  2. **Adversarial Persona Emulator ("REDSPEC")**
     – Instructs the LLM to adopt an attacker mindset and predict a
       concrete kill chain across the real network topology

  3. **Zero-Log Global Anticipation Engine**
     – Cross-references newly-crawled CVEs against the local asset
       inventory and issues preemptive alerts even with *zero* anomalous
       Fluent Bit logs

Consumes:  prediction_tasks  /  zero_log_events   (RabbitMQ)
Produces:  attack-path-predictions                 (OpenSearch)

SAFETY:  All output is **read-only / informational**.  Predictions
         never trigger automated blocking.  Tier-2+ RBAC approval
         is required before any defensive action is taken.
"""

import json
import logging
import os
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import pika

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)

# ─── Lazy imports (graceful in & out of Docker) ─────────────
try:
    from src.llm_client import LLMClient
    from src.topology_graph import TopologyGraph
    from src.cve_enrichment import CVEEnricher
    from src.setup_opensearch import get_opensearch_client
except ImportError:
    from llm_client import LLMClient
    from topology_graph import TopologyGraph
    from cve_enrichment import CVEEnricher
    from setup_opensearch import get_opensearch_client

# ─── Configuration ──────────────────────────────────────────
PREDICTION_INDEX = "attack-path-predictions"
PREDICTION_QUEUE = "prediction_tasks"
ZERO_LOG_QUEUE = "zero_log_events"
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "rabbitmq")
DEDUP_WINDOW_SEC = int(os.getenv("PREDICTION_DEDUP_WINDOW", "300"))  # 5 min

# Criticality weights for risk scoring
_CRIT_WEIGHT = {"Critical": 1.0, "High": 0.75, "Medium": 0.5, "Low": 0.25, "Unknown": 0.3}
_SEV_WEIGHT = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.5, "LOW": 0.25, "UNKNOWN": 0.3}

# ════════════════════════════════════════════════════════════
#  Index Mapping
# ════════════════════════════════════════════════════════════
PREDICTION_INDEX_MAPPING = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "properties": {
            "prediction_id":          {"type": "keyword"},
            "timestamp":              {"type": "date"},
            "tenant_id":              {"type": "keyword"},
            "trigger_type":           {"type": "keyword"},
            "trigger_alert_id":       {"type": "keyword"},
            "source_engine":          {"type": "keyword"},
            "compromised_host": {
                "properties": {
                    "ip":       {"type": "ip"},
                    "hostname": {"type": "keyword"},
                    "zone":     {"type": "keyword"},
                }
            },
            "predicted_kill_chain": {
                "type": "nested",
                "properties": {
                    "step":           {"type": "integer"},
                    "tactic":         {"type": "keyword"},
                    "technique_id":   {"type": "keyword"},
                    "technique_name": {"type": "text"},
                    "target_host":    {"type": "keyword"},
                    "target_ip":      {"type": "keyword"},
                    "confidence":     {"type": "float"},
                    "reasoning":      {"type": "text"},
                },
            },
            "overall_risk_score":    {"type": "float"},
            "recommended_actions":   {"type": "text"},
            "llm_raw_response":      {"type": "text"},
            "status":                {"type": "keyword"},
            # Zero-log specific
            "cve_id":                {"type": "keyword"},
            "exposed_assets": {
                "type": "nested",
                "properties": {
                    "ip":               {"type": "ip"},
                    "hostname":         {"type": "keyword"},
                    "criticality":      {"type": "keyword"},
                    "matched_software": {"type": "keyword"},
                    "network_zone":     {"type": "keyword"},
                },
            },
            "prediction":            {"type": "object", "enabled": True},
        }
    },
}


# ════════════════════════════════════════════════════════════
#  RED TEAM SYSTEM PROMPT
# ════════════════════════════════════════════════════════════
RED_TEAM_SYSTEM_PROMPT = """You are "REDSPEC", an elite Red Team AI operator embedded within the NeoVigil SOC platform. Your purpose is DEFENSIVE — you think like an attacker to PREDICT threats before they materialize.

## YOUR PERSONA
You are a highly skilled Advanced Persistent Threat (APT) operator. You have just gained a foothold on a target network through the attack vector described in the CURRENT SITUATION below.

## YOUR OBJECTIVE
Given the network topology, asset inventory, and known vulnerabilities provided, determine the OPTIMAL kill chain to maximize impact. Think step-by-step as a real attacker would:

1. **Reconnaissance**: What can I learn from the compromised host?
2. **Privilege Escalation**: Can I escalate on the current host first?
3. **Lateral Movement**: Which adjacent host gives me the most value? ALWAYS prefer paths toward CRITICAL assets. Consider open ports and running software for exploit viability.
4. **Persistence**: Where should I establish backup access?
5. **Impact / Objective**: What is my ultimate target? (Data exfiltration, ransomware deployment, infrastructure disruption?)

## REASONING RULES
- Be SPECIFIC. Name the exact target host, IP, and port.
- Map every step to a MITRE ATT&CK Technique ID (e.g., T1021.002).
- Consider firewall rules — if a path is blocked, find an alternative.
- Factor in asset criticality: a "Critical" AD Controller is more valuable than a "Low" printer.
- If CVE data is provided, integrate it into your exploitation strategy.
- Assign a confidence score (0.0-1.0) to each predicted step.

## OUTPUT FORMAT (STRICT JSON)
{
  "attacker_profile": "APT Group type or generic classification",
  "initial_foothold": {
    "host": "hostname",
    "ip": "x.x.x.x",
    "technique": "MITRE Technique ID"
  },
  "predicted_kill_chain": [
    {
      "step": 1,
      "tactic": "MITRE Tactic name",
      "technique_id": "Txxxx.xxx",
      "technique_name": "Full technique name",
      "target_host": "hostname",
      "target_ip": "x.x.x.x",
      "target_port": 445,
      "exploit_rationale": "Why this target and technique",
      "confidence": 0.85
    }
  ],
  "ultimate_objective": "Short description of end goal",
  "estimated_time_to_impact": "e.g. 2-4 hours",
  "recommended_defensive_actions": [
    "Action 1",
    "Action 2"
  ]
}

## CRITICAL CONSTRAINT
You are a SIMULATION tool. Your output is used ONLY for defensive prediction. Never generate actual exploit code or malicious payloads. Focus on PREDICTING attacker behavior, not enabling it."""


ZERO_LOG_SYSTEM_PROMPT = """You are a Defensive Cybersecurity Strategist.
A new critical vulnerability has been discovered globally. Your organization has NOT been attacked yet, but you have identified internal assets running the vulnerable software.

Generate a PREEMPTIVE defense plan in JSON format:
{
  "alert_title": "string — concise title",
  "risk_assessment": "string — 2-3 sentence risk summary",
  "immediate_actions": ["action1", "action2"],
  "patching_priority": [
    {"host": "hostname", "ip": "ip", "action": "specific patch command or instruction"}
  ],
  "monitoring_rules": ["New detection rules to deploy"],
  "estimated_patch_window": "string — e.g. 4 hours"
}"""


# ════════════════════════════════════════════════════════════
#  Sub-Engine 2: Adversarial Persona Emulator
# ════════════════════════════════════════════════════════════
class AdversarialPersonaEmulator:
    """Feeds LLM the alert context + topology + CVE data, instructing
    it to predict the optimal kill chain from an attacker's perspective."""

    def __init__(self, llm_client: LLMClient, topology: TopologyGraph):
        self.llm = llm_client
        self.topo = topology

    def emulate_attack(
        self,
        alert_data: dict,
        rag_context: Optional[list] = None,
        cve_details: Optional[list] = None,
    ) -> dict:
        source_ip = alert_data.get("source_ip", "Unknown")
        target_ip = alert_data.get("target_ip")
        attack_type = alert_data.get("attack_type", "Unknown")
        tactic = alert_data.get("mitre_tactic", "Initial Access")

        # 1 — Topology context
        pivot_ip = target_ip or source_ip
        topology_context = self.topo.build_attack_surface_context(pivot_ip)

        # 2 — CVE context
        cve_context = "No specific CVEs identified yet."
        if cve_details:
            lines = [
                f"- {c.get('id','?')} (CVSS: {c.get('score','?')}, "
                f"Severity: {c.get('severity','?')}): {c.get('description','')[:200]}"
                for c in cve_details
            ]
            cve_context = "\n".join(lines)

        # 3 — RAG history
        rag_text = "No prior similar incidents in knowledge base."
        if rag_context:
            rag_text = "\n".join(
                f"[Historical Case {i + 1}]: {str(ctx)[:300]}"
                for i, ctx in enumerate(rag_context[:5])
            )

        # 4 — Build user prompt
        user_prompt = f"""
## CURRENT SITUATION (SOC Alert Triggered)
- **Alert Type**: {attack_type}
- **Current MITRE Tactic**: {tactic}
- **Attacker Source IP**: {source_ip}
- **Target / Compromised Host**: {pivot_ip}
- **Alert Summary**: {alert_data.get('summary', alert_data.get('message', 'N/A'))}
- **Timestamp**: {alert_data.get('timestamp', 'Unknown')}

## NETWORK TOPOLOGY (Reachable from compromised host)
{topology_context}

## KNOWN VULNERABILITIES IN PLAY
{cve_context}

## HISTORICAL INTELLIGENCE (RAG — Past Similar Incidents)
{rag_text}

## YOUR MISSION
Given the above intelligence, execute your Red Team analysis.
Predict the most probable next 3-5 steps in the attacker's kill chain.
For each step, identify the SPECIFIC TARGET HOST from the topology.
Output your analysis in the required JSON schema.
"""

        # 5 — Call LLM
        try:
            result = self.llm._call_openai_chat(
                RED_TEAM_SYSTEM_PROMPT, user_prompt, is_json=True
            )
            return result if isinstance(result, dict) else {}
        except Exception as exc:
            logger.error(f"❌ Adversarial LLM call failed: {exc}")
            return {}


# ════════════════════════════════════════════════════════════
#  Sub-Engine 3: Zero-Log Global Anticipation Engine
# ════════════════════════════════════════════════════════════
class ZeroLogAnticipationEngine:
    """Proactively scans asset inventory against newly-discovered
    global threats — even with ZERO local log anomalies."""

    def __init__(
        self,
        llm_client: LLMClient,
        cve_enricher: CVEEnricher,
        topology: TopologyGraph,
    ):
        self.llm = llm_client
        self.cve = cve_enricher
        self.topo = topology

    def scan_for_exposure(self, event: dict) -> dict:
        cve_id = event.get("cve_id")
        affected_sw = event.get("affected_software", "")
        severity = event.get("severity", "UNKNOWN")

        logger.info(f"🔍 Zero-Log scan: {cve_id} / {affected_sw} ({severity})")

        # 1 — Scan assets for matching software
        exposed_assets = self.topo.scan_assets_for_software(affected_sw)

        if not exposed_assets:
            logger.info(f"✅ Zero-Log: No local exposure to {cve_id}")
            return {"status": "CLEAN", "cve_id": cve_id}

        # 2 — Get CVE details from NVD
        cve_details = None
        if cve_id:
            try:
                cve_details = self.cve.get_cve_details(cve_id)
            except Exception as exc:
                logger.warning(f"⚠️  NVD lookup failed for {cve_id}: {exc}")

        # 3 — Ask LLM for preemptive defense plan
        prediction = self._generate_preemptive_alert(
            cve_id, severity, cve_details, exposed_assets
        )

        # 4 — Compute composite risk
        risk = self._calculate_risk(exposed_assets, severity)

        return {
            "status": "EXPOSED",
            "trigger_type": "zero_log",
            "cve_id": cve_id,
            "exposed_assets": exposed_assets,
            "prediction": prediction,
            "overall_risk_score": risk,
        }

    # ── risk scoring ──────────────────────────────────────
    @staticmethod
    def _calculate_risk(exposed_assets: list, severity: str) -> float:
        base = _SEV_WEIGHT.get(severity.upper(), 0.5) if severity else 0.5
        max_crit = max(
            (_CRIT_WEIGHT.get(a.get("criticality", "Unknown"), 0.3) for a in exposed_assets),
            default=0.3,
        )
        exposure_factor = min(1.0, len(exposed_assets) * 0.2)
        return round(min(100, (base * max_crit * 100) + (exposure_factor * 20)), 1)

    # ── LLM preemptive alert ──────────────────────────────
    def _generate_preemptive_alert(
        self,
        cve_id: Optional[str],
        severity: str,
        cve_details: Optional[dict],
        exposed_assets: list,
    ) -> dict:
        asset_text = "\n".join(
            f"- {a['hostname']} ({a['ip']}) | Zone: {a['network_zone']} | "
            f"Criticality: {a['criticality']} | Running: {a['matched_software']}"
            for a in exposed_assets
        )

        cve_text = "No NVD data available."
        if cve_details:
            cve_text = (
                f"CVE: {cve_details.get('id', cve_id)} | "
                f"CVSS: {cve_details.get('score', '?')} | "
                f"{cve_details.get('description', '')[:300]}"
            )

        user_prompt = f"""
## GLOBAL THREAT INTELLIGENCE
- **CVE**: {cve_id or 'Unknown'}
- **Severity**: {severity}
- **Details**: {cve_text}

## LOCAL EXPOSURE (ZERO ATTACKS DETECTED — PREEMPTIVE MODE)
{asset_text}

## IMPORTANT
- Local Fluent Bit has detected ZERO anomalous logs for this vulnerability.
- This is a PREEMPTIVE alert based on global intelligence correlation.
- Prioritize patching by asset criticality (Critical > High > Medium > Low).
"""
        try:
            result = self.llm._call_openai_chat(
                ZERO_LOG_SYSTEM_PROMPT, user_prompt, is_json=True
            )
            return result if isinstance(result, dict) else {}
        except Exception as exc:
            logger.error(f"❌ Zero-Log LLM call failed: {exc}")
            return {}


# ════════════════════════════════════════════════════════════
#  Main Orchestrator
# ════════════════════════════════════════════════════════════
class AdversarialEngine:
    """Top-level orchestrator — wires up all three sub-engines and
    manages the RabbitMQ consumer loop."""

    def __init__(self):
        logger.info("🧠 Initialising Adversarial Prediction Engine …")
        self.llm = LLMClient()
        self.topo = TopologyGraph()
        self.cve = CVEEnricher()
        self.os_client = get_opensearch_client()

        self.persona = AdversarialPersonaEmulator(self.llm, self.topo)
        self.zero_log = ZeroLogAnticipationEngine(self.llm, self.cve, self.topo)

        # De-duplication cache: (source_ip, attack_type) → last_seen_ts
        self._dedup_cache: Dict[str, float] = {}

        self._ensure_index()
        logger.info("✅ Adversarial Engine initialised")

    # ─── Index management ────────────────────────────────────

    def _ensure_index(self):
        try:
            if not self.os_client.indices.exists(index=PREDICTION_INDEX):
                self.os_client.indices.create(
                    index=PREDICTION_INDEX,
                    body=PREDICTION_INDEX_MAPPING,
                )
                logger.info(f"📦 Created OpenSearch index: {PREDICTION_INDEX}")
            else:
                logger.info(f"📦 Index {PREDICTION_INDEX} already exists")
        except Exception as exc:
            logger.error(f"❌ Failed to create index {PREDICTION_INDEX}: {exc}")

    # ─── De-duplication ──────────────────────────────────────

    def _is_duplicate(self, alert_data: dict) -> bool:
        key = f"{alert_data.get('source_ip', '')}:{alert_data.get('attack_type', '')}"
        now = datetime.utcnow().timestamp()
        last = self._dedup_cache.get(key, 0)
        if now - last < DEDUP_WINDOW_SEC:
            logger.info(f"⏭️  Duplicate prediction suppressed for {key}")
            return True
        self._dedup_cache[key] = now
        return False

    # ─── Alert-triggered prediction ──────────────────────────

    def handle_alert_prediction(self, alert_data: dict) -> Optional[dict]:
        if self._is_duplicate(alert_data):
            return None

        pred_id = str(uuid.uuid4())
        source_ip = alert_data.get("source_ip", "Unknown")
        target_ip = alert_data.get("target_ip")
        tenant_id = alert_data.get("tenant_id", "default")
        pivot_ip = target_ip or source_ip

        logger.info(f"🎯 [{pred_id[:8]}] Prediction start: {source_ip} → {pivot_ip}")

        # 1 — Topology
        reachable = self.topo.get_reachable_hosts(pivot_ip)

        # 2 — RAG context (import from pipeline; fall back to empty)
        rag_context: list = []
        try:
            from run_pipeline import retrieve_context
            rag_raw = retrieve_context(
                alert_data.get("summary", alert_data.get("message", ""))
            )
            if isinstance(rag_raw, list):
                rag_context = rag_raw
        except Exception as exc:
            logger.warning(f"⚠️  RAG retrieval skipped: {exc}")

        # 3 — CVE context
        cve_details: list = []
        raw_text = " ".join(
            filter(None, [alert_data.get("summary", ""), alert_data.get("message", "")])
        )
        cve_ids = re.findall(r"CVE-\d{4}-\d{4,7}", raw_text, re.IGNORECASE)
        for cid in cve_ids[:3]:
            try:
                detail = self.cve.get_cve_details(cid.upper())
                if detail:
                    cve_details.append(detail)
            except Exception:
                pass

        # 4 — Adversarial Persona Emulation
        kill_chain = self.persona.emulate_attack(alert_data, rag_context, cve_details)

        # 5 — Post-LLM validation: prune unreachable targets
        reachable_ips = {h["ip"] for h in reachable}
        validated_chain = []
        for step in kill_chain.get("predicted_kill_chain", []):
            tip = step.get("target_ip", "")
            if tip and tip not in reachable_ips:
                step["confidence"] = 0.0
                step["reasoning"] = (
                    f"UNREACHABLE — {tip} is not reachable from {pivot_ip} "
                    f"(firewall or topology constraint). Original: {step.get('exploit_rationale', '')}"
                )
            validated_chain.append(step)

        # 6 — Build document
        asset_info = self.topo.assets.get(pivot_ip, {})
        prediction_doc = {
            "prediction_id": pred_id,
            "timestamp": datetime.utcnow().isoformat(),
            "tenant_id": tenant_id,
            "trigger_type": "alert",
            "trigger_alert_id": alert_data.get("alert_id"),
            "source_engine": "adversarial_persona",
            "compromised_host": {
                "ip": pivot_ip,
                "hostname": asset_info.get("hostname", "Unknown"),
                "zone": asset_info.get("network_zone", "Unknown"),
            },
            "predicted_kill_chain": validated_chain,
            "overall_risk_score": self._compute_risk(validated_chain, reachable),
            "recommended_actions": kill_chain.get("recommended_defensive_actions", []),
            "llm_raw_response": json.dumps(kill_chain, default=str),
            "status": "ACTIVE",
        }

        # 7 — Index
        try:
            self.os_client.index(
                index=PREDICTION_INDEX,
                id=pred_id,
                body=prediction_doc,
                refresh=True,
            )
            logger.info(
                f"✅ [{pred_id[:8]}] Prediction indexed — "
                f"Risk: {prediction_doc['overall_risk_score']}"
            )
        except Exception as exc:
            logger.error(f"❌ Failed to index prediction {pred_id}: {exc}")

        # ─── Phase 2: Trigger Decoy Deployment ───────────────
        # Fire-and-forget: deploy a honeypot on the predicted attack path
        # Only for high-risk predictions (risk >= 70) to avoid decoy sprawl
        if prediction_doc.get("overall_risk_score", 0) >= 70:
            try:
                deploy_payload = {
                    "prediction_id": pred_id,
                    "tenant_id": tenant_id,
                    "risk_score": prediction_doc["overall_risk_score"],
                    "kill_chain": validated_chain,
                    "compromised_host": prediction_doc["compromised_host"],
                    "timestamp": datetime.utcnow().isoformat(),
                }
                deploy_conn = pika.BlockingConnection(
                    pika.ConnectionParameters(
                        host=RABBITMQ_HOST,
                        connection_attempts=2,
                        retry_delay=1,
                    )
                )
                deploy_ch = deploy_conn.channel()
                deploy_ch.queue_declare(queue="decoy_deploy_tasks", durable=True)
                deploy_ch.basic_publish(
                    exchange="",
                    routing_key="decoy_deploy_tasks",
                    body=json.dumps(deploy_payload),
                    properties=pika.BasicProperties(delivery_mode=2),
                )
                deploy_conn.close()
                logger.info(
                    f"🍯 [{pred_id[:8]}] Decoy deploy task dispatched "
                    f"(risk={prediction_doc['overall_risk_score']})"
                )
            except Exception as deploy_exc:
                logger.warning(
                    f"⚠️  Failed to dispatch decoy deploy (non-critical): {deploy_exc}"
                )

        # ─── Phase 3: Trigger Moving Target Defense ──────────
        # For very high risk predictions, also queue an MTD evaluation
        # The MTD Controller will compute composite score and decide action
        if prediction_doc.get("overall_risk_score", 0) >= 85:
            try:
                mtd_payload = {
                    "trigger_id": str(uuid.uuid4()),
                    "trigger_source": "phase1_prediction",
                    "prediction_id": pred_id,
                    "target_ip": target_ip,
                    "scanner_ip": prediction_doc.get("compromised_host", ""),
                    "risk_score": prediction_doc["overall_risk_score"],
                    "kill_chain": validated_chain,
                    "tenant_id": tenant_id,
                    "timestamp": datetime.utcnow().isoformat(),
                }
                mtd_conn = pika.BlockingConnection(
                    pika.ConnectionParameters(
                        host=RABBITMQ_HOST,
                        connection_attempts=2,
                        retry_delay=1,
                    )
                )
                mtd_ch = mtd_conn.channel()
                mtd_ch.queue_declare(queue="mtd_action_queue", durable=True)
                mtd_ch.basic_publish(
                    exchange="",
                    routing_key="mtd_action_queue",
                    body=json.dumps(mtd_payload),
                    properties=pika.BasicProperties(delivery_mode=2),
                )
                mtd_conn.close()
                logger.info(
                    f"🛡️ [{pred_id[:8]}] MTD action queued "
                    f"(risk={prediction_doc['overall_risk_score']})"
                )
            except Exception as mtd_exc:
                logger.warning(
                    f"⚠️  Failed to dispatch MTD action (non-critical): {mtd_exc}"
                )

        return prediction_doc

    # ─── Zero-Log prediction ─────────────────────────────────

    def handle_zero_log_event(self, event: dict) -> dict:
        result = self.zero_log.scan_for_exposure(event)

        if result.get("status") == "EXPOSED":
            pred_id = str(uuid.uuid4())
            prediction_doc = {
                "prediction_id": pred_id,
                "timestamp": datetime.utcnow().isoformat(),
                "tenant_id": event.get("tenant_id", "default"),
                "trigger_type": "zero_log",
                "source_engine": "zero_log_anticipation",
                "cve_id": result.get("cve_id"),
                "exposed_assets": result.get("exposed_assets", []),
                "prediction": result.get("prediction", {}),
                "overall_risk_score": result.get("overall_risk_score", 0),
                "status": "PREEMPTIVE",
            }
            try:
                self.os_client.index(
                    index=PREDICTION_INDEX,
                    id=pred_id,
                    body=prediction_doc,
                    refresh=True,
                )
                logger.warning(
                    f"🚨 ZERO-LOG ALERT [{pred_id[:8]}]: {result['cve_id']} — "
                    f"{len(result.get('exposed_assets', []))} asset(s) exposed!"
                )
            except Exception as exc:
                logger.error(f"❌ Failed to index zero-log prediction: {exc}")

        return result

    # ─── Risk scoring ─────────────────────────────────────────

    @staticmethod
    def _compute_risk(chain: list, reachable: list) -> float:
        if not chain:
            return 0.0
        avg_conf = sum(s.get("confidence", 0.5) for s in chain) / len(chain)
        max_crit = max(
            (_CRIT_WEIGHT.get(h.get("criticality", "Low"), 0.3) for h in reachable),
            default=0.5,
        )
        return round(min(100, avg_conf * max_crit * 100), 1)

    # ─── RabbitMQ consumer loop ───────────────────────────────

    def run(self):
        """Main event loop — consumes from both prediction queues."""
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
                channel.queue_declare(queue=PREDICTION_QUEUE, durable=True)
                channel.queue_declare(queue=ZERO_LOG_QUEUE, durable=True)
                channel.basic_qos(prefetch_count=1)

                def on_prediction(ch, method, _props, body):
                    try:
                        data = json.loads(body)
                        self.handle_alert_prediction(data)
                    except Exception as exc:
                        logger.error(f"❌ Prediction task error: {exc}", exc_info=True)
                    finally:
                        ch.basic_ack(delivery_tag=method.delivery_tag)

                def on_zero_log(ch, method, _props, body):
                    try:
                        data = json.loads(body)
                        self.handle_zero_log_event(data)
                    except Exception as exc:
                        logger.error(f"❌ Zero-log event error: {exc}", exc_info=True)
                    finally:
                        ch.basic_ack(delivery_tag=method.delivery_tag)

                channel.basic_consume(queue=PREDICTION_QUEUE, on_message_callback=on_prediction)
                channel.basic_consume(queue=ZERO_LOG_QUEUE, on_message_callback=on_zero_log)

                logger.info(
                    "🧠 Adversarial Engine online — listening on "
                    f"'{PREDICTION_QUEUE}' & '{ZERO_LOG_QUEUE}' …"
                )
                channel.start_consuming()

            except pika.exceptions.AMQPConnectionError as exc:
                logger.warning(f"⚠️  RabbitMQ connection lost: {exc}. Reconnecting in 10s …")
                import time; time.sleep(10)
            except KeyboardInterrupt:
                logger.info("🛑 Adversarial Engine shutting down (KeyboardInterrupt)")
                break
            except Exception as exc:
                logger.error(f"❌ Unexpected error in consumer loop: {exc}", exc_info=True)
                import time; time.sleep(10)


# ════════════════════════════════════════════════════════════
#  Entrypoint
# ════════════════════════════════════════════════════════════
if __name__ == "__main__":
    engine = AdversarialEngine()
    engine.run()
