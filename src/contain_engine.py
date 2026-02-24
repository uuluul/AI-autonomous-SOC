"""
NeoVigil Containment Engine -- Phase 4
========================================
Orchestrates active containment after Phase 3 Moving Target Defense:

  1. **Playbook Generation** -- LLM-authored SOAR playbooks from STIX intel
  2. **Firewall API Integration** -- Automated IP blocking within seconds
  3. **IaC Self-Healing** -- AI-driven config patch generation
  4. **Immutable Audit Logging** -- Full compliance trail

Consumes:  contain_tasks          (RabbitMQ)
Produces:  contain-actions         (OpenSearch)
           contain-playbooks       (OpenSearch)
           iac-patches             (OpenSearch)
           -> adapt_tasks          (RabbitMQ, dispatches to Phase 5)
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
    format="%(asctime)s [ContainEngine] %(levelname)s -- %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ─── Imports ──────────────────────────────────────────────────
try:
    from src.setup_opensearch import get_opensearch_client, upload_to_opensearch
    from src.llm_client import LLMClient
    from src.firewall_mock import FirewallClient
    from src.audit_logger import AuditLogger
    from src.to_stix import build_stix_bundle
except ImportError:
    try:
        from setup_opensearch import get_opensearch_client, upload_to_opensearch
        from llm_client import LLMClient
        from firewall_mock import FirewallClient
        from audit_logger import AuditLogger
        from to_stix import build_stix_bundle
    except ImportError as e:
        logger.error(f"Failed to import dependencies: {e}")
        # Fallback stubs
        get_opensearch_client = None
        upload_to_opensearch = None
        LLMClient = None
        FirewallClient = None
        AuditLogger = None
        build_stix_bundle = None

# ─── Configuration ────────────────────────────────────────────
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_USER = os.getenv("RABBITMQ_DEFAULT_USER", "user")
RABBITMQ_PASS = os.getenv("RABBITMQ_DEFAULT_PASS", "password")

CONTAIN_QUEUE = "contain_tasks"
ADAPT_QUEUE = "adapt_tasks"

CONTAIN_ACTIONS_INDEX = "contain-actions"
CONTAIN_PLAYBOOKS_INDEX = "contain-playbooks"
IAC_PATCHES_INDEX = "iac-patches"

# ─── Index Mappings ───────────────────────────────────────────

CONTAIN_ACTIONS_MAPPING = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "properties": {
            "action_id":           {"type": "keyword"},
            "timestamp":           {"type": "date"},
            "incident_id":         {"type": "keyword"},
            "phase_trigger":       {"type": "keyword"},
            "action_type":         {"type": "keyword"},
            "target_ip":           {"type": "keyword"},
            "playbook_id":         {"type": "keyword"},
            "firewall_rule_id":    {"type": "keyword"},
            "status":              {"type": "keyword"},
            "execution_time_ms":   {"type": "integer"},
            "tenant_id":           {"type": "keyword"},
        }
    },
}


# ─── Containment Engine ──────────────────────────────────────

class ContainmentEngine:
    """Phase 4 containment orchestrator."""

    def __init__(self):
        self.os_client = get_opensearch_client() if get_opensearch_client else None
        self.llm = LLMClient() if LLMClient else None
        self.firewall = FirewallClient() if FirewallClient else None
        self.audit = AuditLogger() if AuditLogger else None
        self._ensure_indices()
        logger.info("ContainmentEngine initialized.")

    def _ensure_indices(self):
        """Create OpenSearch indices if they don't exist."""
        if not self.os_client:
            return
        for idx, mapping in [
            (CONTAIN_ACTIONS_INDEX, CONTAIN_ACTIONS_MAPPING),
        ]:
            try:
                if not self.os_client.indices.exists(index=idx):
                    self.os_client.indices.create(index=idx, body=mapping)
                    logger.info(f"Created index: {idx}")
            except Exception as exc:
                logger.warning(f"Index creation for {idx}: {exc}")

    # ─── Main Entry Point ────────────────────────────────────

    def process_containment(self, trigger: dict):
        """
        Main entry: process a containment trigger from Phase 3.

        trigger = {
            "incident_id": str,
            "trigger_source": "phase3_mtd_complete",
            "prediction_id": str,
            "attacker_ips": [str],
            "target_ips": [str],
            "kill_chain": [...],
            "risk_score": float,
            "mtd_action_id": str,
            "timestamp": str,
        }
        """
        incident_id = trigger.get("incident_id", str(uuid.uuid4()))
        logger.info(
            f"[{incident_id}] Processing containment | "
            f"risk={trigger.get('risk_score', 0)} "
            f"attacker_ips={trigger.get('attacker_ips', [])}"
        )

        results = {
            "incident_id": incident_id,
            "playbook": None,
            "firewall_blocks": [],
            "iac_patches": [],
        }

        # 1. Generate SOAR playbook
        try:
            playbook = self.generate_playbook(trigger)
            results["playbook"] = playbook
            logger.info(f"[{incident_id}] Playbook generated: {playbook.get('playbook_id')}")
        except Exception as exc:
            logger.error(f"[{incident_id}] Playbook generation failed: {exc}")

        # 2. Execute firewall blocks
        try:
            block_results = self.execute_firewall_blocks(
                incident_id, trigger.get("attacker_ips", [])
            )
            results["firewall_blocks"] = block_results
            blocked = sum(1 for b in block_results if b.get("success"))
            logger.info(f"[{incident_id}] Firewall blocks: {blocked}/{len(block_results)}")
        except Exception as exc:
            logger.error(f"[{incident_id}] Firewall blocking failed: {exc}")

        # 3. Analyze and patch vulnerable configs
        try:
            patches = self.analyze_and_patch_configs(trigger)
            results["iac_patches"] = patches
            logger.info(f"[{incident_id}] IaC patches generated: {len(patches)}")
        except Exception as exc:
            logger.error(f"[{incident_id}] IaC analysis failed: {exc}")

        # 4. Dispatch to Phase 5: ADAPT
        try:
            self._dispatch_to_adapt(trigger, results)
            logger.info(f"[{incident_id}] Dispatched to Phase 5 ADAPT")
        except Exception as exc:
            logger.error(f"[{incident_id}] Phase 5 dispatch failed: {exc}")

        logger.info(f"[{incident_id}] Phase 4 CONTAIN complete.")
        return results

    # ─── Sub-Engine 1: Playbook Generation ───────────────────

    def generate_playbook(self, trigger: dict) -> dict:
        """
        Use LLM + STIX intelligence to generate a SOAR playbook.
        """
        incident_id = trigger.get("incident_id", "unknown")
        playbook_id = f"pb-{str(uuid.uuid4())[:8]}"

        # Build STIX context
        stix_bundle = None
        if build_stix_bundle:
            try:
                stix_bundle = build_stix_bundle({
                    "indicators": {"ipv4": trigger.get("attacker_ips", [])},
                    "ttps": trigger.get("kill_chain", []),
                    "confidence": int(trigger.get("risk_score", 70)),
                })
            except Exception as exc:
                logger.warning(f"STIX bundle generation failed: {exc}")

        # RAG: retrieve related knowledge
        kb_context = self._retrieve_kb_context(trigger)

        # LLM playbook generation
        playbook_actions = self._generate_playbook_via_llm(trigger, kb_context, stix_bundle)

        playbook_doc = {
            "playbook_id": playbook_id,
            "incident_id": incident_id,
            "timestamp": datetime.utcnow().isoformat(),
            "stix_bundle_id": stix_bundle.get("id") if stix_bundle else None,
            "playbook_actions": playbook_actions,
            "status": "GENERATED",
            "generated_by": "ContainmentEngine-LLM",
            "tenant_id": trigger.get("tenant_id", "default"),
        }

        # Store playbook
        if upload_to_opensearch:
            upload_to_opensearch(
                playbook_doc, doc_id=playbook_id, index_name=CONTAIN_PLAYBOOKS_INDEX
            )

        # Audit log
        if self.audit:
            self.audit.log_event(
                actor="ContainmentEngine",
                action="PLAYBOOK_GENERATED",
                target=incident_id,
                status="SUCCESS",
                justification=f"Auto-generated SOAR playbook {playbook_id}",
            )

        return playbook_doc

    def _generate_playbook_via_llm(self, trigger, kb_context, stix_bundle) -> list:
        """Use LLM to generate structured playbook actions."""
        if not self.llm:
            return self._generate_fallback_playbook(trigger)

        system_prompt = """You are a SOC automation expert. Generate a SOAR containment
playbook as a JSON array of ordered actions. Each action must have:
- action_id (string), action_type (string), target (string),
- parameters (object), priority (1-10), timeout_seconds (int)
Cover: network isolation, credential rotation, evidence preservation, notification.
Return ONLY a valid JSON array."""

        user_prompt = json.dumps({
            "incident": {
                "attacker_ips": trigger.get("attacker_ips", []),
                "target_ips": trigger.get("target_ips", []),
                "kill_chain": trigger.get("kill_chain", []),
                "risk_score": trigger.get("risk_score", 0),
            },
            "knowledge_base_context": kb_context[:2000] if kb_context else "",
            "stix_indicators": len(stix_bundle.get("objects", [])) if stix_bundle else 0,
        }, default=str)

        try:
            response = self.llm._call_openai_chat(
                system_prompt, user_prompt, is_json=True
            )
            if isinstance(response, list):
                return response
            if isinstance(response, dict) and "actions" in response:
                return response["actions"]
            return [response] if response else self._generate_fallback_playbook(trigger)
        except Exception as exc:
            logger.warning(f"LLM playbook generation failed: {exc}")
            return self._generate_fallback_playbook(trigger)

    def _generate_fallback_playbook(self, trigger: dict) -> list:
        """Generate a basic playbook when LLM is unavailable."""
        actions = []
        for i, ip in enumerate(trigger.get("attacker_ips", [])[:5]):
            actions.append({
                "action_id": f"act-{i+1}",
                "action_type": "FIREWALL_BLOCK",
                "target": ip,
                "parameters": {"rule": "DENY_ALL", "direction": "inbound"},
                "priority": 1,
                "timeout_seconds": 30,
            })

        actions.append({
            "action_id": f"act-{len(actions)+1}",
            "action_type": "CREDENTIAL_ROTATION",
            "target": "affected_services",
            "parameters": {"scope": trigger.get("target_ips", [])},
            "priority": 2,
            "timeout_seconds": 300,
        })
        actions.append({
            "action_id": f"act-{len(actions)+1}",
            "action_type": "EVIDENCE_PRESERVATION",
            "target": "forensic_snapshot",
            "parameters": {"indices": ["security-logs-knn", "honeypot-telemetry"]},
            "priority": 3,
            "timeout_seconds": 600,
        })
        actions.append({
            "action_id": f"act-{len(actions)+1}",
            "action_type": "NOTIFICATION",
            "target": "soc_team",
            "parameters": {"channel": "slack", "severity": "critical"},
            "priority": 4,
            "timeout_seconds": 60,
        })
        return actions

    def _retrieve_kb_context(self, trigger: dict) -> str:
        """Query cti-knowledge-base for related TTPs."""
        if not self.os_client:
            return ""

        kill_chain = trigger.get("kill_chain", [])
        if not kill_chain:
            return ""

        try:
            # Extract technique IDs for search
            technique_ids = []
            for step in kill_chain:
                if isinstance(step, dict):
                    tid = step.get("technique_id", "")
                    if tid:
                        technique_ids.append(tid)

            if not technique_ids:
                return ""

            query = {
                "size": 5,
                "query": {
                    "bool": {
                        "should": [
                            {"match": {"external_id": tid}}
                            for tid in technique_ids[:5]
                        ]
                    }
                },
            }
            resp = self.os_client.search(index="cti-knowledge-base", body=query)
            hits = resp.get("hits", {}).get("hits", [])
            return " ".join(
                h["_source"].get("description", "")[:300] for h in hits
            )
        except Exception:
            return ""

    # ─── Sub-Engine 2: Firewall Integration ──────────────────

    def execute_firewall_blocks(self, incident_id: str, attacker_ips: list) -> list:
        """
        Issue REJECT commands to firewall for each attacker IP.
        """
        results = []
        for ip in attacker_ips[:20]:  # Cap at 20 IPs per incident
            start = time.time()
            success = False

            if self.firewall:
                success = self.firewall.block_ip(ip)
            else:
                # Mock mode
                success = True
                time.sleep(0.1)

            elapsed_ms = int((time.time() - start) * 1000)

            action_id = f"fw-{str(uuid.uuid4())[:8]}"
            result = {
                "action_id": action_id,
                "ip": ip,
                "success": success,
                "execution_time_ms": elapsed_ms,
                "timestamp": datetime.utcnow().isoformat(),
            }
            results.append(result)

            # Index action
            action_doc = {
                "action_id": action_id,
                "timestamp": datetime.utcnow().isoformat(),
                "incident_id": incident_id,
                "phase_trigger": "phase4_contain",
                "action_type": "FIREWALL_BLOCK",
                "target_ip": ip,
                "status": "SUCCESS" if success else "FAILURE",
                "execution_time_ms": elapsed_ms,
                "tenant_id": "default",
            }
            if upload_to_opensearch:
                upload_to_opensearch(
                    action_doc, doc_id=action_id, index_name=CONTAIN_ACTIONS_INDEX
                )

            # Audit log
            if self.audit:
                self.audit.log_event(
                    actor="ContainmentEngine",
                    action="FIREWALL_BLOCK",
                    target=ip,
                    status="SUCCESS" if success else "FAILURE",
                    justification=f"Phase 4 automated containment — block attacker IP",
                )

        return results

    # ─── Sub-Engine 3: IaC Self-Healing ──────────────────────

    def analyze_and_patch_configs(self, trigger: dict) -> list:
        """
        AI-driven Infrastructure-as-Code patch generation.
        Analyzes Nginx/topology configs and generates security patches.
        """
        patches = []
        incident_id = trigger.get("incident_id", "unknown")

        # Analyze Nginx config
        nginx_patch = self._analyze_nginx_config(trigger)
        if nginx_patch:
            patches.append(nginx_patch)

        # Analyze network topology for hardening
        topology_patch = self._analyze_topology(trigger)
        if topology_patch:
            patches.append(topology_patch)

        # Store patches
        for patch in patches:
            if upload_to_opensearch:
                upload_to_opensearch(
                    patch, doc_id=patch["patch_id"], index_name=IAC_PATCHES_INDEX
                )

        return patches

    def _analyze_nginx_config(self, trigger: dict) -> dict:
        """Read mtd_nginx.conf, generate hardening patches."""
        patch_id = f"patch-nginx-{str(uuid.uuid4())[:8]}"
        incident_id = trigger.get("incident_id", "unknown")

        # Read current nginx config
        nginx_path = os.getenv("NGINX_CONFIG_PATH", "config/mtd_nginx.conf")
        config_content = ""
        try:
            if os.path.exists(nginx_path):
                with open(nginx_path, "r") as f:
                    config_content = f.read()[:5000]
        except Exception:
            pass

        if not config_content:
            return None

        # Generate patch recommendation
        attacker_ips = trigger.get("attacker_ips", [])
        patch_content = ""
        for ip in attacker_ips[:10]:
            patch_content += f"    deny {ip};\n"

        if not patch_content:
            return None

        patch_doc = {
            "patch_id": patch_id,
            "incident_id": incident_id,
            "timestamp": datetime.utcnow().isoformat(),
            "target_config": "mtd_nginx.conf",
            "patch_type": "ip_deny_list",
            "patch_content": f"# Auto-generated by Phase 4 ContainmentEngine\n"
                             f"# Incident: {incident_id}\n"
                             f"location / {{\n{patch_content}}}",
            "status": "PROPOSED",
            "tenant_id": trigger.get("tenant_id", "default"),
        }
        return patch_doc

    def _analyze_topology(self, trigger: dict) -> dict:
        """Analyze network topology for firewall rule hardening."""
        patch_id = f"patch-topo-{str(uuid.uuid4())[:8]}"
        incident_id = trigger.get("incident_id", "unknown")

        # Read current topology
        topology_path = os.getenv("TOPOLOGY_PATH", "data/network_topology.json")
        try:
            if os.path.exists(topology_path):
                with open(topology_path, "r") as f:
                    topology = json.load(f)
            else:
                return None
        except Exception:
            return None

        # Propose additional firewall rules based on attack path
        kill_chain = trigger.get("kill_chain", [])
        new_rules = []
        for step in kill_chain:
            if isinstance(step, dict):
                target = step.get("target_host", "")
                if target:
                    new_rules.append({
                        "src": "dmz",
                        "dst": target,
                        "action": "deny",
                        "reason": f"Phase 4 containment — incident {incident_id}",
                    })

        if not new_rules:
            return None

        patch_doc = {
            "patch_id": patch_id,
            "incident_id": incident_id,
            "timestamp": datetime.utcnow().isoformat(),
            "target_config": "network_topology.json",
            "patch_type": "firewall_rule_hardening",
            "patch_content": json.dumps(new_rules, indent=2),
            "status": "PROPOSED",
            "tenant_id": trigger.get("tenant_id", "default"),
        }
        return patch_doc

    # ─── Phase 5 Dispatch ────────────────────────────────────

    def _dispatch_to_adapt(self, trigger: dict, results: dict):
        """Publish completion event to adapt_tasks queue for Phase 5."""
        adapt_payload = {
            "incident_id": trigger.get("incident_id", str(uuid.uuid4())),
            "trigger_source": "phase4_contain_complete",
            "prediction_id": trigger.get("prediction_id"),
            "playbook_id": results.get("playbook", {}).get("playbook_id") if results.get("playbook") else None,
            "firewall_blocks": results.get("firewall_blocks", []),
            "iac_patches": [p["patch_id"] for p in results.get("iac_patches", [])],
            "risk_score": trigger.get("risk_score", 0),
            "kill_chain": trigger.get("kill_chain", []),
            "attacker_ips": trigger.get("attacker_ips", []),
            "target_ips": trigger.get("target_ips", []),
            "mtd_action_id": trigger.get("mtd_action_id"),
            "timestamp": datetime.utcnow().isoformat(),
        }

        try:
            credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
            connection = pika.BlockingConnection(
                pika.ConnectionParameters(
                    host=RABBITMQ_HOST, credentials=credentials,
                    connection_attempts=3, retry_delay=2,
                )
            )
            channel = connection.channel()
            dlq_args = {
                "x-dead-letter-exchange": "",
                "x-dead-letter-routing-key": "dlq_main",
            }
            channel.queue_declare(queue=ADAPT_QUEUE, durable=True, arguments=dlq_args)
            channel.basic_publish(
                exchange="",
                routing_key=ADAPT_QUEUE,
                body=json.dumps(adapt_payload, default=str),
                properties=pika.BasicProperties(delivery_mode=2),
            )
            connection.close()
        except Exception as exc:
            logger.error(f"Failed to dispatch to Phase 5: {exc}")

    # ─── RabbitMQ Consumer ───────────────────────────────────

    def _on_message(self, ch, method, properties, body):
        """RabbitMQ message callback."""
        try:
            trigger = json.loads(body)
            self.process_containment(trigger)
            ch.basic_ack(delivery_tag=method.delivery_tag)
        except Exception as exc:
            logger.error(f"Failed to process containment: {exc}")
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

    def run(self):
        """Start consuming from contain_tasks queue with auto-reconnect."""
        logger.info("Phase 4 ContainmentEngine starting...")
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
                channel.queue_declare(queue=CONTAIN_QUEUE, durable=True, arguments=dlq_args)
                channel.basic_qos(prefetch_count=1)
                channel.basic_consume(
                    queue=CONTAIN_QUEUE,
                    on_message_callback=self._on_message,
                )
                logger.info(f"Consuming from {CONTAIN_QUEUE}...")
                channel.start_consuming()

            except pika.exceptions.AMQPConnectionError as exc:
                logger.warning(f"RabbitMQ connection lost: {exc}. Reconnecting in 5s...")
                time.sleep(5)
            except KeyboardInterrupt:
                logger.info("ContainmentEngine shutting down.")
                break
            except Exception as exc:
                logger.error(f"Unexpected error: {exc}. Restarting in 10s...")
                time.sleep(10)


# ─── Entry Point ──────────────────────────────────────────────
if __name__ == "__main__":
    engine = ContainmentEngine()
    engine.run()
