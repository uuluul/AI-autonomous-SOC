"""
NeoVigil Decoy Manager — Phase 2
=================================
Orchestrates the full lifecycle of dynamic honeypot containers:

  1. **Receive** deployment triggers from Phase 1 predictions (RabbitMQ)
  2. **Select** optimal placement: one hop ahead of the highest-value target
  3. **Generate** CTI-aware decoy configs from the template library
  4. **Deploy** isolated Docker containers via Docker SDK for Python
  5. **Manage** TTL-based auto-teardown & enforce MAX_ACTIVE_DECOYS cap

Consumes:  decoy_deploy_tasks          (RabbitMQ)
Produces:  decoy state records         (OpenSearch + data/decoy_state.json)

NETWORK ISOLATION — 4 LAYERS:
  L1: Docker internal=True bridge (no outbound)
  L2: No shared networks with production (opensearch-net)
  L3: Dual-homed Fluent Bit sidecar (one-way telemetry bridge)
  L4: Container hardening (read_only, no-new-privileges, mem/cpu limits)
"""

import json
import logging
import os
import threading
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import pika

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)

# ─── Lazy imports ────────────────────────────────────────────
try:
    import docker
    import docker.errors
    import docker.types
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    logger.warning(
        "Docker SDK not installed. Decoy Manager will operate in "
        "DRY-RUN mode (predictions logged, no containers spawned)."
    )

try:
    from src.decoy_templates import select_template, DECOY_TEMPLATES
    from src.topology_graph import TopologyGraph
    from src.setup_opensearch import get_opensearch_client
except ImportError:
    from decoy_templates import select_template, DECOY_TEMPLATES
    from topology_graph import TopologyGraph
    from setup_opensearch import get_opensearch_client


# ─── Configuration ───────────────────────────────────────────
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "rabbitmq")
DEPLOY_QUEUE = "decoy_deploy_tasks"
LIFECYCLE_QUEUE = "decoy_lifecycle"
HONEYPOT_NET_PREFIX = "honeypot-net"
PRODUCTION_NETWORK = "opensearch-net"

MAX_ACTIVE_DECOYS = int(os.getenv("MAX_ACTIVE_DECOYS", "10"))
DEFAULT_TTL_HOURS = int(os.getenv("DECOY_TTL_HOURS", "4"))
STATE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "data", "decoy_state.json"
)

DECOY_INDEX = "honeypot-telemetry"

# ─── Criticality weight for placement scoring ────────────────
_CRIT_SCORE = {
    "Critical": 1.0, "High": 0.8, "Medium": 0.5, "Low": 0.3, "Unknown": 0.4,
}


# ════════════════════════════════════════════════════════════
#  OpenSearch Index Mappings (Phase 2)
# ════════════════════════════════════════════════════════════

HONEYPOT_TELEMETRY_MAPPING = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "properties": {
            "event_id":           {"type": "keyword"},
            "timestamp":          {"type": "date"},
            "decoy_id":           {"type": "keyword"},
            "linked_prediction":  {"type": "keyword"},
            "attacker_ip":        {"type": "ip"},
            "service_targeted":   {"type": "keyword"},
            "protocol":           {"type": "keyword"},
            "port":               {"type": "integer"},
            "payload_raw":        {"type": "text"},
            "payload_hash":       {"type": "keyword"},
            "technique_detected": {"type": "keyword"},
            "is_novel_payload":   {"type": "boolean"},
            "severity":           {"type": "keyword"},
        }
    },
}

PREDICTION_ACCURACY_MAPPING = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "properties": {
            "prediction_id":             {"type": "keyword"},
            "prediction_date":           {"type": "date"},
            "validation_date":           {"type": "date"},
            "predicted_target":          {"type": "keyword"},
            "actual_target":             {"type": "keyword"},
            "was_correct":               {"type": "boolean"},
            "confidence_at_prediction":  {"type": "float"},
            "attack_technique":          {"type": "keyword"},
            "decoy_id":                  {"type": "keyword"},
            "feedback_indexed":          {"type": "boolean"},
            "time_to_capture_sec":       {"type": "integer"},
        }
    },
}

DECOY_STATE_MAPPING = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "properties": {
            "decoy_id":          {"type": "keyword"},
            "prediction_id":     {"type": "keyword"},
            "status":            {"type": "keyword"},
            "template_key":      {"type": "keyword"},
            "service_name":      {"type": "keyword"},
            "target_host":       {"type": "keyword"},
            "target_ip":         {"type": "keyword"},
            "container_id":      {"type": "keyword"},
            "sidecar_id":        {"type": "keyword"},
            "network_name":      {"type": "keyword"},
            "created_at":        {"type": "date"},
            "ttl_hours":         {"type": "integer"},
            "expires_at":        {"type": "date"},
            "teardown_reason":   {"type": "keyword"},
            "torn_down_at":      {"type": "date"},
        }
    },
}


# ════════════════════════════════════════════════════════════
#  Placement Selector
# ════════════════════════════════════════════════════════════

def select_placement(kill_chain: list, topology: TopologyGraph) -> dict:
    """
    From the predicted kill chain, select the BEST step to place
    a honeypot — ONE HOP AHEAD of the highest-value lateral
    movement target.

    Strategy:
      Score = step.confidence × criticality_weight(target_host)
      Highest-score step wins — we place the decoy THERE.

    Parameters
    ----------
    kill_chain : list
        The predicted_kill_chain from Phase 1.
    topology : TopologyGraph
        The loaded topology graph for CMDB lookups.

    Returns
    -------
    dict
        The selected kill chain step with enriched asset_profile.
    """
    if not kill_chain:
        logger.warning("Empty kill chain - cannot select placement")
        return {}

    best_step = None
    best_score = -1.0

    for step in kill_chain:
        confidence = step.get("confidence", 0)
        if confidence <= 0:
            continue  # Skip unreachable/pruned steps

        target_ip = step.get("target_ip", "")
        asset = topology.assets.get(target_ip, {})
        criticality = asset.get("criticality", "Unknown")
        crit_weight = _CRIT_SCORE.get(criticality, 0.4)

        score = confidence * crit_weight
        if score > best_score:
            best_score = score
            best_step = {**step, "asset_profile": asset, "placement_score": score}

    if best_step:
        logger.info(
            f"Placement selected: {best_step.get('target_host', '?')} "
            f"({best_step.get('target_ip', '?')}) - "
            f"score={best_step['placement_score']:.2f}"
        )
    else:
        logger.warning("No viable placement found in kill chain")

    return best_step or {}


# ════════════════════════════════════════════════════════════
#  Docker Network Isolation
# ════════════════════════════════════════════════════════════

def create_isolated_network(
    docker_client: "docker.DockerClient",
    decoy_id: str,
) -> "docker.models.networks.Network":
    """
    Create a fully isolated Docker bridge network for the decoy.

    Isolation guarantees:
      - internal=True → DROP all packets destined outside the bridge
      - Unique /24 subnet per decoy (172.30.X.0/24)
      - NeoVigil labels for lifecycle tracking
    """
    subnet_octet = (hash(decoy_id) % 250) + 1
    net_name = f"{HONEYPOT_NET_PREFIX}-{decoy_id[:8]}"

    network = docker_client.networks.create(
        name=net_name,
        driver="bridge",
        internal=True,          # no external routing
        check_duplicate=True,
        ipam=docker.types.IPAMConfig(
            pool_configs=[
                docker.types.IPAMPool(
                    subnet=f"172.30.{subnet_octet}.0/24",
                    gateway=f"172.30.{subnet_octet}.1",
                )
            ]
        ),
        labels={
            "neovigil.role": "honeypot-network",
            "neovigil.decoy_id": decoy_id,
            "neovigil.created": datetime.utcnow().isoformat(),
        },
    )

    logger.info(
        f"Isolated network created: {net_name} "
        f"(internal=True, subnet=172.30.{subnet_octet}.0/24)"
    )
    return network


# ════════════════════════════════════════════════════════════
#  Container Deployment
# ════════════════════════════════════════════════════════════

def deploy_honeypot_container(
    docker_client: "docker.DockerClient",
    decoy_id: str,
    config: dict,
    network_name: str,
) -> str:
    """
    Deploy a honeypot container with strict security constraints.

    Hardening applied:
      - read_only=True (immutable root filesystem)
      - no-new-privileges (blocks privilege escalation)
      - 128MB RAM hard cap
      - 25% CPU quota
      - No auto-restart (restart_policy=no)
      - NeoVigil labels for tracking

    Returns the container ID.
    """
    container = docker_client.containers.run(
        image=config["image"],
        name=f"decoy-{decoy_id[:12]}",
        detach=True,
        network=network_name,
        ports=config.get("ports", {}),
        environment={
            "DECOY_ID": decoy_id,
            "DECOY_SERVICE": config.get("service_name", "generic"),
            **config.get("env", {}),
        },
        labels={
            "neovigil.role": "honeypot",
            "neovigil.decoy_id": decoy_id,
            "neovigil.service": config.get("service_name", "generic"),
            "neovigil.template": config.get("template_key", "unknown"),
            "neovigil.created": datetime.utcnow().isoformat(),
        },
        mem_limit="128m",
        cpu_quota=25000,                            # 25% of one core
        read_only=True,                             # Immutable filesystem
        security_opt=["no-new-privileges:true"],    # Block privesc
        restart_policy={"Name": "no"},              # No auto-restart
    )

    logger.info(
        f"Honeypot deployed: {container.short_id} "
        f"({config.get('service_name', '?')}) on {network_name}"
    )
    return container.id


def deploy_fluent_bit_sidecar(
    docker_client: "docker.DockerClient",
    decoy_id: str,
    honeypot_network_name: str,
) -> str:
    """
    Deploy a Fluent Bit sidecar with DUAL-HOMING:
      1. Connected to the honeypot's isolated bridge  (reads telemetry)
      2. Connected to opensearch-net                  (writes to RabbitMQ)

    This is the ONLY one-directional data bridge between honeypot ↔ production.
    The honeypot container itself has ZERO production network access.

    Returns the sidecar container ID.
    """
    config_path = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "config", "honeypot_fluent_bit.conf",
        )
    )

    container = docker_client.containers.run(
        image="fluent/fluent-bit:latest",
        name=f"sidecar-{decoy_id[:12]}",
        detach=True,
        network=honeypot_network_name,      # honeypot bridge
        environment={
            "DECOY_ID": decoy_id,
            "RABBITMQ_HOST": RABBITMQ_HOST,
        },
        volumes={
            config_path: {
                "bind": "/fluent-bit/etc/fluent-bit.conf",
                "mode": "ro",
            },
        },
        labels={
            "neovigil.role": "honeypot-sidecar",
            "neovigil.decoy_id": decoy_id,
            "neovigil.created": datetime.utcnow().isoformat(),
        },
        mem_limit="64m",                    # Minimal footprint
        cpu_quota=10000,                    # 10% of one core
        read_only=True,
        security_opt=["no-new-privileges:true"],
        restart_policy={"Name": "no"},
    )

    # ★ DUAL-HOMING: Also connect to production network (one-way write path)
    try:
        prod_net = docker_client.networks.get(PRODUCTION_NETWORK)
        prod_net.connect(container)
        logger.info(
            f"Sidecar dual-homed: {container.short_id} -> "
            f"{honeypot_network_name} + {PRODUCTION_NETWORK}"
        )
    except docker.errors.NotFound:
        logger.warning(
            f"Production network '{PRODUCTION_NETWORK}' not found. "
            f"Sidecar will only operate on honeypot bridge."
        )
    except docker.errors.APIError as exc:
        logger.warning(f"Could not dual-home sidecar: {exc}")

    return container.id


# ════════════════════════════════════════════════════════════
#  Lifecycle Manager
# ════════════════════════════════════════════════════════════

class DecoyLifecycleManager:
    """Manages TTL-based teardown, orphan cleanup, and state tracking."""

    def __init__(self, docker_client=None, os_client=None):
        self.docker = docker_client
        self.os_client = os_client
        self._teardown_threads: Dict[str, threading.Thread] = {}

    # ─── TTL Scheduling ────────────────────────────────────

    def schedule_teardown(self, decoy_id: str, ttl_hours: int):
        """Schedule the decoy for automatic teardown after TTL."""
        def _timer():
            time.sleep(ttl_hours * 3600)
            logger.info(f"TTL expired for decoy {decoy_id[:8]} - tearing down")
            self.teardown_decoy(decoy_id, reason="TTL_EXPIRED")

        t = threading.Thread(target=_timer, daemon=True, name=f"ttl-{decoy_id[:8]}")
        t.start()
        self._teardown_threads[decoy_id] = t

        expires_at = (datetime.utcnow() + timedelta(hours=ttl_hours)).isoformat()
        logger.info(f"Teardown scheduled: {decoy_id[:8]} in {ttl_hours}h (expires: {expires_at})")

    # ─── Teardown ──────────────────────────────────────────

    def teardown_decoy(self, decoy_id: str, reason: str = "manual"):
        """Remove all Docker resources associated with a decoy."""
        if not self.docker:
            logger.warning(f"Docker unavailable - cannot teardown {decoy_id[:8]}")
            return

        try:
            # 1. Stop & remove honeypot container
            try:
                hp = self.docker.containers.get(f"decoy-{decoy_id[:12]}")
                hp.stop(timeout=5)
                hp.remove(force=True)
                logger.info(f"  🗑️ Honeypot container removed: decoy-{decoy_id[:12]}")
            except docker.errors.NotFound:
                logger.debug(f"  Honeypot container already removed: decoy-{decoy_id[:12]}")
            except docker.errors.APIError as exc:
                logger.error(f"  Error removing honeypot: {exc}")

            # 2. Stop & remove sidecar
            try:
                sc = self.docker.containers.get(f"sidecar-{decoy_id[:12]}")
                sc.stop(timeout=5)
                sc.remove(force=True)
                logger.info(f"  Sidecar container removed: sidecar-{decoy_id[:12]}")
            except docker.errors.NotFound:
                logger.debug(f"  Sidecar already removed: sidecar-{decoy_id[:12]}")
            except docker.errors.APIError as exc:
                logger.error(f"  Error removing sidecar: {exc}")

            # 3. Remove isolated network bridge
            net_name = f"{HONEYPOT_NET_PREFIX}-{decoy_id[:8]}"
            try:
                net = self.docker.networks.get(net_name)
                net.remove()
                logger.info(f"  Network removed: {net_name}")
            except docker.errors.NotFound:
                logger.debug(f"  Network already removed: {net_name}")
            except docker.errors.APIError as exc:
                logger.error(f"  Error removing network: {exc}")

            # 4. Update OpenSearch state
            if self.os_client:
                try:
                    self.os_client.update(
                        index="decoy-state",
                        id=decoy_id,
                        body={"doc": {
                            "status": "TORN_DOWN",
                            "teardown_reason": reason,
                            "torn_down_at": datetime.utcnow().isoformat(),
                        }},
                        refresh=True,
                    )
                except Exception:
                    pass  # Best-effort state update

            logger.info(f"Decoy {decoy_id[:8]} fully torn down (reason: {reason})")

        except Exception as exc:
            logger.error(f" Teardown failed for {decoy_id[:8]}: {exc}")

        # Cleanup thread reference
        self._teardown_threads.pop(decoy_id, None)

    # ─── Enforce MAX cap ───────────────────────────────────

    def enforce_max_decoys(self):
        """If active decoys exceed MAX_ACTIVE_DECOYS, evict the oldest."""
        if not self.docker:
            return

        try:
            active = [
                c for c in self.docker.containers.list(all=False)
                if c.labels.get("neovigil.role") == "honeypot"
            ]

            if len(active) <= MAX_ACTIVE_DECOYS:
                return

            # Sort by creation time → evict oldest first
            active.sort(key=lambda c: c.attrs.get("Created", ""))
            excess = active[:len(active) - MAX_ACTIVE_DECOYS]

            for c in excess:
                did = c.labels.get("neovigil.decoy_id", "unknown")
                self.teardown_decoy(did, reason="MAX_DECOYS_EXCEEDED")

        except docker.errors.APIError as exc:
            logger.error(f"Error enforcing max decoys: {exc}")

    # ─── Orphan Cleanup ────────────────────────────────────

    def cleanup_orphans(self):
        """
        On startup, find any leftover honeypot containers from a
        previous crash and teardown expired ones.
        """
        if not self.docker:
            return

        try:
            all_honeypots = [
                c for c in self.docker.containers.list(all=True)
                if c.labels.get("neovigil.role") in ("honeypot", "honeypot-sidecar")
            ]

            if not all_honeypots:
                logger.info("No orphan honeypots found")
                return

            logger.info(f"Found {len(all_honeypots)} existing honeypot container(s)")
            now = datetime.utcnow()

            for c in all_honeypots:
                created_str = c.labels.get("neovigil.created", "")
                try:
                    created = datetime.fromisoformat(created_str)
                    age_hours = (now - created).total_seconds() / 3600
                    if age_hours > DEFAULT_TTL_HOURS * 2:
                        did = c.labels.get("neovigil.decoy_id", "unknown")
                        logger.warning(
                            f"Orphan detected: {c.name} (age={age_hours:.1f}h) - tearing down"
                        )
                        c.stop(timeout=5)
                        c.remove(force=True)
                except (ValueError, TypeError):
                    pass 

            # Also clean up orphaned networks
            for net in self.docker.networks.list():
                if net.name.startswith(HONEYPOT_NET_PREFIX):
                    if not net.containers:
                        logger.info(f"Removing empty honeypot network: {net.name}")
                        try:
                            net.remove()
                        except docker.errors.APIError:
                            pass

        except docker.errors.APIError as exc:
            logger.error(f"Orphan cleanup error: {exc}")


# ════════════════════════════════════════════════════════════
#  State Persistence
# ════════════════════════════════════════════════════════════

def _load_state() -> dict:
    """Load active decoy state from disk."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {"active_decoys": {}}


def _save_state(state: dict):
    """Persist decoy state to disk."""
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, default=str)
    except IOError as exc:
        logger.error(f"Failed to save state: {exc}")


# ════════════════════════════════════════════════════════════
#  Main Decoy Manager Orchestrator
# ════════════════════════════════════════════════════════════

class DecoyManager:
    """
    Top-level orchestrator — consumes decoy_deploy_tasks from
    RabbitMQ and manages the full container lifecycle.
    """

    def __init__(self):
        logger.info("Initialising Decoy Manager ...")
        self.topology = TopologyGraph()
        self.os_client = get_opensearch_client()

        # Docker client
        if DOCKER_AVAILABLE:
            try:
                self.docker = docker.from_env()
                self.docker.ping()
                logger.info("Docker daemon connected")
            except docker.errors.DockerException as exc:
                logger.error(f"Docker daemon unreachable: {exc}")
                self.docker = None
        else:
            self.docker = None

        self.lifecycle = DecoyLifecycleManager(self.docker, self.os_client)
        self.state = _load_state()

        self._ensure_indices()

        # Startup: clean orphans
        self.lifecycle.cleanup_orphans()

        logger.info(
            f"Decoy Manager initialised "
            f"(docker={'YES' if self.docker else 'NO (DRYCHECK)'}, "
            f"max_decoys={MAX_ACTIVE_DECOYS}, ttl={DEFAULT_TTL_HOURS}h)"
        )

    # ─── Index Management ─────────────────────────────────

    def _ensure_indices(self):
        """Create OpenSearch indices for Phase 2 if they don't exist."""
        index_map = {
            "honeypot-telemetry":    HONEYPOT_TELEMETRY_MAPPING,
            "prediction-accuracy":   PREDICTION_ACCURACY_MAPPING,
            "decoy-state":           DECOY_STATE_MAPPING,
        }
        for index_name, mapping in index_map.items():
            try:
                if not self.os_client.indices.exists(index=index_name):
                    self.os_client.indices.create(index=index_name, body=mapping)
                    logger.info(f"Created index: {index_name}")
                else:
                    logger.info(f"Index exists: {index_name}")
            except Exception as exc:
                logger.error(f"Failed to create index {index_name}: {exc}")

    # ─── Core Deployment Flow ─────────────────────────────

    def handle_deploy_task(self, payload: dict):
        """
        Main entry point — process a single decoy deploy task:
          1. Select placement from kill chain
          2. Generate template
          3. Deploy Docker containers
          4. Schedule TTL teardown
        """
        prediction_id = payload.get("prediction_id", "unknown")
        kill_chain = payload.get("kill_chain", [])
        tenant_id = payload.get("tenant_id", "default")

        logger.info(
            f"Processing deploy task for prediction {prediction_id[:8]} "
            f"({len(kill_chain)} kill chain steps)"
        )

        # 1. Enforce MAX limit
        self.lifecycle.enforce_max_decoys()

        # Check current count
        if self.docker:
            active_count = len([
                c for c in self.docker.containers.list(all=False)
                if c.labels.get("neovigil.role") == "honeypot"
            ])
            if active_count >= MAX_ACTIVE_DECOYS:
                logger.warning(
                    f"MAX_ACTIVE_DECOYS reached ({active_count}/{MAX_ACTIVE_DECOYS}). "
                    f"Skipping deployment for prediction {prediction_id[:8]}"
                )
                return

        # 2. Select best placement from kill chain
        placement = select_placement(kill_chain, self.topology)
        if not placement:
            logger.warning(f"No placement found for prediction {prediction_id[:8]}")
            return

        # 3. Generate decoy template
        asset_profile = placement.get("asset_profile", {})
        config = select_template(placement, asset_profile)

        # 4. Assign decoy identity
        decoy_id = str(uuid.uuid4())
        ttl_hours = config.get("ttl_hours", DEFAULT_TTL_HOURS)

        # 5. Deploy (or dry-run)
        if not self.docker:
            logger.info(
                f"DRY-RUN: Would deploy '{config['service_name']}' decoy "
                f"for target {placement.get('target_host', '?')} "
                f"({placement.get('target_ip', '?')})"
            )
            self._index_state(decoy_id, prediction_id, config, placement, ttl_hours, "DRY_RUN")
            return

        try:
            # 5a. Create isolated network
            network = create_isolated_network(self.docker, decoy_id)

            # 5b. Deploy honeypot container
            container_id = deploy_honeypot_container(
                self.docker, decoy_id, config, network.name
            )

            # 5c. Deploy Fluent Bit sidecar (dual-homed)
            sidecar_id = deploy_fluent_bit_sidecar(
                self.docker, decoy_id, network.name
            )

            # 5d. Index state to OpenSearch
            self._index_state(
                decoy_id, prediction_id, config, placement, ttl_hours,
                "ACTIVE", container_id, sidecar_id, network.name,
            )

            # 5e. Schedule TTL teardown
            self.lifecycle.schedule_teardown(decoy_id, ttl_hours)

            # 5f. Persist local state
            self.state["active_decoys"][decoy_id] = {
                "prediction_id": prediction_id,
                "container_id": container_id,
                "sidecar_id": sidecar_id,
                "network": network.name,
                "template": config.get("template_key"),
                "created_at": datetime.utcnow().isoformat(),
                "ttl_hours": ttl_hours,
            }
            _save_state(self.state)

            logger.info(
                f"Decoy {decoy_id[:8]} fully operational:\n"
                f"   Honeypot:  {container_id[:12]} ({config['service_name']})\n"
                f"   Sidecar:   {sidecar_id[:12]}\n"
                f"   Network:   {network.name} (internal=True)\n"
                f"   TTL:       {ttl_hours}h\n"
                f"   Target:    {placement.get('target_host', '?')} "
                f"({placement.get('target_ip', '?')})"
            )

        except docker.errors.ImageNotFound as exc:
            logger.error(
                f"Docker image not found: {config['image']}. "
                f"Skipping deployment for {decoy_id[:8]}: {exc}"
            )
        except docker.errors.APIError as exc:
            logger.error(f"Docker API error during deployment: {exc}")
            # Attempt partial cleanup
            self.lifecycle.teardown_decoy(decoy_id, reason="DEPLOY_FAILED")
        except Exception as exc:
            logger.error(f"Unexpected deployment error: {exc}", exc_info=True)
            self.lifecycle.teardown_decoy(decoy_id, reason="DEPLOY_FAILED")

    # ─── State Indexing ────────────────────────────────────

    def _index_state(
        self,
        decoy_id: str,
        prediction_id: str,
        config: dict,
        placement: dict,
        ttl_hours: int,
        status: str,
        container_id: str = "",
        sidecar_id: str = "",
        network_name: str = "",
    ):
        """Index the decoy state document to OpenSearch."""
        now = datetime.utcnow()
        doc = {
            "decoy_id": decoy_id,
            "prediction_id": prediction_id,
            "status": status,
            "template_key": config.get("template_key", "unknown"),
            "service_name": config.get("service_name", "unknown"),
            "target_host": placement.get("target_host", "unknown"),
            "target_ip": placement.get("target_ip", "unknown"),
            "container_id": container_id,
            "sidecar_id": sidecar_id,
            "network_name": network_name,
            "created_at": now.isoformat(),
            "ttl_hours": ttl_hours,
            "expires_at": (now + timedelta(hours=ttl_hours)).isoformat(),
        }
        try:
            self.os_client.index(
                index="decoy-state", id=decoy_id, body=doc, refresh=True,
            )
        except Exception as exc:
            logger.error(f"Failed to index decoy state: {exc}")

    # ─── RabbitMQ Consumer Loop ────────────────────────────

    def run(self):
        """Main event loop — consume from decoy_deploy_tasks queue."""
        logger.info("Decoy Manager online - starting RabbitMQ consumer ...")

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
                channel.queue_declare(queue=DEPLOY_QUEUE, durable=True)
                channel.basic_qos(prefetch_count=1)

                def on_deploy_task(ch, method, _props, body):
                    try:
                        payload = json.loads(body)
                        self.handle_deploy_task(payload)
                    except json.JSONDecodeError as exc:
                        logger.error(f" Invalid JSON in deploy task: {exc}")
                    except Exception as exc:
                        logger.error(f" Deploy task error: {exc}", exc_info=True)
                    finally:
                        ch.basic_ack(delivery_tag=method.delivery_tag)

                channel.basic_consume(
                    queue=DEPLOY_QUEUE, on_message_callback=on_deploy_task,
                )

                logger.info(
                    f" Listening on '{DEPLOY_QUEUE}' "
                    f"(max_decoys={MAX_ACTIVE_DECOYS}, ttl={DEFAULT_TTL_HOURS}h) …"
                )
                channel.start_consuming()

            except pika.exceptions.AMQPConnectionError as exc:
                logger.warning(f"  RabbitMQ lost: {exc}. Reconnecting in 10s …")
                time.sleep(10)
            except KeyboardInterrupt:
                logger.info(" Decoy Manager shutting down (KeyboardInterrupt)")
                break
            except Exception as exc:
                logger.error(f" Unexpected consumer error: {exc}", exc_info=True)
                time.sleep(10)


# ════════════════════════════════════════════════════════════
#  Entrypoint
# ════════════════════════════════════════════════════════════
if __name__ == "__main__":
    manager = DecoyManager()
    manager.run()
