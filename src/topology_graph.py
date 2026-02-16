"""
 NeoVigil Topology-Aware Graph Engine
====================================
Loads network adjacency data and the enhanced asset inventory to provide:
  1. BFS path-finding for lateral-movement prediction
  2. Firewall-rule-aware reachability checks
  3. Natural-language topology summaries for LLM consumption

Files consumed:
  - data/network_topology.json   (adjacency graph + firewall rules)
  - data/assets.json             (enhanced CMDB with software/ports/zones)
"""

import json
import logging
import os
from collections import deque
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ───────────────────────── defaults ─────────────────────────
_DEFAULT_TOPOLOGY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "data", "network_topology.json"
)
_DEFAULT_ASSETS = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "data", "assets.json"
)

# Criticality ordering (lower = more critical)
_CRIT_PRIORITY = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}


class TopologyGraph:
    """In-memory directed graph built from *network_topology.json*."""

    # ─── Construction ────────────────────────────────────────

    def __init__(
        self,
        topology_path: str = _DEFAULT_TOPOLOGY,
        assets_path: str = _DEFAULT_ASSETS,
    ):
        self.topology_path = topology_path
        self.assets_path = assets_path

        self.topology: dict = self._load_json(topology_path)
        self.assets: dict = self._load_json(assets_path)
        self.adjacency: dict = self.topology.get("adjacency", {})
        self.zones: dict = self.topology.get("zones", {})
        self.firewall_rules: list = self.topology.get("firewall_rules", [])

        logger.info(
            f"📡 Topology loaded: {len(self.adjacency)} nodes, "
            f"{len(self.zones)} zones, "
            f"{len(self.firewall_rules)} firewall rules"
        )

    # ─── I/O helpers ─────────────────────────────────────────

    @staticmethod
    def _load_json(path: str) -> dict:
        abs_path = os.path.abspath(path)
        if not os.path.exists(abs_path):
            logger.warning(f"⚠️  File not found: {abs_path} — returning empty dict")
            return {}
        try:
            with open(abs_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, IOError) as exc:
            logger.error(f"❌ Failed to parse {abs_path}: {exc}")
            return {}

    def reload(self) -> None:
        """Hot-reload topology & assets from disk (for runtime updates)."""
        self.topology = self._load_json(self.topology_path)
        self.assets = self._load_json(self.assets_path)
        self.adjacency = self.topology.get("adjacency", {})
        self.zones = self.topology.get("zones", {})
        self.firewall_rules = self.topology.get("firewall_rules", [])
        logger.info("🔄 Topology reloaded from disk")

    # ─── Core graph queries ──────────────────────────────────

    def get_reachable_hosts(
        self, source_ip: str, max_hops: int = 3
    ) -> List[Dict]:
        """
        BFS from *source_ip* through the adjacency graph.

        Returns a list of reachable hosts (excluding source) sorted by
        asset criticality, enriched with CMDB metadata.  Firewall deny
        rules are respected — blocked edges are pruned.
        """
        if source_ip not in self.adjacency and source_ip not in self.assets:
            logger.warning(
                f"⚠️  Source IP {source_ip} not in topology graph — "
                "returning empty reachable set"
            )
            return []

        visited: set = set()
        queue: deque = deque([(source_ip, 0)])
        reachable: List[Dict] = []

        while queue:
            current_ip, hops = queue.popleft()
            if current_ip in visited or hops > max_hops:
                continue
            visited.add(current_ip)

            # Enrich with asset metadata (skip the source itself)
            if current_ip != source_ip:
                asset = self.assets.get(current_ip, {})
                reachable.append(
                    {
                        "ip": current_ip,
                        "hops": hops,
                        "hostname": asset.get("hostname", "Unknown"),
                        "criticality": asset.get("criticality", "Unknown"),
                        "network_zone": asset.get("network_zone", "Unknown"),
                        "os": asset.get("os", "Unknown"),
                        "software": asset.get("software", []),
                        "open_ports": asset.get("open_ports", []),
                    }
                )

            # Traverse neighbours
            for neighbour_ip in self.adjacency.get(current_ip, []):
                if neighbour_ip not in visited:
                    if not self._is_blocked_by_firewall(current_ip, neighbour_ip):
                        queue.append((neighbour_ip, hops + 1))

        # Sort by criticality (Critical first → Low last)
        reachable.sort(key=lambda h: _CRIT_PRIORITY.get(h["criticality"], 4))
        return reachable

    def get_high_value_targets(
        self, min_criticality: str = "High"
    ) -> List[Dict]:
        """Return all assets at or above *min_criticality*."""
        threshold = _CRIT_PRIORITY.get(min_criticality, 1)
        targets = []
        for ip, info in self.assets.items():
            if _CRIT_PRIORITY.get(info.get("criticality", "Low"), 3) <= threshold:
                targets.append({"ip": ip, **info})
        return targets

    # ─── Firewall logic ──────────────────────────────────────

    def _get_zone(self, ip: str) -> Optional[str]:
        return self.assets.get(ip, {}).get("network_zone")

    def _is_blocked_by_firewall(self, src_ip: str, dst_ip: str) -> bool:
        """Return True if an explicit deny rule blocks *src→dst*."""
        src_zone = self._get_zone(src_ip)
        dst_zone = self._get_zone(dst_ip)
        if not src_zone or not dst_zone:
            return False  # Unknown zone → assume reachable (safe default)

        for rule in self.firewall_rules:
            if (
                rule.get("src") == src_zone
                and rule.get("dst") == dst_zone
                and rule.get("action") == "deny"
            ):
                return True
        return False

    # ─── LLM prompt builder ──────────────────────────────────

    def build_attack_surface_context(self, source_ip: str) -> str:
        """
        Render a natural-language topology summary for injection into
        the Red Team LLM prompt.  This is the **bridge** between
        structured graph data and LLM reasoning.
        """
        reachable = self.get_reachable_hosts(source_ip)
        if not reachable:
            return (
                f"No reachable internal hosts found from {source_ip}. "
                "The host may be isolated or not present in the topology graph."
            )

        lines = [f"=== Network Topology from {source_ip} ==="]
        for host in reachable:
            sw_str = ", ".join(host["software"]) if host["software"] else "N/A"
            ports_str = ", ".join(str(p) for p in host["open_ports"]) if host["open_ports"] else "N/A"
            lines.append(
                f"- [{host['hops']} hop(s)] {host['hostname']} ({host['ip']}) | "
                f"Zone: {host['network_zone']} | "
                f"Criticality: {host['criticality']} | "
                f"OS: {host['os']} | "
                f"Software: {sw_str} | "
                f"Open Ports: {ports_str}"
            )

        # Append high-value targets summary
        hvt = self.get_high_value_targets("Critical")
        if hvt:
            lines.append("\n=== High-Value Targets (Critical Assets) ===")
            for t in hvt:
                lines.append(f"- {t.get('hostname', '?')} ({t['ip']}) — {t.get('owner', '?')}")

        return "\n".join(lines)

    def scan_assets_for_software(self, keyword: str) -> List[Dict]:
        """
        Return assets whose *software* list contains *keyword*
        (case-insensitive substring match).  Used by the Zero-Log
        Anticipation Engine.
        """
        keyword_lower = keyword.lower()
        matches = []
        for ip, info in self.assets.items():
            for sw in info.get("software", []):
                if keyword_lower in sw.lower():
                    matches.append(
                        {
                            "ip": ip,
                            "hostname": info.get("hostname", "Unknown"),
                            "criticality": info.get("criticality", "Unknown"),
                            "matched_software": sw,
                            "network_zone": info.get("network_zone", "Unknown"),
                        }
                    )
                    break  # one match per host is enough
        return matches
