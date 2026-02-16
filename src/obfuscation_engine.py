"""
NeoVigil Obfuscation Engine — Phase 3
======================================
Generates and manages dynamic Nginx/Lua obfuscation rules that
spoof server fingerprints when suspicious scanners are detected.

Responsibilities:
  1. Load obfuscation profiles from data/obfuscation_profiles.json
  2. Select the optimal spoof profile (deliberate misdirection)
  3. Generate Nginx-compatible obfuscation rule files
  4. Trigger Nginx reload for live rule activation
  5. Manage rule TTL and pruning

The obfuscation layer runs INSIDE the OpenResty reverse proxy via
Lua access_by_lua and header_filter_by_lua hooks.
"""

import json
import logging
import os
import subprocess
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ─── Lazy import ─────────────────────────────────────────────
try:
    from src.setup_opensearch import get_opensearch_client
except ImportError:
    from setup_opensearch import get_opensearch_client

# ─── Configuration ───────────────────────────────────────────
PROFILES_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "data", "obfuscation_profiles.json"
)
RULES_OUTPUT_PATH = os.getenv(
    "OBFUSCATION_RULES_PATH",
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "config", "obfuscation_rules.json",
    ),
)
DEFAULT_RULE_TTL_HOURS = int(os.getenv("OBFUSCATION_TTL_HOURS", "2"))
NGINX_RELOAD_CMD = os.getenv("NGINX_RELOAD_CMD", "nginx -s reload")
MTD_MUTATIONS_INDEX = "mtd-active-mutations"
MTD_AUDIT_INDEX = "mtd-audit-log"


# ════════════════════════════════════════════════════════════
#  Profile Manager
# ════════════════════════════════════════════════════════════

class ProfileManager:
    """Loads and manages the obfuscation profile library."""

    def __init__(self):
        self.profiles: Dict[str, dict] = {}
        self.opposite_map: Dict[str, str] = {}
        self._load_profiles()

    def _load_profiles(self):
        """Load profiles from JSON file."""
        try:
            with open(PROFILES_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)

            metadata = data.pop("_metadata", {})
            self.opposite_map = metadata.get("opposite_map", {})
            self.profiles = data
            logger.info(
                f"📋 Loaded {len(self.profiles)} obfuscation profiles "
                f"from {os.path.basename(PROFILES_PATH)}"
            )
        except FileNotFoundError:
            logger.warning(f"⚠️  Profiles file not found: {PROFILES_PATH}")
        except json.JSONDecodeError as exc:
            logger.error(f"❌ Invalid JSON in profiles: {exc}")

    def select_profile(self, real_server: str) -> tuple:
        """
        Select the optimal spoof profile using DELIBERATE MISDIRECTION:
        if the real server is Apache, spoof IIS — forcing the attacker
        to prepare IIS-specific exploits that will fail.

        Parameters
        ----------
        real_server : str
            Software name from the CMDB (e.g., "Apache Log4j 2.14", "Nginx")

        Returns
        -------
        tuple
            (profile_key, profile_dict)
        """
        real_lower = real_server.lower() if real_server else ""

        # Check the opposite map for deliberate misdirection
        for keyword, profile_key in self.opposite_map.items():
            if keyword in real_lower:
                if profile_key in self.profiles:
                    logger.info(
                        f"🎭 Misdirection: real='{real_server}' → "
                        f"spoof='{profile_key}'"
                    )
                    return profile_key, self.profiles[profile_key]

        # Default fallback: cloudflare edge (discourages direct exploitation)
        default_key = self.opposite_map.get("default", "cloudflare_edge")
        if default_key in self.profiles:
            return default_key, self.profiles[default_key]

        # Ultimate fallback: first available profile
        first_key = next(iter(self.profiles), None)
        if first_key:
            return first_key, self.profiles[first_key]

        return "none", {}


# ════════════════════════════════════════════════════════════
#  Obfuscation Rule Generator
# ════════════════════════════════════════════════════════════

class ObfuscationEngine:
    """
    Generates and manages per-IP obfuscation rules.

    Rule lifecycle:
      1. MTD Controller calls generate_rule() for a scanner IP
      2. Rule is written to obfuscation_rules.json
      3. Nginx reload picks up new rules via Lua shared dict
      4. Rule TTL expires → pruned on next cycle
    """

    def __init__(self, os_client=None):
        self.profiles = ProfileManager()
        self.os_client = os_client or get_opensearch_client()
        self.active_rules: Dict[str, dict] = {}
        self._load_existing_rules()

    def _load_existing_rules(self):
        """Load existing rules from disk."""
        if os.path.exists(RULES_OUTPUT_PATH):
            try:
                with open(RULES_OUTPUT_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.active_rules = data.get("rules", {})
                logger.info(
                    f"📄 Loaded {len(self.active_rules)} existing "
                    f"obfuscation rules"
                )
            except (json.JSONDecodeError, IOError):
                self.active_rules = {}

    # ─── Rule Generation ──────────────────────────────────

    def generate_rule(
        self,
        scanner_ip: str,
        target_service: str,
        target_host: str,
        trigger_reason: str,
        ttl_hours: int = DEFAULT_RULE_TTL_HOURS,
    ) -> dict:
        """
        Create an obfuscation rule for a specific scanner IP.

        Parameters
        ----------
        scanner_ip : str
            The attacker/scanner IP to obfuscate against.
        target_service : str
            Real server software (from CMDB) to misdirect.
        target_host : str
            Hostname being targeted.
        trigger_reason : str
            Why this rule was created (for audit).
        ttl_hours : int
            How long the rule remains active.

        Returns
        -------
        dict
            The generated rule record.
        """
        profile_key, profile = self.profiles.select_profile(target_service)

        if not profile:
            logger.warning(
                f"⚠️  No spoof profile available for '{target_service}'"
            )
            return {}

        rule_id = f"obf-{uuid.uuid4().hex[:8]}"
        now = datetime.utcnow()
        expires_at = now + timedelta(hours=ttl_hours)

        rule = {
            "rule_id": rule_id,
            "scanner_ip": scanner_ip,
            "target_host": target_host,
            "real_service": target_service,
            "spoof_profile": profile_key,
            "spoof_config": {
                "server_header": profile.get("server_header"),
                "x_powered_by": profile.get("x_powered_by"),
                "remove_headers": profile.get("remove_headers", []),
                "add_headers": profile.get("add_headers", {}),
            },
            "created_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "ttl_hours": ttl_hours,
            "trigger_reason": trigger_reason,
            "status": "ACTIVE",
        }

        # Store in-memory
        self.active_rules[scanner_ip] = rule

        # Persist to file
        self._write_rules_file()

        # Index to OpenSearch
        self._index_mutation(rule)

        logger.info(
            f"🎭 Obfuscation rule created: {rule_id}\n"
            f"   Scanner:  {scanner_ip}\n"
            f"   Target:   {target_host} ({target_service})\n"
            f"   Spoofing: {profile_key} ({profile.get('server_header')})\n"
            f"   TTL:      {ttl_hours}h (expires {expires_at.isoformat()})"
        )

        return rule

    # ─── Rule Removal ─────────────────────────────────────

    def remove_rule(self, scanner_ip: str, reason: str = "manual"):
        """Remove an active obfuscation rule."""
        if scanner_ip in self.active_rules:
            rule = self.active_rules.pop(scanner_ip)
            self._write_rules_file()

            # Update OpenSearch
            try:
                self.os_client.update(
                    index=MTD_MUTATIONS_INDEX,
                    id=rule["rule_id"],
                    body={"doc": {
                        "status": "REMOVED",
                        "removed_at": datetime.utcnow().isoformat(),
                        "removal_reason": reason,
                    }},
                    refresh=True,
                )
            except Exception:
                pass

            logger.info(f"🎭 Obfuscation rule removed: {scanner_ip} ({reason})")

    # ─── TTL Pruning ──────────────────────────────────────

    def prune_expired_rules(self) -> int:
        """Remove rules that have exceeded their TTL."""
        now = datetime.utcnow()
        expired = []

        for ip, rule in self.active_rules.items():
            try:
                expires = datetime.fromisoformat(rule["expires_at"])
                if now > expires:
                    expired.append(ip)
            except (ValueError, KeyError):
                expired.append(ip)

        for ip in expired:
            self.remove_rule(ip, reason="TTL_EXPIRED")

        if expired:
            logger.info(f"🧹 Pruned {len(expired)} expired obfuscation rules")

        return len(expired)

    # ─── Nginx Reload ─────────────────────────────────────

    def reload_nginx(self) -> bool:
        """
        Signal Nginx to reload configuration, picking up new
        obfuscation rules from the shared rules file.
        """
        try:
            result = subprocess.run(
                NGINX_RELOAD_CMD.split(),
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                logger.info("🔄 Nginx reloaded successfully")
                return True
            else:
                logger.error(
                    f"❌ Nginx reload failed: {result.stderr}"
                )
                return False
        except FileNotFoundError:
            logger.warning(
                "⚠️  Nginx not found — running outside proxy container. "
                "Rules written to file for manual reload."
            )
            return False
        except subprocess.TimeoutExpired:
            logger.error("❌ Nginx reload timed out")
            return False
        except Exception as exc:
            logger.error(f"❌ Nginx reload error: {exc}")
            return False

    # ─── File I/O ─────────────────────────────────────────

    def _write_rules_file(self):
        """
        Write active rules to JSON file that the Nginx Lua module
        reads via init_by_lua to populate shared dict.
        """
        output = {
            "generated_at": datetime.utcnow().isoformat(),
            "rule_count": len(self.active_rules),
            "rules": self.active_rules,
        }
        try:
            os.makedirs(os.path.dirname(RULES_OUTPUT_PATH), exist_ok=True)
            with open(RULES_OUTPUT_PATH, "w", encoding="utf-8") as f:
                json.dump(output, f, indent=2, default=str)
        except IOError as exc:
            logger.error(f"❌ Failed to write rules file: {exc}")

    # ─── OpenSearch Indexing ──────────────────────────────

    def _index_mutation(self, rule: dict):
        """Index obfuscation rule to mtd-active-mutations."""
        try:
            doc = {
                **rule,
                "mutation_type": "obfuscation",
            }
            self.os_client.index(
                index=MTD_MUTATIONS_INDEX,
                id=rule["rule_id"],
                body=doc,
                refresh=True,
            )
        except Exception as exc:
            logger.error(f"❌ Failed to index mutation: {exc}")

    # ─── Status ───────────────────────────────────────────

    def get_active_rules(self) -> List[dict]:
        """Return all currently active obfuscation rules."""
        return list(self.active_rules.values())

    def get_rule_count(self) -> int:
        """Return count of active rules."""
        return len(self.active_rules)
