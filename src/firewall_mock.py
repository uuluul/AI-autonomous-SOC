"""
NeoVigil Firewall Client -- Dual Mode (Mock / API)
=====================================================
Supports both mock mode (for testing) and real API mode
(for production firewall integration).

Mode selection via FIREWALL_MODE env var:
  - "mock" (default): Simulates firewall actions with realistic delays
  - "api": Calls real firewall REST API (Fortinet, Palo Alto, etc.)
"""

import logging
import os
import time
import random
import uuid
from datetime import datetime

logger = logging.getLogger(__name__)


class FirewallClient:
    """Dual-mode firewall client supporting mock and API modes."""

    def __init__(self, vendor="Fortinet", mode=None):
        self.vendor = vendor
        self.mode = mode or os.getenv("FIREWALL_MODE", "mock")
        self.api_url = os.getenv("FIREWALL_API_URL", "")
        self.api_key = os.getenv("FIREWALL_API_KEY", "")
        self.connected = False
        self._active_blocks = {}  # ip -> rule_info
        logger.info(
            f"FirewallClient initialized: vendor={vendor} mode={self.mode}"
        )

    def connect(self):
        """Connect to firewall (mock or API)."""
        if self.mode == "api" and self.api_url:
            logger.info(f"Connecting to {self.vendor} Firewall API at {self.api_url}...")
            try:
                import httpx
                resp = httpx.get(
                    f"{self.api_url}/api/v2/cmdb/system/status",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    verify=False,
                    timeout=10,
                )
                if resp.status_code == 200:
                    self.connected = True
                    logger.info(f"Connected to {self.vendor} API.")
                else:
                    logger.warning(f"API connection returned status {resp.status_code}")
                    self.connected = False
            except Exception as exc:
                logger.warning(f"API connection failed: {exc}. Falling back to mock.")
                self.mode = "mock"
                self.connected = True
        else:
            logger.info(f"Connecting to {self.vendor} Firewall (mock mode)...")
            time.sleep(0.3)
            self.connected = True
            logger.info(f"Connected to {self.vendor} API (mock).")

    def block_ip(self, ip_address: str, rule_name: str = None) -> bool:
        """
        Block IP via firewall REJECT rule.
        Returns True if block was successful.
        """
        if not self.connected:
            self.connect()

        if not rule_name:
            rule_name = f"neovigil-block-{str(uuid.uuid4())[:8]}"

        if self.mode == "api":
            return self._api_block(ip_address, rule_name)
        return self._mock_block(ip_address, rule_name)

    def unblock_ip(self, ip_address: str) -> bool:
        """Remove a previously created block rule."""
        if not self.connected:
            self.connect()

        rule_info = self._active_blocks.get(ip_address)
        if not rule_info:
            logger.warning(f"No active block found for {ip_address}")
            return False

        if self.mode == "api":
            return self._api_unblock(ip_address, rule_info)
        return self._mock_unblock(ip_address, rule_info)

    def get_active_blocks(self) -> list:
        """List currently active firewall block rules."""
        return [
            {
                "ip": ip,
                "rule_name": info.get("rule_name"),
                "blocked_at": info.get("blocked_at"),
            }
            for ip, info in self._active_blocks.items()
        ]

    # ─── Mock Mode ────────────────────────────────────────────

    def _mock_block(self, ip_address: str, rule_name: str) -> bool:
        """Simulate firewall block with realistic delays."""
        logger.info(f"[Firewall] Requesting block for IP: {ip_address}...")
        time.sleep(random.uniform(0.3, 1.0))

        # 95% success rate in mock mode
        if random.random() > 0.05:
            self._active_blocks[ip_address] = {
                "rule_name": rule_name,
                "blocked_at": datetime.utcnow().isoformat(),
            }
            logger.info(f"[SUCCESS] Firewall Rule Created: DENY ALL -> {ip_address}")
            return True
        else:
            logger.error(f"[FAIL] Firewall API Timeout for {ip_address}")
            return False

    def _mock_unblock(self, ip_address: str, rule_info: dict) -> bool:
        """Simulate firewall unblock."""
        logger.info(f"[Firewall] Removing block for IP: {ip_address}...")
        time.sleep(0.3)
        self._active_blocks.pop(ip_address, None)
        logger.info(f"[SUCCESS] Firewall Rule Removed: {ip_address}")
        return True

    # ─── API Mode ─────────────────────────────────────────────

    def _api_block(self, ip_address: str, rule_name: str) -> bool:
        """Block IP via real firewall REST API."""
        try:
            import httpx
            payload = {
                "name": rule_name,
                "srcaddr": [{"name": ip_address}],
                "dstaddr": [{"name": "all"}],
                "action": "deny",
                "status": "enable",
                "comments": f"NeoVigil Phase 4 auto-block - {datetime.utcnow().isoformat()}",
            }
            resp = httpx.post(
                f"{self.api_url}/api/v2/cmdb/firewall/policy",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                verify=False,
                timeout=30,
            )
            if resp.status_code in (200, 201):
                self._active_blocks[ip_address] = {
                    "rule_name": rule_name,
                    "blocked_at": datetime.utcnow().isoformat(),
                    "api_response": resp.json() if resp.text else {},
                }
                logger.info(f"[API SUCCESS] Firewall rule created for {ip_address}")
                return True
            else:
                logger.error(
                    f"[API FAIL] Firewall API returned {resp.status_code}: "
                    f"{resp.text[:200]}"
                )
                return False
        except Exception as exc:
            logger.error(f"[API ERROR] Firewall block failed: {exc}")
            return False

    def _api_unblock(self, ip_address: str, rule_info: dict) -> bool:
        """Remove firewall block via REST API."""
        try:
            import httpx
            rule_name = rule_info.get("rule_name", "")
            resp = httpx.delete(
                f"{self.api_url}/api/v2/cmdb/firewall/policy/{rule_name}",
                headers={"Authorization": f"Bearer {self.api_key}"},
                verify=False,
                timeout=30,
            )
            if resp.status_code in (200, 204):
                self._active_blocks.pop(ip_address, None)
                logger.info(f"[API SUCCESS] Firewall rule removed for {ip_address}")
                return True
            else:
                logger.error(f"[API FAIL] Unblock returned {resp.status_code}")
                return False
        except Exception as exc:
            logger.error(f"[API ERROR] Firewall unblock failed: {exc}")
            return False


if __name__ == "__main__":
    fw = FirewallClient()
    fw.block_ip("103.15.22.88")
    print(f"Active blocks: {fw.get_active_blocks()}")
    fw.unblock_ip("103.15.22.88")
    print(f"Active blocks: {fw.get_active_blocks()}")
