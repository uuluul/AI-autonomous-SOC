"""
NeoVigil Decoy Template Generator — Phase 2
============================================
CTI-driven template library for generating honeypot container
configurations that mirror real CMDB assets.

Templates are selected based on:
  1. Phase 1 kill chain target profile (software, ports, hostname)
  2. Asset CMDB metadata (software stack, open ports, OS)
  3. Current CTI trends (which exploit families are active)

Each template specifies:
  - Docker image to use
  - Ports to expose on the honeypot bridge
  - Environment variables for service configuration
  - MITRE ATT&CK lure techniques  (what attackers we expect to trap)
  - Default TTL before auto-teardown
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════
#  Template Library — Lightweight, Alpine-based images
# ════════════════════════════════════════════════════════════

DECOY_TEMPLATES: Dict[str, dict] = {

    "ssh_server": {
        "image": "lscr.io/linuxserver/openssh-server:latest",
        "service_name": "SSH Honeypot",
        "ports": {"22/tcp": None},          # Docker assigns random host port
        "env": {
            "PASSWORD_ACCESS": "true",
            "USER_NAME": "admin",
            "SUDO_ACCESS": "false",
        },
        "mitre_lure": ["T1021.004"],        # Remote Services: SSH
        "ttl_hours": 4,
        "description": "Emulates an SSH endpoint with weak credentials to attract brute-force and credential-stuffing attacks.",
    },

    "smb_server": {
        "image": "dperson/samba:latest",
        "service_name": "SMB/CIFS Honeypot",
        "ports": {"445/tcp": None, "139/tcp": None},
        "env": {
            "SHARE": "financial_data;/share;yes;no;no;admin",
            "USER": "admin;P@ssw0rd!",
        },
        "mitre_lure": ["T1021.002"],        # Remote Services: SMB/Windows Admin Shares
        "ttl_hours": 4,
        "description": "Emulates an SMB file share named 'financial_data' to lure lateral movement via Windows admin shares.",
    },

    "web_server": {
        "image": "nginx:alpine",
        "service_name": "HTTPS Honeypot (Fake Admin Panel)",
        "ports": {"443/tcp": None, "80/tcp": None},
        "env": {},
        "mitre_lure": ["T1190"],            # Exploit Public-Facing Application
        "ttl_hours": 6,
        "description": "Emulates an NGINX web server with a fake admin login panel to attract web-based exploitation attempts.",
    },

    "database": {
        "image": "postgres:15-alpine",
        "service_name": "PostgreSQL Honeypot",
        "ports": {"5432/tcp": None},
        "env": {
            "POSTGRES_USER": "admin",
            "POSTGRES_PASSWORD": "P@ssw0rd!",
            "POSTGRES_DB": "financial_records",
        },
        "mitre_lure": ["T1190", "T1078"],   # Valid Accounts
        "ttl_hours": 4,
        "description": "Emulates a PostgreSQL database with weak credentials and a tempting 'financial_records' schema.",
    },

    "rdp_server": {
        "image": "danielguerra/alpine-xfce4-xrdp:latest",
        "service_name": "RDP Honeypot (Fake Workstation)",
        "ports": {"3389/tcp": None},
        "env": {},
        "mitre_lure": ["T1021.001"],        # Remote Desktop Protocol
        "ttl_hours": 3,
        "description": "Emulates an RDP endpoint to lure lateral movement via Remote Desktop Protocol.",
    },

    "ldap_server": {
        "image": "osixia/openldap:latest",
        "service_name": "LDAP/AD Controller Honeypot",
        "ports": {"389/tcp": None, "636/tcp": None},
        "env": {
            "LDAP_ORGANISATION": "NeoVigil Corp",
            "LDAP_DOMAIN": "neovigil.local",
            "LDAP_ADMIN_PASSWORD": "Admin123!",
        },
        "mitre_lure": ["T1087.002"],        # Account Discovery: Domain Account
        "ttl_hours": 4,
        "description": "Emulates an Active Directory / LDAP controller to attract domain enumeration and DCSync attacks.",
    },
}

# ─── Port → Template Mapping ──────────────────────────────
_PORT_TEMPLATE_MAP: Dict[int, str] = {
    22:   "ssh_server",
    445:  "smb_server",
    139:  "smb_server",
    80:   "web_server",
    443:  "web_server",
    5432: "database",
    3306: "database",     # MySQL falls back to PG honeypot
    3389: "rdp_server",
    389:  "ldap_server",
    636:  "ldap_server",
}

# ─── Hostname Keyword → Template Mapping ──────────────────
_HOSTNAME_HINTS: List[tuple] = [
    (["ad-", "dc-", "controller", "ldap", "domain"],   "ldap_server"),
    (["db", "sql", "postgres", "mysql", "finance"],     "database"),
    (["web", "http", "nginx", "apache", "iis", "api"],  "web_server"),
    (["smb", "file", "share", "nas"],                   "smb_server"),
    (["rdp", "desktop", "workstation", "jump"],         "rdp_server"),
    (["ssh", "bastion", "gateway", "linux"],            "ssh_server"),
]


# ════════════════════════════════════════════════════════════
#  Template Selection Logic
# ════════════════════════════════════════════════════════════

def select_template(
    kill_chain_step: dict,
    asset_profile: Optional[dict] = None,
) -> dict:
    """
    Choose the decoy template that best mimics the PREDICTED TARGET
    from Phase 1's kill chain.

    Selection priority:
      1. Software-based matching  (highest fidelity — mirrors CMDB)
      2. Port-based matching      (target_port from kill chain step)
      3. Hostname keyword hints   (heuristic fallback)
      4. Default SSH lure          (universal catch-all)

    Parameters
    ----------
    kill_chain_step : dict
        A single step from the predicted kill chain, e.g.:
        {"target_host": "FIN-DB-01", "target_ip": "10.0.3.50",
         "target_port": 5432, "technique_id": "T1190"}
    asset_profile : dict, optional
        CMDB entry for the target host from data/assets.json.

    Returns
    -------
    dict
        A copy of the matching DECOY_TEMPLATES entry with an added
        "match_reason" field.
    """
    asset = asset_profile or {}
    software = [s.lower() for s in asset.get("software", [])]
    target_host = (kill_chain_step.get("target_host") or "").lower()
    target_port = kill_chain_step.get("target_port")

    # ─── Priority 1: Software keyword matching ────────────
    _sw_rules = [
        (["active directory", "ldap", "kerberos", "ad ds"],     "ldap_server"),
        (["postgresql", "postgres", "mysql", "mariadb", "sql"], "database"),
        (["nginx", "apache", "iis", "httpd", "tomcat"],         "web_server"),
        (["samba", "smb", "cifs"],                               "smb_server"),
        (["openssh", "ssh"],                                     "ssh_server"),
        (["xrdp", "rdp", "remote desktop"],                      "rdp_server"),
    ]
    for keywords, template_key in _sw_rules:
        if any(kw in sw for sw in software for kw in keywords):
            logger.info(
                f" Template '{template_key}' selected via software match "
                f"(host={target_host})"
            )
            return _make_result(template_key, "software_match")

    # ─── Priority 2: Port-based matching ──────────────────
    if target_port and target_port in _PORT_TEMPLATE_MAP:
        template_key = _PORT_TEMPLATE_MAP[target_port]
        logger.info(
            f" Template '{template_key}' selected via port {target_port} "
            f"(host={target_host})"
        )
        return _make_result(template_key, f"port_{target_port}")

    # ─── Priority 3: Hostname heuristic ───────────────────
    for keywords, template_key in _HOSTNAME_HINTS:
        if any(kw in target_host for kw in keywords):
            logger.info(
                f" Template '{template_key}' selected via hostname hint "
                f"(host={target_host})"
            )
            return _make_result(template_key, "hostname_hint")

    # ─── Priority 4: Default SSH (universal lure) ─────────
    logger.info(
        f" Default template 'ssh_server' selected for "
        f"host={target_host} (no specific match)"
    )
    return _make_result("ssh_server", "default_fallback")


def _make_result(template_key: str, reason: str) -> dict:
    """Return a copy of the template with match metadata attached."""
    template = DECOY_TEMPLATES.get(template_key, DECOY_TEMPLATES["ssh_server"])
    result = {**template}          # shallow copy
    result["template_key"] = template_key
    result["match_reason"] = reason
    return result


def get_all_template_names() -> List[str]:
    """Return the list of available template keys."""
    return list(DECOY_TEMPLATES.keys())


def get_template_by_key(key: str) -> Optional[dict]:
    """Retrieve a specific template by its key."""
    if key in DECOY_TEMPLATES:
        return {**DECOY_TEMPLATES[key], "template_key": key}
    return None
