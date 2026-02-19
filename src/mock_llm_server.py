import json
import re
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [MOCK-LLM] %(message)s")
logger = logging.getLogger("MockLLM")

HOST = "0.0.0.0"
PORT = 8000

# ─── Mock Data Templates ─────────────────────────────────────────────

def generate_red_team_response(prompt_text):
    """
    Generates a realistic Red Team analysis based on the context provided in the prompt.
    Tries to extract IP addresses from the prompt's 'NETWORK TOPOLOGY' section to make
    the kill chain realistic and passing the reachability check.
    """
    # 1. Extract potential target IPs from the prompt to ensure reachability
    # Regex to find IPs (simple version)
    ips = list(set(re.findall(r"\b(?:10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", prompt_text)))
    
    # Filter out likely source IPs or irrelevant ones if possible, but for mock, just pick a few distinct ones.
    # We need at least 2-3 unique IPs for a kill chain.
    # If not enough IPs found, fallback to some defaults that might exist in the lab environment.
    target_pool = ips if len(ips) >= 2 else ["10.20.30.200", "10.0.0.5", "10.0.0.20"]
    
    # Rotate targets
    t1 = target_pool[0]
    t2 = target_pool[1] if len(target_pool) > 1 else t1
    t3 = target_pool[2] if len(target_pool) > 2 else t1

    return {
        "attacker_profile": "APT-29 (Cozy Bear) Simulation",
        "initial_foothold": "Compromised Service Account via Credential Spraying",
        "predicted_kill_chain": [
            {
                "step": 1,
                "tactic": "Lateral Movement",
                "technique_id": "T1021.001",
                "technique_name": "Remote Services — RDP Exploitation",
                "target_host": "prod-webserver-01",
                "target_ip": t1,
                "target_port": "3389",
                "confidence": 0.95,
                "reasoning": f"Lateral movement from compromised host to {t1} using harvested admin credentials. RDP port open in firewall rules."
            },
            {
                "step": 2,
                "tactic": "Execution",
                "technique_id": "T1059.001",
                "technique_name": "PowerShell — Cobalt Strike Beacon",
                "target_host": "internal-db-01",
                "target_ip": t2,
                "target_port": "5985",
                "confidence": 0.88,
                "reasoning": f"Deploy Cobalt Strike beacon on {t2} via WinRM for persistent C2 access. PowerShell execution policy bypass likely."
            },
            {
                "step": 3,
                "tactic": "Credential Access",
                "technique_id": "T1003.001",
                "technique_name": "OS Credential Dumping — LSASS Memory",
                "target_host": "dc-primary-01",
                "target_ip": t3,
                "target_port": "445",
                "confidence": 0.82,
                "reasoning": f"Dump Domain Admin hashes from {t3} LSASS process for Golden Ticket creation. Ultimate objective for full domain compromise."
            }
        ],
        "recommended_defensive_actions": [
            f"CRITICAL: Isolate host {t1} immediately — block all RDP (3389) inbound.",
            "Reset 'srv_backup' and 'admin' service account credentials across the domain.",
            f"Deploy network segmentation between {t1} zone and {t3} zone.",
            "Enable Credential Guard on all domain controllers to prevent LSASS dumping.",
            "Hunt for psexec/Cobalt Strike artifacts across all endpoints."
        ]
    }

ZERO_LOG_RESPONSE = {
    "alert_title": "Preemptive Defense Plan: Zero-Log Vulnerability",
    "risk_assessment": "Global threat intelligence indicates a high probability of targeting unpatched IIS servers. Although no local logs have triggered, the asset is exposed.",
    "immediate_actions": [
        "Apply Kb5001234 security patch within 4 hours.",
        "Restrict access to port 80/443 to known trusted subnets.",
        "Enable 'Strict' mode in the WAF for SQL Injection patterns."
    ],
    "long_term_mitigation": "Migrate legacy IIS applications to containerized Nginx with sidecar security."
}

def generate_default_response(prompt_text):
    """
    Generates a context-aware standard analysis response.
    Extracts IPs from the prompt so the pipeline can route them correctly.
    Matches the schema expected by run_pipeline.py's get_extraction().
    """
    # Extract IPs from prompt so they flow through enrichment & prediction dispatch
    ips = list(set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", prompt_text)))
    # Separate external (attacker) from internal (target) IPs
    external_ips = [ip for ip in ips if not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."))]
    internal_ips = [ip for ip in ips if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")]

    # Determine attack type from keywords
    prompt_upper = prompt_text.upper()
    if "LOG4" in prompt_upper or "JNDI" in prompt_upper or "CVE-2021-44228" in prompt_upper:
        attack_type = "Log4Shell RCE Exploitation"
        ttps = [
            {"mitre_technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
            {"mitre_technique_id": "T1059.004", "technique_name": "Unix Shell", "tactic": "Execution"},
            {"mitre_technique_id": "T1071.001", "technique_name": "Web Protocols", "tactic": "Command and Control"}
        ]
        confidence = 95
        summary = "Log4Shell (CVE-2021-44228) exploitation detected via JNDI lookup injection."
    elif "SQL" in prompt_upper or "INJECTION" in prompt_upper:
        attack_type = "SQL Injection"
        ttps = [
            {"mitre_technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
            {"mitre_technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "Execution"}
        ]
        confidence = 90
        summary = "SQL injection attempt detected in web application traffic."
    elif "BRUTE" in prompt_upper or "FAILED LOGIN" in prompt_upper:
        attack_type = "Brute Force Authentication"
        ttps = [
            {"mitre_technique_id": "T1110", "technique_name": "Brute Force", "tactic": "Credential Access"},
            {"mitre_technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Persistence"}
        ]
        confidence = 85
        summary = "Multiple failed authentication attempts indicating brute force attack."
    else:
        attack_type = "Suspicious Network Activity"
        ttps = [
            {"mitre_technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Defense Evasion"},
            {"mitre_technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "Execution"}
        ]
        confidence = 82
        summary = "Automated analysis complete. Suspicious patterns detected."

    return {
        "attack_type": attack_type,
        "confidence": confidence,
        "confidence_score": confidence,
        "summary": summary,
        "mitre_tactic": "Initial Access",
        "ttps": ttps,
        "mitre_ttps": ttps,
        "indicators": {
            "ipv4": external_ips if external_ips else ips[:2],
            "domains": [],
            "hashes": {}
        },
        "source_ip": external_ips[0] if external_ips else (ips[0] if ips else "unknown"),
        "target_ip": internal_ips[0] if internal_ips else None,
        "cve_ids": re.findall(r"CVE-\d{4}-\d{4,7}", prompt_text),
        "risk_level": "High" if confidence >= 80 else "Medium",
        "recommended_actions": [
            "Isolate affected host immediately",
            "Block source IP at perimeter firewall",
            "Conduct forensic analysis of affected systems"
        ]
    }

# ─── HTTP Server ─────────────────────────────────────────────────────

def _json(handler, status, obj):
    body = json.dumps(obj).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/health"):
            return _json(self, 200, {"status": "ok"})
        if self.path.startswith("/v1/models"):
             return _json(self, 200, {"data": [{"id": "gpt-4", "object": "model"}]})
        return _json(self, 404, {"error": "not found"})

    def do_POST(self):
        # 1. Read request body
        length = int(self.headers.get("Content-Length", "0") or "0")
        body_str = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        
        try:
            body = json.loads(body_str)
        except json.JSONDecodeError:
            return _json(self, 400, {"error": "Invalid JSON"})

        # 2. Parse Messages to determine intent
        messages = body.get("messages", [])
        full_context = " ".join([m.get("content", "") for m in messages])
        
        # 3. Router Logic (Context-Aware)
        if "REDSPEC" in full_context or "Red Team" in full_context:
            logger.info("⚡ Handling RED TEAM prediction request")
            response_data = generate_red_team_response(full_context)

        elif any(kw in full_context for kw in ["T1003", "ssh", "honeypot", "decoy", "credential dump", "lateral", "brute force"]):
            logger.info("⚡ Handling RED TEAM prediction (APT indicator detected)")
            response_data = generate_red_team_response(full_context)
            
        elif "Zero-Log" in full_context or "PREEMPTIVE" in full_context:
            logger.info("🛡️ Handling ZERO-LOG preemptive request")
            response_data = ZERO_LOG_RESPONSE
            
        else:
            logger.info("📝 Handling STANDARD log analysis request")
            response_data = generate_default_response(full_context)

        # 4. Wrap in OpenAI ChatCompletion format
        # Note: The 'content' of the message must be a JSON string as expected by the consumers.
        openai_resp = {
            "id": "mock-chatcmpl-" + body.get("model", "default"),
            "object": "chat.completion",
            "created": 1677858242,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": json.dumps(response_data) # Double-encoding as consumer parses inner JSON
                },
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}
        }

        return _json(self, 200, openai_resp)

    def log_message(self, format, *args):
        # Use our logger instead of stderr
        return

if __name__ == "__main__":
    logger.info(f"🚀 Context-Aware Mock LLM Server running on port {PORT}")
    HTTPServer((HOST, PORT), Handler).serve_forever()
