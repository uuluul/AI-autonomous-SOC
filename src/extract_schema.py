from __future__ import annotations

EXTRACTION_SCHEMA_DESCRIPTION = """
Return a JSON object with these keys:

- summary: string, short summary of the CTI report
- indicators: object with arrays:
    - ipv4: string[]
    - ipv6: string[]
    - domains: string[]
    - urls: string[]
    - hashes: object with arrays:
        - md5: string[]
        - sha1: string[]
        - sha256: string[]
- ttps: array of objects:
    - name: string (e.g., "PowerShell")
    - mitre_technique_id: string | null (e.g., "T1059.001") if confidently mapped
    - description: string
- actor: string | null
- malware_or_tool: string[]  (names if present)

- target_software: string[] (List of specific software names and versions mentioned, e.g., "nginx 1.14.0", "Apache Log4j 2.15.0". Important for NVD lookup.)
- cve_ids: string[] (List of CVE IDs explicitly mentioned in the text, e.g., "CVE-2021-44228")

- confidence: integer 0-100 (your confidence in extraction)
- log_suggestions: array of objects:
    - log_type: string (e.g., "windows_security", "dns", "proxy", "edr_process")
    - fields: string[] (suggested fields, e.g., "process.command_line")
    - rationale: string (why this log_type/fields relates to the TTP/indicator)

Rules:
- Only output valid JSON (no markdown).
- If unknown, use null or empty arrays.
"""

DEFAULT_SYSTEM_PROMPT = """You are a cybersecurity threat intelligence extraction engine.
You must strictly output VALID JSON only. Do not include markdown, comments, or trailing commas.
If you detect specific software versions (e.g., 'nginx 1.14.0') or CVE IDs, extract them into 'target_software' and 'cve_ids' respectively.
"""