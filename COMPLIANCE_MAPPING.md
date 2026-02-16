# 🛡️ Compliance Mapping (ISO 27001 / SOC 2)

This document maps NeoVigil SOC features to standard compliance controls.

## 🏆 ISO/IEC 27001:2013 Controls

| ISO Control | Description | NeoVigil Feature | Verification |
| :--- | :--- | :--- | :--- |
| **A.9.2.1** | User Registration & De-registration | **RBAC System** (`app_ui.py`)<br>Roles: Viewer, Analyst, Admin | Checked in Phase 1 |
| **A.9.4.1** | Information Access Restriction | **Role-Based Views**<br>Restricted "Rollback" & "Export" buttons | Verified via `test_rbac_audit.py` |
| **A.12.4.1** | Event Logging | **Immutable Audit Logs** (`audit_logger.py`)<br>Logs Actor, Action, Target, Hash | Logs stored in `soc-audit-logs` |
| **A.12.4.2** | Protection of Log Information | **Write-Only Index Pattern**<br>Logs are appended, never overwritten | OpenSearch Index Settings |
| **A.12.6.1** | Vulnerability Management | **CVE Enrichment**<br>Matches logs against NIST NVD | Verified in Pipeline |
| **A.16.1.2** | Reporting Information Security Events | **Automated Reporting**<br>PDF Generation with Evidence | `generate_pdf_report()` |

## 🛡️ SOC 2 (Security, Availability, Confidentiality)

| Trust Principle | Criteria | NeoVigil Feature |
| :--- | :--- | :--- |
| **Common Criteria** | **CC6.1 (Detection)** | **Hybrid Detection Engine**<br>AI + Threat Intel (VirusTotal/AbuseIPDB) |
| **Common Criteria** | **CC6.8 (Preventing Unauthorized Actions)** | **SOAR Guardrails**<br>Prevents auto-block on Critical Infrastructure |
| **Confidentiality** | **C1.1 (Data Protection)** | **PII Masking** (`utils.py`)<br>Redacts Emails/Phones before analysis |
| **Availability** | **A1.2 (Resilience)** | **High Availability**<br>Self-healing Docker Containers & RabbitMQ Retry |

## 🔍 Validation
All compliance features are tested via specific unit tests and verified manually during the UAT phase.
