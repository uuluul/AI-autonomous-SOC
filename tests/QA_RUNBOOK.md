
# 🧪 Manual QA Runbook: NeoVigil SOC Dashboard
**Version:** 1.0.0 (Pre-Release Candidate)
**Tester:** Lead QA / SDET

## 1. Navigation & State Persistence (Critical)
**Objective:** Verify session state remains intact across page loads and refreshes.

| Step | Action | Expected Result | Pass/Fail |
|------|--------|-----------------|-----------|
| 1.1 | Login as `admin` / `admin`. | Dashboard loads. Sidebar visible. | [ ] |
| 1.2 | Select **"Active Tenant"** -> `tenant_alpha`. | Dashboard filters data. Tenant selection persists. | [ ] |
| 1.3 | Navigate to **"🕸️ Threat Graph"**. | Threat Graph page loads. | [ ] |
| 1.4 | Click **Browser Refresh (F5)** or Reload. | **CRITICAL:** Page MUST remain "🕸️ Threat Graph". Tenant MUST remain `tenant_alpha`. | [ ] |
| 1.5 | Navigate to **"🛡️ Moving Target Defense"**. | MTD Page loads. | [ ] |
| 1.6 | Click **Reload**. | Page remains MTD. | [ ] |

## 2. Data Binding: Intelligent Remediation Engine
**Objective:** Verify AI-generated playbooks are correctly displayed.

| Step | Action | Expected Result | Pass/Fail |
|------|--------|-----------------|-----------|
| 2.1 | Run `python src/simulate_apt_killchain.py`. | Terminal shows "Simulation Complete". | [ ] |
| 2.2 | Go to **"🚨 Internal Threat Monitor (SOC)"**. | "Intelligent Remediation Engine" section is visible. | [ ] |
| 2.3 | Expand the top **"📘 Playbook"**. | Title includes "Risk: High" (or similar). | [ ] |
| 2.4 | Verify content matches simulation. | "Remediation Steps" should align with the attack (e.g., "Block IP", "Isolate Host"). | [ ] |

## 3. Telemetry Status Indicators
**Objective:** Verify real-time status updates based on data ingestion.

| Step | Action | Expected Result | Pass/Fail |
|------|--------|-----------------|-----------|
| 3.1 | Check **"📡 Active Telemetry Sources"** panel. | Endpoint/Network/Identity icons show 🟢 (Active). | [ ] |
| 3.2 | Stop `ingest_logs.py` (if running) or check if data is stale (> 24h). | Icons might turn 🔴 or ⚠️ (if logic implemented). *Note: Current mock ensures 🟢.* | [ ] |
| 3.3 | Verify "Last Heartbeat" timestamps. | Timestamps should be recent (UTC). | [ ] |

## 4. Edge Cases: Empty Tenant
**Objective:** Verify graceful degradation when no data exists.

| Step | Action | Expected Result | Pass/Fail |
|------|--------|-----------------|-----------|
| 4.1 | Select **"Active Tenant"** -> `tenant_beta` (assuming empty). | Dashboard widgets update. | [ ] |
| 4.2 | Check **"Recent Alerts"** table. | Should show "No alerts found" or empty table. NO CRASH. | [ ] |
| 4.3 | Check **"Threat Graph"**. | Should show empty graph or "No nodes". NO CRASH. | [ ] |
| 4.4 | Check **"Predictive Map"**. | Should show "No predictions generated yet". NO CRASH. | [ ] |

## 5. Role-Based Access Control (RBAC)
**Objective:** Verify permission restrictions.

| Step | Action | Expected Result | Pass/Fail |
|------|--------|-----------------|-----------|
| 5.1 | Logout. Login as `demo` (Role: **Viewer**). | Login successful. | [ ] |
| 5.2 | Check Sidebar options. | **"🔍 CTI Report Review"** and **"📜 Audit Trail"** should be **HIDDEN**. | [ ] |
| 5.3 | Logout. Login as `admin` (Role: **Admin**). | All pages visible. | [ ] |

---
**Sign-off:**
- [ ] Validated by: ________________________
- [ ] Date: ________________________
