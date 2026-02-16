# TENANCY + RBAC (最小版)

## 1) 多租戶資料流（tenant_id）

### 入口訊息（Message）
- `run_pipeline.py` 的 Master 發送 queue 任務時，現在會附上：
  - `tenant_id`（預設 `DEFAULT_TENANT_ID`）
  - `session_id`（mock，格式 `master-<timestamp>`）
- Worker 在 `process_task()` 內讀取 `task_payload.tenant_id` / `task_payload.session_id`，若不存在則回退預設值。

### OpenSearch 文件（Doc）
- 下列文件都會帶入 `tenant_id`：
  - `cti-reports`
  - `security-logs-knn`
  - `soc-audit-logs`
  - `ai-feedback`
  - `cti-indicators`（upsert 時寫入）
- Index mapping 已補上 `tenant_id`（關聯 index）。

### UI 查詢過濾（Query Filter）
- Streamlit 側邊欄新增 **Tenant Selector（mock）**：
  - `tenant-alpha`
  - `tenant-beta`
  - `tenant-gamma`
- 下列 UI 查詢已改為 tenant filter：
  - SOC Dashboard (`security-logs-knn`)
  - Enriched Alerts (`security-alerts`)
  - Knowledge Base / Threat Graph (`cti-reports`)
  - Related Reports (`cti-indicators`)
  - Audit Trail (`soc-audit-logs`)

---

## 2) RBAC 最小版

### 角色
- Viewer
- Tier1
- Tier2
- Admin
- System_Owner

### 權限檢查函式
- 新增 `check_permission(role, action)`（`src/rbac.py`）。
- 以 action string 控管（最小實作）。

### 敏感操作檢查點
- `rollback_block`
- `approve_report`
- `reject_report`
- 頁面級 `view_*` 權限（無權限會阻擋畫面）

---

## 3) Audit Log 欄位擴充

`AuditLogger.log_event()` 新增紀錄欄位：
- `role`
- `tenant_id`
- `session_id`
- `action`
- `result`（沿用 `status` 值）

UI 的 Audit Trail 顯示欄位也加入：`role/tenant_id/session_id/action/result`。

---

## 4) 權限矩陣（最小版）

| Action | Viewer | Tier1 | Tier2 | Admin | System_Owner |
|---|---:|---:|---:|---:|---:|
| view_soc_dashboard | ✅ | ✅ | ✅ | ✅ | ✅ |
| view_enriched_alerts | ✅ | ✅ | ✅ | ✅ | ✅ |
| view_cti_review | ✅ | ✅ | ✅ | ✅ | ✅ |
| view_threat_graph | ✅ | ✅ | ✅ | ✅ | ✅ |
| view_knowledge_base | ✅ | ✅ | ✅ | ✅ | ✅ |
| view_audit_logs | ✅ | ✅ | ✅ | ✅ | ✅ |
| reject_report | ❌ | ✅ | ✅ | ✅ | ✅ |
| approve_report | ❌ | ❌ | ✅ | ✅ | ✅ |
| rollback_block | ❌ | ❌ | ✅ | ✅ | ✅ |
| manage_tenant_selector | ❌ | ❌ | ❌ | ✅ | ✅ |

> `System_Owner` 為 super role（`*`）。
