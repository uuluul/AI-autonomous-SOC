# 📘 NeoVigil SOC - Operational Runbook & Disaster Recovery

## 1. System Overview
NeoVigil is an AI-powered Autonomous SOC platform deployed via Docker Compose.
- **Core Components**: RabbitMQ (Broker), OpenSearch (SIEM), Python Workers (Analysis).
- **Data Path**: `FluentBit` -> `RabbitMQ` -> `run_pipeline.py` -> `OpenSearch` -> `app_ui.py`.

## 2. Emergency Procedures

### 🛑 Service Outage (Critical)
If the dashboard is down or workers are stuck:
1. **Check Status**:
   ```bash
   docker-compose -f docker-compose.prod.yml ps
   ```
2. **Restart Services** (Zero-Downtime attempt):
   ```bash
   docker-compose -f docker-compose.prod.yml restart app worker
   ```
3. **Full Reset** (If rabbitmq is stuck):
   ```bash
   docker-compose -f docker-compose.prod.yml down
   docker-compose -f docker-compose.prod.yml up -d
   ```

### 🔓 Lockdown Mode (Under Attack)
If the SOC itself is compromised:
1. **Isolate Network**: Block external ports 8501 (UI) and 5601 (Kibana) at firewall level.
2. **Enable Panic Mode**: 
   Set `LOCKDOWN_MODE=True` in `.env` and restart.
   This will force all new tasks to "Manual Review" queue.

## 3. Backup & Restore (Disaster Recovery)

### 💾 Backup Strategy
- **OpenSearch Indices**: Snapshots occur daily to `/mnt/backups/opensearch`.
- **Configuration**: `.env` and `src/` are version controlled (Git).

### ♻️ Restore Procedure
To restore OpenSearch data from a snapshot:
```bash
# 1. Close indices
curl -XPOST "localhost:9200/*/_close"

# 2. Restore snapshot
curl -XPOST "localhost:9200/_snapshot/my_backup_repo/snapshot_2023_10_27/_restore"

# 3. Open indices
curl -XPOST "localhost:9200/*/_open"
```

## 4. Multi-Tenancy Operations
- **Onboarding New Tenant**:
  - No infra change needed.
  - Simply start sending logs with `tenant_id` field in payload.
  - Admin can verify visibility via "Active Tenant" selector in UI.

## 5. Maintenance
- **Log Rotation**: Docker logging driver is configured to rotate logs (max-size 10m).
- **Updates**:
  ```bash
  git pull
  docker-compose -f docker-compose.prod.yml build
  docker-compose -f docker-compose.prod.yml up -d
  ```
