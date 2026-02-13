#!/bin/bash

echo "  Starting system initialization process..."

# 等待 OpenSearch 啟動 (由 python 腳本內部的 wait 控制)
echo "  [1/3] Configuring SOAR integration..."
python /app/src/setup_soar_integration.py

# 設定 Dashboards
echo "  [2/3] Setting up Dashboards index patterns..."
python /app/src/setup_dashboards.py

# 未來可以加更多...
# echo "  [3/3] Setting up RCF anomaly detection..."
# python /app/src/setup_rcf.py

echo "  All initialization steps completed successfully!"