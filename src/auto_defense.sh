#!/bin/bash

# --- 維持原本的初始化設定 ---
echo "  System starting..."
python /app/src/setup_soar_integration.py
python /app/src/setup_dashboards.py

echo "  Entering fully automated defense monitoring mode..."

# 進入無限迴圈：自動化閉環
while true
do
    echo "--- $(date) Starting new scan cycle ---"
    
    # 抓取 RSS 並轉 STIX
    python /app/src/run_pipeline.py
    
    # 拿著最新的 STIX 規則去掃描 OpenSearch
    python /app/src/detect_rules.py
    
    echo "  Waiting 1 hour before next cycle..."
    sleep 3600
done