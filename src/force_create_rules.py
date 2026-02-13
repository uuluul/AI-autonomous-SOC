import json
import os
import uuid
from datetime import datetime

def main():
    print("  [Standalone Mode] Forcing creation of STIX detection rule...")
    
    # 直接定義要的 Sigma 規則內容 (YAML 格式)
    sigma_rule_yaml = """
title: Log4j JNDI Injection
id: force-generated-rule-001
status: experimental
description: Detects JNDI injection attempts in logs
author: CTI Pipeline
date: 2026/02/12
logsource:
    category: web_server
detection:
    keywords:
        - 'jndi:ldap'
        - 'jndi:rmi'
        - 'jndi:dns'
    condition: keywords
level: high
"""

    # 手動組裝 STIX Bundle JSON 結構
    # 這是 detect_rules.py 讀取的標準格式
    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--{str(uuid.uuid4())}",
        "objects": [
            {
                "type": "indicator",
                "id": f"indicator--{str(uuid.uuid4())}",
                "created": datetime.now().isoformat() + "Z",
                "modified": datetime.now().isoformat() + "Z",
                "name": "Log4j JNDI Exploit",
                "description": "Auto-generated rule for JNDI detection",
                "pattern_type": "sigma",
                "pattern": sigma_rule_yaml,
                "valid_from": datetime.now().isoformat() + "Z"
            }
        ]
    }

    # 確保輸出目錄存在
    os.makedirs("out", exist_ok=True)
    
    # 寫入檔案
    output_path = "out/bundle_stix21.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(stix_bundle, f, indent=4, ensure_ascii=False)
        
    print(f"  Rule file successfully created: {output_path}")
    print("  Please run: docker-compose run cti-pipeline-master python /app/src/detect_rules.py")

if __name__ == "__main__":
    main()
