import uuid
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

def generate_uuid(type_name: str) -> str:
    """產生符合 STIX 規範的 UUID v4"""
    return f"{type_name}--{str(uuid.uuid4())}"

def get_timestamp() -> str:
    """產生符合 STIX 2.1 嚴格規範的 ISO 時間格式 """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def build_stix_bundle(extracted: Dict[str, Any]) -> Dict[str, Any]:
    timestamp = get_timestamp()
    
    # 信心分數限制在 0-100
    try:
        confidence = int(extracted.get("confidence", 50))
        confidence = max(0, min(100, confidence))
    except (ValueError, TypeError):
        confidence = 50

    # Identity
    identity_id = generate_uuid("identity")
    identity_obj = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": timestamp,
        "modified": timestamp,
        "name": "LLM CTI-to-STIX PoC",
        "identity_class": "organization"
    }

    # TLP:AMBER
    marking_id = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
    marking_obj = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": marking_id,
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:AMBER",
        "definition": { "tlp": "amber" }
    }

    objects: List[Dict[str, Any]] = [identity_obj, marking_obj]
    indicator_ids: List[str] = []

    # Indicators
    indicators_data = extracted.get("indicators", {})
    if not isinstance(indicators_data, dict): indicators_data = {}

    def _create_indicator(name: str, pattern: str, label: str):
        ind_id = generate_uuid("indicator")
        obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created_by_ref": identity_id,
            "created": timestamp,
            "modified": timestamp,
            "name": name,
            "pattern": pattern,
            "pattern_type": "pattern_type",
            "pattern_version": "2.1",
            "valid_from": timestamp,
            "labels": [label, "llm-generated"],
            "confidence": confidence,
            "object_marking_refs": [marking_id]
        }
        objects.append(obj)
        indicator_ids.append(ind_id)

    # IPv4/v6
    ips = (indicators_data.get("ipv4", []) or []) + (indicators_data.get("ipv6", []) or [])
    for ip in ips:
        if isinstance(ip, str):
            p = f"[ipv6-addr:value = '{ip}']" if ":" in ip else f"[ipv4-addr:value = '{ip}']"
            _create_indicator(f"IP: {ip}", p, "malicious-activity")

    # Domains
    for d in (indicators_data.get("domains", []) or []):
        if isinstance(d, str):
            _create_indicator(f"Domain: {d}", f"[domain-name:value = '{d}']", "anomalous-activity")

    # Sigma Rules
    # 假設 extracted 裡面會有一個 "sigma_rules" 的 List
    sigma_rules = extracted.get("sigma_rules", [])
    if isinstance(sigma_rules, list):
        for idx, rule in enumerate(sigma_rules):
            # rule 要是完整的 YAML 字串
            if isinstance(rule, str):
                # 標題設為 Sigma Detection Rule
                _create_indicator(
                    name=f"Sigma Rule #{idx+1} (Auto-Generated)",
                    pattern=rule,          # 直接把 YAML 塞進去
                    label="sigma-detection",
                    pattern_type="sigma"   # 告訴系統是 Sigma 格式
                )

    # 處理攻擊手法
    ttps = extracted.get("ttps", [])
    ttp_ids: List[str] = []
    if isinstance(ttps, list):
        for t in ttps:
            t_name = t.get("name") if isinstance(t, dict) else str(t)
            t_id = generate_uuid("attack-pattern")
            ap_obj = {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": t_id,
                "created_by_ref": identity_id,
                "created": timestamp,
                "modified": timestamp,
                "name": t_name,
                "labels": ["ttp"],
                "object_marking_refs": [marking_id]
            }
            objects.append(ap_obj)
            ttp_ids.append(t_id)

    # 建立關聯
    for i_id in indicator_ids:
        for t_id in ttp_ids[:3]:
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": generate_uuid("relationship"),
                "created_by_ref": identity_id,
                "created": timestamp,
                "modified": timestamp,
                "relationship_type": "indicates",
                "source_ref": i_id,
                "target_ref": t_id,
                "object_marking_refs": [marking_id]
            })

    return {
        "type": "bundle",
        "id": generate_uuid("bundle"),
        "objects": objects
    }