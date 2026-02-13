from __future__ import annotations
import requests
import json
import os
import logging
from pathlib import Path
from typing import Any


def read_text_file(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="ignore")


def ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def write_json(path: str, obj: Any) -> None:
    Path(path).write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def write_text(path: str, text: str) -> None:
    Path(path).write_text(text, encoding="utf-8")


def env(name: str, default: str | None = None) -> str:
    val = os.getenv(name, default)
    if val is None:
        raise RuntimeError(f"Missing required env var: {name}")
    return val

def send_webhook_notification(message):
    """發送告警訊息至 Slack/Discord/Email"""
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook_url:
        logging.warning("  SLACK_WEBHOOK_URL not set, skipping notification.")
        return

    payload = {"text": message}
    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        logging.info("  Alert notification sent successfully.")
    except Exception as e:
        logging.error(f"  Failed to send notification: {e}")

def notify(message):
    """
    統一告警入口：目前支援 Slack，未來可在此擴充 Email 或其他管道
    """
    logger = logging.getLogger("CTI_Pipeline")
    
    # 1. 輸出到 Log
    logger.warning(f"  [Notification] {message}")

    # 2. Slack 告警
    slack_url = os.getenv("SLACK_WEBHOOK_URL")
    if slack_url:
        try:
            payload = {"text": message}
            response = requests.post(slack_url, json=payload, timeout=5)
            response.raise_for_status()
        except Exception as e:
            logger.error(f"  Slack notification failed: {e}")

def chunk_text(text, max_chars=12000):
    """
    將長文本切成多個小塊 (Chunking)。
    預設 12000 字元約等於 3000-4000 Tokens，適合大多數 LLM。
    """
    if len(text) <= max_chars:
        return [text]
    
    chunks = []
    for i in range(0, len(text), max_chars):
        chunks.append(text[i:i + max_chars])
    return chunks

def merge_extractions(extraction_list):
    """
    將多個 AI 分析結果 (JSON) 合併成一份完整的報告。
    """
    merged = {
        "title": "Merged Report",
        "summary": "",
        "confidence_score": 0,
        "indicators": {
            "ipv4": [],
            "domains": [],
            "hashes": {}
        },
        "ttps": [],
        # 要在這裡初始化，不然 run_pipeline 讀不到
        "target_software": [],
        "cve_ids": []
    }
    
    # 用來去重複
    seen_ips = set()
    seen_domains = set()
    seen_ttps = set()
    
    # 軟體與漏洞的去重複集合
    seen_software = set()
    seen_cves = set()
    
    total_confidence = 0
    valid_chunks = 0

    for ext in extraction_list:
        if not ext: continue
        valid_chunks += 1
        
        # 合併摘要
        if ext.get("summary"):
            merged["summary"] += ext["summary"] + "\n\n"
        
        # 合併信心分數
        total_confidence += ext.get("confidence_score", 0)

        # 合併 IOCs
        for ip in ext.get("indicators", {}).get("ipv4", []):
            if ip not in seen_ips:
                merged["indicators"]["ipv4"].append(ip)
                seen_ips.add(ip)
                
        for domain in ext.get("indicators", {}).get("domains", []):
            if domain not in seen_domains:
                merged["indicators"]["domains"].append(domain)
                seen_domains.add(domain)

        # 合併 Hashes
        if "hashes" in ext.get("indicators", {}):
            merged["indicators"]["hashes"].update(ext["indicators"]["hashes"])

        # 合併 TTPs
        for ttp in ext.get("ttps", []):
            ttp_id = ttp.get("mitre_technique_id")
            if ttp_id and ttp_id not in seen_ttps:
                merged["ttps"].append(ttp)
                seen_ttps.add(ttp_id)

        # 合併 軟體名稱
        for soft in ext.get("target_software", []):
            if soft not in seen_software:
                merged["target_software"].append(soft)
                seen_software.add(soft)

        # 合併 CVE IDs
        for cve in ext.get("cve_ids", []):
            if cve not in seen_cves:
                merged["cve_ids"].append(cve)
                seen_cves.add(cve)
    
    # 計算平均信心分數
    if valid_chunks > 0:
        merged["confidence_score"] = int(total_confidence / valid_chunks)
        
    return merged