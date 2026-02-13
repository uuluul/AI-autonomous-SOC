#這邊是參考open source 修改的 https://github.com/oasis-open/cti-stix-validator
from __future__ import annotations
import logging
from collections import Counter
from typing import Any, Dict, List, Tuple
from stix2validator import ValidationOptions, validate_string

logger = logging.getLogger(__name__)

def _issue_to_dict(issue: Any) -> Dict[str, Any]:
    return {
        "severity": getattr(issue, "severity", "unknown"),
        "code": getattr(issue, "code", "N/A"),
        "message": getattr(issue, "message", "No message"),
        "path": getattr(issue, "path", "N/A"),
    }

def validate_stix_json(stix_json_string: str) -> Tuple[bool, Dict[str, Any]]:
    """
    驗證：
    - is_valid = True: 即使有 Warnings，只要沒有致命 Errors 就判定為 True。
    - payload: 包含詳細的統計供內部除錯。
    """
    # 關閉 strict 模式，允許不影響解析的小格式瑕疵
    options = ValidationOptions(strict=False, version="2.1")
    results = validate_string(stix_json_string, options)

    # 提取所有問題
    all_issues = [_issue_to_dict(i) for i in getattr(results, "results", [])]
    
    # 分類
    errors = [i for i in all_issues if i["severity"] == "error"]
    warnings = [i for i in all_issues if i["severity"] == "warning"]

    # 沒有 Error 就是 Valid
    is_valid_for_business = (len(errors) == 0)

    if warnings:
        logger.info(f"  STIX Format Suggestion: Found {len(warnings)} minor warnings (Non-blocking).")

    payload = {
        "is_valid": is_valid_for_business,
        "has_warnings": len(warnings) > 0,
        "counts": {
            "errors": len(errors),
            "warnings": len(warnings)
        },
        "errors": errors,
        "warnings": warnings,
        "top_issue_types": Counter([i["message"] for i in all_issues]).most_common(5)
    }

    return is_valid_for_business, payload

