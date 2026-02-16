from typing import Dict, Set

ROLES = ["Viewer", "Tier1", "Tier2", "Admin", "System_Owner"]

PERMISSIONS: Dict[str, Set[str]] = {
    "Viewer": {
        "view_soc_dashboard",
        "view_enriched_alerts",
        "view_cti_review",
        "view_threat_graph",
        "view_knowledge_base",
        "view_audit_logs",
    },
    "Tier1": {
        "view_soc_dashboard",
        "view_enriched_alerts",
        "view_cti_review",
        "view_threat_graph",
        "view_knowledge_base",
        "view_audit_logs",
        "reject_report",
    },
    "Tier2": {
        "view_soc_dashboard",
        "view_enriched_alerts",
        "view_cti_review",
        "view_threat_graph",
        "view_knowledge_base",
        "view_audit_logs",
        "reject_report",
        "approve_report",
        "rollback_block",
    },
    "Admin": {
        "view_soc_dashboard",
        "view_enriched_alerts",
        "view_cti_review",
        "view_threat_graph",
        "view_knowledge_base",
        "view_audit_logs",
        "reject_report",
        "approve_report",
        "rollback_block",
        "manage_tenant_selector",
    },
    "System_Owner": {
        "*",
    },
}


def check_permission(role: str, action: str) -> bool:
    """Return True when a role is allowed to perform an action."""
    allowed = PERMISSIONS.get(role, set())
    return "*" in allowed or action in allowed
