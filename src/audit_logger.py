
import logging
import uuid
from datetime import datetime
from src.setup_opensearch import upload_to_opensearch

logger = logging.getLogger(__name__)

class AuditLogger:
    """
    Enterprise Audit Logger
    Ensures that every critical action (AI or Human) is logged immutably to 'soc-audit-logs'.
    ISO 27001 / SOC 2 Compliance Requirement.
    """
    def __init__(self):
        self.index_name = "soc-audit-logs"

    def log_event(self, actor: str, action: str, target: str, status: str, justification: str = "", details: dict = None):
        """
        Logs an immutable audit event to OpenSearch.
        
        Args:
            actor (str): Who performed the action (e.g., "AI-Agent", "analyst_admin")
            action (str): What happened (e.g., "BLOCK_IP", "APPROVE_REPORT", "ROLLBACK", "IGNORE_RISK")
            target (str): The object of the action (e.g., IP address, Filename)
            status (str): "SUCCESS", "FAILURE", "PENDING"
            justification (str): Reason for the action (critical for compliance)
            details (dict): Additional context (optional)
        """
        doc = {
            "timestamp": datetime.now().isoformat(),
            "actor": actor,
            "action": action,
            "target": target,
            "status": status,
            "justification": justification,
            "details": details or {},
            "event_id": str(uuid.uuid4()) # Unique ID for traceability
        }
        
        try:
            # We allow OpenSearch to auto-generate the document ID by passing None
            success = upload_to_opensearch(doc, doc_id=doc["event_id"], index_name=self.index_name)
            if success:
                logger.info(f"🔒 [AUDIT] {actor} performed {action} on {target} | Status: {status}")
            else:
                logger.error(f"❌ [AUDIT WRITE ERROR] Failed to write audit log for {action}")
        except Exception as e:
            logger.critical(f"❌ [AUDIT CRITICAL FAILURE] System could not write compliance log! Error: {e}")
