from pydantic import BaseModel
from typing import Optional, Dict, Any

class AuditLogEntry(BaseModel):
    audit_id: str
    timestamp: str
    actor: str  # "SYSTEM", "AUTO_ENGINE", or username
    role: str   # "SYSTEM", "ADMIN", "ANALYST", "AUDITOR"
    action_category: str # "INGESTION", "DETECTION", "DECISION", "EXECUTION", "APPROVAL", "ROLLBACK", "KILL_SWITCH"
    description: str
    target_resource: str
    metadata: Dict[str, Any] = {}
