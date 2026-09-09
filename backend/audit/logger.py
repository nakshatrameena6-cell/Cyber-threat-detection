import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from backend.models.audit import AuditLogEntry

class AuditLogger:
    def __init__(self):
        self._logs: List[AuditLogEntry] = []

    def log(
        self,
        actor: str,
        role: str,
        action_category: str,
        description: str,
        target_resource: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> AuditLogEntry:
        audit_id = f"AUD-{uuid.uuid4().hex[:8].upper()}"
        entry = AuditLogEntry(
            audit_id=audit_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            actor=actor,
            role=role,
            action_category=action_category,
            description=description,
            target_resource=target_resource,
            metadata=metadata or {}
        )
        self._logs.append(entry)
        return entry

    def list_logs(
        self,
        category: Optional[str] = None,
        actor: Optional[str] = None,
        limit: int = 100
    ) -> List[AuditLogEntry]:
        results = self._logs
        if category:
            results = [e for e in results if e.action_category.upper() == category.upper()]
        if actor:
            results = [e for e in results if e.actor.lower() == actor.lower()]
        return sorted(results, key=lambda x: x.timestamp, reverse=True)[:limit]
