"""Audit Logging System (REQ-AUD-001, REQ-AUD-002)."""
import hashlib
import json
import uuid
from datetime import datetime
from typing import Dict, Any, List
from models.schemas.audit import AuditEvent


class AuditPersistenceException(Exception):
    """Raised when audit log persistence fails or precondition is violated."""
    pass


class AuditLogger:
    """Immutable Audit Logger enforcing hard persistence precondition."""

    def __init__(self, log_file_path: str = "data/audit_logs.jsonl"):
        self.log_file_path = log_file_path
        self._in_memory_logs: List[AuditEvent] = []

    def _compute_checksum(self, actor: str, action: str, target: str, timestamp_str: str) -> str:
        payload = f"{actor}|{action}|{target}|{timestamp_str}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def log_event(self, actor: str, action: str, target_resource: str, details: Dict[str, Any] = None) -> AuditEvent:
        """Create and persist audit log event synchronously."""
        if details is None:
            details = {}

        now = datetime.utcnow()
        timestamp_str = now.isoformat()
        checksum = self._compute_checksum(actor, action, target_resource, timestamp_str)

        event = AuditEvent(
            audit_id=f"aud-{uuid.uuid4().hex[:8]}",
            actor=actor,
            action=action,
            target_resource=target_resource,
            details=details,
            timestamp=now,
            persisted=False,
            checksum=checksum,
        )

        try:
            # Synchronous disk persistence check
            with open(self.log_file_path, "a", encoding="utf-8") as f:
                f.write(event.json() + "\n")
            event.persisted = True
            self._in_memory_logs.append(event)
            return event
        except Exception as e:
            event.persisted = False
            raise AuditPersistenceException(f"Failed to persist mandatory audit log: {str(e)}") from e

    def verify_precondition(self, audit_event: AuditEvent) -> bool:
        """Verify that audit log was successfully persisted prior to action execution."""
        if not audit_event or not audit_event.persisted:
            raise AuditPersistenceException(f"Precondition failed: Audit event {getattr(audit_event, 'audit_id', 'UNKNOWN')} was not persisted.")
        return True

    def get_logs(self) -> List[AuditEvent]:
        return self._in_memory_logs
