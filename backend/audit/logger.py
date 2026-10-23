import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from backend.models.audit import AuditLogEntry
from backend.database import DatabaseManager

class AuditLogger:
    def __init__(self, db: Optional[DatabaseManager] = None):
        self.db = db or DatabaseManager()
        self._logs: List[AuditLogEntry] = []
        self.load_from_db()

    def load_from_db(self):
        """
        Recovers audit logs from persistent SQLite store on startup.
        """
        try:
            db_logs = self.db.list_audit_logs(limit=500)
            self._logs = [
                AuditLogEntry(
                    audit_id=row["audit_id"],
                    timestamp=row["timestamp"],
                    actor=row["actor"],
                    role=row["role"],
                    action_category=row["action_category"],
                    description=row["description"],
                    target_resource=row["target_resource"],
                    metadata=row.get("metadata", {})
                )
                for row in db_logs
            ]
        except Exception:
            pass

    def log(
        self,
        actor: str,
        role: str,
        action_category: str,
        description: str,
        target_resource: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> AuditLogEntry:
        """
        Appends an immutable audit log entry and guarantees persistence in SQLite.
        """
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
        self._logs.insert(0, entry)

        # Persist to SQLite
        try:
            self.db.save_audit_log(entry.model_dump())
        except Exception as e:
            # Re-raise to ensure calling safety gates fail closed
            raise RuntimeError(f"Audit log persistence failure: {str(e)}")

        return entry

    def list_logs(
        self,
        category: Optional[str] = None,
        actor: Optional[str] = None,
        limit: int = 100
    ) -> List[AuditLogEntry]:
        try:
            db_logs = self.db.list_audit_logs(category=category, actor=actor, limit=limit)
            if db_logs:
                return [
                    AuditLogEntry(
                        audit_id=r["audit_id"],
                        timestamp=r["timestamp"],
                        actor=r["actor"],
                        role=r["role"],
                        action_category=r["action_category"],
                        description=r["description"],
                        target_resource=r["target_resource"],
                        metadata=r.get("metadata", {})
                    )
                    for r in db_logs
                ]
        except Exception:
            pass

        results = self._logs
        if category:
            results = [e for e in results if e.action_category.upper() == category.upper()]
        if actor:
            results = [e for e in results if e.actor.lower() == actor.lower()]
        return sorted(results, key=lambda x: x.timestamp, reverse=True)[:limit]
