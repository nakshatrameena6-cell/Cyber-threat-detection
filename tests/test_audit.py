import pytest
from backend.audit.logger import AuditLogger

def test_audit_logger():
    logger = AuditLogger()
    entry = logger.log(
        actor="admin1",
        role="ADMIN",
        action_category="EXECUTION",
        description="Block IP executed",
        target_resource="1.2.3.4"
    )
    assert entry.audit_id.startswith("AUD-")
    assert entry.actor == "admin1"

    logs = logger.list_logs(category="EXECUTION")
    assert len(logs) == 1
    assert logs[0].target_resource == "1.2.3.4"
