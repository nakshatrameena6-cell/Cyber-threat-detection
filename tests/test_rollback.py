import pytest
from backend.response.executor import ResponseExecutor
from backend.models.response import ResponseActionType, DecisionTier, ActionStatus

def test_action_rollback():
    executor = ResponseExecutor()
    rec = executor.execute_action(
        incident_id="INC-9999",
        action_type=ResponseActionType.SUSPEND_SESSION,
        target="malicious_user",
        tier=DecisionTier.TIER_C
    )
    assert "malicious_user" in executor.suspended_users

    success, msg, rolled_rec = executor.rollback_action(rec.action_id, actor="admin_test")
    assert success is True
    assert rolled_rec.status == ActionStatus.ROLLED_BACK
    assert "malicious_user" not in executor.suspended_users

def test_double_rollback_fails():
    executor = ResponseExecutor()
    rec = executor.execute_action(
        incident_id="INC-8888",
        action_type=ResponseActionType.ISOLATE_ENDPOINT,
        target="host-01",
        tier=DecisionTier.TIER_C
    )
    executor.rollback_action(rec.action_id)
    success, msg, _ = executor.rollback_action(rec.action_id)
    assert success is False
    assert "already" in msg.lower()
