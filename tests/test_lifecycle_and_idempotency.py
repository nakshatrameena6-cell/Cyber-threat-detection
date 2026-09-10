import pytest
from backend.incidents.manager import IncidentManager
from backend.models.incidents import IncidentStatus, Severity, ThreatCategory
from backend.response.executor import ResponseExecutor
from backend.models.response import ResponseActionType, DecisionTier

def test_incident_lifecycle_valid_transitions():
    mgr = IncidentManager()
    inc = mgr.create_incident(
        event_id="EVT-L1", threat_category=ThreatCategory.SUSPICIOUS_LOGIN, severity=Severity.MEDIUM,
        risk_score=50.0, confidence_score=0.80, source_ip="10.0.0.1", user_id="u1", asset_id="a1",
        details="Suspicious login", recommended_action="SUSPEND_SESSION", decision_tier="TIER_B"
    )
    assert inc.status == IncidentStatus.NEW

    # NEW -> UNDER_INVESTIGATION
    inc2 = mgr.update_status(inc.incident_id, IncidentStatus.UNDER_INVESTIGATION, assigned_to="analyst1")
    assert inc2.status == IncidentStatus.UNDER_INVESTIGATION

    # UNDER_INVESTIGATION -> MITIGATED
    inc3 = mgr.update_status(inc.incident_id, IncidentStatus.MITIGATED, assigned_to="analyst1")
    assert inc3.status == IncidentStatus.MITIGATED

    # MITIGATED -> RESOLVED
    inc4 = mgr.update_status(inc.incident_id, IncidentStatus.RESOLVED, assigned_to="analyst1")
    assert inc4.status == IncidentStatus.RESOLVED

def test_incident_lifecycle_invalid_transition_fails():
    mgr = IncidentManager()
    inc = mgr.create_incident(
        event_id="EVT-L2", threat_category=ThreatCategory.BRUTE_FORCE, severity=Severity.HIGH,
        risk_score=80.0, confidence_score=0.85, source_ip="10.0.0.2", user_id="u2", asset_id="a2",
        details="Brute force", recommended_action="BLOCK_IP", decision_tier="TIER_C"
    )
    mgr.update_status(inc.incident_id, IncidentStatus.FALSE_POSITIVE, assigned_to="analyst1")

    # Trying to change terminal FALSE_POSITIVE -> MITIGATED must raise ValueError
    with pytest.raises(ValueError) as exc_info:
        mgr.update_status(inc.incident_id, IncidentStatus.MITIGATED)
    assert "Invalid state transition" in str(exc_info.value)

def test_idempotent_execution_and_rollback():
    executor = ResponseExecutor()
    rec1 = executor.execute_action(
        incident_id="INC-IDEM-01",
        action_type=ResponseActionType.BLOCK_IP,
        target="198.51.100.77",
        tier=DecisionTier.TIER_C,
        actor="ADMIN",
        actor_role="ADMIN"
    )
    assert rec1.success is True
    assert "198.51.100.77" in executor.blocked_ips

    # Repeated execution on same target
    rec2 = executor.execute_action(
        incident_id="INC-IDEM-01",
        action_type=ResponseActionType.BLOCK_IP,
        target="198.51.100.77",
        tier=DecisionTier.TIER_C,
        actor="ADMIN",
        actor_role="ADMIN"
    )
    assert rec2.success is True
    assert len(executor.blocked_ips) == 1 # No duplicate mutation

    # Rollback
    ok1, rmsg1, rrec1 = executor.rollback_action(rec1.action_id, actor="ADMIN", actor_role="ADMIN")
    assert ok1 is True
    assert "198.51.100.77" not in executor.blocked_ips

    # Double rollback failure
    ok2, rmsg2, _ = executor.rollback_action(rec1.action_id, actor="ADMIN", actor_role="ADMIN")
    assert ok2 is False
    assert "already" in rmsg2.lower()
