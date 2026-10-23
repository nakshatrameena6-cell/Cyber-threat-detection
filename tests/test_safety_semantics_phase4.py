import pytest
from backend.models.response import DecisionTier, ActionStatus, ResponseActionType, VerificationStatus
from backend.models.incidents import ThreatCategory
from backend.response.decision_engine import DecisionEngine
from backend.response.policy_engine import ResponsePolicyEngine
from backend.response.safety_gates import SafetyGatesEvaluator
from backend.response.executor import ResponseExecutor

def test_tier_c_never_auto_executed():
    """
    REQ-SAFE-001: Tier C high-impact actions (e.g. ISOLATE_ENDPOINT) mandate human approval.
    """
    tier, status, act, reason, auto = ResponsePolicyEngine.evaluate_policy(
        threat_category=ThreatCategory.UNUSUAL_DATA_TRANSFER,
        risk_score=95.0,
        confidence_score=0.95,
        recommended_action_str="ISOLATE_ENDPOINT"
    )
    assert tier == DecisionTier.TIER_C
    assert status == ActionStatus.PENDING_APPROVAL
    assert auto is False
    assert "human" in reason.lower() or "analyst" in reason.lower()

def test_anomaly_score_alone_never_authorizes_remediation():
    """
    REQ-SAFE-002: IsolationForest anomaly score alone must never authorize remediation actions.
    """
    tier, status, act, reason, auto = ResponsePolicyEngine.evaluate_policy(
        threat_category=ThreatCategory.NONE,
        risk_score=85.0,
        confidence_score=0.90,
        recommended_action_str="BLOCK_IP",
        is_anomaly_only=True
    )
    assert tier == DecisionTier.TIER_C
    assert status == ActionStatus.PENDING_APPROVAL
    assert act == ResponseActionType.ALERT_ONLY
    assert auto is False
    assert "anomaly score alone" in reason.lower()

def test_critical_asset_disruptive_actions_forbidden():
    """
    REQ-SAFE-003: Whitelisting a critical asset must not authorize destructive/disruptive actions against it.
    """
    store = {"blocked_ips": set(), "suspended_users": set(), "isolated_hosts": set()}
    
    # Disruptive action BLOCK_IP on core asset fails
    passed, gate, reason = SafetyGatesEvaluator.evaluate_gates(
        action_type=ResponseActionType.BLOCK_IP,
        target="127.0.0.1",
        actor_role="ADMIN",
        tier=DecisionTier.TIER_B,
        is_auto_execution=False,
        current_state_store=store
    )
    assert passed is False
    assert "Gate 4" in gate
    assert "critical" in reason.lower() or "core" in reason.lower()

    # Disruptive action ISOLATE_ENDPOINT on core host fails
    passed2, gate2, reason2 = SafetyGatesEvaluator.evaluate_gates(
        action_type=ResponseActionType.ISOLATE_ENDPOINT,
        target="auth-server-01",
        actor_role="ADMIN",
        tier=DecisionTier.TIER_C,
        is_auto_execution=False,
        current_state_store=store
    )
    assert passed2 is False
    assert "critical" in reason2.lower() or "core" in reason2.lower()

def test_gate_6_audit_persistence_failure_blocks_execution():
    """
    REQ-SAFE-004: Execution is blocked and fails closed when mandatory audit persistence check fails.
    """
    executor = ResponseExecutor()
    # Force audit check failure
    executor.audit_checker = lambda: False
    
    rec = executor.execute_action(
        incident_id="INC-AUDIT-FAIL",
        action_type=ResponseActionType.BLOCK_IP,
        target="198.51.100.99",
        tier=DecisionTier.TIER_B,
        actor="ADMIN"
    )
    assert rec.success is False
    assert rec.status == ActionStatus.DENIED
    assert "Gate 6" in rec.gate_message
    assert "198.51.100.99" not in executor.blocked_ips

def test_idempotent_repeated_execution():
    """
    REQ-SAFE-005: Repeated execution requests do not corrupt state or produce unsafe duplicate mutations.
    """
    executor = ResponseExecutor()
    rec1 = executor.execute_action(
        incident_id="INC-IDEM",
        action_type=ResponseActionType.BLOCK_IP,
        target="198.51.100.44",
        tier=DecisionTier.TIER_B,
        actor="ADMIN"
    )
    assert rec1.success is True
    assert "198.51.100.44" in executor.blocked_ips

    # Second execution on same target
    rec2 = executor.execute_action(
        incident_id="INC-IDEM",
        action_type=ResponseActionType.BLOCK_IP,
        target="198.51.100.44",
        tier=DecisionTier.TIER_B,
        actor="ADMIN"
    )
    assert rec2.success is True
    assert list(executor.blocked_ips).count("198.51.100.44") == 1
