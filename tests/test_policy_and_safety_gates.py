import pytest
from backend.response.policy_engine import ResponsePolicyEngine
from backend.response.safety_gates import SafetyGatesEvaluator
from backend.response.kill_switch import EmergencyKillSwitch
from backend.models.response import ResponseActionType, DecisionTier, ActionStatus
from backend.models.incidents import ThreatCategory

def test_response_policy_engine():
    tier, status, act, reason, auto = ResponsePolicyEngine.evaluate_policy(
        ThreatCategory.BRUTE_FORCE, risk_score=85.0, confidence_score=0.90, recommended_action_str="BLOCK_IP"
    )
    assert tier == DecisionTier.TIER_C
    assert status == ActionStatus.APPROVED
    assert auto is True

    # Endpoint isolation high impact policy check
    tier, status, act, reason, auto = ResponsePolicyEngine.evaluate_policy(
        ThreatCategory.UNUSUAL_DATA_TRANSFER, risk_score=90.0, confidence_score=0.92, recommended_action_str="ISOLATE_ENDPOINT"
    )
    assert tier == DecisionTier.TIER_C
    assert status == ActionStatus.PENDING_APPROVAL
    assert auto is False

def test_safety_gate_authorization_failure():
    store = {"blocked_ips": set(), "suspended_users": set(), "isolated_hosts": set()}
    passed, gate_name, reason = SafetyGatesEvaluator.evaluate_gates(
        action_type=ResponseActionType.BLOCK_IP,
        target="198.51.100.10",
        actor_role="AUDITOR", # Auditor lacks EXECUTE_RESPONSE permission
        tier=DecisionTier.TIER_C,
        is_auto_execution=False,
        current_state_store=store
    )
    assert passed is False
    assert "Gate 1" in gate_name

def test_safety_gate_kill_switch():
    EmergencyKillSwitch.enable(actor="test_admin")
    store = {"blocked_ips": set(), "suspended_users": set(), "isolated_hosts": set()}
    passed, gate_name, reason = SafetyGatesEvaluator.evaluate_gates(
        action_type=ResponseActionType.BLOCK_IP,
        target="198.51.100.10",
        actor_role="ADMIN",
        tier=DecisionTier.TIER_C,
        is_auto_execution=True,
        current_state_store=store
    )
    assert passed is False
    assert "Kill Switch" in gate_name
    EmergencyKillSwitch.disable()

def test_safety_gate_whitelist_core_asset():
    store = {"blocked_ips": set(), "suspended_users": set(), "isolated_hosts": set()}
    passed, gate_name, reason = SafetyGatesEvaluator.evaluate_gates(
        action_type=ResponseActionType.ISOLATE_ENDPOINT,
        target="auth-server-01", # Whitelisted core asset
        actor_role="ADMIN",
        tier=DecisionTier.TIER_C,
        is_auto_execution=False,
        current_state_store=store
    )
    assert passed is False
    assert "Whitelist" in reason or "Gate 4" in gate_name

def test_safety_gate_blast_radius_limit():
    # Simulate 5 active blocked IPs
    store = {
        "blocked_ips": {"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5"},
        "suspended_users": set(),
        "isolated_hosts": set()
    }
    passed, gate_name, reason = SafetyGatesEvaluator.evaluate_gates(
        action_type=ResponseActionType.BLOCK_IP,
        target="1.1.1.6", # 6th target exceeds blast radius max limit of 5
        actor_role="ADMIN",
        tier=DecisionTier.TIER_C,
        is_auto_execution=False,
        current_state_store=store
    )
    assert passed is False
    assert "Blast Radius Limit" in gate_name or "Blast radius" in reason
