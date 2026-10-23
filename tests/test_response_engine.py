import pytest
from backend.response.decision_engine import DecisionEngine
from backend.response.executor import ResponseExecutor
from backend.response.verifier import ResponseVerifier
from backend.models.response import DecisionTier, ActionStatus, ResponseActionType, VerificationStatus

def test_decision_tiers():
    # Tier A check: fully automated alert-only
    tier, status, act, _ = DecisionEngine.evaluate_tier(risk_score=25.0, confidence_score=0.90, recommended_action_str="ALERT_ONLY")
    assert tier == DecisionTier.TIER_A
    assert status == ActionStatus.EXECUTED

    # Tier B check: eligible low-to-medium-impact bounded action auto-executes with notification
    tier, status, act, _ = DecisionEngine.evaluate_tier(risk_score=60.0, confidence_score=0.80, recommended_action_str="BLOCK_IP")
    assert tier == DecisionTier.TIER_B
    assert status == ActionStatus.APPROVED

    # Tier C check: high-impact action (ISOLATE_ENDPOINT) mandates human approval (NEVER auto-executed)
    tier, status, act, _ = DecisionEngine.evaluate_tier(risk_score=85.0, confidence_score=0.88, recommended_action_str="ISOLATE_ENDPOINT")
    assert tier == DecisionTier.TIER_C
    assert status == ActionStatus.PENDING_APPROVAL

def test_executor_and_verifier():
    executor = ResponseExecutor()
    rec = executor.execute_action(
        incident_id="INC-1234",
        action_type=ResponseActionType.BLOCK_IP,
        target="198.51.100.55",
        tier=DecisionTier.TIER_B,
        actor="AUTO_ENGINE"
    )
    assert rec.status == ActionStatus.EXECUTED
    assert rec.verification_status == VerificationStatus.PASSED
    assert "198.51.100.55" in executor.blocked_ips
