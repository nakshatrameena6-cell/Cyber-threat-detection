import pytest
from backend.response.decision_engine import DecisionEngine
from backend.response.policy_engine import ResponsePolicyEngine
from backend.response.safety_gates import SafetyGatesEvaluator
from backend.response.executor import ResponseExecutor
from backend.models.response import DecisionTier, ActionStatus, ResponseActionType, VerificationStatus
from backend.models.incidents import ThreatCategory

def test_tier_a_alert_only_semantics():
    """
    Tier A: Fully automated execution permitted ONLY for explicitly allowed, bounded actions (ALERT_ONLY).
    """
    tier, status, act, reason, auto = ResponsePolicyEngine.evaluate_policy(
        threat_category=ThreatCategory.SUSPICIOUS_LOGIN,
        risk_score=25.0, # Low Risk (< 40)
        confidence_score=0.90,
        recommended_action_str="ALERT_ONLY"
    )
    assert tier == DecisionTier.TIER_A
    assert status == ActionStatus.EXECUTED
    assert act == ResponseActionType.ALERT_ONLY
    assert auto is True

def test_tier_b_bounded_remediation_semantics():
    """
    Tier B: Eligible low-to-medium-impact actions (BLOCK_IP, SUSPEND_SESSION) execute automatically
    with immediate notification when confidence >= 0.75 and all gates pass.
    """
    tier, status, act, reason, auto = ResponsePolicyEngine.evaluate_policy(
        threat_category=ThreatCategory.BRUTE_FORCE,
        risk_score=65.0, # Medium Risk
        confidence_score=0.85, # Conf >= 0.75
        recommended_action_str="BLOCK_IP"
    )
    assert tier == DecisionTier.TIER_B
    assert status == ActionStatus.APPROVED
    assert act == ResponseActionType.BLOCK_IP
    assert auto is True

def test_tier_c_mandatory_human_approval_high_impact():
    """
    Tier C: High-impact actions (ISOLATE_ENDPOINT) strictly require human approval. NEVER auto-executed.
    """
    tier, status, act, reason, auto = ResponsePolicyEngine.evaluate_policy(
        threat_category=ThreatCategory.UNUSUAL_DATA_TRANSFER,
        risk_score=95.0,
        confidence_score=0.95,
        recommended_action_str="ISOLATE_ENDPOINT"
    )
    assert tier == DecisionTier.TIER_C
    assert status == ActionStatus.PENDING_APPROVAL
    assert act == ResponseActionType.ISOLATE_ENDPOINT
    assert auto is False

def test_tier_c_low_confidence_fails_closed():
    """
    Tier C: Ambiguous or low-confidence threats (< 0.75) fail closed to human review.
    """
    tier, status, act, reason, auto = ResponsePolicyEngine.evaluate_policy(
        threat_category=ThreatCategory.BRUTE_FORCE,
        risk_score=70.0,
        confidence_score=0.60, # Low confidence (< 0.75)
        recommended_action_str="BLOCK_IP"
    )
    assert tier == DecisionTier.TIER_C
    assert status == ActionStatus.PENDING_APPROVAL
    assert auto is False
    assert "low confidence" in reason.lower()

from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_evaluation_api_endpoints():
    """
    REQ-EVAL-008: Verify /api/evaluation/latest and /api/evaluation/run endpoints.
    """
    # 1. Latest report endpoint
    res = client.get("/api/evaluation/latest")
    assert res.status_code == 200
    report = res.json()
    assert "overall_hybrid_metrics" in report
    assert "incident_correlation_evaluation" in report

    # 2. Trigger run endpoint
    res2 = client.post("/api/evaluation/run", headers={"X-Role": "ADMIN", "X-User-Id": "test_admin"})
    assert res2.status_code == 200
    report2 = res2.json()
    assert "overall_hybrid_metrics" in report2
