import pytest
from backend.evaluation.ml_evaluator import MLEvaluator
from backend.detection.ml_detector import MLAnomalyDetector

def test_model_training_and_holdout_evaluation():
    """
    REQ-EVAL-004: Evaluates IsolationForest on holdout data (seed 101) with zero training data leakage.
    """
    detector = MLAnomalyDetector()
    evaluator = MLEvaluator(detector)

    result = evaluator.evaluate_holdout_performance(threshold=0.50, random_seed=101)

    assert result["training_seed"] == 42
    assert result["holdout_seed"] == 101
    assert result["total_holdout_samples"] == 200
    assert result["normal_samples"] == 150
    assert result["anomalous_samples"] == 50

    metrics = result["metrics"]
    assert 0.0 <= metrics["precision"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0
    assert 0.0 <= metrics["f1_score"] <= 1.0
    assert metrics["precision"] >= 0.80

def test_ml_anomaly_score_alone_never_authorizes_remediation():
    """
    Safety invariant: Anomaly score alone must never authorize response execution.
    """
    from backend.response.policy_engine import ResponsePolicyEngine
    from backend.models.response import DecisionTier, ActionStatus, ResponseActionType
    from backend.models.incidents import ThreatCategory

    tier, status, act, reason, auto = ResponsePolicyEngine.evaluate_policy(
        threat_category=ThreatCategory.NONE,
        risk_score=90.0,
        confidence_score=0.95,
        recommended_action_str="BLOCK_IP",
        is_anomaly_only=True
    )
    assert tier == DecisionTier.TIER_C
    assert status == ActionStatus.PENDING_APPROVAL
    assert act == ResponseActionType.ALERT_ONLY
    assert auto is False
