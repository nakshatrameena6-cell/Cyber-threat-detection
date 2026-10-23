import pytest
from backend.evaluation.metrics import (
    calculate_confusion_matrix,
    calculate_classification_metrics,
    calculate_per_category_metrics,
    calculate_correlation_metrics,
)

def test_confusion_matrix_calculation():
    y_true = [True, True, False, False, True]
    y_pred = [True, False, False, True, True]

    cm = calculate_confusion_matrix(y_true, y_pred)
    assert cm["tp"] == 2
    assert cm["fn"] == 1
    assert cm["tn"] == 1
    assert cm["fp"] == 1

def test_confusion_matrix_length_mismatch():
    with pytest.raises(ValueError, match="Length mismatch"):
        calculate_confusion_matrix([True, False], [True])

def test_classification_metrics_standard():
    metrics = calculate_classification_metrics(tp=8, fp=2, tn=8, fn=2)
    assert metrics["precision"] == 0.8
    assert metrics["recall"] == 0.8
    assert metrics["f1_score"] == 0.8
    assert metrics["false_positive_rate"] == 0.2
    assert metrics["accuracy"] == 0.8

def test_classification_metrics_zero_denominators():
    """
    Explicit test for zero-denominator handling policy (Workstream C).
    """
    # 1. No positive predictions (TP + FP == 0) -> Precision = 0.0
    m1 = calculate_classification_metrics(tp=0, fp=0, tn=10, fn=5)
    assert m1["precision"] == 0.0
    assert m1["recall"] == 0.0
    assert m1["f1_score"] == 0.0

    # 2. No true positives or negatives (all zero) -> all 0.0
    m2 = calculate_classification_metrics(tp=0, fp=0, tn=0, fn=0)
    assert m2["precision"] == 0.0
    assert m2["recall"] == 0.0
    assert m2["f1_score"] == 0.0
    assert m2["false_positive_rate"] == 0.0

    # 3. No actual negatives (FP + TN == 0) -> FPR = 0.0
    m3 = calculate_classification_metrics(tp=5, fp=0, tn=0, fn=0)
    assert m3["false_positive_rate"] == 0.0

def test_per_category_breakdown():
    categories = ["BRUTE_FORCE", "C2_ACTIVITY", "NONE"]
    y_true = ["BRUTE_FORCE", "BRUTE_FORCE", "C2_ACTIVITY", "NONE"]
    y_pred = ["BRUTE_FORCE", "NONE", "C2_ACTIVITY", "NONE"]

    per_cat = calculate_per_category_metrics(categories, y_true, y_pred)
    assert "BRUTE_FORCE" in per_cat
    assert per_cat["BRUTE_FORCE"]["confusion_matrix"]["tp"] == 1
    assert per_cat["BRUTE_FORCE"]["confusion_matrix"]["fn"] == 1
    assert per_cat["C2_ACTIVITY"]["metrics"]["recall"] == 1.0

def test_correlation_metrics_calculation():
    scenario_groups = ["GROUP_A", "GROUP_A", "GROUP_B", None]
    actual_incident_ids = ["INC-01", "INC-01", "INC-02", None]
    is_threat = [True, True, True, False]

    corr = calculate_correlation_metrics(scenario_groups, actual_incident_ids, is_threat)
    assert corr["total_attack_scenarios"] == 2
    assert corr["correctly_grouped_scenarios"] == 2
    assert corr["split_scenarios_count"] == 0
    assert corr["cross_contaminated_incidents_count"] == 0
    assert corr["grouping_accuracy"] == 1.0
    assert corr["benign_unintended_incidents"] == 0
