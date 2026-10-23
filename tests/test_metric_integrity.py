"""
Suraksha AI - Phase 7 Metric Integrity Tests (Requirement A)
Verifies authoritative confusion matrix calculation, zero-denominator safety,
consistency between JSON/Markdown reports, and rejection of malformed evaluation states.
"""
import pytest
from backend.evaluation.metrics import (
    calculate_confusion_matrix,
    calculate_classification_metrics,
    validate_confusion_matrix,
    validate_evaluation_report,
    calculate_stream_deduplication_metrics,
)


def test_phase6_confusion_matrix_produces_exact_20_percent_fpr():
    """
    Mandatory SDD Test: Verifies that Phase 6 counts (TP=21, FP=2, TN=8, FN=0)
    produce exactly FPR = 20% (0.2000), proving that the Phase 6 summary's '10%'
    was an editorial transcription error while the underlying math is 20%.
    """
    tp = 21
    fp = 2
    tn = 8
    fn = 0

    metrics = calculate_classification_metrics(tp=tp, fp=fp, tn=tn, fn=fn)

    assert metrics["false_positive_rate"] == 0.2000, f"Expected 0.2000 (20%), got {metrics['false_positive_rate']}"
    assert metrics["precision"] == round(21 / 23, 4)
    assert metrics["recall"] == 1.0000
    assert metrics["specificity"] == round(8 / 10, 4)
    assert metrics["accuracy"] == round(29 / 31, 4)
    assert metrics["f1_score"] == round(2 * (21/23 * 1.0) / (21/23 + 1.0), 4)


def test_alternative_valid_confusion_matrices():
    """Tests metric derivation across multiple valid boundary matrices."""
    # 1. Perfect classifier
    perfect = calculate_classification_metrics(tp=50, fp=0, tn=50, fn=0)
    assert perfect["precision"] == 1.0
    assert perfect["recall"] == 1.0
    assert perfect["false_positive_rate"] == 0.0
    assert perfect["specificity"] == 1.0
    assert perfect["f1_score"] == 1.0
    assert perfect["accuracy"] == 1.0

    # 2. All negative predictions
    all_neg = calculate_classification_metrics(tp=0, fp=0, tn=80, fn=20)
    assert all_neg["precision"] == 0.0
    assert all_neg["recall"] == 0.0
    assert all_neg["false_positive_rate"] == 0.0
    assert all_neg["specificity"] == 1.0
    assert all_neg["accuracy"] == 0.8000

    # 3. All positive predictions
    all_pos = calculate_classification_metrics(tp=40, fp=60, tn=0, fn=0)
    assert all_pos["precision"] == 0.4000
    assert all_pos["recall"] == 1.0
    assert all_pos["false_positive_rate"] == 1.0
    assert all_pos["specificity"] == 0.0
    assert all_pos["accuracy"] == 0.4000


def test_zero_denominator_handling_deterministic():
    """Verifies documented zero-denominator fallbacks (no division by zero)."""
    # Empty counts
    empty = calculate_classification_metrics(tp=0, fp=0, tn=0, fn=0)
    assert empty["precision"] == 0.0
    assert empty["recall"] == 0.0
    assert empty["specificity"] == 0.0
    assert empty["f1_score"] == 0.0
    assert empty["false_positive_rate"] == 0.0
    assert empty["accuracy"] == 0.0
    assert empty["balanced_accuracy"] == 0.0


def test_validate_confusion_matrix_invariants():
    """Verifies that invalid or mismatching confusion matrices raise ValueError."""
    # Negative count
    with pytest.raises(ValueError, match="non-negative int"):
        validate_confusion_matrix({"tp": -1, "fp": 0, "tn": 5, "fn": 0})

    # Missing key
    with pytest.raises(ValueError, match="missing required keys"):
        validate_confusion_matrix({"tp": 5, "fp": 0, "tn": 5})

    # Expected total sum mismatch
    with pytest.raises(ValueError, match="Confusion matrix sum mismatch"):
        validate_confusion_matrix({"tp": 10, "fp": 2, "tn": 8, "fn": 0}, expected_total=30)

    # Valid
    assert validate_confusion_matrix({"tp": 10, "fp": 2, "tn": 8, "fn": 0}, expected_total=20) is True


def test_validate_evaluation_report_gate():
    """Tests the comprehensive evaluation report validation gate."""
    # 1. Valid report structure
    valid_report = {
        "raw_stream_deduplication_metrics": {
            "raw_events_received": 33,
            "unique_events_analyzed": 31,
            "duplicates_suppressed": 2
        },
        "overall_hybrid_metrics": {
            "confusion_matrix": {"tp": 21, "fp": 0, "tn": 10, "fn": 0},
            "metrics": {
                "precision": 1.0,
                "recall": 1.0,
                "f1_score": 1.0,
                "false_positive_rate": 0.0,
                "accuracy": 1.0
            }
        },
        "per_category_metrics": {
            "BRUTE_FORCE": {"support": 10},
            "PORT_SCAN": {"support": 11},
            "NONE / BENIGN": {"support": 10}
        }
    }
    is_valid, errors = validate_evaluation_report(valid_report)
    assert is_valid is True, f"Validation failed unexpectedly: {errors}"
    assert len(errors) == 0

    # 2. Invalid report: raw != unique + duplicates
    bad_stream_report = dict(valid_report)
    bad_stream_report["raw_stream_deduplication_metrics"] = {
        "raw_events_received": 35,
        "unique_events_analyzed": 31,
        "duplicates_suppressed": 2
    }
    is_valid, errors = validate_evaluation_report(bad_stream_report)
    assert is_valid is False
    assert any("Stream count mismatch" in err for err in errors)

    # 3. Invalid report: contradictory precision metric
    bad_metric_report = dict(valid_report)
    bad_metric_report["overall_hybrid_metrics"] = {
        "confusion_matrix": {"tp": 21, "fp": 0, "tn": 10, "fn": 0},
        "metrics": {
            "precision": 0.50, # Contradicts 21 / (21 + 0) = 1.0
            "recall": 1.0,
            "f1_score": 1.0,
            "false_positive_rate": 0.0,
            "accuracy": 1.0
        }
    }
    is_valid, errors = validate_evaluation_report(bad_metric_report)
    assert is_valid is False
    assert any("Metric inconsistency for 'precision'" in err for err in errors)
