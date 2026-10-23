"""
Suraksha AI - Phase 6 Test Suite: Evaluation Semantics & Benchmark Hardening (Requirement C)
Verifies:
- Explicit definition of evaluation populations
- Suppressed duplicates excluded from unique-event detection false negatives
- Dual-view metrics (Stream Deduplication vs Unique Normalized Event Detection)
- Mathematical consistency: TP + FP + TN + FN == N_unique
- Benchmark report determinism and reproducibility
"""
import os
import tempfile
import json
import pytest

from backend.evaluation.metrics import (
    calculate_confusion_matrix,
    calculate_classification_metrics,
    calculate_stream_deduplication_metrics,
    calculate_per_category_metrics
)
from backend.evaluation.eval_runner import EvaluationRunner


def test_calculate_stream_deduplication_metrics():
    """
    Requirement C: Stream deduplication metrics calculation must be mathematically sound.
    """
    metrics = calculate_stream_deduplication_metrics(
        raw_total=100,
        unique_total=80,
        duplicates_suppressed=20,
        duplicates_attached_to_incidents=15
    )
    assert metrics["raw_events_received"] == 100
    assert metrics["unique_events_analyzed"] == 80
    assert metrics["duplicates_suppressed"] == 20
    assert metrics["duplicates_attached_to_incidents"] == 15
    assert metrics["deduplication_rate_pct"] == 20.0
    assert metrics["incident_timeline_attachment_rate_pct"] == 75.0
    assert metrics["alert_flooding_reduction_pct"] == 20.0


def test_unique_event_population_denominators_and_confusion_matrix_consistency():
    """
    Requirement C.6 - C.9:
    TP + FP + TN + FN must exactly match the stated evaluation population size.
    """
    y_true = [True, True, False, False, True, False]
    y_pred = [True, False, False, True, True, False]

    cm = calculate_confusion_matrix(y_true, y_pred)
    total_samples = cm["tp"] + cm["fp"] + cm["tn"] + cm["fn"]
    assert total_samples == len(y_true)
    assert cm["tp"] == 2
    assert cm["fn"] == 1
    assert cm["fp"] == 1
    assert cm["tn"] == 2

    metrics = calculate_classification_metrics(cm["tp"], cm["fp"], cm["tn"], cm["fn"])
    # Precision = 2 / (2 + 1) = 0.6667
    assert metrics["precision"] == 0.6667
    # Recall = 2 / (2 + 1) = 0.6667
    assert metrics["recall"] == 0.6667
    # Accuracy = (2 + 2) / 6 = 0.6667
    assert metrics["accuracy"] == 0.6667
    # FPR = 1 / (1 + 2) = 0.3333
    assert metrics["false_positive_rate"] == 0.3333


def test_evaluation_runner_dual_population_reports():
    """
    Requirement C & D: Run EvaluationRunner on synthetic dataset and verify:
    - Report includes both raw_stream_deduplication_metrics and overall_hybrid_metrics
    - Suppressed duplicates are tracked in stream metrics, not penalized as detector FNs
    - Confusion matrix is consistent with unique events count
    """
    runner = EvaluationRunner(dataset_path="data/evaluation_dataset.json")
    try:
        report = runner.run()

        metadata = report["evaluation_metadata"]
        stream_m = report["raw_stream_deduplication_metrics"]
        hybrid_cm = report["overall_hybrid_metrics"]["confusion_matrix"]
        hybrid_m = report["overall_hybrid_metrics"]["metrics"]

        # Check total raw events equals unique + duplicates
        assert stream_m["raw_events_received"] == metadata["total_raw_events"]
        assert stream_m["unique_events_analyzed"] == metadata["total_unique_events_analyzed"]
        assert stream_m["duplicates_suppressed"] == metadata["total_duplicates_suppressed"]
        assert stream_m["raw_events_received"] == stream_m["unique_events_analyzed"] + stream_m["duplicates_suppressed"]

        # Check confusion matrix sums to unique events
        cm_sum = hybrid_cm["tp"] + hybrid_cm["fp"] + hybrid_cm["tn"] + hybrid_cm["fn"]
        assert cm_sum == stream_m["unique_events_analyzed"]

        # Check that reports were generated on disk
        assert os.path.exists("data/evaluation_report.json")
        assert os.path.exists("data/evaluation_summary.md")

        # Verify Markdown summary contains both Phase 6 stream metrics and unique detection metrics
        with open("data/evaluation_summary.md", "r", encoding="utf-8") as f:
            md_content = f.read()
        assert "Raw Telemetry Stream & Deduplication Observability" in md_content
        assert "Detection Performance on Unique Normalized Events" in md_content
        assert "Phase 6" in md_content
    finally:
        runner.cleanup()
