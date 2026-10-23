import os
import json
import pytest
from backend.evaluation.eval_runner import EvaluationRunner, run_evaluation
from backend.database import get_db_path

def test_dataset_schema_and_integrity():
    """
    REQ-EVAL-001: Evaluation dataset must be well-formed with ground truth labels and scenario IDs.
    """
    dataset_path = "data/evaluation_dataset.json"
    assert os.path.exists(dataset_path), "Evaluation dataset file missing"

    with open(dataset_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert len(data) >= 20, "Evaluation dataset must contain at least 20 events"

    for idx, item in enumerate(data):
        assert "raw_id" in item, f"Event {idx} missing raw_id"
        assert "timestamp" in item, f"Event {idx} missing timestamp"
        assert "event_type" in item, f"Event {idx} missing event_type"
        assert "ground_truth_is_threat" in item, f"Event {idx} missing ground_truth_is_threat"
        assert "ground_truth_category" in item, f"Event {idx} missing ground_truth_category"
        assert "scenario_id" in item, f"Event {idx} missing scenario_id"

def test_reproducible_runner_execution(tmp_path):
    """
    REQ-EVAL-007: Evaluation runner produces valid reports and isolates database storage.
    """
    eval_db = str(tmp_path / "test_eval_isolated.db")
    runner = EvaluationRunner(dataset_path="data/evaluation_dataset.json", db_path=eval_db)

    report = runner.run()
    assert "overall_hybrid_metrics" in report
    assert "pipeline_comparison" in report
    assert "per_category_metrics" in report
    assert "incident_correlation_evaluation" in report

    metrics = report["overall_hybrid_metrics"]["metrics"]
    assert 0.0 <= metrics["precision"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0
    assert 0.0 <= metrics["f1_score"] <= 1.0

    # Verify generated report files
    assert os.path.exists("data/evaluation_report.json")
    assert os.path.exists("data/evaluation_summary.md")

def test_risk_and_evidence_consistency():
    """
    REQ-EVAL-006: Risk scores must fall in [0, 100], confidence in [0, 1], and evidence must be present.
    """
    report = run_evaluation()
    risk_eval = report["risk_and_explainability_evaluation"]

    assert risk_eval["risk_bounds_invariant_passed"] is True
    assert risk_eval["explainable_evidence_present"] is True
    assert 0.0 <= risk_eval["min_risk_observed"] <= 100.0
    assert 0.0 <= risk_eval["max_risk_observed"] <= 100.0

def test_incident_correlation_evaluation():
    """
    REQ-EVAL-005: Multi-event attack campaigns are grouped correctly.
    """
    report = run_evaluation()
    corr = report["incident_correlation_evaluation"]

    assert corr["total_attack_scenarios"] > 0
    assert corr["grouping_accuracy"] >= 0.85
    assert corr["cross_contaminated_incidents_count"] == 0
