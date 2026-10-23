"""
Suraksha AI - Evaluation Metrics Engine (Workstream C & F)
Implements rigorous statistical metrics for event-level and incident-level security detection.
"""
from typing import Dict, List, Any, Optional, Tuple


def calculate_confusion_matrix(y_true: List[bool], y_pred: List[bool]) -> Dict[str, int]:
    """
    Computes binary confusion matrix counts: TP, FP, TN, FN.
    y_true: Ground truth boolean list (True = Malicious/Threat, False = Benign/Normal)
    y_pred: Predicted boolean list (True = Threat Detected, False = Benign)
    """
    if len(y_true) != len(y_pred):
        raise ValueError(f"Length mismatch: y_true ({len(y_true)}) != y_pred ({len(y_pred)})")

    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt and yp)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if not yt and yp)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if not yt and not yp)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt and not yp)

    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def calculate_classification_metrics(tp: int, fp: int, tn: int, fn: int) -> Dict[str, float]:
    """
    Calculates Precision, Recall, F1 Score, and False Positive Rate.
    
    Zero-Denominator Policy:
    - Precision: If (TP + FP) == 0, returns 0.0 (no positive predictions made).
    - Recall: If (TP + FN) == 0, returns 0.0 (no actual positives present).
    - F1: If (Precision + Recall) == 0, returns 0.0.
    - False Positive Rate: If (FP + TN) == 0, returns 0.0 (no actual negatives present).
    """
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    return {
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1_score": round(float(f1), 4),
        "false_positive_rate": round(float(fpr), 4),
        "accuracy": round(float((tp + tn) / max(1, tp + fp + tn + fn)), 4),
    }


def calculate_per_category_metrics(
    categories: List[str],
    ground_truth_cats: List[str],
    predicted_cats: List[str]
) -> Dict[str, Dict[str, Any]]:
    """
    Computes One-vs-Rest classification metrics for each threat category.
    """
    results: Dict[str, Dict[str, Any]] = {}

    for cat in categories:
        y_true_binary = [c == cat for c in ground_truth_cats]
        y_pred_binary = [c == cat for c in predicted_cats]

        cm = calculate_confusion_matrix(y_true_binary, y_pred_binary)
        metrics = calculate_classification_metrics(cm["tp"], cm["fp"], cm["tn"], cm["fn"])

        results[cat] = {
            "confusion_matrix": cm,
            "metrics": metrics,
            "support": sum(y_true_binary)
        }

    return results


def calculate_correlation_metrics(
    scenario_groups: List[Optional[str]],
    actual_incident_ids: List[Optional[str]],
    is_threat: List[bool]
) -> Dict[str, Any]:
    """
    Evaluates Incident Correlation Engine Quality (Workstream F):
    - Correctly grouped attack sequences: All events belonging to the same expected group mapped to the same incident ID.
    - Incorrectly merged incidents (false grouping / contamination): Events from different expected groups merged into one incident.
    - Incorrectly split incidents (fragmentation): Events from the same expected group split across multiple incidents.
    - Unrelated events isolation: Independent threat events remain in distinct incidents.
    - Benign event isolation: Benign events correctly do NOT spawn unintended incidents.
    """
    # Map expected group -> list of generated incident IDs
    group_to_incidents: Dict[str, List[str]] = {}
    incident_to_groups: Dict[str, set] = {}

    benign_unintended_incidents = 0
    threat_without_incident = 0

    for exp_grp, inc_id, threat in zip(scenario_groups, actual_incident_ids, is_threat):
        if not threat:
            if inc_id is not None:
                benign_unintended_incidents += 1
            continue

        if threat and inc_id is None:
            threat_without_incident += 1
            continue

        if exp_grp and inc_id:
            group_to_incidents.setdefault(exp_grp, []).append(inc_id)
            incident_to_groups.setdefault(inc_id, set()).add(exp_grp)

    # Calculate grouping accuracy
    total_expected_groups = len(group_to_incidents)
    correctly_grouped_sequences = 0
    split_incident_groups = 0

    for exp_grp, inc_list in group_to_incidents.items():
        unique_inc_ids = set(inc_list)
        if len(unique_inc_ids) == 1:
            correctly_grouped_sequences += 1
        else:
            split_incident_groups += 1

    # Check for cross-group contamination (merging different groups)
    merged_incident_count = 0
    for inc_id, groups in incident_to_groups.items():
        if len(groups) > 1:
            merged_incident_count += 1

    group_accuracy = (
        round(correctly_grouped_sequences / total_expected_groups, 4)
        if total_expected_groups > 0
        else 1.0
    )

    return {
        "total_attack_scenarios": total_expected_groups,
        "correctly_grouped_scenarios": correctly_grouped_sequences,
        "split_scenarios_count": split_incident_groups,
        "cross_contaminated_incidents_count": merged_incident_count,
        "grouping_accuracy": group_accuracy,
        "benign_unintended_incidents": benign_unintended_incidents,
        "threats_missing_incidents": threat_without_incident,
    }


def calculate_stream_deduplication_metrics(
    raw_total: int,
    unique_total: int,
    duplicates_suppressed: int,
    duplicates_attached_to_incidents: int
) -> Dict[str, Any]:
    """
    Computes metrics for the raw ingestion stream and deduplication subsystem (Requirement C & Workstream G).
    Distinguishes raw ingestion stream metrics from unique normalized event detection metrics.
    """
    dedup_ratio = (duplicates_suppressed / raw_total) if raw_total > 0 else 0.0
    incident_attach_rate = (duplicates_attached_to_incidents / duplicates_suppressed) if duplicates_suppressed > 0 else 0.0

    return {
        "raw_events_received": raw_total,
        "unique_events_analyzed": unique_total,
        "duplicates_suppressed": duplicates_suppressed,
        "duplicates_attached_to_incidents": duplicates_attached_to_incidents,
        "deduplication_rate_pct": round(dedup_ratio * 100.0, 2),
        "incident_timeline_attachment_rate_pct": round(incident_attach_rate * 100.0, 2),
        "alert_flooding_reduction_pct": round(dedup_ratio * 100.0, 2)
    }

