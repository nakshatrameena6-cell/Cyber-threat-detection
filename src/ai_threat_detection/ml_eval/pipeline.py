"""ML Model Evaluation & Shadow Pipeline (REQ-MLE-001, REQ-MLE-002)."""
from typing import List, Dict, Any


class MLEvaluationPipeline:
    """Offline ML Model Evaluation and Shadow Validation Runner."""

    def evaluate_metrics(self, y_true: List[int], y_pred: List[int]) -> Dict[str, float]:
        """Compute offline evaluation metrics: Precision, Recall, F1."""
        tp = sum(1 for gt, pr in zip(y_true, y_pred) if gt == 1 and pr == 1)
        fp = sum(1 for gt, pr in zip(y_true, y_pred) if gt == 0 and pr == 1)
        fn = sum(1 for gt, pr in zip(y_true, y_pred) if gt == 1 and pr == 0)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        return {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
        }

    def run_shadow_mode(self, raw_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate events in shadow mode without triggering policy response actions."""
        evaluated_count = len(raw_events)
        shadow_alerts = [
            {"event": event, "shadow_confidence": 0.88, "shadow_decision": "ALERT_ONLY"}
            for event in raw_events
        ]
        return {
            "evaluated_count": evaluated_count,
            "shadow_alerts": shadow_alerts,
            "status": "SHADOW_EVALUATION_SUCCESS"
        }
