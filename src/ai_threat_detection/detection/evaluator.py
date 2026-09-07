"""ML Anomaly Confidence Evaluator (REQ-DET-002)."""
from typing import Dict, Any
from models.schemas.telemetry import NormalizedEvent


class MLEvaluator:
    """Mock ML anomaly evaluator returning confidence score in range [0.0, 1.0]."""

    def evaluate_anomaly(self, event: NormalizedEvent) -> float:
        """Calculate ML confidence score based on event attributes."""
        # Simple heuristic for skeleton demo
        if event.event_type == "FAILED_LOGIN_BURST":
            return 0.85
        if event.event_type == "SUSPICIOUS_POWERSHELL":
            return 0.92
        if event.event_type == "PORT_SCAN":
            return 0.75
        return 0.20
