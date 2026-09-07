"""Threat Detector Engine (REQ-DET-001)."""
import uuid
from typing import List, Optional
from models.schemas.telemetry import NormalizedEvent
from models.schemas.alert import ThreatAlert
from ai_threat_detection.detection.evaluator import MLEvaluator


class ThreatDetector:
    """Hybrid signature & ML anomaly detector."""

    KNOWN_SIGNATURES = {
        "SUSPICIOUS_POWERSHELL": ("SIG-001", "Execution of Encoded PowerShell Command", "HIGH"),
        "FAILED_LOGIN_BURST": ("SIG-002", "Brute Force Authentication Attempt", "MEDIUM"),
        "PORT_SCAN": ("SIG-003", "Network Reconnaissance Port Scan", "LOW"),
    }

    def __init__(self, ml_evaluator: MLEvaluator = None):
        self.ml_evaluator = ml_evaluator or MLEvaluator()

    def evaluate_event(self, event: NormalizedEvent) -> Optional[ThreatAlert]:
        """Evaluate event against signature rules and ML models."""
        target_entity = event.host_id or event.user_id or event.source_ip or "UNKNOWN_ENTITY"

        if event.event_type in self.KNOWN_SIGNATURES:
            rule_id, rule_name, severity = self.KNOWN_SIGNATURES[event.event_type]
            confidence = self.ml_evaluator.evaluate_anomaly(event)

            return ThreatAlert(
                alert_id=f"alt-{uuid.uuid4().hex[:8]}",
                event_id=event.event_id,
                rule_id=rule_id,
                rule_name=rule_name,
                detection_type="HYBRID_RULE_ML",
                confidence_score=confidence,
                severity=severity,
                target_entity=target_entity,
                details=event.attributes
            )
        return None
