from typing import Dict, Tuple, List
from backend.models.events import NormalizedEvent, AssetCriticality
from backend.models.incidents import Severity, ThreatCategory
from backend.detection.behavioral_engine import BehavioralVector

class RiskCalculator:
    SEVERITY_WEIGHTS = {
        Severity.LOW: 15.0,
        Severity.MEDIUM: 45.0,
        Severity.HIGH: 75.0,
        Severity.CRITICAL: 95.0
    }

    ASSET_CRITICALITY_MULTIPLIER = {
        AssetCriticality.LOW: 1.0,
        AssetCriticality.MEDIUM: 1.25,
        AssetCriticality.HIGH: 1.5
    }

    @classmethod
    def calculate(
        cls,
        event: NormalizedEvent,
        threat_cat: ThreatCategory,
        rule_severity: Severity,
        rule_confidence: float,
        ml_score: float,
        vector: BehavioralVector = None,
        evidence: List[str] = None
    ) -> Tuple[float, float, str]:
        """
        Calculates (RiskScore, ConfidenceScore, RecommendedAction)
        RiskScore = min(100.0, (RuleWeight * 0.55 + MLScore * 45) * AssetMultiplier)
        Safety Constraint: High ML score alone without rule match cannot trigger automated execution.
        """
        if threat_cat == ThreatCategory.NONE:
            if ml_score >= 0.75:
                # Behavioral anomaly detected without rule match -> Moderate Risk (Tier B Human Approval)
                return (55.0, round(ml_score * 0.7, 2), "ALERT_ONLY")
            return (5.0, 0.95, "ALERT_ONLY")

        base_sev_weight = cls.SEVERITY_WEIGHTS.get(rule_severity, 20.0)
        mult = cls.ASSET_CRITICALITY_MULTIPLIER.get(event.asset_criticality, 1.0)

        # Composite risk formula
        raw_risk = (base_sev_weight * 0.55) + (ml_score * 45.0)

        # Boost risk if behavioral vector shows extreme activity
        if vector:
            if vector.failed_login_count >= 5.0 or vector.data_transfer_volume_mb >= 500.0:
                raw_risk += 10.0

        adjusted_risk = round(min(100.0, raw_risk * mult), 1)

        # Confidence calculation
        confidence = round(min(1.0, max(0.0, (rule_confidence * 0.6) + (ml_score * 0.4))), 2)

        # Recommend Action Mapping
        if threat_cat in [ThreatCategory.BRUTE_FORCE, ThreatCategory.C2_ACTIVITY]:
            recommended_action = "BLOCK_IP"
        elif threat_cat in [ThreatCategory.SUSPICIOUS_LOGIN, ThreatCategory.PRIVILEGE_ESCALATION]:
            recommended_action = "SUSPEND_SESSION"
        elif threat_cat in [ThreatCategory.LATERAL_MOVEMENT, ThreatCategory.UNUSUAL_DATA_TRANSFER]:
            recommended_action = "ISOLATE_ENDPOINT"
        else:
            recommended_action = "ALERT_ONLY"

        return (adjusted_risk, confidence, recommended_action)
