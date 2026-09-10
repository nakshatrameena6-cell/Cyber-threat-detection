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
    ) -> Tuple[float, float, str, List[str]]:
        """
        Calculates (RiskScore, ConfidenceScore, RecommendedAction, WhyEvidenceBullets)
        RiskScore = min(100.0, (RuleWeight * 0.55 + MLScore * 45) * AssetMultiplier)
        Safety Constraint: High ML score alone without rule match cannot trigger automated execution.
        """
        why_bullets: List[str] = []

        if threat_cat == ThreatCategory.NONE:
            if ml_score >= 0.75:
                why_bullets.append(f"Behavioral anomaly score elevated ({ml_score:.2f}) without deterministic rule match")
                return (55.0, round(ml_score * 0.7, 2), "ALERT_ONLY", why_bullets)
            
            why_bullets.append("Normal operational event baseline")
            return (5.0, 0.95, "ALERT_ONLY", why_bullets)

        base_sev_weight = cls.SEVERITY_WEIGHTS.get(rule_severity, 20.0)
        mult = cls.ASSET_CRITICALITY_MULTIPLIER.get(event.asset_criticality, 1.0)

        why_bullets.append(f"Threat category identified: {threat_cat.value} ({rule_severity.value} severity rule)")

        # Composite risk formula
        raw_risk = (base_sev_weight * 0.55) + (ml_score * 45.0)

        # Boost risk if behavioral vector shows extreme activity
        if vector:
            if vector.failed_login_count >= 5.0:
                raw_risk += 10.0
                why_bullets.append(f"{int(vector.failed_login_count)} failed login attempts in rolling window")
            if vector.data_transfer_volume_mb >= 500.0:
                raw_risk += 10.0
                why_bullets.append(f"Massive data transfer volume ({vector.data_transfer_volume_mb:.1f} MB)")
            if vector.off_hours_flag > 0.0:
                why_bullets.append("Off-hours access context detected")
            if vector.privilege_change_events >= 1.0:
                why_bullets.append(f"{int(vector.privilege_change_events)} privilege escalation (sudo) attempt(s)")
            if vector.unique_destinations_count >= 5.0:
                why_bullets.append(f"Internal subnet probing across {int(vector.unique_destinations_count)} targets")

        if event.asset_criticality == AssetCriticality.HIGH:
            why_bullets.append(f"Target asset '{event.asset_id}' flagged as HIGH CRITICALITY (1.5x risk multiplier)")
        elif event.asset_criticality == AssetCriticality.MEDIUM:
            why_bullets.append(f"Target asset '{event.asset_id}' flagged as MEDIUM CRITICALITY")

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

        return (adjusted_risk, confidence, recommended_action, why_bullets)
