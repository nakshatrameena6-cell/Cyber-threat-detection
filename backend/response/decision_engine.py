from typing import Tuple
from backend.models.response import DecisionTier, ResponseActionType, ActionStatus
from backend.response.kill_switch import EmergencyKillSwitch

class DecisionEngine:
    @staticmethod
    def evaluate_tier(
        risk_score: float,
        confidence_score: float,
        recommended_action_str: str
    ) -> Tuple[DecisionTier, ActionStatus, ResponseActionType, str]:
        """
        Evaluates (DecisionTier, ActionStatus, ResponseActionType, Reason)
        """
        # Parse action type
        try:
            action_type = ResponseActionType(recommended_action_str)
        except ValueError:
            action_type = ResponseActionType.ALERT_ONLY

        if action_type == ResponseActionType.ALERT_ONLY or risk_score < 40.0:
            return (
                DecisionTier.TIER_A,
                ActionStatus.EXECUTED,
                ResponseActionType.ALERT_ONLY,
                "Tier A: Low Risk (<40). Logged alert notification only."
            )

        if risk_score <= 75.0 or confidence_score < 0.75:
            return (
                DecisionTier.TIER_B,
                ActionStatus.PENDING_APPROVAL,
                action_type,
                f"Tier B: Moderate Risk ({risk_score}) / Confidence ({confidence_score}). Requires Analyst Approval before execution."
            )

        # High Risk (> 75) & High Confidence (>= 0.75) -> Tier C
        # Check Emergency Kill Switch
        if EmergencyKillSwitch.is_active():
            return (
                DecisionTier.TIER_C,
                ActionStatus.PENDING_APPROVAL,
                action_type,
                f"Tier C High Risk ({risk_score}), BUT Emergency Kill Switch is ACTIVE. Automated execution overridden -> Pending Human Approval."
            )

        return (
            DecisionTier.TIER_C,
            ActionStatus.APPROVED,  # Ready for auto execution
            action_type,
            f"Tier C: High Risk ({risk_score}) & High Confidence ({confidence_score}). Auto-execution triggered."
        )
