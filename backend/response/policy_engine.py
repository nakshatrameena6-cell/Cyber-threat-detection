from typing import Tuple, Dict, Any
from backend.models.response import DecisionTier, ResponseActionType, ActionStatus
from backend.models.incidents import ThreatCategory

class ResponsePolicyEngine:
    """
    Centralized Response Policy Engine.
    Evaluates threat signals against security policy rules establishing Tier A, Tier B, Tier C semantics.
    """
    @staticmethod
    def evaluate_policy(
        threat_category: ThreatCategory,
        risk_score: float,
        confidence_score: float,
        recommended_action_str: str
    ) -> Tuple[DecisionTier, ActionStatus, ResponseActionType, str, bool]:
        """
        Evaluates (DecisionTier, ActionStatus, ResponseActionType, PolicyReason, AutomationPermitted)
        """
        try:
            action_type = ResponseActionType(recommended_action_str)
        except ValueError:
            action_type = ResponseActionType.ALERT_ONLY

        # Tier A: Low Risk (< 40) or Alert Only
        if action_type == ResponseActionType.ALERT_ONLY or risk_score < 40.0:
            return (
                DecisionTier.TIER_A,
                ActionStatus.EXECUTED,
                ResponseActionType.ALERT_ONLY,
                "Policy Tier A (Low Risk / Alert Only): Informational alert logged without remediation action.",
                True
            )

        # Tier B: Moderate Risk (40 <= Risk <= 75) or Low Confidence (< 0.75)
        if risk_score <= 75.0 or confidence_score < 0.75:
            return (
                DecisionTier.TIER_B,
                ActionStatus.PENDING_APPROVAL,
                action_type,
                f"Policy Tier B (Moderate Risk {risk_score} / Confidence {confidence_score}): Requires Analyst Approval before execution.",
                False
            )

        # High Impact Action Policy Safeguard: Endpoint Isolation always requires Human Approval (Tier C Candidate)
        if action_type == ResponseActionType.ISOLATE_ENDPOINT:
            return (
                DecisionTier.TIER_C,
                ActionStatus.PENDING_APPROVAL,
                action_type,
                f"Policy Tier C (High Impact Action 'ISOLATE_ENDPOINT'): High Risk ({risk_score}). Policy requires Analyst Approval prior to host isolation.",
                False
            )

        # High Risk (> 75) & High Confidence (>= 0.75) -> Tier C Auto-Execution Candidate
        return (
            DecisionTier.TIER_C,
            ActionStatus.APPROVED,
            action_type,
            f"Policy Tier C (High Risk {risk_score} / High Confidence {confidence_score}): Automated containment candidate.",
            True
        )
