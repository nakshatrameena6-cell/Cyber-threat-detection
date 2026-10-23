from typing import Tuple, Dict, Any, Optional
from backend.models.response import DecisionTier, ResponseActionType, ActionStatus
from backend.models.incidents import ThreatCategory
from backend.response.kill_switch import EmergencyKillSwitch

class ResponsePolicyEngine:
    """
    Centralized Response Policy Engine.
    Evaluates threat signals against security policy rules establishing strict Tier A, Tier B, Tier C semantics:
    - Tier A: fully automated execution permitted only for explicitly allowed, bounded actions (ALERT_ONLY).
    - Tier B: eligible low-to-medium-impact actions (e.g. bounded BLOCK_IP / SUSPEND_SESSION) execute automatically with notification.
    - Tier C: high impact (e.g. ISOLATE_ENDPOINT) or high risk requiring human approval. NEVER auto-executed.
    - IsolationForest anomaly score alone must never authorize remediation.
    - Missing, ambiguous or unreliable detection information fails closed to Tier C (human review).
    """
    @staticmethod
    def evaluate_policy(
        threat_category: Optional[ThreatCategory],
        risk_score: float,
        confidence_score: float,
        recommended_action_str: str,
        is_anomaly_only: bool = False
    ) -> Tuple[DecisionTier, ActionStatus, ResponseActionType, str, bool]:
        """
        Evaluates (DecisionTier, ActionStatus, ResponseActionType, PolicyReason, AutomationPermitted)
        """
        try:
            action_type = ResponseActionType(recommended_action_str)
        except (ValueError, TypeError):
            # Fail closed on missing/unrecognized action
            action_type = ResponseActionType.ALERT_ONLY

        # Fail closed on missing or invalid threat category
        if not threat_category or threat_category == ThreatCategory.NONE:
            is_anomaly_only = True

        # Safety Rule: IsolationForest anomaly score alone must never authorize remediation
        if is_anomaly_only and action_type != ResponseActionType.ALERT_ONLY:
            return (
                DecisionTier.TIER_C,
                ActionStatus.PENDING_APPROVAL,
                ResponseActionType.ALERT_ONLY,
                "Policy Tier C (Safety Override): ML anomaly score alone cannot authorize remediation. Capped at Alert-Only / Human Review.",
                False
            )

        # Tier A: Low Risk (< 40) or Alert Only
        if action_type == ResponseActionType.ALERT_ONLY or risk_score < 40.0:
            return (
                DecisionTier.TIER_A,
                ActionStatus.EXECUTED,
                ResponseActionType.ALERT_ONLY,
                "Policy Tier A (Low Risk / Alert Only): Informational alert logged without remediation action.",
                True
            )

        # High Impact Action Safeguard: Endpoint Isolation ALWAYS requires Human Approval (Tier C)
        if action_type == ResponseActionType.ISOLATE_ENDPOINT:
            return (
                DecisionTier.TIER_C,
                ActionStatus.PENDING_APPROVAL,
                action_type,
                f"Policy Tier C (High Impact Action 'ISOLATE_ENDPOINT'): High Risk ({risk_score}). Policy mandates Human Analyst Approval prior to host isolation.",
                False
            )

        # Emergency Kill Switch Check
        if EmergencyKillSwitch.is_active():
            return (
                DecisionTier.TIER_C,
                ActionStatus.PENDING_APPROVAL,
                action_type,
                f"Policy Tier C (Kill Switch Active): Emergency Kill Switch is ACTIVE. Automated response prohibited -> Analyst Review Required.",
                False
            )

        # Low Confidence (< 0.75) fails closed to Tier C (human approval)
        if confidence_score < 0.75:
            return (
                DecisionTier.TIER_C,
                ActionStatus.PENDING_APPROVAL,
                action_type,
                f"Policy Tier C (Low Confidence {confidence_score} < 0.75): Ambiguous/uncertain threat. Requires Analyst Review before execution.",
                False
            )

        # Tier B: Eligible low-to-medium impact actions with high confidence (>= 0.75) execute automatically with notification
        if action_type in [ResponseActionType.BLOCK_IP, ResponseActionType.SUSPEND_SESSION]:
            return (
                DecisionTier.TIER_B,
                ActionStatus.APPROVED,
                action_type,
                f"Policy Tier B (Bounded Action '{action_type.value}'): Risk {risk_score}, Conf {confidence_score}. Auto-execution permitted with immediate notification.",
                True
            )

        # Fallback: Tier C Human Approval
        return (
            DecisionTier.TIER_C,
            ActionStatus.PENDING_APPROVAL,
            action_type,
            f"Policy Tier C: Human Approval Required for action '{action_type.value}' (Risk: {risk_score}).",
            False
        )
