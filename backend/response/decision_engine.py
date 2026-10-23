from typing import Tuple
from backend.models.response import DecisionTier, ResponseActionType, ActionStatus
from backend.response.kill_switch import EmergencyKillSwitch

class DecisionEngine:
    @staticmethod
    def evaluate_tier(
        risk_score: float,
        confidence_score: float,
        recommended_action_str: str,
        is_anomaly_only: bool = False
    ) -> Tuple[DecisionTier, ActionStatus, ResponseActionType, str]:
        """
        Evaluates (DecisionTier, ActionStatus, ResponseActionType, Reason)
        Enforces Phase 4 Safety Semantics:
        - Tier A: fully automated execution permitted only for explicitly allowed, bounded actions (e.g. ALERT_ONLY).
        - Tier B: eligible low-to-medium-impact actions (e.g. bounded BLOCK_IP / SUSPEND_SESSION) execute automatically with notification.
        - Tier C: high impact (e.g. ISOLATE_ENDPOINT) or high risk requiring human approval. NEVER auto-executed.
        - IsolationForest anomaly score alone must never authorize remediation.
        """
        # Parse action type
        try:
            action_type = ResponseActionType(recommended_action_str)
        except ValueError:
            action_type = ResponseActionType.ALERT_ONLY

        # Safety Rule: IsolationForest anomaly score alone must never authorize remediation
        if is_anomaly_only and action_type != ResponseActionType.ALERT_ONLY:
            return (
                DecisionTier.TIER_C,
                ActionStatus.PENDING_APPROVAL,
                ResponseActionType.ALERT_ONLY,
                "Tier C (Safety Override): ML anomaly score alone cannot authorize remediation. Capped at Alert-Only / Human Review."
            )

        # Tier A: Low Risk (< 40) or Alert Only
        if action_type == ResponseActionType.ALERT_ONLY or risk_score < 40.0:
            return (
                DecisionTier.TIER_A,
                ActionStatus.EXECUTED,
                ResponseActionType.ALERT_ONLY,
                "Tier A: Low Risk (<40) or Informational Alert. Logged alert notification only."
            )

        # Tier C Safeguard: High Impact Action ISOLATE_ENDPOINT always requires Human Approval
        if action_type == ResponseActionType.ISOLATE_ENDPOINT:
            return (
                DecisionTier.TIER_C,
                ActionStatus.PENDING_APPROVAL,
                action_type,
                f"Tier C: High-impact action 'ISOLATE_ENDPOINT' (Risk: {risk_score}). Mandatory human analyst approval required."
            )

        # Emergency Kill Switch Check
        if EmergencyKillSwitch.is_active():
            return (
                DecisionTier.TIER_C,
                ActionStatus.PENDING_APPROVAL,
                action_type,
                f"Tier C (Kill Switch Active): Emergency Kill Switch is ACTIVE. Automated execution overridden -> Pending Human Approval."
            )

        # Low Confidence (< 0.75) fails closed to Tier C Human Approval
        if confidence_score < 0.75:
            return (
                DecisionTier.TIER_C,
                ActionStatus.PENDING_APPROVAL,
                action_type,
                f"Tier C: Low Confidence ({confidence_score} < 0.75). Fails closed -> Requires Analyst Approval before execution."
            )

        # Tier B: Eligible low-to-medium impact actions with high confidence (>= 0.75) execute automatically with notification
        if action_type in [ResponseActionType.BLOCK_IP, ResponseActionType.SUSPEND_SESSION]:
            return (
                DecisionTier.TIER_B,
                ActionStatus.APPROVED,
                action_type,
                f"Tier B: Eligible bounded action '{action_type.value}' (Risk: {risk_score}, Conf: {confidence_score}). Auto-execution permitted with immediate notification."
            )

        # Default fallback: Tier C Human Approval
        return (
            DecisionTier.TIER_C,
            ActionStatus.PENDING_APPROVAL,
            action_type,
            f"Tier C: Action requires human approval (Risk: {risk_score}, Conf: {confidence_score})."
        )
