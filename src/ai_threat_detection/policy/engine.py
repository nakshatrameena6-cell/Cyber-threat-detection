"""Policy & Response-Tier Engine (REQ-POL-001, REQ-POL-002)."""
from models.schemas.incident import CorrelatedIncident
from models.schemas.policy import PolicyDecision


class PolicyEngine:
    """Evaluates incident risk scores against policy tiers and enforces safety limits."""

    def evaluate_policy(self, incident: CorrelatedIncident) -> PolicyDecision:
        risk = incident.risk_score if incident.risk_score is not None else 1.0

        if risk < 0.30:
            return PolicyDecision(
                incident_id=incident.incident_id,
                risk_score=risk,
                response_tier="ALERT_ONLY",
                recommended_actions=["tag_siem_event", "send_slack_notification"],
                requires_human_approval=False,
                reasoning="Low risk incident; auto-notification allowed."
            )
        elif risk < 0.70:
            return PolicyDecision(
                incident_id=incident.incident_id,
                risk_score=risk,
                response_tier="HUMAN_REVIEW",
                recommended_actions=["create_jira_ticket", "enrich_ip_reputation"],
                requires_human_approval=True,
                reasoning="Medium risk incident; routed for analyst review."
            )
        else:
            # REQ-POL-002: Autonomous containment is forbidden in MVP
            return PolicyDecision(
                incident_id=incident.incident_id,
                risk_score=risk,
                response_tier="CONTAINMENT_PROPOSAL",
                recommended_actions=["propose_host_isolation", "propose_user_suspension"],
                requires_human_approval=True,  # HARD MVP SAFETY GUARD
                reasoning="High risk incident; containment proposed. Requires human authorization."
            )
