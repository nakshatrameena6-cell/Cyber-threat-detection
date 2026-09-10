import uuid
from typing import Dict, List, Optional
from datetime import datetime, timezone
from backend.models.incidents import Incident, IncidentStatus, Severity, ThreatCategory, VALID_TRANSITIONS

class IncidentManager:
    def __init__(self):
        self._incidents: Dict[str, Incident] = {}

    def create_incident(
        self,
        event_id: str,
        threat_category: ThreatCategory,
        severity: Severity,
        risk_score: float,
        confidence_score: float,
        source_ip: str,
        user_id: str,
        asset_id: str,
        details: str,
        recommended_action: str,
        decision_tier: str,
        is_anomalous: bool = True,
        behavioral_evidence: Optional[List[str]] = None,
        why_evidence: Optional[List[str]] = None,
        event_timestamp: Optional[str] = None
    ) -> Incident:
        inc_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        now_str = datetime.now(timezone.utc).isoformat()
        ts_str = event_timestamp or now_str
        
        incident = Incident(
            incident_id=inc_id,
            event_id=event_id,
            threat_category=threat_category,
            threat_categories=[threat_category],
            severity=severity,
            risk_score=risk_score,
            confidence_score=confidence_score,
            source_ip=source_ip,
            user_id=user_id,
            affected_user=user_id,
            asset_id=asset_id,
            affected_endpoint=asset_id,
            details=details,
            status=IncidentStatus.NEW,
            created_at=now_str,
            first_seen=ts_str,
            last_seen=ts_str,
            recommended_action=recommended_action,
            decision_tier=decision_tier,
            action_executed=False,
            is_anomalous=is_anomalous,
            behavioral_evidence=behavioral_evidence or [],
            why_evidence=why_evidence or [],
            related_events=[event_id],
            timeline=[{
                "timestamp": ts_str,
                "event_id": event_id,
                "event_type": "INCIDENT_CREATED",
                "description": f"Incident created for threat '{threat_category.value}' (Risk: {risk_score})",
                "threat_category": threat_category.value,
                "risk_score": risk_score
            }]
        )
        self._incidents[inc_id] = incident
        return incident

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self._incidents.get(incident_id)

    def list_incidents(self, status: Optional[IncidentStatus] = None) -> List[Incident]:
        incidents = list(self._incidents.values())
        if status:
            incidents = [inc for inc in incidents if inc.status == status]
        return sorted(incidents, key=lambda x: x.created_at, reverse=True)

    def update_status(self, incident_id: str, new_status: IncidentStatus, assigned_to: Optional[str] = None) -> Incident:
        incident = self._incidents.get(incident_id)
        if not incident:
            raise KeyError(f"Incident '{incident_id}' not found.")

        # Enforce valid lifecycle transitions
        allowed = VALID_TRANSITIONS.get(incident.status, [])
        if new_status not in allowed:
            raise ValueError(f"Invalid state transition: Cannot change status from '{incident.status.value}' to '{new_status.value}'. Allowed: {[s.value for s in allowed]}")

        incident.status = new_status
        if assigned_to:
            incident.assigned_to = assigned_to

        now_str = datetime.now(timezone.utc).isoformat()
        incident.timeline.append({
            "timestamp": now_str,
            "event_id": f"SYS-{uuid.uuid4().hex[:6]}",
            "event_type": "STATUS_CHANGED",
            "description": f"Incident status changed to '{new_status.value}' by {assigned_to or 'SYSTEM'}",
            "threat_category": incident.threat_category.value,
            "risk_score": incident.risk_score
        })
        return incident

    def mark_action_executed(self, incident_id: str) -> Optional[Incident]:
        incident = self._incidents.get(incident_id)
        if incident:
            incident.action_executed = True
            try:
                self.update_status(incident_id, IncidentStatus.MITIGATED, assigned_to="AUTO_ENGINE")
            except ValueError:
                incident.status = IncidentStatus.MITIGATED
        return incident
