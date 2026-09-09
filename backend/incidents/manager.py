import uuid
from typing import Dict, List, Optional
from datetime import datetime, timezone
from backend.models.incidents import Incident, IncidentStatus, Severity, ThreatCategory

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
        behavioral_evidence: Optional[List[str]] = None
    ) -> Incident:
        inc_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        incident = Incident(
            incident_id=inc_id,
            event_id=event_id,
            threat_category=threat_category,
            severity=severity,
            risk_score=risk_score,
            confidence_score=confidence_score,
            source_ip=source_ip,
            user_id=user_id,
            asset_id=asset_id,
            details=details,
            status=IncidentStatus.NEW,
            created_at=datetime.now(timezone.utc).isoformat(),
            recommended_action=recommended_action,
            decision_tier=decision_tier,
            action_executed=False,
            is_anomalous=is_anomalous,
            behavioral_evidence=behavioral_evidence or []
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

    def update_status(self, incident_id: str, new_status: IncidentStatus, assigned_to: Optional[str] = None) -> Optional[Incident]:
        incident = self._incidents.get(incident_id)
        if incident:
            incident.status = new_status
            if assigned_to:
                incident.assigned_to = assigned_to
        return incident

    def mark_action_executed(self, incident_id: str) -> Optional[Incident]:
        incident = self._incidents.get(incident_id)
        if incident:
            incident.action_executed = True
            incident.status = IncidentStatus.MITIGATED
        return incident
