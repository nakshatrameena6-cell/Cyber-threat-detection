"""Incident Correlation Engine (REQ-COR-001)."""
import uuid
from typing import List, Dict
from models.schemas.alert import ThreatAlert
from models.schemas.incident import CorrelatedIncident


class CorrelationEngine:
    """Groups threat alerts into unified incidents based on target entity identifiers."""

    def __init__(self):
        self._open_incidents: Dict[str, CorrelatedIncident] = {}

    def correlate_alert(self, alert: ThreatAlert) -> CorrelatedIncident:
        entity = alert.target_entity

        if entity in self._open_incidents:
            incident = self._open_incidents[entity]
            incident.alerts.append(alert)
            incident.confidence = max(incident.confidence, alert.confidence_score)
            if alert.severity == "CRITICAL" or incident.max_severity == "CRITICAL":
                incident.max_severity = "CRITICAL"
            elif alert.severity == "HIGH" and incident.max_severity != "CRITICAL":
                incident.max_severity = "HIGH"
            return incident

        # Create new incident
        new_incident = CorrelatedIncident(
            incident_id=f"inc-{uuid.uuid4().hex[:8]}",
            title=f"Suspicious activity detected on entity {entity}",
            target_entity=entity,
            alerts=[alert],
            confidence=alert.confidence_score,
            max_severity=alert.severity,
            status="OPEN"
        )
        self._open_incidents[entity] = new_incident
        return new_incident
