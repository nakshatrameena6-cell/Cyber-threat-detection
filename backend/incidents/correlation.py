from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
from backend.models.events import NormalizedEvent
from backend.models.incidents import Incident, IncidentStatus, Severity, ThreatCategory

class IncidentCorrelationEngine:
    """
    Deterministic Incident Correlation Engine.
    Correlates related security telemetry events by user, source IP, or asset within a sliding time window (10 minutes).
    """
    def __init__(self, correlation_window_seconds: float = 600.0):
        self.window_seconds = correlation_window_seconds

    def find_correlatable_incident(self, event: NormalizedEvent, active_incidents: List[Incident]) -> Optional[Incident]:
        """
        Finds an existing open incident that correlates with the incoming event.
        """
        try:
            evt_time = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
        except Exception:
            evt_time = datetime.now(timezone.utc)

        for inc in active_incidents:
            # Skip resolved or false-positive incidents
            if inc.status in [IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE]:
                continue

            # Check time window
            try:
                last_time = datetime.fromisoformat(inc.last_seen.replace("Z", "+00:00"))
            except Exception:
                last_time = datetime.now(timezone.utc)

            time_diff = abs((evt_time - last_time).total_seconds())
            if time_diff > self.window_seconds:
                continue

            # Correlation match signals
            user_match = (event.user_id and event.user_id != "unknown" and event.user_id == inc.user_id)
            ip_match = (event.source_ip and event.source_ip != "0.0.0.0" and event.source_ip == inc.source_ip)
            asset_match = (event.asset_id and event.asset_id != "unspecified-host" and event.asset_id == inc.asset_id)

            if user_match or ip_match or asset_match:
                return inc

        return None

    def merge_event_into_incident(
        self,
        incident: Incident,
        event: NormalizedEvent,
        threat_cat: ThreatCategory,
        new_risk: float,
        new_confidence: float,
        evidence: List[str],
        why_bullets: List[str]
    ) -> Incident:
        """
        Merges a correlated event into an existing incident, updating timeline and escalating risk.
        """
        # Update timestamps
        incident.last_seen = event.timestamp
        if event.event_id not in incident.related_events:
            incident.related_events.append(event.event_id)

        # Update threat categories
        if threat_cat not in incident.threat_categories:
            incident.threat_categories.append(threat_cat)

        # Aggregate evidence tags uniquely
        for tag in evidence:
            if tag not in incident.behavioral_evidence:
                incident.behavioral_evidence.append(tag)

        for why in why_bullets:
            if why not in incident.why_evidence:
                incident.why_evidence.append(why)

        # Escalation boost for multi-event correlated attacks
        multi_event_boost = min(15.0, (len(incident.related_events) - 1) * 5.0)
        incident.risk_score = round(min(100.0, max(incident.risk_score, new_risk) + multi_event_boost), 1)
        incident.confidence_score = round(max(incident.confidence_score, new_confidence), 2)

        # Update severity if escalated
        if incident.risk_score >= 85.0:
            incident.severity = Severity.CRITICAL
        elif incident.risk_score >= 70.0:
            incident.severity = Severity.HIGH

        # Add timeline entry
        timeline_entry = {
            "timestamp": event.timestamp,
            "event_id": event.event_id,
            "event_type": event.event_type.value,
            "description": f"Correlated event: {event.event_type.value} from {event.source_ip} targeting {event.asset_id}. {event.details}",
            "threat_category": threat_cat.value,
            "risk_score": new_risk
        }
        incident.timeline.append(timeline_entry)
        
        return incident

    def record_duplicate_observation(self, incident: Incident, event: NormalizedEvent) -> Incident:
        """
        Appends a duplicate-observation record to an existing incident timeline
        and increments the incident's duplicate suppression counter without
        modifying risk or triggering repeated response actions (Requirement B).
        """
        incident.duplicate_events_count += 1
        if event.event_id not in incident.suppressed_duplicates:
            incident.suppressed_duplicates.append(event.event_id)

        incident.last_seen = event.timestamp
        timeline_entry = {
            "timestamp": event.timestamp,
            "event_id": event.event_id,
            "event_type": event.event_type.value,
            "description": f"Duplicate observation suppressed within sliding window ({incident.duplicate_events_count} total duplicates observed). Original response remains in effect.",
            "threat_category": incident.threat_category.value,
            "is_duplicate": True,
            "risk_score": incident.risk_score
        }
        incident.timeline.append(timeline_entry)
        return incident
