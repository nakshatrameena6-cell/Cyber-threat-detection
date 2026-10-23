import ipaddress
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
from backend.models.events import NormalizedEvent
from backend.models.incidents import Incident, IncidentStatus, Severity, ThreatCategory

class IncidentCorrelationEngine:
    """
    Deterministic Incident Correlation Engine.
    Correlates related security telemetry events by user, source IP, asset,
    or common CIDR subnet (Requirement D) within a sliding time window (10 minutes).
    """
    def __init__(
        self,
        correlation_window_seconds: float = 600.0,
        ipv4_cidr_prefix: int = 24,
        ipv6_cidr_prefix: int = 64
    ):
        self.window_seconds = correlation_window_seconds
        self.ipv4_cidr_prefix = ipv4_cidr_prefix
        self.ipv6_cidr_prefix = ipv6_cidr_prefix

    @staticmethod
    def is_same_subnet(
        ip1_str: str,
        ip2_str: str,
        v4_prefix: int = 24,
        v6_prefix: int = 64
    ) -> Tuple[bool, Optional[str]]:
        """
        Determines whether two IP strings belong to the same IPv4 or IPv6 subnet.
        Returns (is_same, subnet_cidr_string).
        """
        if not ip1_str or not ip2_str:
            return False, None
        if ip1_str in ["0.0.0.0", "unknown"] or ip2_str in ["0.0.0.0", "unknown"]:
            return False, None

        try:
            ip1 = ipaddress.ip_address(ip1_str)
            ip2 = ipaddress.ip_address(ip2_str)
            if ip1.version != ip2.version:
                return False, None

            prefix = v4_prefix if ip1.version == 4 else v6_prefix
            net1 = ipaddress.ip_network(f"{ip1}/{prefix}", strict=False)
            net2 = ipaddress.ip_network(f"{ip2}/{prefix}", strict=False)

            if net1 == net2:
                return True, str(net1)
            return False, None
        except ValueError:
            return False, None

    def find_correlatable_incident(
        self,
        event: NormalizedEvent,
        active_incidents: List[Incident],
        threat_cat: Optional[ThreatCategory] = None
    ) -> Optional[Incident]:
        """
        Finds an existing open incident that correlates with the incoming event.
        Preserves backward compatibility returning Optional[Incident], while recording
        explainable correlation reason in self.last_correlation_reason.
        """
        inc, reason = self.find_correlatable_incident_with_reason(event, active_incidents, threat_cat)
        self.last_correlation_reason = reason
        return inc

    def find_correlatable_incident_with_reason(
        self,
        event: NormalizedEvent,
        active_incidents: List[Incident],
        threat_cat: Optional[ThreatCategory] = None
    ) -> Tuple[Optional[Incident], Optional[str]]:
        """
        Finds an existing open incident and returns (incident, correlation_reason).
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

            # 1. Exact entity correlation matches
            user_match = bool(event.user_id and event.user_id != "unknown" and event.user_id == inc.user_id)
            ip_match = bool(event.source_ip and event.source_ip != "0.0.0.0" and event.source_ip == inc.source_ip)
            asset_match = bool(event.asset_id and event.asset_id != "unspecified-host" and event.asset_id == inc.asset_id)

            if user_match:
                return inc, f"Exact user account match: {event.user_id}"
            if ip_match:
                return inc, f"Exact source IP match: {event.source_ip}"
            if asset_match and (user_match or ip_match or (threat_cat and threat_cat in inc.threat_categories)):
                return inc, f"Target asset match with shared context: {event.asset_id}"

            # 2. Context-aware Subnet Distributed Correlation (Requirement D)
            same_subnet, subnet_cidr = self.is_same_subnet(
                event.source_ip,
                inc.source_ip,
                self.ipv4_cidr_prefix,
                self.ipv6_cidr_prefix
            )

            if same_subnet:
                # Subnet grouping is an additional correlation signal, NOT an unconditional incident merger.
                # Requires corroborating contextual evidence to prevent merging unrelated campaigns:
                has_common_target = bool(event.asset_id and event.asset_id != "unspecified-host" and event.asset_id == inc.asset_id)
                has_common_threat = bool(threat_cat and threat_cat in inc.threat_categories)
                has_common_user = bool(event.user_id and event.user_id != "unknown" and event.user_id == inc.user_id)

                if has_common_target or has_common_threat or has_common_user:
                    reason = f"Distributed subnet campaign ({subnet_cidr}) with corroborated context"
                    if has_common_target:
                        reason += f" targeting shared asset '{event.asset_id}'"
                    elif has_common_threat:
                        reason += f" sharing threat category '{threat_cat.value}'"
                    return inc, reason

        return None, None


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

        # Append correlation reason if available
        corr_reason = getattr(self, "last_correlation_reason", None)
        if corr_reason and corr_reason not in incident.why_evidence:
            incident.why_evidence.append(corr_reason)

        # Escalation boost for multi-event correlated attacks
        multi_event_boost = min(15.0, (len(incident.related_events) - 1) * 5.0)
        incident.risk_score = round(min(100.0, max(incident.risk_score, new_risk) + multi_event_boost), 1)
        incident.confidence_score = round(max(incident.confidence_score, new_confidence), 2)

        # Update severity if escalated
        if incident.risk_score >= 85.0:
            incident.severity = Severity.CRITICAL
        elif incident.risk_score >= 70.0:
            incident.severity = Severity.HIGH

        # Add timeline entry with explainable correlation note
        desc = f"Correlated event: {event.event_type.value} from {event.source_ip} targeting {event.asset_id}."
        if corr_reason:
            desc += f" Reason: {corr_reason}."
        desc += f" {event.details}"

        timeline_entry = {
            "timestamp": event.timestamp,
            "event_id": event.event_id,
            "event_type": event.event_type.value,
            "description": desc,
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
