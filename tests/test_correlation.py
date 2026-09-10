import pytest
from backend.detection.normalizer import EventNormalizer
from backend.incidents.correlation import IncidentCorrelationEngine
from backend.incidents.manager import IncidentManager
from backend.models.incidents import ThreatCategory, Severity, IncidentStatus

def test_incident_correlation_same_user():
    mgr = IncidentManager()
    corr = IncidentCorrelationEngine(correlation_window_seconds=600.0)

    raw1 = {"raw_id": "CORR-01", "timestamp": "2026-09-10T10:00:00Z", "source_ip": "10.0.0.1", "user_id": "attacker_john", "event_type": "LOGIN_FAILED", "payload_metric": 5.0}
    norm1, _ = EventNormalizer.normalize(raw1)

    inc1 = mgr.create_incident(
        event_id=norm1.event_id,
        threat_category=ThreatCategory.BRUTE_FORCE,
        severity=Severity.HIGH,
        risk_score=75.0,
        confidence_score=0.85,
        source_ip=norm1.source_ip,
        user_id=norm1.user_id,
        asset_id=norm1.asset_id,
        details="Initial brute force event",
        recommended_action="BLOCK_IP",
        decision_tier="TIER_C"
    )

    # Second event for same user 2 minutes later
    raw2 = {"raw_id": "CORR-02", "timestamp": "2026-09-10T10:02:00Z", "source_ip": "10.0.0.1", "user_id": "attacker_john", "event_type": "SUDO_EXEC", "details": "sudo su root"}
    norm2, _ = EventNormalizer.normalize(raw2)

    found_inc = corr.find_correlatable_incident(norm2, mgr.list_incidents())
    assert found_inc is not None
    assert found_inc.incident_id == inc1.incident_id

    merged = corr.merge_event_into_incident(
        found_inc, norm2, ThreatCategory.PRIVILEGE_ESCALATION, new_risk=85.0, new_confidence=0.90, evidence=["Privilege escalation attempt"], why_bullets=["sudo su root executed"]
    )
    assert len(merged.related_events) == 2
    assert len(merged.timeline) == 2
    assert ThreatCategory.PRIVILEGE_ESCALATION in merged.threat_categories

def test_unrelated_events_do_not_correlate():
    mgr = IncidentManager()
    corr = IncidentCorrelationEngine(correlation_window_seconds=600.0)

    raw1 = {"raw_id": "CORR-10", "timestamp": "2026-09-10T10:00:00Z", "source_ip": "1.1.1.1", "user_id": "user_a", "asset_id": "host-a", "event_type": "LOGIN_FAILED", "payload_metric": 5.0}
    norm1, _ = EventNormalizer.normalize(raw1)
    inc1 = mgr.create_incident(
        event_id=norm1.event_id, threat_category=ThreatCategory.BRUTE_FORCE, severity=Severity.HIGH,
        risk_score=75.0, confidence_score=0.85, source_ip=norm1.source_ip, user_id=norm1.user_id,
        asset_id=norm1.asset_id, details="Brute force", recommended_action="BLOCK_IP", decision_tier="TIER_C"
    )

    # Completely different user, IP, and asset
    raw2 = {"raw_id": "CORR-20", "timestamp": "2026-09-10T10:01:00Z", "source_ip": "2.2.2.2", "user_id": "user_b", "asset_id": "host-b", "event_type": "C2_BEACON", "details": "c2 domain"}
    norm2, _ = EventNormalizer.normalize(raw2)

    found_inc = corr.find_correlatable_incident(norm2, mgr.list_incidents())
    assert found_inc is None

def test_time_window_correlation_expiry():
    mgr = IncidentManager()
    corr = IncidentCorrelationEngine(correlation_window_seconds=300.0) # 5 min window

    raw1 = {"raw_id": "CORR-30", "timestamp": "2026-09-10T10:00:00Z", "source_ip": "10.0.0.5", "user_id": "user_c", "event_type": "LOGIN_FAILED", "payload_metric": 5.0}
    norm1, _ = EventNormalizer.normalize(raw1)
    mgr.create_incident(
        event_id=norm1.event_id, threat_category=ThreatCategory.BRUTE_FORCE, severity=Severity.HIGH,
        risk_score=75.0, confidence_score=0.85, source_ip=norm1.source_ip, user_id=norm1.user_id,
        asset_id=norm1.asset_id, details="Brute force", recommended_action="BLOCK_IP", decision_tier="TIER_C"
    )

    # Same user 15 minutes later (> 5 min window)
    raw2 = {"raw_id": "CORR-40", "timestamp": "2026-09-10T10:15:00Z", "source_ip": "10.0.0.5", "user_id": "user_c", "event_type": "BYTES_OUT", "payload_metric": 800.0}
    norm2, _ = EventNormalizer.normalize(raw2)

    found_inc = corr.find_correlatable_incident(norm2, mgr.list_incidents())
    assert found_inc is None
