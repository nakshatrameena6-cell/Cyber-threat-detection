import pytest
from backend.main import process_telemetry_pipeline
from backend.models.incidents import IncidentStatus
from backend.models.response import ActionStatus, VerificationStatus

def test_phase3_multi_stage_attack_correlation_pipeline():
    user_id = "attacker_target"
    ip = "198.51.100.200"
    asset = "finance-db-server"

    # Step 1: Failed Logins
    raw1 = {
        "raw_id": "P3-01",
        "timestamp": "2026-09-10T09:00:00Z",
        "source_ip": ip,
        "user_id": user_id,
        "event_type": "LOGIN_FAILED",
        "asset_id": asset,
        "asset_criticality": "HIGH",
        "payload_metric": 5.0,
        "details": "5 consecutive failed logins"
    }
    resp1 = process_telemetry_pipeline(raw1, actor="E2E_SIM", role="ADMIN")
    assert resp1.threat_detected is True
    inc1 = resp1.incident
    assert inc1 is not None

    # Step 2: Auth Success (same user & IP within 2 mins)
    raw2 = {
        "raw_id": "P3-02",
        "timestamp": "2026-09-10T09:02:00Z",
        "source_ip": ip,
        "user_id": user_id,
        "event_type": "AUTH_SUCCESS",
        "asset_id": asset,
        "asset_criticality": "HIGH",
        "payload_metric": 1.0,
        "details": "Successful login after failed attempts"
    }
    resp2 = process_telemetry_pipeline(raw2, actor="E2E_SIM", role="ADMIN")
    inc2 = resp2.incident
    assert inc2.incident_id == inc1.incident_id # Correlated!

    # Step 3: Privilege Escalation
    raw3 = {
        "raw_id": "P3-03",
        "timestamp": "2026-09-10T09:03:00Z",
        "source_ip": ip,
        "user_id": user_id,
        "event_type": "SUDO_EXEC",
        "asset_id": asset,
        "asset_criticality": "HIGH",
        "payload_metric": 1.0,
        "details": "sudo su root escalation"
    }
    resp3 = process_telemetry_pipeline(raw3, actor="E2E_SIM", role="ADMIN")
    inc3 = resp3.incident
    assert inc3.incident_id == inc1.incident_id

    # Step 4: Massive Data Exfiltration (950 MB)
    raw4 = {
        "raw_id": "P3-04",
        "timestamp": "2026-09-10T09:04:00Z",
        "source_ip": ip,
        "user_id": user_id,
        "event_type": "BYTES_OUT",
        "asset_id": asset,
        "asset_criticality": "HIGH",
        "payload_metric": 950.0,
        "details": "Exfiltration of 950 MB customer archive"
    }
    resp4 = process_telemetry_pipeline(raw4, actor="E2E_SIM", role="ADMIN")
    final_inc = resp4.incident

    # Assert Correlation & Timeline Capabilities
    assert final_inc.incident_id == inc1.incident_id
    assert len(final_inc.related_events) == 4
    assert len(final_inc.timeline) >= 4
    assert final_inc.risk_score >= 85.0

    # Assert Transparent "Why" Evidence
    assert len(final_inc.why_evidence) > 0
    assert any("failed login" in why.lower() for why in final_inc.why_evidence)
    assert any("exfiltration" in why.lower() or "950" in why.lower() for why in final_inc.why_evidence)
