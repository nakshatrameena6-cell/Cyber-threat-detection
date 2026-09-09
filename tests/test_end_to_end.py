import pytest
from backend.main import process_telemetry_pipeline
from backend.models.response import ActionStatus, VerificationStatus

def test_full_pipeline_high_risk_auto_execution():
    raw_c2 = {
        "raw_id": "E2E-C2-001",
        "timestamp": "2026-09-09T05:00:00Z",
        "source_ip": "10.0.9.99",
        "user_id": "infected_host",
        "event_type": "C2_BEACON",
        "asset_id": "finance-workstation",
        "asset_criticality": "HIGH",
        "payload_metric": 15.0,
        "details": "High-frequency beaconing to malicious C2 domain"
    }

    resp = process_telemetry_pipeline(raw_c2, actor="E2E_TEST", role="ADMIN")
    assert resp.threat_detected is True
    assert resp.incident is not None
    assert resp.incident.risk_score >= 75.0
    assert resp.response_record is not None
    assert resp.response_record.status == ActionStatus.EXECUTED
    assert resp.response_record.verification_status == VerificationStatus.PASSED

def test_full_pipeline_medium_risk_human_approval():
    raw_susp = {
        "raw_id": "E2E-SUSP-002",
        "timestamp": "2026-09-09T03:00:00Z",
        "source_ip": "198.51.100.12",
        "user_id": "employee_bob",
        "event_type": "SUSPICIOUS_LOGIN",
        "asset_id": "vpn-portal",
        "asset_criticality": "MEDIUM",
        "payload_metric": 1.0,
        "details": "Login attempt from unexpected country code"
    }

    resp = process_telemetry_pipeline(raw_susp, actor="E2E_TEST", role="ADMIN")
    assert resp.threat_detected is True
    assert resp.incident is not None
    # Tier B medium risk should require analyst approval (response record not auto-executed)
    assert resp.response_record is None
    assert resp.incident.action_executed is False
