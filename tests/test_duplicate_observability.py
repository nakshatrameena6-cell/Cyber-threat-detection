"""
Suraksha AI - Phase 6 Test Suite: Duplicate Event Observability & Correlation (Requirement B)
Verifies:
- Observable duplicate suppression counters
- Zero duplicate incident spawning
- Safe duplicate observation timeline attachment
- Repeated ingestion idempotency
- Zero duplicate remediation authorization
- Handling duplicates before and after incident creation
- Telemetry stats API exposure
- Database persistence and restart recovery of duplicate counts
"""
import os
import tempfile
import pytest
from datetime import datetime, timezone

from backend.database import DatabaseManager
from backend.models.events import NormalizedEvent, EventType, AssetCriticality
from backend.models.incidents import ThreatCategory, Severity, IncidentStatus
from backend.incidents.manager import IncidentManager
from backend.incidents.correlation import IncidentCorrelationEngine
from backend.main import process_telemetry_pipeline, app, incident_manager
from fastapi.testclient import TestClient

client = TestClient(app)


@pytest.fixture
def clean_db():
    temp_file = tempfile.NamedTemporaryFile(suffix="_dup_test.db", delete=False)
    db_path = temp_file.name
    temp_file.close()

    db = DatabaseManager(db_path)
    db.initialize_db()
    yield db

    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except Exception:
            pass


def make_raw_log(raw_id: str, timestamp_str: str, source_ip: str = "198.51.100.99") -> dict:
    return {
        "raw_id": raw_id,
        "timestamp": timestamp_str,
        "source_ip": source_ip,
        "destination_ip": "10.0.0.5",
        "user_id": "test_target",
        "event_type": "LOGIN_FAILED",
        "asset_id": "auth-server",
        "asset_criticality": "HIGH",
        "payload_metric": 8.0,
        "details": "Brute force attack wave"
    }


def test_duplicate_suppression_and_timeline_correlation():
    """
    Requirement B.1 - B.4:
    First event creates an incident. Second identical event in sliding window is suppressed from detection,
    does NOT create a second incident, but attaches a duplicate observation to the incident timeline.
    """
    raw1 = make_raw_log("RAW-DUP-01", "2026-10-23T10:00:00Z", "198.51.100.123")
    res1 = process_telemetry_pipeline(raw1, actor="TEST_AGENT", role="ANALYST")

    assert res1.is_duplicate is False
    assert res1.threat_detected is True
    assert res1.incident is not None
    inc_id = res1.incident.incident_id
    initial_dup_count = res1.incident.duplicate_events_count
    assert initial_dup_count == 0

    # Second event arriving 5 seconds later with identical parameters (triggers sliding window deduplication)
    raw2 = make_raw_log("RAW-DUP-02", "2026-10-23T10:00:05Z", "198.51.100.123")
    res2 = process_telemetry_pipeline(raw2, actor="TEST_AGENT", role="ANALYST")

    assert res2.is_duplicate is True
    assert res2.threat_detected is False  # Does not manufacture threat
    assert res2.incident is None  # Does NOT create a second incident
    assert res2.response_record is None  # Zero response action executed

    # Check that the existing incident timeline and duplicate count were updated
    import backend.main as main_mod
    stored_inc = main_mod.incident_manager.get_incident(inc_id)
    assert stored_inc is not None
    assert stored_inc.duplicate_events_count >= 1

    dup_entries = [tl for tl in stored_inc.timeline if tl.get("event_type") == "DUPLICATE_OBSERVATION" or tl.get("is_duplicate")]
    assert len(dup_entries) >= 1
    assert dup_entries[-1]["event_id"] == res2.normalized_event.event_id


def test_duplicate_before_incident_creation():
    """
    Requirement B.6: Duplicate events that arrive before any correlatable incident has been created
    are cleanly suppressed without errors and return incident=None.
    """
    # Benign normal event
    benign_raw1 = {
        "raw_id": "BENIGN-DUP-01",
        "timestamp": "2026-10-23T11:00:00Z",
        "source_ip": "10.0.1.55",
        "destination_ip": "10.0.0.2",
        "user_id": "normal_dev_1",
        "event_type": "AUTH_SUCCESS",
        "asset_id": "laptop-55",
        "asset_criticality": "LOW",
        "payload_metric": 1.0,
        "details": "Routine login"
    }
    benign_raw2 = dict(benign_raw1)
    benign_raw2["raw_id"] = "BENIGN-DUP-02"
    benign_raw2["timestamp"] = "2026-10-23T11:00:10Z"

    res1 = process_telemetry_pipeline(benign_raw1)
    assert res1.is_duplicate is False
    assert res1.incident is None

    res2 = process_telemetry_pipeline(benign_raw2)
    assert res2.is_duplicate is True
    assert res2.incident is None  # No incident exists, handled safely without crash
    assert "Duplicate telemetry event ignored" in res2.behavioral_evidence[0]


def test_repeated_ingestion_is_idempotent():
    """
    Requirement B.8: Repeated ingestion of identical events is strictly idempotent.
    """
    raw = make_raw_log("RAW-IDEMP-01", "2026-10-23T12:00:00Z", "198.51.100.222")

    res1 = process_telemetry_pipeline(raw)
    first_incident_id = res1.incident.incident_id if res1.incident else None

    # Repeated identical ingestion 3 times
    for _ in range(3):
        res_dup = process_telemetry_pipeline(raw)
        assert res_dup.is_duplicate is True
        assert res_dup.threat_detected is False
        assert res_dup.response_record is None
        if first_incident_id and res_dup.incident:
            assert res_dup.incident.incident_id == first_incident_id


def test_duplicate_events_cannot_authorize_remediation():
    """
    Requirement B.9 & Mandatory Constraint:
    Duplicate events must NEVER independently authorize remediation, trigger Tier B actions,
    or bypass safety gates.
    """
    raw1 = make_raw_log("RAW-SAFE-01", "2026-10-23T13:00:00Z", "198.51.100.111")
    res1 = process_telemetry_pipeline(raw1)

    raw2 = make_raw_log("RAW-SAFE-02", "2026-10-23T13:00:04Z", "198.51.100.111")
    res2 = process_telemetry_pipeline(raw2)

    assert res2.is_duplicate is True
    assert res2.response_record is None  # Mandatory: zero automated remediation authorized on duplicates


def test_telemetry_stats_api_exposes_duplicates():
    """
    Requirement B.11 & E:
    Expose meaningful duplicate statistics through GET /api/telemetry/stats.
    """
    # Ingest 1 event then 1 duplicate
    raw1 = make_raw_log("RAW-STAT-01", "2026-10-23T14:00:00Z", "198.51.100.77")
    raw2 = make_raw_log("RAW-STAT-02", "2026-10-23T14:00:05Z", "198.51.100.77")
    client.post("/api/telemetry/event", json=raw1)
    client.post("/api/telemetry/event", json=raw2)

    res = client.get("/api/telemetry/stats")
    assert res.status_code == 200
    stats = res.json()

    assert "total_raw_events" in stats
    assert "total_unique_events" in stats
    assert "total_duplicates_suppressed" in stats
    assert "deduplication_rate_pct" in stats
    assert stats["total_raw_events"] >= 2
    assert stats["total_duplicates_suppressed"] >= 1


def test_database_persistence_and_recovery_of_duplicate_counts(clean_db):
    """
    Requirement B.10: Duplicate counts and timeline flags persist in SQLite and survive restart recovery.
    """
    inc_mgr = IncidentManager(db=clean_db)
    corr_eng = IncidentCorrelationEngine()

    evt1 = NormalizedEvent(
        event_id="EVT-PERSIST-01",
        timestamp="2026-10-23T15:00:00Z",
        source_ip="198.51.100.88",
        destination_ip="10.0.0.5",
        user_id="victim_user",
        event_type=EventType.LOGIN_FAILED,
        asset_id="vpn-gateway",
        asset_criticality=AssetCriticality.HIGH,
        payload_metric=6.0,
        details="Brute force login"
    )
    inc = inc_mgr.create_incident(
        event_id=evt1.event_id,
        threat_category=ThreatCategory.BRUTE_FORCE,
        severity=Severity.HIGH,
        risk_score=75.0,
        confidence_score=0.90,
        source_ip=evt1.source_ip,
        user_id=evt1.user_id,
        asset_id=evt1.asset_id,
        details="Test incident",
        recommended_action="SUSPEND_SESSION",
        decision_tier="TIER_B"
    )

    # Attach duplicate observation
    evt_dup = NormalizedEvent(
        event_id="EVT-PERSIST-DUP-01",
        timestamp="2026-10-23T15:00:05Z",
        source_ip="198.51.100.88",
        destination_ip="10.0.0.5",
        user_id="victim_user",
        event_type=EventType.LOGIN_FAILED,
        asset_id="vpn-gateway",
        asset_criticality=AssetCriticality.HIGH,
        payload_metric=6.0,
        details="Brute force login duplicate"
    )
    corr_eng.record_duplicate_observation(inc, evt_dup)
    inc_mgr.save_incident_update(inc)

    # Simulate restart by instantiating fresh IncidentManager from clean_db
    recovered_mgr = IncidentManager(db=clean_db)
    recovered_inc = recovered_mgr.get_incident(inc.incident_id)

    assert recovered_inc is not None
    assert recovered_inc.duplicate_events_count == 1
    assert len(recovered_inc.timeline) >= 2
    # Check timeline is_duplicate flag persisted
    dup_tl = [tl for tl in recovered_inc.timeline if tl.get("is_duplicate")]
    assert len(dup_tl) == 1
    assert dup_tl[0]["event_id"] == "EVT-PERSIST-DUP-01"
