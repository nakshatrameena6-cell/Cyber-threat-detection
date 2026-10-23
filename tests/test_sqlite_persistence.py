import os
import pytest
from datetime import datetime, timezone
from backend.database import DatabaseManager, init_db

def test_sqlite_schema_initialization(tmp_path):
    """
    REQ-DB-001: SQLite schema initialization with indexes and constraints.
    """
    db_file = str(tmp_path / "schema_test.db")
    db = DatabaseManager(db_file)
    conn = db.get_conn()
    tables = [row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    conn.close()

    assert "telemetry_events" in tables
    assert "incidents" in tables
    assert "incident_events" in tables
    assert "incident_timelines" in tables
    assert "incident_evidence" in tables
    assert "response_records" in tables
    assert "response_pre_states" in tables
    assert "simulated_security_state" in tables
    assert "audit_logs" in tables

def test_telemetry_persistence_and_retrieval(tmp_path):
    """
    REQ-DB-002: Ingestion metadata and telemetry persistence.
    """
    db_file = str(tmp_path / "telemetry_test.db")
    db = DatabaseManager(db_file)
    
    evt = {
        "event_id": "EVT-TEST-001",
        "timestamp": "2026-10-23T05:00:00Z",
        "source_ip": "198.51.100.15",
        "user_id": "analyst_bob",
        "event_type": "LOGIN_FAILED",
        "asset_id": "app-server-01",
        "asset_criticality": "HIGH",
        "payload_metric": 3.0,
        "details": "Failed password attempt"
    }
    saved = db.save_telemetry_event(evt, raw_json='{"sample": true}')
    assert saved is True

    fetched = db.get_telemetry_event("EVT-TEST-001")
    assert fetched is not None
    assert fetched["source_ip"] == "198.51.100.15"
    assert fetched["event_type"] == "LOGIN_FAILED"
    assert db.get_telemetry_count() == 1

def test_incident_persistence_with_timelines_and_evidence(tmp_path):
    """
    REQ-DB-002: Incident and relationship persistence.
    """
    db_file = str(tmp_path / "inc_test.db")
    db = DatabaseManager(db_file)

    inc = {
        "incident_id": "INC-TEST-99",
        "event_id": "EVT-99",
        "threat_category": "Brute Force",
        "threat_categories": ["Brute Force"],
        "severity": "HIGH",
        "risk_score": 82.5,
        "confidence_score": 0.88,
        "source_ip": "198.51.100.22",
        "user_id": "target_user",
        "asset_id": "auth-portal",
        "details": "Repeated failed logins",
        "status": "NEW",
        "created_at": "2026-10-23T06:00:00Z",
        "first_seen": "2026-10-23T06:00:00Z",
        "last_seen": "2026-10-23T06:05:00Z",
        "recommended_action": "BLOCK_IP",
        "decision_tier": "TIER_B",
        "action_executed": False,
        "is_anomalous": True,
        "behavioral_evidence": ["High failed login velocity"],
        "why_evidence": ["8 failed attempts within 2 minutes"],
        "related_events": ["EVT-99", "EVT-100"],
        "timeline": [
            {
                "timestamp": "2026-10-23T06:00:00Z",
                "event_id": "EVT-99",
                "event_type": "LOGIN_FAILED",
                "description": "First failed attempt",
                "threat_category": "Brute Force",
                "risk_score": 50.0
            },
            {
                "timestamp": "2026-10-23T06:05:00Z",
                "event_id": "EVT-100",
                "event_type": "LOGIN_FAILED",
                "description": "Threshold breached",
                "threat_category": "Brute Force",
                "risk_score": 82.5
            }
        ]
    }
    db.save_incident(inc)

    retrieved = db.get_incident("INC-TEST-99")
    assert retrieved is not None
    assert retrieved["incident_id"] == "INC-TEST-99"
    assert len(retrieved["related_events"]) == 2
    assert len(retrieved["timeline"]) == 2
    assert "High failed login velocity" in retrieved["behavioral_evidence"]
    assert "8 failed attempts within 2 minutes" in retrieved["why_evidence"]

def test_audit_logs_persistence_and_filtering(tmp_path):
    """
    REQ-DB-003: Audit log append-only persistence and filterable query.
    """
    db_file = str(tmp_path / "audit_test.db")
    db = DatabaseManager(db_file)

    db.save_audit_log({
        "audit_id": "AUD-001",
        "timestamp": "2026-10-23T07:00:00Z",
        "actor": "admin_user",
        "role": "ADMIN",
        "action_category": "EXECUTION",
        "description": "Block IP action executed",
        "target_resource": "198.51.100.5",
        "metadata": {"action": "BLOCK_IP"}
    })

    db.save_audit_log({
        "audit_id": "AUD-002",
        "timestamp": "2026-10-23T07:01:00Z",
        "actor": "system",
        "role": "SYSTEM",
        "action_category": "DETECTION",
        "description": "Threat identified",
        "target_resource": "EVT-55",
        "metadata": {}
    })

    logs_exec = db.list_audit_logs(category="EXECUTION")
    assert len(logs_exec) == 1
    assert logs_exec[0]["actor"] == "admin_user"

    logs_all = db.list_audit_logs()
    assert len(logs_all) == 2
