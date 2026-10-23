import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_system_state_endpoint():
    """
    REQ-DASH-004: Dashboard API provides system state, simulation disclaimer, and SQLite metadata.
    """
    response = client.get("/api/system/state")
    assert response.status_code == 200
    data = response.json()
    assert "total_incidents" in data
    assert "total_actions" in data
    assert "total_telemetry_events" in data
    assert "SIMULATED ENFORCEMENT ONLY" in data.get("simulation_disclaimer", "")
    assert "SQLite" in data.get("database_storage", "")
    assert "kill_switch" in data
    assert "syslog_listener" in data

def test_telemetry_stats_endpoint():
    """
    REQ-DASH-004: Stats endpoint returns persisted event count and database info.
    """
    response = client.get("/api/telemetry/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_persisted_events" in data
    assert "database_path" in data
    assert "syslog_enabled" in data

def test_frontend_dashboard_served():
    """
    REQ-DASH-004: Static frontend HTML is served at root.
    """
    response = client.get("/")
    assert response.status_code == 200
    assert "Suraksha" in response.text
    assert "SAFE SIMULATED EXECUTION" in response.text
