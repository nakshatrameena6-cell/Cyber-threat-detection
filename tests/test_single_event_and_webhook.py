import os
import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_single_event_ingestion_api():
    """
    REQ-INGEST-003: Real-time single-event telemetry ingestion endpoint.
    """
    payload = {
        "raw_id": "TEST-SE-001",
        "timestamp": "2026-10-23T08:00:00Z",
        "source_ip": "198.51.100.88",
        "user_id": "test_victim",
        "event_type": "LOGIN_FAILED",
        "asset_id": "portal-01",
        "asset_criticality": "HIGH",
        "payload_metric": 6.0,
        "details": "Password guessing attempts"
    }

    response = client.post("/api/telemetry/event", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["threat_detected"] is True
    assert data["incident"] is not None
    assert data["normalized_event"]["source_ip"] == "198.51.100.88"

def test_generic_webhook_ingestion_api(monkeypatch):
    """
    REQ-INGEST-004: Generic JSON security webhook endpoint.
    """
    monkeypatch.delenv("SURAKSHA_WEBHOOK_SECRET", raising=False)
    webhook_data = {
        "src_ip": "10.0.9.15",
        "user": "compromised_service",
        "action": "C2_BEACON",
        "host": "database-cluster",
        "asset_criticality": "HIGH",
        "bytes": 25.0,
        "description": "Outbound DNS beaconing to external domain"
    }

    response = client.post("/api/telemetry/webhook", json=webhook_data)
    assert response.status_code == 201
    data = response.json()
    assert data["threat_detected"] is True
    assert data["normalized_event"]["source_ip"] == "10.0.9.15"

def test_webhook_secret_authentication(monkeypatch):
    """
    REQ-INGEST-004: Webhook secret token authentication.
    """
    monkeypatch.setenv("SURAKSHA_WEBHOOK_SECRET", "secret-key-1234")

    webhook_data = {
        "source_ip": "10.0.1.5",
        "user_id": "alice",
        "event_type": "LOGIN_FAILED"
    }

    # Request without secret -> 401
    unauth_resp = client.post("/api/telemetry/webhook", json=webhook_data)
    assert unauth_resp.status_code == 401

    # Request with invalid secret -> 401
    wrong_resp = client.post(
        "/api/telemetry/webhook",
        json=webhook_data,
        headers={"X-Webhook-Secret": "wrong-secret"}
    )
    assert wrong_resp.status_code == 401

    # Request with valid secret -> 201
    auth_resp = client.post(
        "/api/telemetry/webhook",
        json=webhook_data,
        headers={"X-Webhook-Secret": "secret-key-1234"}
    )
    assert auth_resp.status_code == 201

def test_webhook_malformed_json_handling():
    """
    REQ-FAIL-001: Malformed JSON or invalid schema rejects cleanly without crashing.
    """
    response = client.post(
        "/api/telemetry/webhook",
        content="not a json string",
        headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 400

def test_single_event_duplicate_idempotency():
    """
    REQ-INGEST-003: Duplicate event within sliding window is ignored and does not create duplicate incidents.
    """
    payload = {
        "raw_id": "DUP-SE-001",
        "timestamp": "2026-10-23T08:30:00Z",
        "source_ip": "198.51.100.99",
        "user_id": "test_user",
        "event_type": "SUSPICIOUS_LOGIN",
        "asset_id": "vpn-01",
        "asset_criticality": "MEDIUM",
        "payload_metric": 1.0,
        "details": "Geo login anomaly"
    }

    # First ingestion
    resp1 = client.post("/api/telemetry/event", json=payload)
    assert resp1.status_code == 201
    assert resp1.json()["is_duplicate"] is False

    # Second immediate ingestion of duplicate event
    resp2 = client.post("/api/telemetry/event", json=payload)
    assert resp2.status_code == 201
    data2 = resp2.json()
    assert data2["is_duplicate"] is True
    assert data2["incident"] is None
