import pytest
from backend.detection.normalizer import EventNormalizer
from backend.models.events import EventType, AssetCriticality

def test_normalizer_valid_raw():
    raw = {
        "raw_id": "RAW-101",
        "timestamp": "2026-09-09T03:15:00Z",
        "source_ip": "192.168.1.100",
        "user_id": "test_user",
        "event_type": "LOGIN_FAILED",
        "asset_id": "server-01",
        "asset_criticality": "HIGH",
        "payload_metric": 5.0,
        "details": "5 failed logins"
    }
    norm, is_dup = EventNormalizer.normalize(raw)
    assert norm.event_id == "RAW-101"
    assert norm.source_ip == "192.168.1.100"
    assert norm.event_type == EventType.LOGIN_FAILED
    assert norm.asset_criticality == AssetCriticality.HIGH
    assert norm.payload_metric == 5.0

def test_normalizer_defaults_and_fallback():
    raw = {
        "source_ip": "10.0.0.1",
        "user_id": "anon",
        "event_type": "UNKNOWN_EVT"
    }
    norm, is_dup = EventNormalizer.normalize(raw)
    assert norm.event_id.startswith("EVT-")
    assert norm.event_type == EventType.CUSTOM
    assert norm.asset_criticality == AssetCriticality.MEDIUM
    assert norm.payload_metric == 0.0
