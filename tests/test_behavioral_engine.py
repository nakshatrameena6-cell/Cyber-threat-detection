import pytest
from backend.detection.normalizer import EventNormalizer
from backend.detection.behavioral_engine import BehavioralFeatureEngine

def test_behavioral_engine_failed_logins():
    engine = BehavioralFeatureEngine()
    
    raw1 = {"raw_id": "B1", "source_ip": "10.0.0.1", "user_id": "test_user", "event_type": "LOGIN_FAILED", "payload_metric": 3.0}
    raw2 = {"raw_id": "B2", "source_ip": "10.0.0.1", "user_id": "test_user", "event_type": "LOGIN_FAILED", "payload_metric": 2.0}

    norm1, _ = EventNormalizer.normalize(raw1)
    norm2, _ = EventNormalizer.normalize(raw2)

    vec1, ev1 = engine.update_and_extract(norm1)
    vec2, ev2 = engine.update_and_extract(norm2)

    assert vec2.failed_login_count >= 5.0
    assert any("failed login" in tag.lower() for tag in ev2)

def test_behavioral_engine_exfiltration():
    engine = BehavioralFeatureEngine()
    
    raw = {"raw_id": "B3", "source_ip": "10.0.0.2", "user_id": "admin_user", "event_type": "BYTES_OUT", "payload_metric": 850.0}
    norm, _ = EventNormalizer.normalize(raw)
    vec, evidence = engine.update_and_extract(norm)

    assert vec.data_transfer_volume_mb == 850.0
    assert any("exfiltration" in tag.lower() for tag in evidence)

def test_behavioral_engine_normal():
    engine = BehavioralFeatureEngine()
    
    raw = {"raw_id": "B4", "source_ip": "10.0.0.3", "user_id": "regular_user", "event_type": "AUTH_SUCCESS", "timestamp": "2026-09-09T10:00:00Z"}
    norm, _ = EventNormalizer.normalize(raw)
    vec, evidence = engine.update_and_extract(norm)

    assert vec.off_hours_flag == 0.0
    assert vec.failed_login_count == 0.0
    assert "Normal baseline operational behavior" in evidence
