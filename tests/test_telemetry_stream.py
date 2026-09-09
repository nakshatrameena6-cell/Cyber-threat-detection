import pytest
from backend.detection.normalizer import EventNormalizer, EventDeduplicator
from backend.models.events import EventType

def test_sliding_window_deduplication():
    dedup = EventDeduplicator(window_seconds=60.0)
    raw = {"source_ip": "1.1.1.1", "user_id": "u1", "event_type": "LOGIN_FAILED", "payload_metric": 5.0, "details": "Brute force"}
    
    norm1, is_dup1 = EventNormalizer.normalize(raw)
    assert is_dup1 is False

    # Immediate second identical event should be marked duplicate
    norm2, is_dup2 = EventNormalizer.normalize(raw)
    assert is_dup2 is True

def test_batch_stream_out_of_order_sorting():
    raw_list = [
        {"raw_id": "E3", "timestamp": "2026-09-09T03:00:00Z", "source_ip": "10.0.0.1", "user_id": "u1", "event_type": "LOGIN_FAILED"},
        {"raw_id": "E1", "timestamp": "2026-09-09T01:00:00Z", "source_ip": "10.0.0.1", "user_id": "u1", "event_type": "AUTH_SUCCESS"},
        {"raw_id": "E2", "timestamp": "2026-09-09T02:00:00Z", "source_ip": "10.0.0.1", "user_id": "u1", "event_type": "BYTES_OUT", "payload_metric": 50.0}
    ]

    results = EventNormalizer.normalize_batch(raw_list)
    assert len(results) == 3
    # Verify chronological sorting order
    assert results[0][0].event_id == "E1"
    assert results[1][0].event_id == "E2"
    assert results[2][0].event_id == "E3"

def test_invalid_and_malformed_events():
    malformed = {
        "invalid_field": 1234,
        "source_ip": None,
        "payload_metric": "invalid_number_string"
    }
    norm, is_dup = EventNormalizer.normalize(malformed)
    assert norm.source_ip == "0.0.0.0"
    assert norm.user_id == "unknown"
    assert norm.event_type == EventType.CUSTOM
    assert norm.payload_metric == 0.0
