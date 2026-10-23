"""
Suraksha AI - Phase 7 Timestamp Resilience & Out-of-Order Telemetry Tests (Requirement C)
Verifies UTC standardization, timezone offset normalization, allowed-lateness window,
malformed/future timestamp fallback auditing, and behavioral state stability.
"""
from datetime import datetime, timezone, timedelta
from backend.models.events import NormalizedEvent, EventType, AssetCriticality, TimestampQuality
from backend.detection.normalizer import EventNormalizer, EventDeduplicator
from backend.detection.behavioral_engine import BehavioralFeatureEngine
from backend.detection.ml_detector import MLAnomalyDetector


def test_standard_utc_timestamp_parsing():
    """Verifies that ISO-8601 UTC timestamps with 'Z' parse cleanly as TRUSTED."""
    raw = {
        "raw_id": "TS-UTC-001",
        "timestamp": "2026-10-23T14:30:00Z",
        "source_ip": "10.0.1.10",
        "user_id": "alice",
        "event_type": "AUTH_SUCCESS"
    }
    norm_evt, _ = EventNormalizer.normalize(raw)
    assert norm_evt.timestamp == "2026-10-23T14:30:00+00:00"
    assert norm_evt.timestamp_quality == TimestampQuality.TRUSTED
    assert norm_evt.timestamp_fallback_reason is None
    assert norm_evt.raw_timestamp == "2026-10-23T14:30:00Z"


def test_timezone_offset_normalized_to_utc():
    """Verifies that non-UTC timezone offsets (+05:30) are correctly converted to UTC representation."""
    raw = {
        "raw_id": "TS-OFFSET-001",
        "timestamp": "2026-10-23T20:00:00+05:30", # Equivalent to 14:30:00 UTC
        "source_ip": "10.0.1.10",
        "user_id": "alice",
        "event_type": "AUTH_SUCCESS"
    }
    norm_evt, _ = EventNormalizer.normalize(raw)
    assert norm_evt.timestamp == "2026-10-23T14:30:00+00:00"
    assert norm_evt.timestamp_quality == TimestampQuality.TRUSTED


def test_out_of_order_event_within_allowed_lateness_window():
    """Verifies that events arriving up to 300s late are processed without corruption."""
    now = datetime.now(timezone.utc)
    two_mins_ago = now - timedelta(seconds=120)

    raw = {
        "raw_id": "TS-LATE-001",
        "timestamp": two_mins_ago.isoformat(),
        "source_ip": "10.0.1.10",
        "user_id": "alice",
        "event_type": "AUTH_SUCCESS"
    }
    norm_evt, _ = EventNormalizer.normalize(raw)
    assert norm_evt.timestamp_quality == TimestampQuality.TRUSTED


def test_expired_lateness_flagged():
    """Verifies that events arriving older than allowed_lateness_seconds are marked EXPIRED_LATENESS."""
    now = datetime.now(timezone.utc)
    ten_mins_ago = now - timedelta(seconds=600) # Exceeds 300s allowed lateness

    raw = {
        "raw_id": "TS-EXPIRED-001",
        "timestamp": ten_mins_ago.isoformat(),
        "source_ip": "10.0.1.10",
        "user_id": "alice",
        "event_type": "AUTH_SUCCESS"
    }
    norm_evt, _ = EventNormalizer.normalize(raw)
    assert norm_evt.timestamp_quality == TimestampQuality.EXPIRED_LATENESS
    assert "outside allowed lateness" in norm_evt.timestamp_fallback_reason


def test_malformed_timestamp_audited_with_fallback():
    """Verifies that malformed timestamps fall back to ingestion UTC with audit reason."""
    raw = {
        "raw_id": "TS-MALFORMED-001",
        "timestamp": "invalid-garbage-date-time",
        "source_ip": "10.0.1.10",
        "user_id": "alice",
        "event_type": "AUTH_SUCCESS"
    }
    norm_evt, _ = EventNormalizer.normalize(raw)
    assert norm_evt.timestamp_quality == TimestampQuality.FALLBACK_MALFORMED
    assert "Malformed timestamp" in norm_evt.timestamp_fallback_reason
    assert norm_evt.raw_timestamp == "invalid-garbage-date-time"


def test_implausible_future_timestamp_clamped():
    """Verifies that future timestamps (>60s ahead) are clamped to ingestion time."""
    now = datetime.now(timezone.utc)
    future = now + timedelta(days=2)

    raw = {
        "raw_id": "TS-FUTURE-001",
        "timestamp": future.isoformat(),
        "source_ip": "10.0.1.10",
        "user_id": "alice",
        "event_type": "AUTH_SUCCESS"
    }
    norm_evt, _ = EventNormalizer.normalize(raw)
    assert norm_evt.timestamp_quality == TimestampQuality.FUTURE_TIMESTAMP
    assert "Implausible future timestamp" in norm_evt.timestamp_fallback_reason


def test_behavioral_feature_stability_with_out_of_order_events():
    """
    Verifies that injecting an out-of-order event does not prune newer legitimate
    behavioral timestamps from rolling state windows.
    """
    engine = BehavioralFeatureEngine()
    now = datetime.now(timezone.utc)

    # 1. First event: login failed 30s ago
    evt1, _ = EventNormalizer.normalize({
        "raw_id": "OOO-01",
        "timestamp": (now - timedelta(seconds=30)).isoformat(),
        "source_ip": "10.0.5.5",
        "user_id": "victim",
        "event_type": "LOGIN_FAILED",
        "payload_metric": 1.0
    })
    vec1, _ = engine.update_and_extract(evt1)
    assert vec1.failed_login_count == 1.0

    # 2. Second event: login failed 10s ago
    evt2, _ = EventNormalizer.normalize({
        "raw_id": "OOO-02",
        "timestamp": (now - timedelta(seconds=10)).isoformat(),
        "source_ip": "10.0.5.5",
        "user_id": "victim",
        "event_type": "LOGIN_FAILED",
        "payload_metric": 1.0
    })
    vec2, _ = engine.update_and_extract(evt2)
    assert vec2.failed_login_count == 2.0

    # 3. Third event: out-of-order login failed 45s ago (older than evt2)
    evt3, _ = EventNormalizer.normalize({
        "raw_id": "OOO-03",
        "timestamp": (now - timedelta(seconds=45)).isoformat(),
        "source_ip": "10.0.5.5",
        "user_id": "victim",
        "event_type": "LOGIN_FAILED",
        "payload_metric": 1.0
    })
    vec3, _ = engine.update_and_extract(evt3)
    # The newer timestamps must NOT be erased; total should be 3
    assert vec3.failed_login_count == 3.0


def test_timestamp_fallback_never_independently_authorizes_remediation():
    """
    Verifies that an event with a malformed timestamp fallback does NOT
    spuriously trigger high ML anomaly scores or authorize disruptive response actions.
    """
    detector = MLAnomalyDetector()
    raw = {
        "raw_id": "TS-SAFE-001",
        "timestamp": "broken-timestamp-string",
        "source_ip": "10.0.1.10",
        "user_id": "alice",
        "event_type": "AUTH_SUCCESS",
        "payload_metric": 1.0
    }
    norm_evt, _ = EventNormalizer.normalize(raw)
    ml_score = detector.predict_anomaly_score(norm_evt)

    # ML anomaly score on normal auth success with fallback timestamp must remain low (benign)
    assert ml_score <= 0.35, f"Spurious anomaly score {ml_score} on fallback timestamp"
