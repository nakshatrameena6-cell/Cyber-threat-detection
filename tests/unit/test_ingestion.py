"""Tests for Telemetry Ingestion, Normalization, and Deduplication (REQ-ING-001, REQ-ING-002, REQ-ING-003)."""
from models.schemas.telemetry import RawTelemetryEvent
from ai_threat_detection.ingestion.ingestor import TelemetryIngestor
from ai_threat_detection.ingestion.normalizer import TelemetryNormalizer
from ai_threat_detection.ingestion.deduplicator import TelemetryDeduplicator


def test_telemetry_ingestion():
    ingestor = TelemetryIngestor()
    raw = RawTelemetryEvent(
        source_id="siem-01",
        vendor="Splunk",
        raw_payload='{"event_type": "SUSPICIOUS_POWERSHELL", "user_id": "usr-admin", "host_id": "host-01"}'
    )
    result = ingestor.process_raw_event(raw)
    assert len(result) == 1
    assert result[0].event_type == "SUSPICIOUS_POWERSHELL"
    assert result[0].user_id == "usr-admin"


def test_event_normalization():
    normalizer = TelemetryNormalizer()
    raw = RawTelemetryEvent(
        source_id="edr-01",
        vendor="CrowdStrike",
        raw_payload='{"event_type": "FAILED_LOGIN_BURST", "user": "usr-test", "host": "host-srv"}'
    )
    normalized = normalizer.normalize(raw)
    assert normalized.event_type == "FAILED_LOGIN_BURST"
    assert normalized.user_id == "usr-test"
    assert normalized.host_id == "host-srv"


def test_event_deduplication():
    deduplicator = TelemetryDeduplicator(window_seconds=300)
    normalizer = TelemetryNormalizer()
    raw = RawTelemetryEvent(
        source_id="siem-01",
        vendor="Splunk",
        raw_payload='{"event_type": "PORT_SCAN", "ip": "10.0.0.1"}'
    )
    event1 = normalizer.normalize(raw)
    event2 = normalizer.normalize(raw)

    assert deduplicator.is_duplicate(event1) is False
    assert deduplicator.is_duplicate(event2) is True
