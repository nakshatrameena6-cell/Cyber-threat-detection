"""Telemetry Ingestor Pipeline (REQ-ING-001)."""
from typing import List
from models.schemas.telemetry import RawTelemetryEvent, NormalizedEvent
from ai_threat_detection.ingestion.normalizer import TelemetryNormalizer
from ai_threat_detection.ingestion.deduplicator import TelemetryDeduplicator


class TelemetryIngestor:
    """Ingestion pipeline coordinator."""

    def __init__(self, normalizer: TelemetryNormalizer = None, deduplicator: TelemetryDeduplicator = None):
        self.normalizer = normalizer or TelemetryNormalizer()
        self.deduplicator = deduplicator or TelemetryDeduplicator()

    def process_raw_event(self, raw_event: RawTelemetryEvent) -> List[NormalizedEvent]:
        """Normalize raw event and filter if duplicate."""
        normalized = self.normalizer.normalize(raw_event)
        if self.deduplicator.is_duplicate(normalized):
            return []
        return [normalized]
