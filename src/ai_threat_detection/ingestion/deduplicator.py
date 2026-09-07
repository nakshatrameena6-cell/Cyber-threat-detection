"""Telemetry Deduplicator (REQ-ING-003)."""
import hashlib
from datetime import datetime, timedelta
from typing import Dict
from models.schemas.telemetry import NormalizedEvent


class TelemetryDeduplicator:
    """Sliding-window hash-based telemetry deduplicator."""

    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        self._seen_hashes: Dict[str, datetime] = {}

    def _compute_event_fingerprint(self, event: NormalizedEvent) -> str:
        key = f"{event.source_id}|{event.event_type}|{event.user_id}|{event.host_id}|{event.source_ip}"
        return hashlib.md5(key.encode("utf-8")).hexdigest()

    def is_duplicate(self, event: NormalizedEvent) -> bool:
        fingerprint = self._compute_event_fingerprint(event)
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.window_seconds)

        # Cleanup expired entries
        self._seen_hashes = {
            fp: ts for fp, ts in self._seen_hashes.items() if ts > cutoff
        }

        if fingerprint in self._seen_hashes:
            return True

        self._seen_hashes[fingerprint] = now
        return False
