"""Telemetry Normalizer (REQ-ING-002)."""
import json
import hashlib
from datetime import datetime
from models.schemas.telemetry import RawTelemetryEvent, NormalizedEvent


class TelemetryNormalizer:
    """Converts raw vendor telemetry into schema-validated NormalizedEvent objects."""

    def normalize(self, raw_event: RawTelemetryEvent) -> NormalizedEvent:
        payload_data = {}
        try:
            payload_data = json.loads(raw_event.raw_payload)
        except Exception:
            payload_data = {"raw_text": raw_event.raw_payload}

        event_type = payload_data.get("event_type", "UNKNOWN_EVENT")
        user_id = payload_data.get("user") or payload_data.get("user_id")
        host_id = payload_data.get("host") or payload_data.get("host_id")
        source_ip = payload_data.get("ip") or payload_data.get("source_ip")
        dest_ip = payload_data.get("dest_ip") or payload_data.get("destination_ip")

        # Map to MITRE ATT&CK if present in raw log
        tactic = payload_data.get("mitre_tactic", "INITIAL_ACCESS")
        technique = payload_data.get("mitre_technique_id", "T1078")

        # Generate deterministic event ID from hash of source + payload + timestamp
        hash_input = f"{raw_event.source_id}|{raw_event.raw_payload}|{raw_event.ingested_at.isoformat()}"
        event_id = f"evt-{hashlib.sha256(hash_input.encode()).hexdigest()[:12]}"

        return NormalizedEvent(
            event_id=event_id,
            source_id=raw_event.source_id,
            vendor=raw_event.vendor,
            event_type=event_type,
            timestamp=raw_event.ingested_at,
            source_ip=source_ip,
            destination_ip=dest_ip,
            user_id=user_id,
            host_id=host_id,
            mitre_tactic=tactic,
            mitre_technique_id=technique,
            attributes=payload_data
        )
