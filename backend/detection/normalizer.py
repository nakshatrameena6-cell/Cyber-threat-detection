import uuid
from datetime import datetime, timezone
from backend.models.events import RawLogEvent, NormalizedEvent, EventType, AssetCriticality

class EventNormalizer:
    @staticmethod
    def normalize(raw: dict) -> NormalizedEvent:
        """
        Normalizes a raw telemetry dictionary into a schema-validated NormalizedEvent.
        """
        event_id = raw.get("raw_id") or f"EVT-{uuid.uuid4().hex[:8].upper()}"
        
        # Standardize timestamp
        ts_raw = raw.get("timestamp")
        if not ts_raw:
            ts_str = datetime.now(timezone.utc).isoformat()
        else:
            try:
                # Validate ISO parsing
                dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                ts_str = dt.isoformat()
            except Exception:
                ts_str = datetime.now(timezone.utc).isoformat()
                
        # Parse EventType
        raw_evt_type = str(raw.get("event_type", "")).upper()
        try:
            event_type = EventType(raw_evt_type)
        except ValueError:
            event_type = EventType.CUSTOM

        # Parse AssetCriticality
        raw_crit = str(raw.get("asset_criticality", "")).upper()
        try:
            criticality = AssetCriticality(raw_crit)
        except ValueError:
            criticality = AssetCriticality.MEDIUM

        return NormalizedEvent(
            event_id=event_id,
            timestamp=ts_str,
            source_ip=str(raw.get("source_ip", "0.0.0.0")),
            user_id=str(raw.get("user_id", "unknown")),
            event_type=event_type,
            asset_id=str(raw.get("asset_id", "unspecified-host")),
            asset_criticality=criticality,
            payload_metric=float(raw.get("payload_metric", 0.0)),
            details=str(raw.get("details", "")),
            normalized_at=datetime.now(timezone.utc).isoformat()
        )
