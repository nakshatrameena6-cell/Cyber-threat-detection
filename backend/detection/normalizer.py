import uuid
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Tuple, Set
from backend.models.events import RawLogEvent, NormalizedEvent, EventType, AssetCriticality

class EventDeduplicator:
    """
    Sliding window event deduplication.
    Filters out duplicate event hashes seen within a 60-second sliding window.
    """
    def __init__(self, window_seconds: float = 60.0):
        self.window_seconds = window_seconds
        self.seen_hashes: Dict[str, datetime] = {}

    def is_duplicate(self, event_hash: str, current_time: datetime) -> bool:
        expired = [h for h, t in self.seen_hashes.items() if (current_time - t).total_seconds() > self.window_seconds]
        for h in expired:
            del self.seen_hashes[h]

        if event_hash in self.seen_hashes:
            return True

        self.seen_hashes[event_hash] = current_time
        return False


class EventNormalizer:
    deduplicator = EventDeduplicator(window_seconds=60.0)

    @staticmethod
    def generate_hash(source_ip: str, user_id: str, event_type: str, details: str, payload_metric: float) -> str:
        raw_str = f"{source_ip}|{user_id}|{event_type}|{details}|{payload_metric}"
        return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def normalize(cls, raw: dict) -> Tuple[NormalizedEvent, bool]:
        """
        Normalizes a raw telemetry dictionary safely handling malformed inputs.
        Returns (NormalizedEvent, is_duplicate)
        """
        event_id = str(raw.get("raw_id") or f"EVT-{uuid.uuid4().hex[:8].upper()}")
        
        # Standardize timestamp
        ts_raw = raw.get("timestamp")
        if not ts_raw:
            ts_dt = datetime.now(timezone.utc)
            ts_str = ts_dt.isoformat()
        else:
            try:
                ts_dt = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
                ts_str = ts_dt.isoformat()
            except Exception:
                ts_dt = datetime.now(timezone.utc)
                ts_str = ts_dt.isoformat()
                
        # Parse EventType
        raw_evt_type = str(raw.get("event_type") or "").upper()
        try:
            event_type = EventType(raw_evt_type)
        except ValueError:
            event_type = EventType.CUSTOM

        # Parse AssetCriticality
        raw_crit = str(raw.get("asset_criticality") or "").upper()
        try:
            criticality = AssetCriticality(raw_crit)
        except ValueError:
            criticality = AssetCriticality.MEDIUM

        src_ip = str(raw.get("source_ip") or "0.0.0.0")
        usr_id = str(raw.get("user_id") or "unknown")
        dtls = str(raw.get("details") or "")
        
        try:
            metric = float(raw.get("payload_metric") or 0.0)
        except (ValueError, TypeError):
            metric = 0.0

        # Check deduplication
        event_hash = cls.generate_hash(src_ip, usr_id, event_type.value, dtls, metric)
        is_dup = cls.deduplicator.is_duplicate(event_hash, ts_dt)

        norm_event = NormalizedEvent(
            event_id=event_id,
            timestamp=ts_str,
            source_ip=src_ip,
            user_id=usr_id,
            event_type=event_type,
            asset_id=str(raw.get("asset_id") or "unspecified-host"),
            asset_criticality=criticality,
            payload_metric=metric,
            details=dtls,
            normalized_at=datetime.now(timezone.utc).isoformat()
        )

        return norm_event, is_dup

    @classmethod
    def normalize_batch(cls, raw_list: List[dict]) -> List[Tuple[NormalizedEvent, bool]]:
        """
        Normalizes a batch of raw telemetry events.
        Sorts out-of-order events by timestamp before processing.
        """
        def parse_ts(item: dict) -> datetime:
            ts = item.get("timestamp")
            if not ts:
                return datetime.min.replace(tzinfo=timezone.utc)
            try:
                return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            except Exception:
                return datetime.min.replace(tzinfo=timezone.utc)

        # Sort batch by timestamp to handle out-of-order streams
        sorted_raw = sorted(raw_list, key=parse_ts)

        results = []
        for raw in sorted_raw:
            norm, is_dup = cls.normalize(raw)
            results.append((norm, is_dup))

        return results
