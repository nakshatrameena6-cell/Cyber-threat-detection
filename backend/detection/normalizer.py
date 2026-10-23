import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Tuple, Set, Optional
from backend.models.events import RawLogEvent, NormalizedEvent, EventType, AssetCriticality, TimestampQuality

class EventDeduplicator:
    """
    Sliding window event deduplication.
    Filters out duplicate event hashes seen within a sliding window (default: 60s).
    Hardened against out-of-order timestamp corruption.
    """
    def __init__(self, window_seconds: float = 60.0):
        self.window_seconds = window_seconds
        self.seen_hashes: Dict[str, datetime] = {}

    def is_duplicate(self, event_hash: str, reference_time: Optional[datetime] = None) -> bool:
        now = reference_time or datetime.now(timezone.utc)
        
        # Only prune entries that are older than reference_time by window_seconds
        expired = [
            h for h, t in self.seen_hashes.items()
            if (now >= t and (now - t).total_seconds() > self.window_seconds)
        ]
        for h in expired:
            del self.seen_hashes[h]

        if event_hash in self.seen_hashes:
            return True

        self.seen_hashes[event_hash] = now
        return False


class EventNormalizer:
    deduplicator = EventDeduplicator(window_seconds=60.0)
    allowed_lateness_seconds: float = 300.0  # 5 minutes allowed lateness

    @staticmethod
    def generate_hash(source_ip: str, user_id: str, event_type: str, details: str, payload_metric: float) -> str:
        raw_str = f"{source_ip}|{user_id}|{event_type}|{details}|{payload_metric}"
        return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def parse_timestamp_safe(
        cls,
        raw_ts: Any,
        ingestion_time: Optional[datetime] = None
    ) -> Tuple[datetime, str, TimestampQuality, Optional[str]]:
        """
        Parses and validates telemetry timestamps robustly (Requirement C).
        Handles UTC 'Z', arbitrary timezone offsets (+05:30, -04:00), space-separated formats,
        implausible future timestamps, and expired lateness.
        """
        now_utc = ingestion_time or datetime.now(timezone.utc)

        if not raw_ts or str(raw_ts).strip() == "":
            return now_utc, now_utc.isoformat(), TimestampQuality.FALLBACK_MISSING, "Missing timestamp in telemetry payload; defaulted to ingestion UTC"

        ts_str_clean = str(raw_ts).strip().replace("Z", "+00:00")
        
        # Handle space between date and time (e.g. '2026-10-23 09:00:15')
        if " " in ts_str_clean and "T" not in ts_str_clean:
            ts_str_clean = ts_str_clean.replace(" ", "T")

        try:
            parsed_dt = datetime.fromisoformat(ts_str_clean)
            # If naive, assume UTC
            if parsed_dt.tzinfo is None:
                parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
            else:
                # Convert to UTC
                parsed_dt = parsed_dt.astimezone(timezone.utc)
        except Exception as e:
            return (
                now_utc,
                now_utc.isoformat(),
                TimestampQuality.FALLBACK_MALFORMED,
                f"Malformed timestamp '{raw_ts}' ({str(e)}); defaulted to ingestion UTC"
            )

        # Check for implausible future timestamp (drift > 60.0s ahead of now_utc)
        future_drift = (parsed_dt - now_utc).total_seconds()
        if future_drift > 60.0:
            return (
                now_utc,
                now_utc.isoformat(),
                TimestampQuality.FUTURE_TIMESTAMP,
                f"Implausible future timestamp ({future_drift:.1f}s ahead of ingestion); clamped to ingestion UTC"
            )

        # Check for expired lateness (> allowed_lateness_seconds)
        past_lag = (now_utc - parsed_dt).total_seconds()
        if past_lag > cls.allowed_lateness_seconds:
            return (
                parsed_dt,
                parsed_dt.isoformat(),
                TimestampQuality.EXPIRED_LATENESS,
                f"Telemetry arrived outside allowed lateness window ({past_lag:.1f}s old)"
            )

        return parsed_dt, parsed_dt.isoformat(), TimestampQuality.TRUSTED, None

    @classmethod
    def normalize(cls, raw: dict) -> Tuple[NormalizedEvent, bool]:
        """
        Normalizes a raw telemetry dictionary safely handling malformed inputs and timestamps.
        Returns (NormalizedEvent, is_duplicate)
        """
        event_id = str(raw.get("raw_id") or f"EVT-{uuid.uuid4().hex[:8].upper()}")
        ingest_now = datetime.now(timezone.utc)
        
        # Standardize and audit timestamp (Requirement C)
        raw_ts = raw.get("timestamp")
        ts_dt, ts_str, ts_quality, ts_reason = cls.parse_timestamp_safe(raw_ts, ingestion_time=ingest_now)
                
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

        src_ip = str(raw.get("source_ip") or "0.0.0.0").strip()
        usr_id = str(raw.get("user_id") or "unknown").strip()
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
            raw_timestamp=str(raw_ts) if raw_ts is not None else None,
            timestamp_quality=ts_quality,
            timestamp_fallback_reason=ts_reason,
            ingestion_timestamp=ingest_now.isoformat(),
            normalized_at=ingest_now.isoformat()
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
                dt, _, _, _ = cls.parse_timestamp_safe(ts)
                return dt
            except Exception:
                return datetime.min.replace(tzinfo=timezone.utc)

        # Sort batch by parsed timestamp to handle out-of-order streams
        sorted_raw = sorted(raw_list, key=parse_ts)

        results = []
        for raw in sorted_raw:
            norm, is_dup = cls.normalize(raw)
            results.append((norm, is_dup))

        return results

