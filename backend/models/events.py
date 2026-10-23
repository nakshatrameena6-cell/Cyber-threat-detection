from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from enum import Enum
from datetime import datetime, timezone

class AssetCriticality(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class EventType(str, Enum):
    LOGIN_FAILED = "LOGIN_FAILED"
    SUSPICIOUS_LOGIN = "SUSPICIOUS_LOGIN"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    SUDO_EXEC = "SUDO_EXEC"
    PORT_SCAN = "PORT_SCAN"
    C2_BEACON = "C2_BEACON"
    BYTES_OUT = "BYTES_OUT"
    CUSTOM = "CUSTOM"

class TimestampQuality(str, Enum):
    TRUSTED = "TRUSTED"
    FALLBACK_MALFORMED = "FALLBACK_MALFORMED"
    FALLBACK_MISSING = "FALLBACK_MISSING"
    OUT_OF_ORDER = "OUT_OF_ORDER"
    EXPIRED_LATENESS = "EXPIRED_LATENESS"
    FUTURE_TIMESTAMP = "FUTURE_TIMESTAMP"

class RawLogEvent(BaseModel):
    raw_id: Optional[str] = None
    timestamp: Optional[str] = None
    source_ip: str
    user_id: str
    event_type: str
    asset_id: str = "default-asset"
    asset_criticality: Optional[str] = "MEDIUM"
    payload_metric: float = 0.0
    details: Optional[str] = ""

class NormalizedEvent(BaseModel):
    event_id: str
    timestamp: str
    source_ip: str
    user_id: str
    event_type: EventType
    asset_id: str
    asset_criticality: AssetCriticality
    payload_metric: float
    details: str
    raw_timestamp: Optional[str] = None
    timestamp_quality: TimestampQuality = TimestampQuality.TRUSTED
    timestamp_fallback_reason: Optional[str] = None
    ingestion_timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    normalized_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


