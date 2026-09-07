"""Telemetry data schemas (REQ-ING-001, REQ-ING-002, REQ-ING-003)."""
from datetime import datetime
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class RawTelemetryEvent(BaseModel):
    """Raw ingested log event prior to normalization."""
    source_id: str = Field(..., description="ID of source telemetry producer")
    vendor: str = Field(..., description="Vendor name (e.g. Splunk, Crowdstrike)")
    raw_payload: str = Field(..., description="Unstructured or raw JSON payload")
    ingested_at: datetime = Field(default_factory=datetime.utcnow)


class NormalizedEvent(BaseModel):
    """Normalized security event mapped to standard schema."""
    event_id: str = Field(..., description="Unique event identifier or hash")
    source_id: str
    vendor: str
    event_type: str = Field(..., description="Categorized event type (e.g., LOGIN_FAILED)")
    timestamp: datetime
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user_id: Optional[str] = None
    host_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
