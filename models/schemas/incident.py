"""Incident data schemas (REQ-COR-001, REQ-SCO-001)."""
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field
from models.schemas.alert import ThreatAlert


class CorrelatedIncident(BaseModel):
    """Correlated group of threat alerts sharing entities and time proximity."""
    incident_id: str = Field(..., description="Unique incident identifier")
    title: str
    target_entity: str = Field(..., description="Correlated entity (host, user, IP)")
    alerts: List[ThreatAlert] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    max_severity: str = Field(default="LOW")
    risk_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    status: str = Field(default="OPEN", description="OPEN, IN_REVIEW, CONTAINED, CLOSED")
    created_at: datetime = Field(default_factory=datetime.utcnow)
