"""Threat Alert schemas (REQ-DET-001, REQ-DET-002)."""
from datetime import datetime
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, FloatRange


class ThreatAlert(BaseModel):
    """Threat Alert produced by signature rule or ML anomaly evaluator."""
    alert_id: str = Field(..., description="Unique alert identifier")
    event_id: str = Field(..., description="Source normalized event ID")
    rule_id: str = Field(..., description="Signature rule or model ID")
    rule_name: str
    detection_type: str = Field(..., description="RULE_BASED or ML_ANOMALY")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Confidence in [0.0, 1.0]")
    severity: str = Field(..., description="LOW, MEDIUM, HIGH, CRITICAL")
    target_entity: str = Field(..., description="Affected host_id, user_id, or IP")
    details: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
