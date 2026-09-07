"""Policy decision schemas (REQ-POL-001, REQ-POL-002)."""
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class PolicyDecision(BaseModel):
    """Policy engine routing decision."""
    incident_id: str
    risk_score: float = Field(..., ge=0.0, le=1.0)
    response_tier: str = Field(..., description="ALERT_ONLY, HUMAN_REVIEW, CONTAINMENT_PROPOSAL")
    recommended_actions: List[str] = Field(default_factory=list)
    requires_human_approval: bool = True
    audit_verifiable: bool = False
    reasoning: str
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)
