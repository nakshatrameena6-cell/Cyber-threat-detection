"""Playbook execution schemas (REQ-PLY-001, REQ-PLY-002)."""
from datetime import datetime
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class PlaybookStep(BaseModel):
    name: str
    action: str
    args: Dict[str, Any] = Field(default_factory=dict)
    status: str = Field(default="PENDING", description="PENDING, SUCCESS, FAILED, SKIPPED")


class PlaybookDefinition(BaseModel):
    id: str
    name: str
    target_entity_type: str
    risk_tier: str
    steps: List[PlaybookStep]


class PlaybookExecutionState(BaseModel):
    execution_id: str
    playbook_id: str
    incident_id: str
    status: str = Field(default="PENDING", description="PENDING, AUDITED, EXECUTING, COMPLETED, FAILED, ROLLED_BACK, KILLED")
    audit_event_id: Optional[str] = None
    step_results: List[Dict[str, Any]] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
