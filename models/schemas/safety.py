"""Safety & Kill Switch schemas (REQ-SAF-001, REQ-VRF-001)."""
from datetime import datetime
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class KillSwitchState(BaseModel):
    is_engaged: bool = False
    engaged_by: Optional[str] = None
    reason: Optional[str] = None
    last_updated: datetime = Field(default_factory=datetime.utcnow)


class PreActionStateSnapshot(BaseModel):
    snapshot_id: str
    target_entity: str
    state_data: Dict[str, Any] = Field(default_factory=dict)
    captured_at: datetime = Field(default_factory=datetime.utcnow)
