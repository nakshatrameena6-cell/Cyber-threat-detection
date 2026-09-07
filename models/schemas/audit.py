"""Audit event schemas (REQ-AUD-001, REQ-AUD-002)."""
from datetime import datetime
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class AuditEvent(BaseModel):
    """Immutable audit record."""
    audit_id: str = Field(..., description="Unique audit event ID")
    actor: str = Field(..., description="User ID or Service Name")
    action: str = Field(..., description="Action description")
    target_resource: str = Field(..., description="Target entity / asset ID")
    details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    persisted: bool = Field(default=False, description="Hard precondition status")
    checksum: Optional[str] = Field(default=None, description="Cryptographic integrity hash")
