from pydantic import BaseModel
from enum import Enum
from typing import Optional

class ResponseActionType(str, Enum):
    BLOCK_IP = "BLOCK_IP"
    SUSPEND_SESSION = "SUSPEND_SESSION"
    ISOLATE_ENDPOINT = "ISOLATE_ENDPOINT"
    ALERT_ONLY = "ALERT_ONLY"

class DecisionTier(str, Enum):
    TIER_A = "TIER_A"  # Low risk -> Alert log only
    TIER_B = "TIER_B"  # Medium risk -> Human approval required
    TIER_C = "TIER_C"  # High risk -> Auto execute if Kill Switch OFF

class ActionStatus(str, Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"

class VerificationStatus(str, Enum):
    NOT_VERIFIED = "NOT_VERIFIED"
    PASSED = "PASSED"
    FAILED = "FAILED"

class ResponseRecord(BaseModel):
    action_id: str
    incident_id: str
    action_type: ResponseActionType
    target: str
    tier: DecisionTier
    status: ActionStatus
    verification_status: VerificationStatus = VerificationStatus.NOT_VERIFIED
    executed_by: str  # "AUTO_ENGINE" or user_id
    execution_time: str
    verification_time: Optional[str] = None
    is_reversible: bool = True
    rolled_back: bool = False
    details: str
