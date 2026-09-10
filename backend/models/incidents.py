from pydantic import BaseModel, Field
from enum import Enum
from typing import Optional, List, Dict, Any

class ThreatCategory(str, Enum):
    SUSPICIOUS_LOGIN = "Suspicious Login"
    BRUTE_FORCE = "Brute Force"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    LATERAL_MOVEMENT = "Lateral Movement"
    C2_ACTIVITY = "C2-like Activity"
    UNUSUAL_DATA_TRANSFER = "Unusual Data Transfer"
    NONE = "None / Benign"

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class IncidentStatus(str, Enum):
    NEW = "NEW"
    UNDER_INVESTIGATION = "UNDER_INVESTIGATION"
    MITIGATED = "MITIGATED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"

# Allowed lifecycle state transitions
VALID_TRANSITIONS: Dict[IncidentStatus, List[IncidentStatus]] = {
    IncidentStatus.NEW: [IncidentStatus.UNDER_INVESTIGATION, IncidentStatus.MITIGATED, IncidentStatus.FALSE_POSITIVE],
    IncidentStatus.UNDER_INVESTIGATION: [IncidentStatus.MITIGATED, IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE],
    IncidentStatus.MITIGATED: [IncidentStatus.RESOLVED, IncidentStatus.UNDER_INVESTIGATION],
    IncidentStatus.RESOLVED: [], # Terminal
    IncidentStatus.FALSE_POSITIVE: [] # Terminal
}

class Incident(BaseModel):
    incident_id: str
    event_id: str
    threat_category: ThreatCategory
    threat_categories: List[ThreatCategory] = []
    severity: Severity
    risk_score: float
    confidence_score: float
    source_ip: str
    user_id: str
    affected_user: str = ""
    asset_id: str
    affected_endpoint: str = ""
    details: str
    status: IncidentStatus = IncidentStatus.NEW
    created_at: str
    first_seen: str = ""
    last_seen: str = ""
    recommended_action: str
    decision_tier: str
    action_executed: bool = False
    assigned_to: Optional[str] = None
    is_anomalous: bool = True
    behavioral_evidence: List[str] = []
    why_evidence: List[str] = []
    related_events: List[str] = []
    timeline: List[Dict[str, Any]] = []
    verification_status: str = "NOT_VERIFIED"
    rollback_status: str = "NOT_ROLLED_BACK"
