from pydantic import BaseModel
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

class Incident(BaseModel):
    incident_id: str
    event_id: str
    threat_category: ThreatCategory
    severity: Severity
    risk_score: float
    confidence_score: float
    source_ip: str
    user_id: str
    asset_id: str
    details: str
    status: IncidentStatus = IncidentStatus.NEW
    created_at: str
    recommended_action: str
    decision_tier: str
    action_executed: bool = False
    assigned_to: Optional[str] = None
    is_anomalous: bool = True
    behavioral_evidence: List[str] = []
