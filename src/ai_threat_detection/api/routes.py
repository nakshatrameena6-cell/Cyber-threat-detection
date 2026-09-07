"""API Routes Definition (REQ-API-001)."""
from typing import Dict, Any, List
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from models.schemas.telemetry import RawTelemetryEvent
from ai_threat_detection.ingestion.ingestor import TelemetryIngestor
from ai_threat_detection.detection.detector import ThreatDetector
from ai_threat_detection.correlation.engine import CorrelationEngine
from ai_threat_detection.scoring.engine import RiskScoringEngine
from ai_threat_detection.policy.engine import PolicyEngine
from ai_threat_detection.safety.kill_switch import GlobalKillSwitch, KillSwitchEngagedException
from ai_threat_detection.audit.logger import AuditLogger
from ai_threat_detection.security.auth import AuthManager, SecurityContext
from ai_threat_detection.security.rbac import RBACController

router = APIRouter(prefix="/api/v1")

ingestor = TelemetryIngestor()
detector = ThreatDetector()
correlator = CorrelationEngine()
scorer = RiskScoringEngine()
policy_engine = PolicyEngine()
kill_switch = GlobalKillSwitch()
audit_logger = AuditLogger()
auth_manager = AuthManager()
rbac = RBACController()


def get_current_user(auth_header: str = "analyst-token") -> SecurityContext:
    try:
        return auth_manager.authenticate(auth_header)
    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")


class IngestRequest(BaseModel):
    source_id: str
    vendor: str
    events: List[Dict[str, Any]]


@router.post("/telemetry/ingest")
def ingest_telemetry(req: IngestRequest, ctx: SecurityContext = Depends(get_current_user)):
    rbac.authorize(ctx.role, "telemetry:ingest")
    
    processed_count = 0
    alerts_created = []

    for item in req.events:
        raw_event = RawTelemetryEvent(
            source_id=req.source_id,
            vendor=req.vendor,
            raw_payload=str(item)
        )
        normalized_list = ingestor.process_raw_event(raw_event)
        for norm in normalized_list:
            processed_count += 1
            alert = detector.evaluate_event(norm)
            if alert:
                alerts_created.append(alert)
                incident = correlator.correlate_alert(alert)
                scorer.calculate_risk(incident)
                policy_engine.evaluate_policy(incident)

    return {
        "status": "SUCCESS",
        "processed_events": processed_count,
        "alerts_generated": len(alerts_created)
    }


@router.get("/safety/kill-switch")
def get_kill_switch_status(ctx: SecurityContext = Depends(get_current_user)):
    rbac.authorize(ctx.role, "telemetry:read")
    return {
        "is_engaged": kill_switch.is_engaged(),
        "state": kill_switch._load_state().dict()
    }


class KillSwitchToggleRequest(BaseModel):
    engage: bool
    reason: str


@router.post("/safety/kill-switch")
def toggle_kill_switch(req: KillSwitchToggleRequest, ctx: SecurityContext = Depends(get_current_user)):
    rbac.authorize(ctx.role, "safety:kill_switch")
    if req.engage:
        state = kill_switch.engage(ctx.user_id, req.reason)
    else:
        state = kill_switch.disengage(ctx.user_id)
    return {"status": "SUCCESS", "kill_switch_state": state.dict()}
