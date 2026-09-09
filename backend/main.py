import json
import os
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Depends, Header, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.models.events import RawLogEvent, NormalizedEvent
from backend.models.incidents import Incident, IncidentStatus
from backend.models.response import ResponseRecord, ResponseActionType, ActionStatus, DecisionTier
from backend.models.audit import AuditLogEntry

from backend.detection.normalizer import EventNormalizer
from backend.detection.behavioral_engine import BehavioralFeatureEngine, BehavioralVector
from backend.detection.rules_engine import RulesEngine
from backend.detection.ml_detector import MLAnomalyDetector
from backend.detection.risk_calculator import RiskCalculator
from backend.incidents.manager import IncidentManager
from backend.response.kill_switch import EmergencyKillSwitch
from backend.response.decision_engine import DecisionEngine
from backend.response.executor import ResponseExecutor
from backend.audit.logger import AuditLogger
from backend.rbac import RBACManager, require_role_permission

app = FastAPI(
    title="Suraksha AI - Cyber Threat Detection & Safe Response System",
    version="2.0.0",
    description="Suraksha AI: Behavioral Stream Telemetry, Composite Risk Scoring, Tiered Decision Engine, Safe Response Execution, Verification & Rollback."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pipeline Singletons
ml_detector = MLAnomalyDetector()
behavioral_engine = BehavioralFeatureEngine()
incident_manager = IncidentManager()
response_executor = ResponseExecutor()
audit_logger = AuditLogger()


class IngestResponse(BaseModel):
    normalized_event: NormalizedEvent
    threat_detected: bool
    is_duplicate: bool = False
    is_anomalous: bool = False
    behavioral_evidence: List[str] = []
    incident: Optional[Incident] = None
    response_record: Optional[ResponseRecord] = None
    message: str

class KillSwitchRequest(BaseModel):
    enable: bool

class ApprovalRequest(BaseModel):
    approved: bool
    reason: Optional[str] = "Analyst review completed"

class RollbackRequest(BaseModel):
    reason: Optional[str] = "Manual analyst rollback request"


def process_telemetry_pipeline(raw_dict: dict, actor: str = "SYSTEM", role: str = "SYSTEM") -> IngestResponse:
    """
    Executes the 9-stage Suraksha AI pipeline:
    Input Logs -> Deduplicate & Normalize -> Extract Behavioral Features -> Detect Threat (Rules + ML) -> Calculate Risk -> Create Incident -> Decide Response -> Execute Safe Action -> Verify & Audit
    """
    # 1. Normalize & Deduplicate
    norm_evt, is_dup = EventNormalizer.normalize(raw_dict)
    
    if is_dup:
        audit_logger.log(
            actor=actor, role=role, action_category="INGESTION",
            description=f"Duplicate event hash detected for '{norm_evt.event_type}' from {norm_evt.source_ip}. Skipped.",
            target_resource=norm_evt.event_id
        )
        return IngestResponse(
            normalized_event=norm_evt,
            threat_detected=False,
            is_duplicate=True,
            is_anomalous=False,
            behavioral_evidence=["Duplicate telemetry event ignored"],
            incident=None,
            response_record=None,
            message="Event ignored: Duplicate event in sliding window."
        )

    audit_logger.log(
        actor=actor, role=role, action_category="INGESTION",
        description=f"Ingested event '{norm_evt.event_type}' from {norm_evt.source_ip}",
        target_resource=norm_evt.event_id,
        metadata={"source_ip": norm_evt.source_ip, "user_id": norm_evt.user_id}
    )

    # 2. Behavioral Feature Extraction
    vec, evidence = behavioral_engine.update_and_extract(norm_evt)

    # 3. Hybrid Threat Detection (Rules + ML Behavioral Anomaly)
    threat_cat, rule_sev, rule_conf, rule_reason = RulesEngine.evaluate(norm_evt)
    ml_score = ml_detector.predict_anomaly_score(norm_evt, vec)
    is_anomalous = (ml_score >= 0.50)

    audit_logger.log(
        actor="DETECTION_ENGINE", role="SYSTEM", action_category="DETECTION",
        description=f"Behavioral evaluation score: {ml_score}. Threat Category: {threat_cat.value}",
        target_resource=norm_evt.event_id,
        metadata={"threat_category": threat_cat.value, "rule_severity": rule_sev.value, "ml_score": ml_score}
    )

    # If benign and low anomaly score, return early
    if threat_cat == "None / Benign" and ml_score < 0.65:
        return IngestResponse(
            normalized_event=norm_evt,
            threat_detected=False,
            is_duplicate=False,
            is_anomalous=is_anomalous,
            behavioral_evidence=evidence,
            incident=None,
            response_record=None,
            message="Event processed: Normal traffic."
        )

    # 4. Calculate Composite Risk & Confidence
    risk_score, confidence_score, rec_action_str = RiskCalculator.calculate(
        norm_evt, threat_cat, rule_sev, rule_conf, ml_score, vec, evidence
    )

    # 5. Decide Response Tier
    tier, initial_action_status, action_type, decision_reason = DecisionEngine.evaluate_tier(
        risk_score, confidence_score, rec_action_str
    )

    # 6. Create Incident with Behavioral Evidence
    full_details = f"{rule_reason} (ML Score: {ml_score}). {decision_reason}"
    incident = incident_manager.create_incident(
        event_id=norm_evt.event_id,
        threat_category=threat_cat,
        severity=rule_sev,
        risk_score=risk_score,
        confidence_score=confidence_score,
        source_ip=norm_evt.source_ip,
        user_id=norm_evt.user_id,
        asset_id=norm_evt.asset_id,
        details=full_details,
        recommended_action=action_type.value,
        decision_tier=tier.value,
        is_anomalous=is_anomalous,
        behavioral_evidence=evidence
    )

    audit_logger.log(
        actor="INCIDENT_ENGINE", role="SYSTEM", action_category="INCIDENT",
        description=f"Created incident {incident.incident_id} (Risk: {risk_score}, Tier: {tier.value})",
        target_resource=incident.incident_id,
        metadata={"risk_score": risk_score, "tier": tier.value, "evidence": evidence}
    )

    # Determine target resource for response action
    target_res = norm_evt.source_ip
    if action_type == ResponseActionType.SUSPEND_SESSION:
        target_res = norm_evt.user_id
    elif action_type == ResponseActionType.ISOLATE_ENDPOINT:
        target_res = norm_evt.asset_id

    response_rec = None

    # 7. Execute Safe Action if APPROVED automatically (Tier C & Kill Switch OFF)
    if initial_action_status == ActionStatus.APPROVED:
        response_rec = response_executor.execute_action(
            incident_id=incident.incident_id,
            action_type=action_type,
            target=target_res,
            tier=tier,
            actor="AUTO_ENGINE",
            details=f"Automated Tier C execution for Incident {incident.incident_id}"
        )
        incident_manager.mark_action_executed(incident.incident_id)

        audit_logger.log(
            actor="AUTO_ENGINE", role="SYSTEM", action_category="EXECUTION",
            description=f"Executed automated response {action_type.value} on '{target_res}'. Verification: {response_rec.verification_status.value}",
            target_resource=response_rec.action_id,
            metadata={"verification": response_rec.verification_status.value, "target": target_res}
        )
    else:
        audit_logger.log(
            actor="DECISION_ENGINE", role="SYSTEM", action_category="DECISION",
            description=f"Incident {incident.incident_id} queued with status '{initial_action_status.value}'. Reason: {decision_reason}",
            target_resource=incident.incident_id,
            metadata={"status": initial_action_status.value, "tier": tier.value}
        )

    return IngestResponse(
        normalized_event=norm_evt,
        threat_detected=True,
        is_duplicate=False,
        is_anomalous=is_anomalous,
        behavioral_evidence=evidence,
        incident=incident,
        response_record=response_rec,
        message=f"Threat processed: Incident {incident.incident_id} created."
    )


# --- REST API Endpoints ---

@app.post("/api/telemetry/ingest", response_model=IngestResponse)
def ingest_telemetry(
    raw_event: RawLogEvent,
    user_info: dict = Depends(lambda: {"user_id": "api_user", "role": "ANALYST"})
):
    return process_telemetry_pipeline(raw_event.model_dump(), actor=user_info["user_id"], role=user_info["role"])


@app.post("/api/telemetry/ingest-batch", response_model=List[IngestResponse])
def ingest_telemetry_batch(
    raw_events: List[RawLogEvent],
    user_info: dict = Depends(lambda: {"user_id": "stream_ingest", "role": "ANALYST"})
):
    """
    Batch ingestion endpoint for telemetry stream files or sequential log arrays.
    Sorts out-of-order timestamps and processes events sequentially through deduplication and behavioral engine.
    """
    raw_list = [e.model_dump() for e in raw_events]
    batch_results = EventNormalizer.normalize_batch(raw_list)

    responses = []
    for norm_evt, is_dup in batch_results:
        res = process_telemetry_pipeline(norm_evt.model_dump(), actor=user_info["user_id"], role=user_info["role"])
        responses.append(res)
    return responses


@app.get("/api/incidents", response_model=List[Incident])
def get_incidents(status: Optional[IncidentStatus] = None):
    return incident_manager.list_incidents(status=status)


@app.get("/api/incidents/{incident_id}", response_model=Incident)
def get_incident_detail(incident_id: str):
    inc = incident_manager.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


@app.post("/api/incidents/{incident_id}/approve")
def approve_and_execute_response(
    incident_id: str,
    req: ApprovalRequest,
    user_info: dict = Depends(lambda: {"user_id": "analyst_john", "role": "ANALYST"})
):
    inc = incident_manager.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    if inc.action_executed:
        return {"message": f"Action already executed for incident {incident_id}."}

    if not req.approved:
        incident_manager.update_status(incident_id, IncidentStatus.FALSE_POSITIVE, assigned_to=user_info["user_id"])
        audit_logger.log(
            actor=user_info["user_id"], role=user_info["role"], action_category="APPROVAL",
            description=f"Analyst DENIED response action for incident {incident_id}. Marked as FALSE_POSITIVE.",
            target_resource=incident_id
        )
        return {"message": f"Incident {incident_id} response DENIED and marked FALSE_POSITIVE."}

    try:
        act_type = ResponseActionType(inc.recommended_action)
    except ValueError:
        act_type = ResponseActionType.ALERT_ONLY

    target = inc.source_ip
    if act_type == ResponseActionType.SUSPEND_SESSION:
        target = inc.user_id
    elif act_type == ResponseActionType.ISOLATE_ENDPOINT:
        target = inc.asset_id

    rec = response_executor.execute_action(
        incident_id=incident_id,
        action_type=act_type,
        target=target,
        tier=DecisionTier(inc.decision_tier),
        actor=user_info["user_id"],
        details=f"Manual Analyst Approval by {user_info['user_id']}: {req.reason}"
    )

    incident_manager.mark_action_executed(incident_id)

    audit_logger.log(
        actor=user_info["user_id"], role=user_info["role"], action_category="APPROVAL",
        description=f"Analyst APPROVED & EXECUTED action {act_type.value} on '{target}' for Incident {incident_id}",
        target_resource=rec.action_id
    )

    return {"message": "Response executed successfully", "response_record": rec}


@app.post("/api/response/{action_id}/rollback")
def rollback_response_action(
    action_id: str,
    req: RollbackRequest,
    user_info: dict = Depends(lambda: {"user_id": "admin_alice", "role": "ADMIN"})
):
    success, msg, rec = response_executor.rollback_action(action_id, actor=user_info["user_id"])
    if not success:
        raise HTTPException(status_code=400, detail=msg)

    audit_logger.log(
        actor=user_info["user_id"], role=user_info["role"], action_category="ROLLBACK",
        description=f"Admin rolled back action {action_id}: {msg}",
        target_resource=action_id
    )

    return {"message": msg, "response_record": rec}


@app.get("/api/response/records", response_model=List[ResponseRecord])
def list_response_records():
    return response_executor.list_records()


@app.post("/api/kill-switch/toggle")
def toggle_kill_switch(
    req: KillSwitchRequest,
    user_info: dict = Depends(lambda: {"user_id": "admin_alice", "role": "ADMIN"})
):
    if req.enable:
        res = EmergencyKillSwitch.enable(actor=user_info["user_id"])
    else:
        res = EmergencyKillSwitch.disable(actor=user_info["user_id"])

    audit_logger.log(
        actor=user_info["user_id"], role=user_info["role"], action_category="KILL_SWITCH",
        description=res["message"],
        target_resource="GLOBAL_KILL_SWITCH"
    )
    return res


@app.get("/api/kill-switch/status")
def get_kill_switch_status():
    return EmergencyKillSwitch.get_state()


@app.get("/api/audit", response_model=List[AuditLogEntry])
def get_audit_logs(category: Optional[str] = None, actor: Optional[str] = None):
    return audit_logger.list_logs(category=category, actor=actor)


@app.get("/api/system/state")
def get_system_state():
    store = response_executor.get_state_store()
    return {
        "blocked_ips": list(store["blocked_ips"]),
        "suspended_users": list(store["suspended_users"]),
        "isolated_hosts": list(store["isolated_hosts"]),
        "total_incidents": len(incident_manager.list_incidents()),
        "total_actions": len(response_executor.list_records()),
        "kill_switch": EmergencyKillSwitch.get_state()
    }


@app.post("/api/simulator/inject-attack")
def inject_simulated_attack(attack_type: str = "BRUTE_FORCE"):
    attacks = {
        "BRUTE_FORCE": {
            "raw_id": f"SIM-BF-{os.urandom(2).hex()}",
            "source_ip": "198.51.100.99",
            "user_id": "victim_user",
            "event_type": "LOGIN_FAILED",
            "asset_id": "auth-portal-01",
            "asset_criticality": "HIGH",
            "payload_metric": 8.0,
            "details": "Simulated password spraying brute force attack (8 attempts)"
        },
        "SUSPICIOUS_LOGIN": {
            "raw_id": f"SIM-SL-{os.urandom(2).hex()}",
            "source_ip": "185.220.101.5",
            "user_id": "executive_sec",
            "event_type": "SUSPICIOUS_LOGIN",
            "asset_id": "vpn-gateway",
            "asset_criticality": "MEDIUM",
            "payload_metric": 1.0,
            "details": "Simulated impossible travel login from unknown country proxy"
        },
        "PRIVILEGE_ESCALATION": {
            "raw_id": f"SIM-PE-{os.urandom(2).hex()}",
            "source_ip": "10.0.3.15",
            "user_id": "web_guest",
            "event_type": "SUDO_EXEC",
            "asset_id": "app-server-02",
            "asset_criticality": "HIGH",
            "payload_metric": 1.0,
            "details": "Simulated local privilege escalation attempt (sudo su root)"
        },
        "LATERAL_MOVEMENT": {
            "raw_id": f"SIM-LM-{os.urandom(2).hex()}",
            "source_ip": "10.0.5.40",
            "user_id": "compromised_host",
            "event_type": "PORT_SCAN",
            "asset_id": "subnet-finance",
            "asset_criticality": "HIGH",
            "payload_metric": 50.0,
            "details": "Simulated internal network port scan targeting SMB port 445"
        },
        "C2_BEACON": {
            "raw_id": f"SIM-C2-{os.urandom(2).hex()}",
            "source_ip": "10.0.2.19",
            "user_id": "workstation-09",
            "event_type": "C2_BEACON",
            "asset_id": "workstation-09",
            "asset_criticality": "MEDIUM",
            "payload_metric": 10.0,
            "details": "Simulated malware C2 beaconing to domain darknet-cmd.org"
        },
        "UNUSUAL_DATA_TRANSFER": {
            "raw_id": f"SIM-EX-{os.urandom(2).hex()}",
            "source_ip": "10.0.1.77",
            "user_id": "db_admin",
            "event_type": "BYTES_OUT",
            "asset_id": "customer-db-primary",
            "asset_criticality": "HIGH",
            "payload_metric": 950.0,
            "details": "Simulated mass data exfiltration of 950 MB to external cloud"
        }
    }

    raw = attacks.get(attack_type.upper())
    if not raw:
        raise HTTPException(status_code=400, detail=f"Unknown attack type '{attack_type}'. Available: {list(attacks.keys())}")

    return process_telemetry_pipeline(raw, actor="ATTACK_SIMULATOR", role="ADMIN")


@app.post("/api/simulator/inject-stream")
def inject_telemetry_stream():
    """
    Simulates reading and ingesting the realistic stream dataset from data/sample_telemetry.json
    """
    data_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "sample_telemetry.json")
    if not os.path.exists(data_path):
        raise HTTPException(status_code=404, detail="Sample dataset sample_telemetry.json not found")

    with open(data_path, "r", encoding="utf-8") as f:
        events = json.load(f)

    batch_results = EventNormalizer.normalize_batch(events)
    responses = []
    for norm_evt, is_dup in batch_results:
        res = process_telemetry_pipeline(norm_evt.model_dump(), actor="STREAM_SIMULATOR", role="ADMIN")
        responses.append(res)

    return {"total_stream_events": len(events), "processed_responses": responses}


# Mount static frontend directory
frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
