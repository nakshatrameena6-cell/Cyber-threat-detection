import json
import os
from contextlib import asynccontextmanager
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Depends, Header, Request, status
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.models.events import RawLogEvent, NormalizedEvent
from backend.models.incidents import Incident, IncidentStatus, ThreatCategory
from backend.models.response import ResponseRecord, ResponseActionType, ActionStatus, DecisionTier
from backend.models.audit import AuditLogEntry

from backend.database import DatabaseManager, get_db_path
from backend.detection.normalizer import EventNormalizer
from backend.detection.behavioral_engine import BehavioralFeatureEngine, BehavioralVector
from backend.detection.rules_engine import RulesEngine
from backend.detection.ml_detector import MLAnomalyDetector
from backend.detection.risk_calculator import RiskCalculator
from backend.incidents.manager import IncidentManager
from backend.incidents.correlation import IncidentCorrelationEngine
from backend.response.kill_switch import EmergencyKillSwitch
from backend.response.decision_engine import DecisionEngine
from backend.response.policy_engine import ResponsePolicyEngine
from backend.response.executor import ResponseExecutor
from backend.audit.logger import AuditLogger
from backend.rbac import RBACManager, require_role_permission
from backend.telemetry.syslog_listener import SyslogListener

# Pipeline & Persistence Singletons
db_manager = DatabaseManager()
ml_detector = MLAnomalyDetector()
behavioral_engine = BehavioralFeatureEngine()
correlation_engine = IncidentCorrelationEngine()
incident_manager = IncidentManager(db=db_manager)
response_executor = ResponseExecutor(db=db_manager)
audit_logger = AuditLogger(db=db_manager)

# Check and apply kill switch startup configuration
kill_switch_startup = os.environ.get("SURAKSHA_KILL_SWITCH_DEFAULT", "0").lower()
if kill_switch_startup in ("1", "true", "active"):
    EmergencyKillSwitch.enable(actor="STARTUP_CONFIG")

def syslog_callback(event_dict: dict, actor: str, role: str):
    try:
        process_telemetry_pipeline(event_dict, actor=actor, role=role)
    except Exception:
        pass

syslog_listener = SyslogListener(pipeline_callback=syslog_callback)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: start optional syslog listener if configured
    if syslog_listener.is_enabled:
        syslog_listener.start()
    yield
    # Shutdown: stop syslog listener safely
    syslog_listener.stop()

app = FastAPI(
    title="Suraksha AI - Real-Time Cyber Threat Detection & Safe Response System",
    version="4.0.0",
    description="Suraksha AI Phase 4: Real-Time Ingestion, SQLite Persistence, Strict Tier Semantics & Reliability Hardening.",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class IngestResponse(BaseModel):
    normalized_event: NormalizedEvent
    threat_detected: bool
    is_duplicate: bool = False
    is_anomalous: bool = False
    behavioral_evidence: List[str] = []
    why_evidence: List[str] = []
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
    Executes the 9-stage Suraksha AI pipeline with Phase 4 Reliability & Persistence:
    Telemetry -> Normalization & Sliding Deduplication -> SQLite Ingestion Persistence ->
    Behavioral Feature Extraction -> Rules + ML Anomaly Detection -> Composite Risk & "Why" Evidence ->
    Incident Correlation & Persistence -> Policy Engine (Tier A/B/C) -> 10 Safety Gates ->
    Simulated Response & Independent Verification -> Tamper-Evident SQLite Audit Trail
    """
    # 1. Normalize & Deduplicate
    norm_evt, is_dup = EventNormalizer.normalize(raw_dict)

    # Persist normalized telemetry event in SQLite
    try:
        db_manager.save_telemetry_event(
            norm_evt.model_dump(),
            raw_json=json.dumps(raw_dict),
            is_dup=is_dup
        )
    except Exception as e:
        # If telemetry persistence fails, log and continue safely
        pass

    if is_dup:
        audit_logger.log(
            actor=actor, role=role, action_category="INGESTION",
            description=f"Duplicate event hash detected for '{norm_evt.event_type.value}' from {norm_evt.source_ip}. Suppressed from primary detection.",
            target_resource=norm_evt.event_id
        )
        active_incidents = incident_manager.list_incidents()
        existing_incident = correlation_engine.find_correlatable_incident(norm_evt, active_incidents)
        if existing_incident:
            # Safely append duplicate observation to incident timeline without triggering remediation
            correlation_engine.record_duplicate_observation(existing_incident, norm_evt)
            incident_manager.save_incident_update(existing_incident)
            audit_logger.log(
                actor="CORRELATION_ENGINE", role="SYSTEM", action_category="CORRELATION",
                description=f"Duplicate observation of event '{norm_evt.event_id}' associated with incident {existing_incident.incident_id} (count: {existing_incident.duplicate_events_count}). Zero remediation executed.",
                target_resource=existing_incident.incident_id
            )
            return IngestResponse(
                normalized_event=norm_evt,
                threat_detected=False,
                is_duplicate=True,
                is_anomalous=False,
                behavioral_evidence=[f"Duplicate telemetry event observed ({existing_incident.duplicate_events_count} total suppressed for incident)"],
                why_evidence=["Duplicate observation associated with active incident timeline without response re-execution."],
                incident=existing_incident,
                response_record=None,
                message=f"Duplicate event observed and correlated to incident {existing_incident.incident_id}."
            )
        else:
            return IngestResponse(
                normalized_event=norm_evt,
                threat_detected=False,
                is_duplicate=True,
                is_anomalous=False,
                behavioral_evidence=["Duplicate telemetry event ignored (no active incident found)"],
                why_evidence=["Duplicate event in 60s sliding window without active incident."],
                incident=None,
                response_record=None,
                message="Event ignored: Duplicate event in sliding window."
            )

    audit_logger.log(
        actor=actor, role=role, action_category="INGESTION",
        description=f"Ingested event '{norm_evt.event_type.value}' from {norm_evt.source_ip}",
        target_resource=norm_evt.event_id,
        metadata={"source_ip": norm_evt.source_ip, "user_id": norm_evt.user_id}
    )

    # 2. Behavioral Feature Extraction
    vec, evidence = behavioral_engine.update_and_extract(norm_evt)

    # 3. Hybrid Threat Detection (Deterministic Rules + ML Behavioral Anomaly)
    threat_cat, rule_sev, rule_conf, rule_reason = RulesEngine.evaluate(norm_evt, vector=vec)
    ml_score = ml_detector.predict_anomaly_score(norm_evt, vec)
    is_anomalous = (ml_score >= 0.50)
    is_anomaly_only = (threat_cat == ThreatCategory.NONE or threat_cat == "None / Benign")

    audit_logger.log(
        actor="DETECTION_ENGINE", role="SYSTEM", action_category="DETECTION",
        description=f"Behavioral evaluation score: {ml_score}. Threat Category: {threat_cat.value}",
        target_resource=norm_evt.event_id,
        metadata={"threat_category": threat_cat.value, "rule_severity": rule_sev.value, "ml_score": ml_score}
    )

    # Check existing open incidents for correlation
    active_incidents = incident_manager.list_incidents()
    existing_incident = correlation_engine.find_correlatable_incident(norm_evt, active_incidents)

    # If benign and low anomaly score AND no correlated active incident exists, return early
    if is_anomaly_only and ml_score < 0.65 and not existing_incident:
        return IngestResponse(
            normalized_event=norm_evt,
            threat_detected=False,
            is_duplicate=False,
            is_anomalous=is_anomalous,
            behavioral_evidence=evidence,
            why_evidence=["Normal operational telemetry"],
            incident=None,
            response_record=None,
            message="Event processed: Normal traffic."
        )

    # 4. Composite Risk & Transparent "Why" Evidence Calculation
    risk_score, confidence_score, rec_action_str, why_bullets = RiskCalculator.calculate(
        norm_evt, threat_cat, rule_sev, rule_conf, ml_score, vec, evidence
    )

    # Phase 4 Safety Rule: IsolationForest anomaly score alone must never authorize remediation
    if is_anomaly_only:
        rec_action_str = ResponseActionType.ALERT_ONLY.value
        why_bullets.append("ML anomaly score alone cannot authorize remediation actions.")

    # 5. Response Policy Evaluation (Tier A, Tier B, Tier C)
    tier, policy_status, action_type, policy_reason, auto_allowed = ResponsePolicyEngine.evaluate_policy(
        threat_cat, risk_score, confidence_score, rec_action_str, is_anomaly_only=is_anomaly_only
    )

    # 6. Incident Correlation Engine (Merge into existing open incident or create new)
    if existing_incident:
        incident = correlation_engine.merge_event_into_incident(
            incident=existing_incident,
            event=norm_evt,
            threat_cat=threat_cat,
            new_risk=risk_score,
            new_confidence=confidence_score,
            evidence=evidence,
            why_bullets=why_bullets
        )
        incident_manager.save_incident_update(incident)
        audit_logger.log(
            actor="CORRELATION_ENGINE", role="SYSTEM", action_category="CORRELATION",
            description=f"Correlated event {norm_evt.event_id} into incident {incident.incident_id}. Escalated Risk: {incident.risk_score}",
            target_resource=incident.incident_id
        )
    else:
        full_details = f"{rule_reason} (ML Score: {ml_score}). {policy_reason}"
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
            behavioral_evidence=evidence,
            why_evidence=why_bullets,
            event_timestamp=norm_evt.timestamp
        )
        audit_logger.log(
            actor="INCIDENT_ENGINE", role="SYSTEM", action_category="INCIDENT",
            description=f"Created incident {incident.incident_id} (Risk: {risk_score}, Tier: {tier.value})",
            target_resource=incident.incident_id
        )

    # Determine target resource for response action
    target_res = norm_evt.source_ip
    if action_type == ResponseActionType.SUSPEND_SESSION:
        target_res = norm_evt.user_id
    elif action_type == ResponseActionType.ISOLATE_ENDPOINT:
        target_res = norm_evt.asset_id

    response_rec = None

    # 7. Execute Safe Response via 10 Safety Gates
    # Strict Rule: Tier C actions are NEVER auto-executed!
    if policy_status == ActionStatus.APPROVED and auto_allowed and tier != DecisionTier.TIER_C:
        response_rec = response_executor.execute_action(
            incident_id=incident.incident_id,
            action_type=action_type,
            target=target_res,
            tier=tier,
            actor="AUTO_ENGINE",
            actor_role="ADMIN",
            is_auto_execution=True,
            details=f"Automated policy execution for Incident {incident.incident_id}"
        )

        if response_rec.success:
            incident_manager.mark_action_executed(incident.incident_id)
            incident.verification_status = response_rec.verification_status.value
            audit_logger.log(
                actor="AUTO_ENGINE", role="SYSTEM", action_category="EXECUTION",
                description=f"Executed automated response {action_type.value} on '{target_res}'. Verification: {response_rec.verification_status.value}",
                target_resource=response_rec.action_id
            )
        else:
            audit_logger.log(
                actor="SAFETY_GATES", role="SYSTEM", action_category="DECISION",
                description=f"Execution blocked for Incident {incident.incident_id}: {response_rec.gate_message}",
                target_resource=incident.incident_id
            )
    else:
        audit_logger.log(
            actor="POLICY_ENGINE", role="SYSTEM", action_category="DECISION",
            description=f"Incident {incident.incident_id} queued with status '{policy_status.value}'. Reason: {policy_reason}",
            target_resource=incident.incident_id
        )

    return IngestResponse(
        normalized_event=norm_evt,
        threat_detected=True,
        is_duplicate=False,
        is_anomalous=is_anomalous,
        behavioral_evidence=evidence,
        why_evidence=why_bullets,
        incident=incident,
        response_record=response_rec,
        message=f"Threat processed: Incident {incident.incident_id} updated/created."
    )


# --- REST API Endpoints ---

@app.post("/api/telemetry/event", response_model=IngestResponse, status_code=status.HTTP_201_CREATED)
def ingest_single_event(
    raw_event: RawLogEvent,
    user_info: dict = Depends(lambda: {"user_id": "api_client", "role": "ANALYST"})
):
    """
    Workstream C: Real-time single-event telemetry ingestion endpoint.
    Validates payload, normalizes timestamps to UTC ISO, reuses the 9-stage pipeline, and persists in SQLite.
    """
    try:
        return process_telemetry_pipeline(raw_event.model_dump(), actor=user_info["user_id"], role=user_info["role"])
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=f"Validation Error: {str(ve)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal ingestion processing error.")


@app.post("/api/telemetry/webhook", response_model=IngestResponse, status_code=status.HTTP_201_CREATED)
async def ingest_webhook(
    request: Request,
    x_webhook_secret: Optional[str] = Header(None, alias="X-Webhook-Secret"),
    authorization: Optional[str] = Header(None)
):
    """
    Workstream C: Generic JSON webhook endpoint for external security-event producers.
    Accepts arbitrary JSON payloads, maps standard SIEM/webhook fields, checks optional secret,
    and runs through the unified detection and persistence pipeline.
    """
    # Verify optional webhook secret
    expected_secret = os.environ.get("SURAKSHA_WEBHOOK_SECRET")
    if expected_secret:
        auth_token = None
        if authorization and authorization.startswith("Bearer "):
            auth_token = authorization.split("Bearer ", 1)[1]
        provided_secret = x_webhook_secret or auth_token
        if provided_secret != expected_secret:
            raise HTTPException(status_code=401, detail="Unauthorized: Invalid webhook secret token.")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed JSON: Request body must be valid JSON.")

    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Invalid payload: Webhook body must be a JSON object.")

    # Gracefully map generic JSON fields to RawLogEvent schema
    source_ip = body.get("source_ip") or body.get("src_ip") or body.get("ip") or body.get("client_ip") or "127.0.0.1"
    user_id = body.get("user_id") or body.get("username") or body.get("user") or body.get("account") or "webhook_user"
    event_type = body.get("event_type") or body.get("action") or body.get("event") or body.get("type") or "WEBHOOK_EVENT"
    asset_id = body.get("asset_id") or body.get("host") or body.get("hostname") or body.get("destination") or "webhook-asset"
    asset_criticality = body.get("asset_criticality", "MEDIUM")
    payload_metric = float(body.get("payload_metric") or body.get("bytes") or body.get("count") or 1.0)
    details = body.get("details") or body.get("message") or body.get("description") or f"Webhook event received: {event_type}"

    raw_event = {
        "raw_id": body.get("raw_id") or f"WH-{os.urandom(3).hex().upper()}",
        "timestamp": body.get("timestamp"),
        "source_ip": str(source_ip),
        "user_id": str(user_id),
        "event_type": str(event_type),
        "asset_id": str(asset_id),
        "asset_criticality": str(asset_criticality),
        "payload_metric": payload_metric,
        "details": str(details)
    }

    try:
        return process_telemetry_pipeline(raw_event, actor="WEBHOOK_PRODUCER", role="SYSTEM")
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=f"Webhook Validation Error: {str(ve)}")
    except Exception:
        raise HTTPException(status_code=500, detail="Internal webhook ingestion failure.")


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
    raw_list = [e.model_dump() for e in raw_events]
    batch_results = EventNormalizer.normalize_batch(raw_list)

    responses = []
    for norm_evt, is_dup in batch_results:
        res = process_telemetry_pipeline(norm_evt.model_dump(), actor=user_info["user_id"], role=user_info["role"])
        responses.append(res)
    return responses


@app.get("/api/telemetry/stats")
def get_telemetry_stats():
    """
    Returns telemetry ingestion statistics loaded from SQLite, including Phase 6 duplicate metrics.
    """
    latest = db_manager.get_latest_telemetry_event()
    tstats = db_manager.get_telemetry_stats()
    return {
        "total_persisted_events": db_manager.get_telemetry_count(),
        "total_raw_events": tstats["total_raw_events"],
        "total_unique_events": tstats["total_unique_events"],
        "total_duplicates_suppressed": tstats["total_duplicates_suppressed"],
        "duplicates_attached_to_incidents": tstats["duplicates_attached_to_incidents"],
        "deduplication_rate_pct": tstats["deduplication_rate_pct"],
        "latest_event": latest,
        "database_path": get_db_path(),
        "syslog_enabled": syslog_listener.is_enabled
    }


@app.get("/api/incidents", response_model=List[Incident])
def get_incidents(status: Optional[IncidentStatus] = None):
    return incident_manager.list_incidents(status=status)


@app.get("/api/incidents/{incident_id}", response_model=Incident)
def get_incident_detail(incident_id: str):
    inc = incident_manager.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


@app.get("/api/incidents/{incident_id}/timeline")
def get_incident_timeline(incident_id: str):
    inc = incident_manager.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"incident_id": incident_id, "timeline": inc.timeline}


@app.post("/api/incidents/{incident_id}/investigate")
def mark_incident_investigating(
    incident_id: str,
    user_info: dict = Depends(lambda: {"user_id": "analyst_john", "role": "ANALYST"})
):
    try:
        inc = incident_manager.update_status(incident_id, IncidentStatus.UNDER_INVESTIGATION, assigned_to=user_info["user_id"])
        audit_logger.log(
            actor=user_info["user_id"], role=user_info["role"], action_category="INCIDENT",
            description=f"Analyst {user_info['user_id']} marked incident {incident_id} as UNDER_INVESTIGATION",
            target_resource=incident_id
        )
        return {"message": f"Incident {incident_id} state updated to UNDER_INVESTIGATION", "incident": inc}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except KeyError:
        raise HTTPException(status_code=404, detail="Incident not found")


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

    # Execute through 10 Safety Gates with Human Authorization
    rec = response_executor.execute_action(
        incident_id=incident_id,
        action_type=act_type,
        target=target,
        tier=DecisionTier(inc.decision_tier),
        actor=user_info["user_id"],
        actor_role=user_info["role"],
        is_auto_execution=False,
        details=f"Manual Analyst Approval by {user_info['user_id']}: {req.reason}"
    )

    if not rec.success:
        audit_logger.log(
            actor=user_info["user_id"], role=user_info["role"], action_category="APPROVAL",
            description=f"Analyst approved action for Incident {incident_id}, BUT safety gate blocked execution: {rec.gate_message}",
            target_resource=incident_id
        )
        raise HTTPException(status_code=400, detail=f"Response blocked by safety gate: {rec.gate_message}")

    incident_manager.mark_action_executed(incident_id)
    inc.verification_status = rec.verification_status.value
    incident_manager.save_incident_update(inc)

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
    success, msg, rec = response_executor.rollback_action(action_id, actor=user_info["user_id"], actor_role=user_info["role"])
    if not success:
        raise HTTPException(status_code=400, detail=msg)

    if rec and rec.incident_id:
        inc = incident_manager.get_incident(rec.incident_id)
        if inc:
            inc.rollback_status = "ROLLED_BACK"
            incident_manager.save_incident_update(inc)

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
        "total_telemetry_events": db_manager.get_telemetry_count(),
        "database_storage": "SQLite (Persistent)",
        "database_path": get_db_path(),
        "simulation_disclaimer": "SIMULATED ENFORCEMENT ONLY - No actual OS, network, or hardware configs are altered.",
        "kill_switch": EmergencyKillSwitch.get_state(),
        "syslog_listener": {
            "enabled": syslog_listener.is_enabled,
            "host": syslog_listener.host,
            "port": syslog_listener.port
        }
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


# --- Workstream H: Detection Quality Evaluation Endpoints ---

@app.get("/api/evaluation/latest")
def get_latest_evaluation_report():
    """
    Returns the latest Phase 5 Detection Quality Evaluation Report.
    If no report exists, executes a fresh evaluation run.
    """
    report_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "evaluation_report.json")
    if os.path.exists(report_path):
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    from backend.evaluation.eval_runner import run_evaluation
    return run_evaluation()


@app.post("/api/evaluation/run")
def trigger_evaluation_run(
    user_info: dict = Depends(require_role_permission("VIEW_AUDIT_LOGS"))
):
    """
    Executes a reproducible evaluation run in an isolated database environment
    and returns the freshly computed metrics report.
    """
    from backend.evaluation.eval_runner import run_evaluation
    report = run_evaluation()
    audit_logger.log(
        actor=user_info.get("user_id", "ANALYST"),
        role=user_info.get("role", "ANALYST"),
        action_category="EVALUATION",
        description=f"Executed Phase 5 detection quality benchmark. Hybrid Precision: {report['overall_hybrid_metrics']['metrics']['precision']}, Recall: {report['overall_hybrid_metrics']['metrics']['recall']}",
        target_resource="data/evaluation_report.json"
    )
    return report


# Mount static frontend directory
frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
