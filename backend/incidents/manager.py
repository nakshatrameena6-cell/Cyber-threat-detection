import uuid
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from backend.models.incidents import Incident, IncidentStatus, Severity, ThreatCategory, VALID_TRANSITIONS
from backend.database import DatabaseManager

def parse_enum_safe(cls, val: Any, default: Any):
    if isinstance(val, cls):
        return val
    if not val:
        return default
    val_str = str(val).strip()
    for member in cls:
        if member.value == val_str or member.name == val_str or str(member) == val_str:
            return member
        if member.value.lower() == val_str.lower() or member.name.lower() == val_str.lower():
            return member
    try:
        return cls(val_str)
    except Exception:
        return default

class IncidentManager:
    def __init__(self, db: Optional[DatabaseManager] = None):
        self.db = db or DatabaseManager()
        self._incidents: Dict[str, Incident] = {}
        self.load_from_db()

    def _dict_to_incident(self, rec: dict) -> Optional[Incident]:
        try:
            tc = parse_enum_safe(ThreatCategory, rec.get("threat_category"), ThreatCategory.NONE)
            sev = parse_enum_safe(Severity, rec.get("severity"), Severity.MEDIUM)
            stat = parse_enum_safe(IncidentStatus, rec.get("status"), IncidentStatus.NEW)

            raw_tcs = rec.get("threat_categories", [rec.get("threat_category")])
            tcs = [parse_enum_safe(ThreatCategory, c, ThreatCategory.NONE) for c in raw_tcs]

            return Incident(
                incident_id=rec["incident_id"],
                event_id=rec["event_id"],
                threat_category=tc,
                threat_categories=tcs,
                severity=sev,
                risk_score=float(rec["risk_score"]),
                confidence_score=float(rec["confidence_score"]),
                source_ip=rec["source_ip"],
                user_id=rec["user_id"],
                affected_user=rec.get("affected_user", rec["user_id"]),
                asset_id=rec["asset_id"],
                affected_endpoint=rec.get("affected_endpoint", rec["asset_id"]),
                details=rec.get("details", ""),
                status=stat,
                created_at=rec["created_at"],
                first_seen=rec.get("first_seen", rec["created_at"]),
                last_seen=rec.get("last_seen", rec["created_at"]),
                recommended_action=rec.get("recommended_action", "ALERT_ONLY"),
                decision_tier=rec.get("decision_tier", "TIER_A"),
                action_executed=bool(rec.get("action_executed", False)),
                assigned_to=rec.get("assigned_to"),
                is_anomalous=bool(rec.get("is_anomalous", True)),
                behavioral_evidence=rec.get("behavioral_evidence", []),
                why_evidence=rec.get("why_evidence", []),
                related_events=rec.get("related_events", [rec["event_id"]]),
                timeline=rec.get("timeline", []),
                verification_status=rec.get("verification_status", "NOT_VERIFIED"),
                rollback_status=rec.get("rollback_status", "NOT_ROLLED_BACK")
            )
        except Exception:
            return None

    def load_from_db(self):
        """
        Recovers persistent incidents, relationships, timelines, and evidence from SQLite.
        """
        try:
            inc_records = self.db.list_incidents()
            for rec in inc_records:
                inc = self._dict_to_incident(rec)
                if inc:
                    self._incidents[inc.incident_id] = inc
        except Exception:
            pass

    def create_incident(
        self,
        event_id: str,
        threat_category: ThreatCategory,
        severity: Severity,
        risk_score: float,
        confidence_score: float,
        source_ip: str,
        user_id: str,
        asset_id: str,
        details: str,
        recommended_action: str,
        decision_tier: str,
        is_anomalous: bool = True,
        behavioral_evidence: Optional[List[str]] = None,
        why_evidence: Optional[List[str]] = None,
        event_timestamp: Optional[str] = None
    ) -> Incident:
        inc_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        now_str = datetime.now(timezone.utc).isoformat()
        ts_str = event_timestamp or now_str
        
        tc_val = getattr(threat_category, "value", str(threat_category))
        timeline_entry = {
            "timestamp": ts_str,
            "event_id": event_id,
            "event_type": "INCIDENT_CREATED",
            "description": f"Incident created for threat '{tc_val}' (Risk: {risk_score})",
            "threat_category": tc_val,
            "risk_score": risk_score
        }

        incident = Incident(
            incident_id=inc_id,
            event_id=event_id,
            threat_category=threat_category,
            threat_categories=[threat_category],
            severity=severity,
            risk_score=risk_score,
            confidence_score=confidence_score,
            source_ip=source_ip,
            user_id=user_id,
            affected_user=user_id,
            asset_id=asset_id,
            affected_endpoint=asset_id,
            details=details,
            status=IncidentStatus.NEW,
            created_at=now_str,
            first_seen=ts_str,
            last_seen=ts_str,
            recommended_action=recommended_action,
            decision_tier=decision_tier,
            action_executed=False,
            is_anomalous=is_anomalous,
            behavioral_evidence=behavioral_evidence or [],
            why_evidence=why_evidence or [],
            related_events=[event_id],
            timeline=[timeline_entry]
        )
        self._incidents[inc_id] = incident

        # Persist to SQLite
        try:
            self.db.save_incident(incident.model_dump())
        except Exception:
            pass

        return incident

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        inc = self._incidents.get(incident_id)
        if not inc:
            db_dict = self.db.get_incident(incident_id)
            if db_dict:
                inc = self._dict_to_incident(db_dict)
                if inc:
                    self._incidents[incident_id] = inc
        return inc

    def list_incidents(self, status: Optional[IncidentStatus] = None) -> List[Incident]:
        incidents = list(self._incidents.values())
        if status:
            incidents = [inc for inc in incidents if inc.status == status]
        return sorted(incidents, key=lambda x: x.created_at, reverse=True)

    def update_status(self, incident_id: str, new_status: IncidentStatus, assigned_to: Optional[str] = None) -> Incident:
        incident = self.get_incident(incident_id)
        if not incident:
            raise KeyError(f"Incident '{incident_id}' not found.")

        # Enforce valid lifecycle transitions
        allowed = VALID_TRANSITIONS.get(incident.status, [])
        if new_status not in allowed:
            raise ValueError(f"Invalid state transition: Cannot change status from '{incident.status.value}' to '{new_status.value}'. Allowed: {[s.value for s in allowed]}")

        incident.status = new_status
        if assigned_to:
            incident.assigned_to = assigned_to

        now_str = datetime.now(timezone.utc).isoformat()
        tl_item = {
            "timestamp": now_str,
            "event_id": f"SYS-{uuid.uuid4().hex[:6]}",
            "event_type": "STATUS_CHANGED",
            "description": f"Incident status changed to '{new_status.value}' by {assigned_to or 'SYSTEM'}",
            "threat_category": incident.threat_category.value,
            "risk_score": incident.risk_score
        }
        incident.timeline.append(tl_item)

        # Persist to SQLite
        try:
            self.db.update_incident_status(
                incident_id=incident_id,
                new_status=new_status.value,
                assigned_to=assigned_to,
                timeline_item=tl_item
            )
        except Exception:
            pass

        return incident

    def mark_action_executed(self, incident_id: str) -> Optional[Incident]:
        incident = self.get_incident(incident_id)
        if incident:
            incident.action_executed = True
            try:
                self.update_status(incident_id, IncidentStatus.MITIGATED, assigned_to="AUTO_ENGINE")
            except ValueError:
                incident.status = IncidentStatus.MITIGATED
            try:
                self.db.mark_incident_action_executed(incident_id, IncidentStatus.MITIGATED.value)
            except Exception:
                pass
        return incident

    def save_incident_update(self, incident: Incident):
        """
        Saves updated incident state (e.g. after correlation merge).
        """
        self._incidents[incident.incident_id] = incident
        try:
            self.db.save_incident(incident.model_dump())
        except Exception:
            pass
