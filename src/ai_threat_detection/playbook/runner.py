"""Playbook Framework & Execution Runner (REQ-PLY-001, REQ-PLY-002, REQ-AUD-002, REQ-SAF-001)."""
import uuid
from datetime import datetime
from typing import Dict, Any
from models.schemas.playbook import PlaybookDefinition, PlaybookExecutionState
from models.schemas.incident import CorrelatedIncident
from ai_threat_detection.audit.logger import AuditLogger, AuditPersistenceException
from ai_threat_detection.safety.kill_switch import GlobalKillSwitch, KillSwitchEngagedException
from ai_threat_detection.safety.guardrails import BlastRadiusGuardrail
from ai_threat_detection.verification.rollback import RollbackManager
from ai_threat_detection.playbook.verification import ActionVerifier
from ai_threat_detection.connectors.mock_connector import MockVendorConnector


class PlaybookExecutionException(Exception):
    pass


class PlaybookRunner:
    """Executes playbooks under strict audit, kill switch, and rollback guardrails."""

    def __init__(
        self,
        audit_logger: AuditLogger = None,
        kill_switch: GlobalKillSwitch = None,
        guardrail: BlastRadiusGuardrail = None,
        rollback_manager: RollbackManager = None,
        connector: MockVendorConnector = None,
    ):
        self.audit_logger = audit_logger or AuditLogger()
        self.kill_switch = kill_switch or GlobalKillSwitch()
        self.guardrail = guardrail or BlastRadiusGuardrail()
        self.rollback_manager = rollback_manager or RollbackManager()
        self.connector = connector or MockVendorConnector()
        self.verifier = ActionVerifier()

    def execute_playbook(self, playbook: PlaybookDefinition, incident: CorrelatedIncident, actor: str) -> PlaybookExecutionState:
        execution_id = f"exec-{uuid.uuid4().hex[:8]}"
        state = PlaybookExecutionState(
            execution_id=execution_id,
            playbook_id=playbook.id,
            incident_id=incident.incident_id,
            status="PENDING",
            started_at=datetime.utcnow()
        )

        # 1. Check Global Kill Switch
        self.kill_switch.assert_not_engaged()

        # 2. Check Blast Radius Rate Limit
        self.guardrail.check_and_record_action(incident.target_entity)

        # 3. Log Audit Precondition (REQ-AUD-002)
        audit_event = self.audit_logger.log_event(
            actor=actor,
            action=f"PLAYBOOK_EXECUTE:{playbook.id}",
            target_resource=incident.target_entity,
            details={"execution_id": execution_id, "incident_id": incident.incident_id}
        )

        # HARD PRECONDITION: Verify audit log persistence
        self.audit_logger.verify_precondition(audit_event)
        state.audit_event_id = audit_event.audit_id
        state.status = "AUDITED"

        # 4. Snapshot Pre-Action State
        snapshot = self.rollback_manager.capture_snapshot(
            target_entity=incident.target_entity,
            current_state={"status": incident.status, "max_severity": incident.max_severity}
        )

        # 5. Execute Steps
        state.status = "EXECUTING"
        for step in playbook.steps:
            # Re-verify kill switch before every single step
            self.kill_switch.assert_not_engaged()

            result = self.connector.execute_action(step.action, step.args)
            verification = self.verifier.verify_action(step.name, result)

            if not verification.is_successful:
                # Trigger Rollback if step verification fails
                state.status = "FAILED"
                self.rollback_manager.rollback(snapshot.snapshot_id)
                state.status = "ROLLED_BACK"
                raise PlaybookExecutionException(f"Step '{step.name}' verification failed: {verification.message}. Rollback performed.")

            state.step_results.append({"step": step.name, "result": result})

        state.status = "COMPLETED"
        state.completed_at = datetime.utcnow()
        return state
