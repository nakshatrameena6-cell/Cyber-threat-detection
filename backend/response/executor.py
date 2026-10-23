import uuid
from typing import Dict, Set, List, Optional, Tuple, Callable
from datetime import datetime, timezone
from backend.models.response import (
    ResponseRecord, ResponseActionType, DecisionTier, ActionStatus, VerificationStatus
)
from backend.response.verifier import ResponseVerifier
from backend.response.safety_gates import SafetyGatesEvaluator
from backend.rbac import RBACManager
from backend.database import DatabaseManager

def parse_enum_safe(cls, val, default=None):
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

class ResponseExecutor:
    def __init__(self, db: Optional[DatabaseManager] = None):
        self.db = db or DatabaseManager()
        # Simulated security state tables (in-memory synchronized with SQLite)
        self.blocked_ips: Set[str] = set()
        self.suspended_users: Set[str] = set()
        self.isolated_hosts: Set[str] = set()
        self.records: Dict[str, ResponseRecord] = {}
        self.pre_states: Dict[str, dict] = {} # Captures pre-action state for rollback
        self.audit_checker: Optional[Callable[[], bool]] = self.db.test_audit_persistence_available
        self.load_from_db()

    def load_from_db(self):
        """
        Recovers persistent response history, pre-states, and active simulated security states from SQLite.
        """
        try:
            active_states = self.db.get_active_security_states()
            self.blocked_ips = active_states.get("blocked_ips", set())
            self.suspended_users = active_states.get("suspended_users", set())
            self.isolated_hosts = active_states.get("isolated_hosts", set())

            records_data = self.db.list_response_records()
            for r_dict in records_data:
                try:
                    act_type = parse_enum_safe(ResponseActionType, r_dict["action_type"], ResponseActionType.ALERT_ONLY)
                    tier = parse_enum_safe(DecisionTier, r_dict["tier"], DecisionTier.TIER_A)
                    stat = parse_enum_safe(ActionStatus, r_dict["status"], ActionStatus.EXECUTED)
                    v_stat = parse_enum_safe(VerificationStatus, r_dict.get("verification_status"), VerificationStatus.NOT_VERIFIED)

                    rec = ResponseRecord(
                        action_id=r_dict["action_id"],
                        incident_id=r_dict["incident_id"],
                        action_type=act_type,
                        target=r_dict["target"],
                        tier=tier,
                        status=stat,
                        verification_status=v_stat,
                        executed_by=r_dict["executed_by"],
                        execution_time=r_dict["execution_time"],
                        verification_time=r_dict.get("verification_time"),
                        is_reversible=r_dict.get("is_reversible", True),
                        rolled_back=r_dict.get("rolled_back", False),
                        details=r_dict.get("details", ""),
                        success=r_dict.get("success", True),
                        gate_message=r_dict.get("gate_message", "")
                    )
                    self.records[rec.action_id] = rec

                    ps = self.db.get_pre_state(rec.action_id)
                    if ps:
                        self.pre_states[rec.action_id] = ps
                except Exception:
                    continue
        except Exception:
            pass

    def get_state_store(self) -> dict:
        return {
            "blocked_ips": self.blocked_ips,
            "suspended_users": self.suspended_users,
            "isolated_hosts": self.isolated_hosts
        }

    def capture_pre_state(self, action_id: str, target: str, action_type: ResponseActionType):
        """
        Captures pre-action state for strict rollback validation and persists to SQLite.
        """
        now_str = datetime.now(timezone.utc).isoformat()
        pre_state = {
            "target": target,
            "action_type": action_type.value,
            "was_blocked": target in self.blocked_ips,
            "was_suspended": target in self.suspended_users,
            "was_isolated": target in self.isolated_hosts,
            "timestamp": now_str
        }
        self.pre_states[action_id] = pre_state
        try:
            self.db.save_pre_state(
                action_id=action_id,
                target=target,
                action_type=action_type.value,
                was_blocked=pre_state["was_blocked"],
                was_suspended=pre_state["was_suspended"],
                was_isolated=pre_state["was_isolated"],
                timestamp=now_str
            )
        except Exception:
            pass

    def execute_action(
        self,
        incident_id: str,
        action_type: ResponseActionType,
        target: str,
        tier: DecisionTier,
        actor: str = "ADMIN",
        actor_role: str = "ADMIN",
        is_auto_execution: Optional[bool] = None,
        details: str = ""
    ) -> ResponseRecord:
        """
        Evaluates safety gates (including audit persistence pre-check),
        captures pre-state, executes safe simulated action, verifies result, and persists to SQLite.
        """
        if is_auto_execution is None:
            is_auto_execution = (actor == "AUTO_ENGINE")

        # Evaluate 10 Pre-Execution Safety Gates
        gate_passed, gate_name, gate_reason = SafetyGatesEvaluator.evaluate_gates(
            action_type=action_type,
            target=target,
            actor_role=actor_role,
            tier=tier,
            is_auto_execution=is_auto_execution,
            current_state_store=self.get_state_store(),
            audit_checker=self.audit_checker,
            verifier_available=True
        )

        action_id = f"ACT-{uuid.uuid4().hex[:8].upper()}"
        now_str = datetime.now(timezone.utc).isoformat()

        if not gate_passed:
            record = ResponseRecord(
                action_id=action_id,
                incident_id=incident_id,
                action_type=action_type,
                target=target,
                tier=tier,
                status=ActionStatus.DENIED,
                verification_status=VerificationStatus.FAILED,
                executed_by=actor,
                execution_time=now_str,
                is_reversible=False,
                rolled_back=False,
                details=f"Execution BLOCKED by {gate_name}: {gate_reason}",
                success=False,
                gate_message=f"Blocked by {gate_name}: {gate_reason}"
            )
            self.records[action_id] = record
            try:
                self.db.save_response_record(record.model_dump())
            except Exception:
                pass
            return record

        # Capture Pre-State for Rollback
        self.capture_pre_state(action_id, target, action_type)

        # Idempotent State Mutation
        if action_type == ResponseActionType.BLOCK_IP:
            self.blocked_ips.add(target)
            try:
                self.db.save_security_state("BLOCKED_IP", target, action_id)
            except Exception:
                pass
            msg = f"Simulated Firewall: IP '{target}' added to drop packet table."
        elif action_type == ResponseActionType.SUSPEND_SESSION:
            self.suspended_users.add(target)
            try:
                self.db.save_security_state("SUSPENDED_USER", target, action_id)
            except Exception:
                pass
            msg = f"Simulated IdP: Revoked tokens for user '{target}'."
        elif action_type == ResponseActionType.ISOLATE_ENDPOINT:
            self.isolated_hosts.add(target)
            try:
                self.db.save_security_state("ISOLATED_HOST", target, action_id)
            except Exception:
                pass
            msg = f"Simulated Agent: Host '{target}' network interfaces set to ISOLATED."
        else:
            msg = f"Logged informational alert for target '{target}'."

        record = ResponseRecord(
            action_id=action_id,
            incident_id=incident_id,
            action_type=action_type,
            target=target,
            tier=tier,
            status=ActionStatus.EXECUTED,
            verification_status=VerificationStatus.NOT_VERIFIED,
            executed_by=actor,
            execution_time=now_str,
            is_reversible=(action_type != ResponseActionType.ALERT_ONLY),
            rolled_back=False,
            details=f"{details} - {msg}",
            success=True,
            gate_message="All 10 safety gates passed"
        )

        # Independent Verification Check
        ver_status, ver_msg = ResponseVerifier.verify_action(action_type, target, self.get_state_store())
        record.verification_status = ver_status
        record.verification_time = datetime.now(timezone.utc).isoformat()
        record.details += f" | {ver_msg}"

        self.records[action_id] = record
        try:
            self.db.save_response_record(record.model_dump())
        except Exception:
            pass
        return record

    def rollback_action(self, action_id: str, actor: str = "ADMIN", actor_role: str = "ADMIN") -> Tuple[bool, str, Optional[ResponseRecord]]:
        # RBAC Check
        if not RBACManager.verify_permission(actor_role, "ROLLBACK_RESPONSE"):
            return (False, f"Role '{actor_role}' lacks permission to perform action rollback.", None)

        record = self.records.get(action_id)
        if not record:
            rec_dict = self.db.get_response_record(action_id)
            if rec_dict:
                record = ResponseRecord(
                    action_id=rec_dict["action_id"],
                    incident_id=rec_dict["incident_id"],
                    action_type=ResponseActionType(rec_dict["action_type"]),
                    target=rec_dict["target"],
                    tier=DecisionTier(rec_dict["tier"]),
                    status=ActionStatus(rec_dict["status"]),
                    verification_status=VerificationStatus(rec_dict.get("verification_status", "NOT_VERIFIED")),
                    executed_by=rec_dict["executed_by"],
                    execution_time=rec_dict["execution_time"],
                    verification_time=rec_dict.get("verification_time"),
                    is_reversible=rec_dict.get("is_reversible", True),
                    rolled_back=rec_dict.get("rolled_back", False),
                    details=rec_dict.get("details", ""),
                    success=rec_dict.get("success", True),
                    gate_message=rec_dict.get("gate_message", "")
                )
                self.records[action_id] = record

        if not record:
            return (False, f"Action record '{action_id}' not found.", None)

        if record.status != ActionStatus.EXECUTED and not record.rolled_back:
            return (False, f"Cannot rollback action in status '{record.status}'.", record)

        if record.rolled_back:
            return (False, f"Action '{action_id}' has already been rolled back. Double rollback prevented.", record)

        if not record.is_reversible:
            return (False, f"Action '{action_id}' of type '{record.action_type}' is not reversible.", record)

        pre_state = self.pre_states.get(action_id) or self.db.get_pre_state(action_id)
        if not pre_state:
            return (False, "Pre-state capture missing. Rollback aborted for safety.", record)

        target = record.target
        action_type = record.action_type

        # Reverse state based on pre-state
        if action_type == ResponseActionType.BLOCK_IP:
            if not pre_state.get("was_blocked", False):
                self.blocked_ips.discard(target)
                try:
                    self.db.remove_security_state("BLOCKED_IP", target)
                except Exception:
                    pass
            msg = f"Simulated Firewall: IP '{target}' unblocked."
        elif action_type == ResponseActionType.SUSPEND_SESSION:
            if not pre_state.get("was_suspended", False):
                self.suspended_users.discard(target)
                try:
                    self.db.remove_security_state("SUSPENDED_USER", target)
                except Exception:
                    pass
            msg = f"Simulated IdP: Session reactivated for '{target}'."
        elif action_type == ResponseActionType.ISOLATE_ENDPOINT:
            if not pre_state.get("was_isolated", False):
                self.isolated_hosts.discard(target)
                try:
                    self.db.remove_security_state("ISOLATED_HOST", target)
                except Exception:
                    pass
            msg = f"Simulated Agent: Restored network adapter for host '{target}'."
        else:
            msg = f"Reversed alert status for '{target}'."

        record.rolled_back = True
        record.status = ActionStatus.ROLLED_BACK
        record.details += f" | ROLLED BACK by {actor} at {datetime.now(timezone.utc).isoformat()} - {msg}"

        try:
            self.db.save_response_record(record.model_dump())
        except Exception:
            pass
        return (True, msg, record)

    def list_records(self) -> List[ResponseRecord]:
        return sorted(list(self.records.values()), key=lambda x: x.execution_time, reverse=True)
