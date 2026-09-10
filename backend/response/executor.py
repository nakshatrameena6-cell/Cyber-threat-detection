import uuid
from typing import Dict, Set, List, Optional, Tuple
from datetime import datetime, timezone
from backend.models.response import (
    ResponseRecord, ResponseActionType, DecisionTier, ActionStatus, VerificationStatus
)
from backend.response.verifier import ResponseVerifier
from backend.response.safety_gates import SafetyGatesEvaluator

class ResponseExecutor:
    def __init__(self):
        # Simulated security state tables
        self.blocked_ips: Set[str] = set()
        self.suspended_users: Set[str] = set()
        self.isolated_hosts: Set[str] = set()
        self.records: Dict[str, ResponseRecord] = {}
        self.pre_states: Dict[str, dict] = {} # Captures pre-action state for rollback

    def get_state_store(self) -> dict:
        return {
            "blocked_ips": self.blocked_ips,
            "suspended_users": self.suspended_users,
            "isolated_hosts": self.isolated_hosts
        }

    def capture_pre_state(self, action_id: str, target: str, action_type: ResponseActionType):
        """
        Captures pre-action state for strict rollback validation.
        """
        self.pre_states[action_id] = {
            "target": target,
            "action_type": action_type,
            "was_blocked": target in self.blocked_ips,
            "was_suspended": target in self.suspended_users,
            "was_isolated": target in self.isolated_hosts,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def execute_action(
        self,
        incident_id: str,
        action_type: ResponseActionType,
        target: str,
        tier: DecisionTier,
        actor: str = "AUTO_ENGINE",
        actor_role: str = "ADMIN",
        is_auto_execution: bool = True,
        details: str = ""
    ) -> Tuple[bool, ResponseRecord, str]:
        """
        Evaluates safety gates, captures pre-state, executes safe action, and verifies result.
        Returns (success: bool, ResponseRecord, message: str)
        """
        # Evaluate 10 Pre-Execution Safety Gates
        gate_passed, gate_name, gate_reason = SafetyGatesEvaluator.evaluate_gates(
            action_type=action_type,
            target=target,
            actor_role=actor_role,
            tier=tier,
            is_auto_execution=is_auto_execution,
            current_state_store=self.get_state_store()
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
                details=f"Execution BLOCKED by {gate_name}: {gate_reason}"
            )
            self.records[action_id] = record
            return (False, record, f"Blocked by {gate_name}: {gate_reason}")

        # Capture Pre-State for Rollback
        self.capture_pre_state(action_id, target, action_type)

        # Idempotent State Mutation
        if action_type == ResponseActionType.BLOCK_IP:
            self.blocked_ips.add(target)
            msg = f"Simulated Firewall: IP '{target}' added to drop packet table."
        elif action_type == ResponseActionType.SUSPEND_SESSION:
            self.suspended_users.add(target)
            msg = f"Simulated IdP: Revoked tokens for user '{target}'."
        elif action_type == ResponseActionType.ISOLATE_ENDPOINT:
            self.isolated_hosts.add(target)
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
            details=f"{details} - {msg}"
        )

        # Independent Verification Check
        ver_status, ver_msg = ResponseVerifier.verify_action(action_type, target, self.get_state_store())
        record.verification_status = ver_status
        record.verification_time = datetime.now(timezone.utc).isoformat()
        record.details += f" | {ver_msg}"

        self.records[action_id] = record
        return (True, record, msg)

    def rollback_action(self, action_id: str, actor: str = "ADMIN", actor_role: str = "ADMIN") -> Tuple[bool, str, Optional[ResponseRecord]]:
        # RBAC Check
        if not RBACManager.verify_permission(actor_role, "ROLLBACK_RESPONSE"):
            return (False, f"Role '{actor_role}' lacks permission to perform action rollback.", None)

        record = self.records.get(action_id)
        if not record:
            return (False, f"Action record '{action_id}' not found.", None)

        if record.status != ActionStatus.EXECUTED and not record.rolled_back:
            return (False, f"Cannot rollback action in status '{record.status}'.", record)

        if record.rolled_back:
            return (False, f"Action '{action_id}' has already been rolled back. Double rollback prevented.", record)

        if not record.is_reversible:
            return (False, f"Action '{action_id}' of type '{record.action_type}' is not reversible.", record)

        pre_state = self.pre_states.get(action_id)
        if not pre_state:
            return (False, "Pre-state capture missing. Rollback aborted for safety.", record)

        target = record.target
        action_type = record.action_type

        # Reverse state based on pre-state
        if action_type == ResponseActionType.BLOCK_IP:
            if not pre_state.get("was_blocked", False):
                self.blocked_ips.discard(target)
            msg = f"Simulated Firewall: IP '{target}' unblocked."
        elif action_type == ResponseActionType.SUSPEND_SESSION:
            if not pre_state.get("was_suspended", False):
                self.suspended_users.discard(target)
            msg = f"Simulated IdP: Session reactivated for '{target}'."
        elif action_type == ResponseActionType.ISOLATE_ENDPOINT:
            if not pre_state.get("was_isolated", False):
                self.isolated_hosts.discard(target)
            msg = f"Simulated Agent: Restored network adapter for host '{target}'."
        else:
            msg = f"Reversed alert status for '{target}'."

        record.rolled_back = True
        record.status = ActionStatus.ROLLED_BACK
        record.details += f" | ROLLED BACK by {actor} at {datetime.now(timezone.utc).isoformat()} - {msg}"

        return (True, msg, record)

    def list_records(self) -> List[ResponseRecord]:
        return sorted(list(self.records.values()), key=lambda x: x.execution_time, reverse=True)
