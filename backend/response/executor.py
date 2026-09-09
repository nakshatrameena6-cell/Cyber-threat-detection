import uuid
from typing import Dict, Set, List, Optional
from datetime import datetime, timezone
from backend.models.response import (
    ResponseRecord, ResponseActionType, DecisionTier, ActionStatus, VerificationStatus
)
from backend.response.verifier import ResponseVerifier

class ResponseExecutor:
    def __init__(self):
        # Simulated security state tables
        self.blocked_ips: Set[str] = set()
        self.suspended_users: Set[str] = set()
        self.isolated_hosts: Set[str] = set()
        self.records: Dict[str, ResponseRecord] = {}

    def get_state_store(self) -> dict:
        return {
            "blocked_ips": self.blocked_ips,
            "suspended_users": self.suspended_users,
            "isolated_hosts": self.isolated_hosts
        }

    def execute_action(
        self,
        incident_id: str,
        action_type: ResponseActionType,
        target: str,
        tier: DecisionTier,
        actor: str = "AUTO_ENGINE",
        details: str = ""
    ) -> ResponseRecord:
        action_id = f"ACT-{uuid.uuid4().hex[:8].upper()}"
        now_str = datetime.now(timezone.utc).isoformat()

        if action_type == ResponseActionType.BLOCK_IP:
            self.blocked_ips.add(target)
            msg = f"Simulated Firewall: IP {target} added to dropped packet table."
        elif action_type == ResponseActionType.SUSPEND_SESSION:
            self.suspended_users.add(target)
            msg = f"Simulated Identity Provider: Revoked all active tokens for user '{target}'."
        elif action_type == ResponseActionType.ISOLATE_ENDPOINT:
            self.isolated_hosts.add(target)
            msg = f"Simulated Host Agent: Endpoint '{target}' network interfaces set to ISOLATED."
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

        # Run verification check
        ver_status, ver_msg = ResponseVerifier.verify_action(action_type, target, self.get_state_store())
        record.verification_status = ver_status
        record.verification_time = datetime.now(timezone.utc).isoformat()
        record.details += f" | {ver_msg}"

        self.records[action_id] = record
        return record

    def rollback_action(self, action_id: str, actor: str = "ADMIN") -> Tuple[bool, str, Optional[ResponseRecord]]:
        record = self.records.get(action_id)
        if not record:
            return (False, "Action record not found.", None)

        if record.rolled_back:
            return (False, "Action has already been rolled back.", record)

        if not record.is_reversible:
            return (False, "Action is not reversible.", record)

        target = record.target
        action_type = record.action_type

        if action_type == ResponseActionType.BLOCK_IP:
            self.blocked_ips.discard(target)
            msg = f"Simulated Firewall: IP {target} unblocked and removed from drop list."
        elif action_type == ResponseActionType.SUSPEND_SESSION:
            self.suspended_users.discard(target)
            msg = f"Simulated Identity Provider: Re-activated user '{target}' session permissions."
        elif action_type == ResponseActionType.ISOLATE_ENDPOINT:
            self.isolated_hosts.discard(target)
            msg = f"Simulated Host Agent: Restored network adapter state for host '{target}'."
        else:
            msg = f"Reversed alert state for '{target}'."

        record.rolled_back = True
        record.status = ActionStatus.ROLLED_BACK
        record.details += f" | ROLLED BACK by {actor} at {datetime.now(timezone.utc).isoformat()} - {msg}"

        return (True, msg, record)

    def list_records(self) -> List[ResponseRecord]:
        return sorted(list(self.records.values()), key=lambda x: x.execution_time, reverse=True)
