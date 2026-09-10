from typing import Tuple
from datetime import datetime, timezone
from backend.models.response import ResponseActionType, VerificationStatus

class ResponseVerifier:
    @staticmethod
    def verify_action(action_type: ResponseActionType, target: str, current_state_store: dict) -> Tuple[VerificationStatus, str]:
        """
        Independently verifies post-execution state for safe response actions.
        Returns (VerificationStatus, verification_detail_message)
        """
        if action_type == ResponseActionType.BLOCK_IP:
            blocked_ips = current_state_store.get("blocked_ips", set())
            if target in blocked_ips:
                return (VerificationStatus.PASSED, f"Independent Verification PASSED: Target IP '{target}' confirmed active in simulated firewall block table.")
            return (VerificationStatus.FAILED, f"Independent Verification FAILED: Target IP '{target}' missing from firewall block table.")

        elif action_type == ResponseActionType.SUSPEND_SESSION:
            suspended_users = current_state_store.get("suspended_users", set())
            if target in suspended_users:
                return (VerificationStatus.PASSED, f"Independent Verification PASSED: Session for user '{target}' confirmed revoked.")
            return (VerificationStatus.FAILED, f"Independent Verification FAILED: User session '{target}' remains active in session table.")

        elif action_type == ResponseActionType.ISOLATE_ENDPOINT:
            isolated_hosts = current_state_store.get("isolated_hosts", set())
            if target in isolated_hosts:
                return (VerificationStatus.PASSED, f"Independent Verification PASSED: Host adapter for '{target}' confirmed isolated.")
            return (VerificationStatus.FAILED, f"Independent Verification FAILED: Endpoint '{target}' interface remains connected.")

        return (VerificationStatus.PASSED, "Independent Verification PASSED: Informational alert logged.")
