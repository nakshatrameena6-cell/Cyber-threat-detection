from datetime import datetime, timezone
from backend.models.response import ResponseActionType, VerificationStatus

class ResponseVerifier:
    @staticmethod
    def verify_action(action_type: ResponseActionType, target: str, current_state_store: dict) -> Tuple[VerificationStatus, str]:
        """
        Verifies post-execution state for safe response actions.
        Returns (VerificationStatus, verification_detail_message)
        """
        if action_type == ResponseActionType.BLOCK_IP:
            blocked_ips = current_state_store.get("blocked_ips", set())
            if target in blocked_ips:
                return (VerificationStatus.PASSED, f"Verification PASSED: Target IP {target} actively blocked in simulated firewall table.")
            return (VerificationStatus.FAILED, f"Verification FAILED: Target IP {target} not found in firewall block table.")

        elif action_type == ResponseActionType.SUSPEND_SESSION:
            suspended_users = current_state_store.get("suspended_users", set())
            if target in suspended_users:
                return (VerificationStatus.PASSED, f"Verification PASSED: User session for '{target}' actively invalidated.")
            return (VerificationStatus.FAILED, f"Verification FAILED: User session '{target}' remains active.")

        elif action_type == ResponseActionType.ISOLATE_ENDPOINT:
            isolated_hosts = current_state_store.get("isolated_hosts", set())
            if target in isolated_hosts:
                return (VerificationStatus.PASSED, f"Verification PASSED: Endpoint '{target}' network interfaces isolated.")
            return (VerificationStatus.FAILED, f"Verification FAILED: Endpoint '{target}' still connected to network.")

        return (VerificationStatus.PASSED, "Verification PASSED: Informational alert logged.")
