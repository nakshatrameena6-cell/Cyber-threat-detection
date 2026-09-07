"""Playbook Action Verification (REQ-PLY-001)."""
from typing import Dict, Any


class ActionVerificationResult:
    def __init__(self, is_successful: bool, message: str):
        self.is_successful = is_successful
        self.message = message


class ActionVerifier:
    """Verifies that executed playbook actions succeeded post-execution."""

    def verify_action(self, action_name: str, result: Dict[str, Any]) -> ActionVerificationResult:
        if not result or result.get("status") != "SUCCESS":
            return ActionVerificationResult(
                is_successful=False,
                message=f"Action '{action_name}' failed or returned non-success status."
            )
        return ActionVerificationResult(is_successful=True, message=f"Action '{action_name}' verified successfully.")
