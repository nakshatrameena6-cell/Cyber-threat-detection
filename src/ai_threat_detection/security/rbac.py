"""Role-Based Access Control (RBAC) Module (REQ-SEC-001)."""
from typing import Dict, Set, List


class UnauthorizedException(Exception):
    """Raised when an actor lacks permission for an operation."""
    pass


class RBACController:
    """Enforces fine-grained permission matrix."""

    DEFAULT_ROLES: Dict[str, Set[str]] = {
        "SOC_ANALYST": {
            "telemetry:read",
            "incidents:read",
            "alerts:read",
            "audit:read",
        },
        "SECURITY_ADMIN": {
            "telemetry:read",
            "incidents:read",
            "incidents:write",
            "playbooks:execute",
            "playbooks:approve",
            "safety:kill_switch",
            "audit:read",
        },
        "SYSTEM_SERVICE": {
            "telemetry:ingest",
            "incidents:create",
            "audit:write",
        },
    }

    def __init__(self, roles: Dict[str, Set[str]] = None):
        self.roles = roles or self.DEFAULT_ROLES

    def authorize(self, role: str, permission: str) -> bool:
        """Verify if role holds permission, otherwise raise UnauthorizedException."""
        permissions = self.roles.get(role, set())
        if permission not in permissions:
            raise UnauthorizedException(
                f"Role '{role}' is not authorized to perform action '{permission}'"
            )
        return True
