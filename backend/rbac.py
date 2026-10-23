from enum import Enum
from typing import Set, Dict
from fastapi import HTTPException, Header, Security

class Role(str, Enum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    AUDITOR = "AUDITOR"

# Role capabilities mapping
ROLE_PERMISSIONS: Dict[Role, Set[str]] = {
    Role.ADMIN: {
        "INGEST_TELEMETRY",
        "VIEW_INCIDENTS",
        "UPDATE_INCIDENT",
        "APPROVE_RESPONSE",
        "EXECUTE_RESPONSE",
        "ROLLBACK_RESPONSE",
        "TOGGLE_KILL_SWITCH",
        "VIEW_AUDIT_LOGS"
    },
    Role.ANALYST: {
        "INGEST_TELEMETRY",
        "VIEW_INCIDENTS",
        "UPDATE_INCIDENT",
        "APPROVE_RESPONSE",
        "EXECUTE_RESPONSE",
        "VIEW_AUDIT_LOGS"
    },
    Role.AUDITOR: {
        "VIEW_INCIDENTS",
        "VIEW_AUDIT_LOGS"
    }
}

class RBACManager:
    @staticmethod
    def verify_permission(role_str: str, required_permission: str) -> bool:
        try:
            role = Role(role_str.upper())
        except ValueError:
            return False
        return required_permission in ROLE_PERMISSIONS.get(role, set())

def require_role_permission(permission: str):
    """
    FastAPI Dependency checking RBAC authorization header.
    """
    def _dependency(
        x_role: str = Header(default="ANALYST", alias="X-Role"),
        x_user_id: str = Header(default="demo_user", alias="X-User-Id")
    ):
        if not RBACManager.verify_permission(x_role, permission):
            raise HTTPException(
                status_code=403,
                detail=f"Forbidden: Role '{x_role}' lacks required permission '{permission}'."
            )
        return {"user_id": x_user_id, "role": x_role}
    return _dependency
