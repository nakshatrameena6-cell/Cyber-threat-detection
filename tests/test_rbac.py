import pytest
from backend.rbac import RBACManager, Role

def test_rbac_permissions():
    # Admin permissions
    assert RBACManager.verify_permission("ADMIN", "ROLLBACK_RESPONSE") is True
    assert RBACManager.verify_permission("ADMIN", "TOGGLE_KILL_SWITCH") is True

    # Analyst permissions
    assert RBACManager.verify_permission("ANALYST", "APPROVE_RESPONSE") is True
    assert RBACManager.verify_permission("ANALYST", "TOGGLE_KILL_SWITCH") is False

    # Auditor permissions
    assert RBACManager.verify_permission("AUDITOR", "VIEW_AUDIT_LOGS") is True
    assert RBACManager.verify_permission("AUDITOR", "APPROVE_RESPONSE") is False
