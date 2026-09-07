"""Authentication and Context Middleware (REQ-SEC-001)."""
from dataclasses import dataclass
from typing import Optional


@dataclass
class SecurityContext:
    user_id: str
    role: str
    token: Optional[str] = None


class AuthenticationError(Exception):
    pass


class AuthManager:
    """Mock Auth Manager for token validation and SecurityContext creation."""

    MOCK_TOKENS = {
        "analyst-token": SecurityContext(user_id="user-analyst-1", role="SOC_ANALYST"),
        "admin-token": SecurityContext(user_id="user-admin-1", role="SECURITY_ADMIN"),
        "service-token": SecurityContext(user_id="svc-ingestion-1", role="SYSTEM_SERVICE"),
    }

    def authenticate(self, token: str) -> SecurityContext:
        if token not in self.MOCK_TOKENS:
            raise AuthenticationError("Invalid or expired authentication token")
        return self.MOCK_TOKENS[token]
