"""Rate Limiter Module (REQ-SEC-002)."""
from datetime import datetime, timedelta
from typing import Dict, List


class RateLimitExceededException(Exception):
    """Raised when request rate exceeds configured limit."""
    pass


class SlidingWindowRateLimiter:
    """Sliding window rate limiter for API calls."""

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._timestamps: Dict[str, List[datetime]] = {}

    def is_allowed(self, client_id: str) -> bool:
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.window_seconds)

        if client_id not in self._timestamps:
            self._timestamps[client_id] = []

        # Filter out timestamps outside window
        self._timestamps[client_id] = [
            ts for ts in self._timestamps[client_id] if ts > cutoff
        ]

        if len(self._timestamps[client_id]) >= self.max_requests:
            raise RateLimitExceededException(
                f"Rate limit of {self.max_requests} req/{self.window_seconds}s exceeded for '{client_id}'"
            )

        self._timestamps[client_id].append(now)
        return True
