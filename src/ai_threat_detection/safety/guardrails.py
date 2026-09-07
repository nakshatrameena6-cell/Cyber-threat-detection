"""Safety Guardrails & Blast Radius Enforcement (REQ-SEC-002, REQ-SAF-001)."""
from typing import Dict, List
from datetime import datetime, timedelta


class BlastRadiusExceededException(Exception):
    """Raised when an operation exceeds blast radius limits."""
    pass


class BlastRadiusGuardrail:
    """Enforces blast-radius rate limits per asset to avoid system-wide outages."""

    def __init__(self, max_actions_per_asset: int = 5, window_seconds: int = 3600):
        self.max_actions = max_actions_per_asset
        self.window_seconds = window_seconds
        self._action_history: Dict[str, List[datetime]] = {}

    def check_and_record_action(self, asset_id: str) -> bool:
        """Check if action is allowed on asset and record timestamp."""
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.window_seconds)

        if asset_id not in self._action_history:
            self._action_history[asset_id] = []

        # Prune old timestamps
        self._action_history[asset_id] = [
            ts for ts in self._action_history[asset_id] if ts > cutoff
        ]

        if len(self._action_history[asset_id]) >= self.max_actions:
            raise BlastRadiusExceededException(
                f"Blast radius threshold exceeded for asset '{asset_id}': "
                f"Maximum {self.max_actions} actions per {self.window_seconds}s allowed."
            )

        self._action_history[asset_id].append(now)
        return True
