"""Global Emergency Kill Switch & Safety Gate (REQ-SAF-001)."""
import os
import yaml
from datetime import datetime
from typing import Optional
from models.schemas.safety import KillSwitchState


class KillSwitchEngagedException(Exception):
    """Raised when an operation is blocked because the Global Kill Switch is engaged."""
    pass


class GlobalKillSwitch:
    """Atomic file & memory-backed global emergency kill switch."""

    def __init__(self, config_path: str = "config/kill_switch.yaml"):
        self.config_path = config_path
        self._state = self._load_state()

    def _load_state(self) -> KillSwitchState:
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                return KillSwitchState(**data)
            except Exception:
                # Fail safe: if state cannot be loaded, default to engaged
                return KillSwitchState(is_engaged=True, reason="Failed to load kill switch config - default fail safe")
        return KillSwitchState(is_engaged=False)

    def _save_state(self) -> None:
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        data = {
            "is_engaged": self._state.is_engaged,
            "engaged_by": self._state.engaged_by,
            "reason": self._state.reason,
            "last_updated": self._state.last_updated.isoformat(),
        }
        with open(self.config_path, "w", encoding="utf-8") as f:
            yaml.dump(data, f)

    def engage(self, actor: str, reason: str) -> KillSwitchState:
        """Engage the kill switch immediately."""
        self._state.is_engaged = True
        self._state.engaged_by = actor
        self._state.reason = reason
        self._state.last_updated = datetime.utcnow()
        self._save_state()
        return self._state

    def disengage(self, actor: str) -> KillSwitchState:
        """Disengage the kill switch."""
        self._state.is_engaged = False
        self._state.engaged_by = actor
        self._state.reason = f"Disengaged by {actor}"
        self._state.last_updated = datetime.utcnow()
        self._save_state()
        return self._state

    def is_engaged(self) -> bool:
        self._state = self._load_state()
        return self._state.is_engaged

    def assert_not_engaged(self) -> None:
        """Check kill switch and raise exception if engaged."""
        if self.is_engaged():
            raise KillSwitchEngagedException(
                f"Global Kill Switch is ENGAGED by {self._state.engaged_by}: {self._state.reason}"
            )
