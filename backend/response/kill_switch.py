class EmergencyKillSwitch:
    """
    Global Emergency Kill Switch singleton.
    When ACTIVE, prevents any automated Tier C response execution across the entire pipeline.
    All automated triggers are immediately downgraded to PENDING_HUMAN_APPROVAL.
    """
    _is_active: bool = False
    _toggled_by: str = "SYSTEM"
    _toggled_at: str = ""

    @classmethod
    def is_active(cls) -> bool:
        return cls._is_active

    @classmethod
    def enable(cls, actor: str = "ADMIN") -> dict:
        from datetime import datetime, timezone
        cls._is_active = True
        cls._toggled_by = actor
        cls._toggled_at = datetime.now(timezone.utc).isoformat()
        return {
            "status": "ACTIVE",
            "message": "Emergency Kill Switch ENABLED. Automated responses HALTED.",
            "toggled_by": cls._toggled_by,
            "toggled_at": cls._toggled_at
        }

    @classmethod
    def disable(cls, actor: str = "ADMIN") -> dict:
        from datetime import datetime, timezone
        cls._is_active = False
        cls._toggled_by = actor
        cls._toggled_at = datetime.now(timezone.utc).isoformat()
        return {
            "status": "INACTIVE",
            "message": "Emergency Kill Switch DISABLED. Normal decision pipeline operational.",
            "toggled_by": cls._toggled_by,
            "toggled_at": cls._toggled_at
        }

    @classmethod
    def get_state(cls) -> dict:
        return {
            "is_active": cls._is_active,
            "toggled_by": cls._toggled_by,
            "toggled_at": cls._toggled_at
        }
