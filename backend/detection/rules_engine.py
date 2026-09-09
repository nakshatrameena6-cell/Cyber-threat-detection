from typing import Tuple
from backend.models.events import NormalizedEvent, EventType
from backend.models.incidents import ThreatCategory, Severity

class RulesEngine:
    """
    Rule-based threat evaluation covering 6 primary threat categories.
    Returns (ThreatCategory, RuleSeverity, Confidence, RuleMatchReason)
    """
    @staticmethod
    def evaluate(event: NormalizedEvent) -> Tuple[ThreatCategory, Severity, float, str]:
        # 1. Brute Force Detection
        if event.event_type == EventType.LOGIN_FAILED:
            if event.payload_metric >= 5.0:
                return (
                    ThreatCategory.BRUTE_FORCE,
                    Severity.HIGH,
                    0.90,
                    f"High-frequency failed logins detected ({int(event.payload_metric)} attempts)."
                )
            elif event.payload_metric >= 3.0:
                return (
                    ThreatCategory.BRUTE_FORCE,
                    Severity.MEDIUM,
                    0.75,
                    f"Multiple failed login attempts detected ({int(event.payload_metric)} attempts)."
                )

        # 2. Suspicious Login Detection
        if event.event_type == EventType.SUSPICIOUS_LOGIN or "unknown country" in event.details.lower() or "off-hours" in event.details.lower():
            return (
                ThreatCategory.SUSPICIOUS_LOGIN,
                Severity.MEDIUM,
                0.80,
                f"Suspicious authentication source or context: {event.details}"
            )

        # 3. Privilege Escalation Detection
        if event.event_type == EventType.SUDO_EXEC or "sudo" in event.details.lower() or "root" in event.details.lower():
            return (
                ThreatCategory.PRIVILEGE_ESCALATION,
                Severity.HIGH,
                0.85,
                f"Unauthorized or sensitive privilege escalation attempt by user '{event.user_id}'."
            )

        # 4. Lateral Movement Detection
        if event.event_type == EventType.PORT_SCAN or event.payload_metric >= 20.0 and "internal" in event.details.lower():
            return (
                ThreatCategory.LATERAL_MOVEMENT,
                Severity.HIGH,
                0.88,
                f"Internal network probing/port scan across internal hosts ({int(event.payload_metric)} hosts target)."
            )

        # 5. C2-like Activity Detection
        if event.event_type == EventType.C2_BEACON or "beacon" in event.details.lower() or "c2" in event.details.lower():
            return (
                ThreatCategory.C2_ACTIVITY,
                Severity.CRITICAL,
                0.92,
                f"Periodic outbound beaconing pattern detected to potential C2 host: {event.details}"
            )

        # 6. Unusual Data Transfer (Exfiltration)
        if event.event_type == EventType.BYTES_OUT or event.payload_metric >= 500.0:
            if event.payload_metric >= 500.0:
                return (
                    ThreatCategory.UNUSUAL_DATA_TRANSFER,
                    Severity.CRITICAL,
                    0.95,
                    f"Massive outbound data exfiltration volume ({event.payload_metric} MB)."
                )
            elif event.payload_metric >= 100.0:
                return (
                    ThreatCategory.UNUSUAL_DATA_TRANSFER,
                    Severity.HIGH,
                    0.80,
                    f"Elevated outbound data transfer ({event.payload_metric} MB)."
                )

        # Default Benign
        return (ThreatCategory.NONE, Severity.LOW, 0.10, "Normal operational telemetry.")
