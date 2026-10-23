import os
from typing import Tuple, Optional, Set
from backend.models.events import NormalizedEvent, EventType, AssetCriticality
from backend.models.incidents import ThreatCategory, Severity
from backend.detection.behavioral_engine import BehavioralVector

class RulesEngine:
    """
    Rule-based threat evaluation covering 6 primary threat categories with context-aware lateral movement tuning.
    Returns (ThreatCategory, RuleSeverity, Confidence, RuleMatchReason)
    """
    # Configurable detection thresholds and authorized scanner settings
    MIN_SCAN_TARGETS_THRESHOLD: float = float(os.environ.get("SURAKSHA_SCAN_MIN_THRESHOLD", "5.0"))
    HIGH_VOLUME_SCAN_THRESHOLD: float = float(os.environ.get("SURAKSHA_SCAN_HIGH_THRESHOLD", "20.0"))
    AUTHORIZED_SCANNER_USERS: Set[str] = {"carol_ops", "health_check_service", "ops_monitor", "netadmin", "monitoring_agent"}
    AUTHORIZED_SCANNER_IPS: Set[str] = {"10.0.2.14", "10.0.0.254", "127.0.0.1"}
    AUTHORIZED_SCANNER_SUBSTRINGS: Tuple[str, ...] = ("health check", "service check", "port check", "heartbeat", "synthetic probe")

    @classmethod
    def evaluate(
        cls,
        event: NormalizedEvent,
        vector: Optional[BehavioralVector] = None
    ) -> Tuple[ThreatCategory, Severity, float, str]:
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

        # 4. Context-Aware Lateral Movement Detection (Phase 6 Tuned)
        if event.event_type == EventType.PORT_SCAN or (event.payload_metric >= cls.HIGH_VOLUME_SCAN_THRESHOLD and "internal" in event.details.lower()):
            scan_volume = float(event.payload_metric or 0.0)
            is_missing_or_malformed = (scan_volume <= 0.0)

            # Check asset criticality
            is_critical_target = (
                event.asset_criticality == AssetCriticality.HIGH
                or any(crit in event.asset_id.lower() for crit in ("core", "dc", "auth", "vault", "prod", "primary"))
            )

            # Cumulative scan metrics from behavioral vector
            cumulative_targets = float(vector.cumulative_scan_targets if vector else scan_volume)
            cumulative_scans = float(vector.port_scan_count if vector else 1.0)

            # Check authorization and operational health-check context
            is_authorized_user = event.user_id in cls.AUTHORIZED_SCANNER_USERS
            is_authorized_ip = event.source_ip in cls.AUTHORIZED_SCANNER_IPS
            has_health_check_detail = any(kw in event.details.lower() for kw in cls.AUTHORIZED_SCANNER_SUBSTRINGS)
            is_authorized_context = (is_authorized_user or is_authorized_ip or has_health_check_detail)

            # Condition 4A: Critical Asset Protection - Probing critical infrastructure is NEVER silently exempted
            if is_critical_target:
                sev = Severity.CRITICAL if (scan_volume >= cls.HIGH_VOLUME_SCAN_THRESHOLD or cumulative_targets >= cls.HIGH_VOLUME_SCAN_THRESHOLD) else Severity.HIGH
                return (
                    ThreatCategory.LATERAL_MOVEMENT,
                    sev,
                    0.92,
                    f"Lateral movement probing targeting CRITICAL asset '{event.asset_id}' ({scan_volume:.1f} ports/hosts queried)."
                )

            # Condition 4B: High-Volume Internal Port Scan
            if scan_volume >= cls.HIGH_VOLUME_SCAN_THRESHOLD or (event.payload_metric >= cls.HIGH_VOLUME_SCAN_THRESHOLD and "internal" in event.details.lower()):
                return (
                    ThreatCategory.LATERAL_MOVEMENT,
                    Severity.HIGH,
                    0.90,
                    f"Aggressive internal port scan across {int(scan_volume)} targets/hosts."
                )

            # Condition 4C: Cumulative Low-Volume Port Scanning (Stealth reconnaissance)
            # Prevents attacker from evading single-event thresholds by sending repeated small scans
            if cumulative_targets >= cls.MIN_SCAN_TARGETS_THRESHOLD and cumulative_scans > 1:
                return (
                    ThreatCategory.LATERAL_MOVEMENT,
                    Severity.HIGH,
                    0.86,
                    f"Cumulative internal reconnaissance detected across {int(cumulative_scans)} sequential probes ({cumulative_targets:.1f} total targets)."
                )

            # Condition 4D: Authorized Low-Volume Service Health Check
            # Distinguish routine low-volume checks (< 5.0) on non-critical assets with authorized context
            if not is_missing_or_malformed and scan_volume < cls.MIN_SCAN_TARGETS_THRESHOLD and is_authorized_context:
                return (
                    ThreatCategory.NONE,
                    Severity.LOW,
                    0.15,
                    f"Authorized low-volume operational health check ({scan_volume:.1f} targets) by '{event.user_id}' on non-critical asset '{event.asset_id}'."
                )

            # Condition 4E: Missing or Malformed Volume Metric
            # Handle missing or zero payload_metric conservatively
            if is_missing_or_malformed:
                if is_authorized_context and not is_critical_target:
                    return (
                        ThreatCategory.NONE,
                        Severity.LOW,
                        0.20,
                        f"Authorized scanner activity with unspecified volume on non-critical asset '{event.asset_id}'."
                    )
                return (
                    ThreatCategory.LATERAL_MOVEMENT,
                    Severity.MEDIUM,
                    0.70,
                    f"Unverified internal port probe with missing/malformed volume metrics on '{event.asset_id}'."
                )

            # Condition 4F: Unauthorized Low-Volume Probe (Conservative classification)
            return (
                ThreatCategory.LATERAL_MOVEMENT,
                Severity.MEDIUM,
                0.75,
                f"Suspicious unapproved internal port probe ({scan_volume:.1f} targets) by '{event.user_id}' from {event.source_ip}."
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
