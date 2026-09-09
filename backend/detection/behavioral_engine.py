import math
from datetime import datetime, timezone
from typing import Dict, List, Set, Tuple
from pydantic import BaseModel
from backend.models.events import NormalizedEvent, EventType

class BehavioralVector(BaseModel):
    failed_login_count: float = 0.0
    login_frequency: float = 0.0
    off_hours_flag: float = 0.0
    unique_destinations_count: float = 0.0
    privilege_change_events: float = 0.0
    data_transfer_volume_mb: float = 0.0
    connection_frequency: float = 0.0

class EntityState:
    def __init__(self):
        self.failed_login_timestamps: List[datetime] = []
        self.login_timestamps: List[datetime] = []
        self.connection_timestamps: List[datetime] = []
        self.unique_destinations: Set[str] = set()
        self.privilege_count: int = 0
        self.total_data_out_mb: float = 0.0

class BehavioralFeatureEngine:
    """
    Rolling window behavioral state accumulator per user and source IP.
    Calculates behavioral metrics and human-readable evidence tags.
    """
    def __init__(self):
        self.user_states: Dict[str, EntityState] = {}
        self.ip_states: Dict[str, EntityState] = {}

    def _get_or_create_state(self, store: Dict[str, EntityState], key: str) -> EntityState:
        if key not in store:
            store[key] = EntityState()
        return store[key]

    def update_and_extract(self, event: NormalizedEvent) -> Tuple[BehavioralVector, List[str]]:
        u_state = self._get_or_create_state(self.user_states, event.user_id)
        ip_state = self._get_or_create_state(self.ip_states, event.source_ip)

        # Parse timestamp
        try:
            evt_time = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
        except Exception:
            evt_time = datetime.now(timezone.utc)

        # Update state
        u_state.unique_destinations.add(event.asset_id)
        ip_state.unique_destinations.add(event.asset_id)

        if event.event_type == EventType.LOGIN_FAILED:
            u_state.failed_login_timestamps.append(evt_time)
            ip_state.failed_login_timestamps.append(evt_time)
            if event.payload_metric > 1.0:
                # Account for bulk reported attempts
                for _ in range(int(event.payload_metric) - 1):
                    u_state.failed_login_timestamps.append(evt_time)
                    ip_state.failed_login_timestamps.append(evt_time)

        elif event.event_type == EventType.AUTH_SUCCESS or event.event_type == EventType.SUSPICIOUS_LOGIN:
            u_state.login_timestamps.append(evt_time)
            ip_state.login_timestamps.append(evt_time)

        elif event.event_type == EventType.SUDO_EXEC or "sudo" in event.details.lower():
            u_state.privilege_count += 1
            ip_state.privilege_count += 1

        elif event.event_type == EventType.BYTES_OUT:
            u_state.total_data_out_mb += event.payload_metric
            ip_state.total_data_out_mb += event.payload_metric

        elif event.event_type == EventType.C2_BEACON or event.event_type == EventType.PORT_SCAN:
            u_state.connection_timestamps.append(evt_time)
            ip_state.connection_timestamps.append(evt_time)

        # Prune old timestamps (> 5 minutes old)
        window_seconds = 300.0
        u_state.failed_login_timestamps = [t for t in u_state.failed_login_timestamps if (evt_time - t).total_seconds() <= window_seconds]
        ip_state.failed_login_timestamps = [t for t in ip_state.failed_login_timestamps if (evt_time - t).total_seconds() <= window_seconds]

        # Calculate metrics
        failed_logins = float(max(len(u_state.failed_login_timestamps), len(ip_state.failed_login_timestamps)))
        login_freq = float(len(u_state.login_timestamps))
        
        # Off-hours check (before 8 AM or after 6 PM UTC)
        hour = evt_time.hour
        off_hours = 1.0 if (hour < 8 or hour >= 18) else 0.0

        unique_dests = float(max(len(u_state.unique_destinations), len(ip_state.unique_destinations)))
        priv_events = float(max(u_state.privilege_count, ip_state.privilege_count))
        data_vol = max(event.payload_metric if event.event_type == EventType.BYTES_OUT else 0.0, u_state.total_data_out_mb)
        conn_freq = float(len(u_state.connection_timestamps)) + (event.payload_metric if event.event_type in [EventType.PORT_SCAN, EventType.C2_BEACON] else 0.0)

        vec = BehavioralVector(
            failed_login_count=failed_logins,
            login_frequency=login_freq,
            off_hours_flag=off_hours,
            unique_destinations_count=unique_dests,
            privilege_change_events=priv_events,
            data_transfer_volume_mb=data_vol,
            connection_frequency=conn_freq
        )

        # Generate human-readable behavioral evidence
        evidence = []
        if failed_logins >= 3.0:
            evidence.append(f"Elevated failed login velocity ({int(failed_logins)} attempts in window)")
        if off_hours > 0.0:
            evidence.append(f"Off-hours access detected ({hour:02d}:00 UTC)")
        if unique_dests >= 5.0:
            evidence.append(f"Cross-subnet destination expansion ({int(unique_dests)} unique targets)")
        if priv_events >= 1.0:
            evidence.append(f"Privilege escalation activity detected ({int(priv_events)} sudo events)")
        if data_vol >= 100.0:
            evidence.append(f"Large data exfiltration volume ({data_vol:.1f} MB total)")
        if conn_freq >= 5.0:
            evidence.append(f"High frequency network probing/beaconing ({int(conn_freq)} connections)")

        if not evidence:
            evidence.append("Normal baseline operational behavior")

        return vec, evidence
