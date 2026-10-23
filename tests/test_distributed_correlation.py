"""
Suraksha AI - Phase 7 Subnet-Aware Distributed Threat Correlation Tests (Requirement D)
Verifies multi-source IP correlation across IPv4 /24 and IPv6 /64 subnets, contextual corroboration,
and prevention of unintended incident merges across unrelated campaigns.
"""
from datetime import datetime, timezone, timedelta
from backend.models.events import NormalizedEvent, EventType, AssetCriticality
from backend.models.incidents import Incident, IncidentStatus, Severity, ThreatCategory
from backend.incidents.correlation import IncidentCorrelationEngine
from backend.incidents.manager import IncidentManager
from backend.database import DatabaseManager


def test_distributed_scan_same_ipv4_subnet_merges_with_common_target():
    """
    Verifies that multiple attacking IPs in the same /24 subnet (e.g. 198.51.100.10 and 198.51.100.11)
    targeting the same asset are successfully grouped into a unified incident with subnet why_evidence.
    """
    mgr = IncidentManager()
    corr = IncidentCorrelationEngine(correlation_window_seconds=600.0, ipv4_cidr_prefix=24)
    now = datetime.now(timezone.utc).isoformat()

    # Initial incident from IP 198.51.100.10
    inc = mgr.create_incident(
        event_id="EVT-SRC1",
        threat_category=ThreatCategory.LATERAL_MOVEMENT,
        severity=Severity.HIGH,
        risk_score=75.0,
        confidence_score=0.85,
        source_ip="198.51.100.10",
        user_id="recon_bot_1",
        asset_id="core-db-server",
        details="Port sweep from bot 1",
        recommended_action="BLOCK_IP",
        decision_tier="TIER_B",
        event_timestamp=now
    )

    # Second event from different IP in same /24 subnet targeting the same asset
    evt2 = NormalizedEvent(
        event_id="EVT-SRC2",
        timestamp=now,
        source_ip="198.51.100.11", # Same /24 subnet: 198.51.100.0/24
        user_id="recon_bot_2",
        event_type=EventType.PORT_SCAN,
        asset_id="core-db-server", # Shared target asset
        asset_criticality=AssetCriticality.HIGH,
        payload_metric=15.0,
        details="Coordinated port sweep from bot 2"
    )

    found_inc = corr.find_correlatable_incident(evt2, mgr.list_incidents(), threat_cat=ThreatCategory.LATERAL_MOVEMENT)
    assert found_inc is not None, "Failed to correlate distributed scan from matching /24 subnet"
    assert found_inc.incident_id == inc.incident_id

    # Merge and verify explainable subnet evidence
    merged = corr.merge_event_into_incident(
        incident=found_inc,
        event=evt2,
        threat_cat=ThreatCategory.LATERAL_MOVEMENT,
        new_risk=80.0,
        new_confidence=0.90,
        evidence=["High volume port scan"],
        why_bullets=["Coordinated multi-source reconnaissance"]
    )
    assert any("Distributed subnet campaign" in w for w in merged.why_evidence)
    assert "EVT-SRC2" in merged.related_events


def test_distributed_attack_same_ipv6_subnet_merges(isolated_db):
    """Verifies that attacking hosts in the same /64 IPv6 prefix are correlated."""
    mgr = IncidentManager(isolated_db)
    corr = IncidentCorrelationEngine(correlation_window_seconds=600.0, ipv6_cidr_prefix=64)
    now = datetime.now(timezone.utc).isoformat()

    inc = mgr.create_incident(
        event_id="EVT-IPV6-1",
        threat_category=ThreatCategory.BRUTE_FORCE,
        severity=Severity.HIGH,
        risk_score=75.0,
        confidence_score=0.85,
        source_ip="2001:db8:abcd:0012::10",
        user_id="admin_target",
        asset_id="gateway-v6",
        details="SSH password spray",
        recommended_action="BLOCK_IP",
        decision_tier="TIER_B",
        event_timestamp=now
    )

    evt_v6_2 = NormalizedEvent(
        event_id="EVT-IPV6-2",
        timestamp=now,
        source_ip="2001:db8:abcd:0012::55", # Same /64 prefix (2001:db8:abcd:12::/64)
        user_id="admin_target",
        event_type=EventType.LOGIN_FAILED,
        asset_id="gateway-v6",
        asset_criticality=AssetCriticality.HIGH,
        payload_metric=8.0,
        details="Continued password spray from IPv6 bot 2"
    )

    found_inc = corr.find_correlatable_incident(evt_v6_2, mgr.list_incidents(), threat_cat=ThreatCategory.BRUTE_FORCE)
    assert found_inc is not None, "Failed to correlate IPv6 distributed attack in same /64 subnet"
    assert found_inc.incident_id == inc.incident_id


def test_unrelated_campaigns_in_same_subnet_do_not_merge(isolated_db):
    """
    Mandatory Safety Invariant: Two events from the same /24 subnet that target
    different assets, belong to different threat categories, and have different users
    represent UNRELATED activity and must NOT be accidentally merged.
    """
    mgr = IncidentManager(isolated_db)
    corr = IncidentCorrelationEngine(correlation_window_seconds=600.0, ipv4_cidr_prefix=24)
    now = datetime.now(timezone.utc).isoformat()

    # Campaign 1: Brute force login on Auth Gateway from 198.51.100.10
    inc1 = mgr.create_incident(
        event_id="EVT-CAMP1",
        threat_category=ThreatCategory.BRUTE_FORCE,
        severity=Severity.HIGH,
        risk_score=75.0,
        confidence_score=0.85,
        source_ip="198.51.100.10",
        user_id="target_admin",
        asset_id="auth-gateway",
        details="Brute force login wave",
        recommended_action="BLOCK_IP",
        decision_tier="TIER_B",
        event_timestamp=now
    )

    # Campaign 2: Data exfiltration from internal DB to 198.51.100.99 by rogue user
    evt2 = NormalizedEvent(
        event_id="EVT-CAMP2",
        timestamp=now,
        source_ip="198.51.100.99", # Same /24 subnet, but DIFFERENT asset, category, and user
        user_id="rogue_contractor",
        event_type=EventType.BYTES_OUT,
        asset_id="customer-vault", # Different asset
        asset_criticality=AssetCriticality.HIGH,
        payload_metric=900.0,
        details="Unrelated sensitive database transfer"
    )

    # Must NOT merge with inc1
    found_inc = corr.find_correlatable_incident(evt2, mgr.list_incidents(), threat_cat=ThreatCategory.UNUSUAL_DATA_TRANSFER)
    assert found_inc is None, "Accidentally merged unrelated campaigns sharing a subnet"


def test_unrelated_benign_activity_in_same_subnet_never_merges(isolated_db):
    """Verifies that benign traffic from a shared subnet never contaminates a malicious incident."""
    mgr = IncidentManager(isolated_db)
    corr = IncidentCorrelationEngine(correlation_window_seconds=600.0, ipv4_cidr_prefix=24)
    now = datetime.now(timezone.utc).isoformat()

    # Active malware incident
    inc = mgr.create_incident(
        event_id="EVT-MAL",
        threat_category=ThreatCategory.C2_ACTIVITY,
        severity=Severity.HIGH,
        risk_score=80.0,
        confidence_score=0.90,
        source_ip="10.0.1.5",
        user_id="bot_agent",
        asset_id="infected-laptop",
        details="C2 beaconing",
        recommended_action="BLOCK_IP",
        decision_tier="TIER_B",
        event_timestamp=now
    )

    # Benign routine login from coworker on same /24 subnet
    benign_evt = NormalizedEvent(
        event_id="EVT-BENIGN",
        timestamp=now,
        source_ip="10.0.1.20", # Same /24 subnet (10.0.1.0/24)
        user_id="legitimate_worker",
        event_type=EventType.AUTH_SUCCESS,
        asset_id="workstation-20",
        asset_criticality=AssetCriticality.LOW,
        payload_metric=1.0,
        details="Routine morning login"
    )

    found_inc = corr.find_correlatable_incident(benign_evt, mgr.list_incidents(), threat_cat=ThreatCategory.NONE)
    assert found_inc is None, "Benign event from shared subnet was incorrectly correlated to malware incident"


def test_time_window_expiry_prevents_distributed_merge(isolated_db):
    """Verifies that events outside the correlation window (e.g. >10 minutes) do not merge."""
    mgr = IncidentManager(isolated_db)
    corr = IncidentCorrelationEngine(correlation_window_seconds=600.0, ipv4_cidr_prefix=24)
    now_dt = datetime.now(timezone.utc)

    # Incident from 15 minutes ago
    old_time = (now_dt - timedelta(seconds=900)).isoformat()
    inc = mgr.create_incident(
        event_id="EVT-OLD",
        threat_category=ThreatCategory.PORT_SCAN,
        severity=Severity.HIGH,
        risk_score=75.0,
        confidence_score=0.85,
        source_ip="198.51.100.10",
        user_id="scanner_1",
        asset_id="target-host",
        details="Scan 15 mins ago",
        recommended_action="BLOCK_IP",
        decision_tier="TIER_B",
        event_timestamp=old_time
    )

    # Current event
    current_evt = NormalizedEvent(
        event_id="EVT-CURRENT",
        timestamp=now_dt.isoformat(),
        source_ip="198.51.100.11",
        user_id="scanner_2",
        event_type=EventType.PORT_SCAN,
        asset_id="target-host",
        asset_criticality=AssetCriticality.HIGH,
        payload_metric=10.0,
        details="New scan wave"
    )

    found_inc = corr.find_correlatable_incident(current_evt, mgr.list_incidents(), threat_cat=ThreatCategory.LATERAL_MOVEMENT)
    assert found_inc is None, "Expired incident was merged across correlation window boundary"
