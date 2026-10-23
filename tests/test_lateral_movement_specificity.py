"""
Suraksha AI - Phase 6 Test Suite: Lateral Movement Detection Specificity (Requirement A)
Verifies context-aware lateral movement detection, elimination of benign port health check FP,
protection of critical assets, detection of cumulative low-volume stealth reconnaissance,
and regression coverage across all threat categories.
"""
import pytest
from datetime import datetime, timezone

from backend.models.events import NormalizedEvent, EventType, AssetCriticality
from backend.models.incidents import ThreatCategory, Severity
from backend.detection.rules_engine import RulesEngine
from backend.detection.behavioral_engine import BehavioralFeatureEngine, BehavioralVector


@pytest.fixture
def behavioral_engine():
    return BehavioralFeatureEngine()


def make_port_scan_event(
    event_id: str,
    user_id: str,
    source_ip: str,
    asset_id: str,
    asset_criticality: AssetCriticality,
    payload_metric: float,
    details: str
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        source_ip=source_ip,
        destination_ip="10.0.0.10",
        user_id=user_id,
        event_type=EventType.PORT_SCAN,
        asset_id=asset_id,
        asset_criticality=asset_criticality,
        payload_metric=payload_metric,
        details=details
    )


def test_benign_administrative_port_health_check_not_flagged(behavioral_engine):
    """
    Requirement A.1 & Root Cause Verification:
    EVAL-NORM-005 scenario: Routine low-volume port check by ops on sandbox must NOT trigger lateral movement alert.
    """
    evt = make_port_scan_event(
        event_id="EVT-HEALTH-001",
        user_id="carol_ops",
        source_ip="10.0.2.14",
        asset_id="dev-sandbox-01",
        asset_criticality=AssetCriticality.LOW,
        payload_metric=2.0,
        details="Routine health check of dev services on port 80 and 443"
    )
    vec, evidence = behavioral_engine.update_and_extract(evt)
    threat_cat, sev, conf, reason = RulesEngine.evaluate(evt, vector=vec)

    assert threat_cat == ThreatCategory.NONE
    assert sev == Severity.LOW
    assert "Authorized low-volume operational health check" in reason or "health check" in reason.lower()
    assert conf <= 0.20


def test_high_volume_internal_port_scan_detected(behavioral_engine):
    """
    Requirement A.2: High-volume internal port scan (>= 15 targets) must be detected as LATERAL_MOVEMENT.
    """
    evt = make_port_scan_event(
        event_id="EVT-SCAN-HIGH-001",
        user_id="attacker_recon",
        source_ip="10.0.1.100",
        asset_id="corp-subnet-scan",
        asset_criticality=AssetCriticality.MEDIUM,
        payload_metric=25.0,
        details="Massive internal port sweep across 25 targets"
    )
    vec, evidence = behavioral_engine.update_and_extract(evt)
    threat_cat, sev, conf, reason = RulesEngine.evaluate(evt, vector=vec)

    assert threat_cat == ThreatCategory.LATERAL_MOVEMENT
    assert sev == Severity.HIGH
    assert conf >= 0.85
    assert "internal port scan" in reason.lower() or "targets" in reason.lower()


def test_cumulative_low_volume_scans_detected(behavioral_engine):
    """
    Requirement A.3: Repeated low-volume scans that accumulate across events must trigger detection.
    Prevents an attacker from evading single-event thresholds by sending repeated small scans.
    """
    user = "stealth_attacker"
    ip = "10.0.50.99"

    # Event 1: Probe 2 ports on host 1 (below single-event threshold 5.0)
    e1 = make_port_scan_event("EVT-STEALTH-01", user, ip, "host-1", AssetCriticality.LOW, 2.0, "Port probe 1")
    v1, _ = behavioral_engine.update_and_extract(e1)
    cat1, _, _, _ = RulesEngine.evaluate(e1, vector=v1)

    # Event 2: Probe 2 ports on host 2 (cumulative: 4 targets)
    e2 = make_port_scan_event("EVT-STEALTH-02", user, ip, "host-2", AssetCriticality.LOW, 2.0, "Port probe 2")
    v2, _ = behavioral_engine.update_and_extract(e2)
    cat2, _, _, _ = RulesEngine.evaluate(e2, vector=v2)

    # Event 3: Probe 2 ports on host 3 (cumulative: 6 targets >= MIN_SCAN_TARGETS_THRESHOLD 5.0)
    e3 = make_port_scan_event("EVT-STEALTH-03", user, ip, "host-3", AssetCriticality.LOW, 2.0, "Port probe 3")
    v3, _ = behavioral_engine.update_and_extract(e3)
    cat3, sev3, conf3, reason3 = RulesEngine.evaluate(e3, vector=v3)

    assert v3.port_scan_count == 3.0
    assert v3.cumulative_scan_targets == 6.0
    assert cat3 == ThreatCategory.LATERAL_MOVEMENT
    assert "Cumulative internal reconnaissance detected" in reason3


def test_critical_asset_scan_never_silently_exempted(behavioral_engine):
    """
    Requirement A.4: Probing ports on a CRITICAL asset must NEVER be silently exempted,
    even if the volume is low (e.g. 2 targets).
    """
    evt = make_port_scan_event(
        event_id="EVT-CRIT-001",
        user_id="carol_ops",
        source_ip="10.0.2.14",
        asset_id="core-banking-db-01",
        asset_criticality=AssetCriticality.CRITICAL,
        payload_metric=2.0,
        details="Port probe targeting critical banking database cluster"
    )
    vec, evidence = behavioral_engine.update_and_extract(evt)
    threat_cat, sev, conf, reason = RulesEngine.evaluate(evt, vector=vec)

    assert threat_cat == ThreatCategory.LATERAL_MOVEMENT
    assert "CRITICAL" in reason
    assert conf >= 0.90


def test_missing_or_malformed_scan_volume_fields_handled_conservatively(behavioral_engine):
    """
    Requirement A.5: Missing or zero payload_metric on unverified assets must be handled conservatively.
    """
    evt = make_port_scan_event(
        event_id="EVT-MISSING-001",
        user_id="unknown_guest",
        source_ip="10.0.77.12",
        asset_id="internal-file-node",
        asset_criticality=AssetCriticality.HIGH,
        payload_metric=0.0,
        details="Port scan event with missing volume metric"
    )
    vec, evidence = behavioral_engine.update_and_extract(evt)
    threat_cat, sev, conf, reason = RulesEngine.evaluate(evt, vector=vec)

    assert threat_cat == ThreatCategory.LATERAL_MOVEMENT
    assert sev in [Severity.MEDIUM, Severity.HIGH]
    assert conf >= 0.70


def test_authorized_scanner_vs_unauthorized_scanner(behavioral_engine):
    """
    Requirement A.6: Distinguish an authorized scanner from an unauthorized source.
    """
    # Authorized scanner
    auth_evt = make_port_scan_event(
        event_id="EVT-AUTH-SCAN-01",
        user_id="nessus_scanner",
        source_ip="10.0.2.14",
        asset_id="test-sandbox",
        asset_criticality=AssetCriticality.LOW,
        payload_metric=3.0,
        details="Approved weekly vulnerability scan"
    )
    v_auth, _ = behavioral_engine.update_and_extract(auth_evt)
    cat_auth, _, _, _ = RulesEngine.evaluate(auth_evt, vector=v_auth)
    assert cat_auth == ThreatCategory.NONE

    # Unauthorized scanner
    unauth_evt = make_port_scan_event(
        event_id="EVT-UNAUTH-SCAN-01",
        user_id="external_contractor",
        source_ip="192.168.10.88",
        asset_id="test-sandbox",
        asset_criticality=AssetCriticality.LOW,
        payload_metric=3.0,
        details="Port probe by contractor outside authorized scanning tools"
    )
    v_unauth, _ = behavioral_engine.update_and_extract(unauth_evt)
    cat_unauth, sev_unauth, _, reason_unauth = RulesEngine.evaluate(unauth_evt, vector=v_unauth)
    assert cat_unauth == ThreatCategory.LATERAL_MOVEMENT
    assert "Suspicious unapproved internal port probe" in reason_unauth


def test_regression_all_other_threat_categories(behavioral_engine):
    """
    Requirement A.7: Ensure refactoring does not regress detection of other threat categories.
    """
    # 1. Brute Force
    bf_evt = NormalizedEvent(
        event_id="EVT-BF-REG", timestamp=datetime.now(timezone.utc).isoformat(),
        source_ip="1.2.3.4", destination_ip="10.0.0.1", user_id="target",
        event_type=EventType.LOGIN_FAILED, asset_id="server-1", asset_criticality=AssetCriticality.HIGH,
        payload_metric=7.0, details="Failed logins"
    )
    cat, _, _, _ = RulesEngine.evaluate(bf_evt)
    assert cat == ThreatCategory.BRUTE_FORCE

    # 2. Suspicious Login
    sl_evt = NormalizedEvent(
        event_id="EVT-SL-REG", timestamp=datetime.now(timezone.utc).isoformat(),
        source_ip="1.2.3.4", destination_ip="10.0.0.1", user_id="target",
        event_type=EventType.SUSPICIOUS_LOGIN, asset_id="vpn", asset_criticality=AssetCriticality.HIGH,
        payload_metric=1.0, details="Anomalous login"
    )
    cat, _, _, _ = RulesEngine.evaluate(sl_evt)
    assert cat == ThreatCategory.SUSPICIOUS_LOGIN

    # 3. Privilege Escalation
    pe_evt = NormalizedEvent(
        event_id="EVT-PE-REG", timestamp=datetime.now(timezone.utc).isoformat(),
        source_ip="1.2.3.4", destination_ip="10.0.0.1", user_id="target",
        event_type=EventType.SUDO_EXEC, asset_id="server-1", asset_criticality=AssetCriticality.HIGH,
        payload_metric=1.0, details="Sudo root shell"
    )
    cat, _, _, _ = RulesEngine.evaluate(pe_evt)
    assert cat == ThreatCategory.PRIVILEGE_ESCALATION

    # 4. C2 Activity
    c2_evt = NormalizedEvent(
        event_id="EVT-C2-REG", timestamp=datetime.now(timezone.utc).isoformat(),
        source_ip="1.2.3.4", destination_ip="10.0.0.1", user_id="target",
        event_type=EventType.C2_BEACON, asset_id="server-1", asset_criticality=AssetCriticality.HIGH,
        payload_metric=10.0, details="Periodic beaconing"
    )
    cat, _, _, _ = RulesEngine.evaluate(c2_evt)
    assert cat == ThreatCategory.C2_ACTIVITY

    # 5. Unusual Data Transfer
    exfil_evt = NormalizedEvent(
        event_id="EVT-EXFIL-REG", timestamp=datetime.now(timezone.utc).isoformat(),
        source_ip="1.2.3.4", destination_ip="10.0.0.1", user_id="target",
        event_type=EventType.BYTES_OUT, asset_id="server-1", asset_criticality=AssetCriticality.HIGH,
        payload_metric=650.0, details="Data exfil"
    )
    cat, _, _, _ = RulesEngine.evaluate(exfil_evt)
    assert cat == ThreatCategory.UNUSUAL_DATA_TRANSFER
