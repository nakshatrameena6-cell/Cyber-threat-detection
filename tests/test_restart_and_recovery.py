import os
import pytest
from datetime import datetime, timezone
from backend.database import DatabaseManager, init_db
from backend.incidents.manager import IncidentManager
from backend.response.executor import ResponseExecutor
from backend.audit.logger import AuditLogger
from backend.models.incidents import ThreatCategory, Severity, IncidentStatus
from backend.models.response import ResponseActionType, DecisionTier, ActionStatus
from backend.response.kill_switch import EmergencyKillSwitch

def test_restart_recovery_persisted_entities(tmp_path):
    """
    REQ-RECOVERY-001: Historical incidents, response actions, active simulated enforcements,
    and audit trail survive application restart using a real database file.
    """
    real_db_path = str(tmp_path / "persistent_suraksha.db")
    
    # 1. First run: Initialize and create entities
    db1 = DatabaseManager(real_db_path)
    inc_mgr1 = IncidentManager(db=db1)
    resp_exec1 = ResponseExecutor(db=db1)
    audit1 = AuditLogger(db=db1)

    # Create incident with timeline
    inc = inc_mgr1.create_incident(
        event_id="EVT-PERSIST-1",
        threat_category=ThreatCategory.BRUTE_FORCE,
        severity=Severity.HIGH,
        risk_score=85.0,
        confidence_score=0.90,
        source_ip="198.51.100.99",
        user_id="victim_alice",
        asset_id="web-server-01",
        details="8 brute force attempts",
        recommended_action="BLOCK_IP",
        decision_tier="TIER_B",
        behavioral_evidence=["High attempt rate"],
        why_evidence=["Multiple password failures"]
    )
    inc_id = inc.incident_id

    # Execute response action (simulates firewall block)
    rec = resp_exec1.execute_action(
        incident_id=inc_id,
        action_type=ResponseActionType.BLOCK_IP,
        target="198.51.100.99",
        tier=DecisionTier.TIER_B,
        actor="ADMIN",
        actor_role="ADMIN"
    )
    assert rec.success is True
    assert "198.51.100.99" in resp_exec1.blocked_ips

    # Log audit entry
    audit1.log(
        actor="admin_tester",
        role="ADMIN",
        action_category="EXECUTION",
        description="Blocked attacker IP",
        target_resource="198.51.100.99"
    )

    # 2. Simulate Application Restart: Destroy in-memory instances and instantiate fresh ones from real_db_path
    del db1
    del inc_mgr1
    del resp_exec1
    del audit1

    db2 = DatabaseManager(real_db_path)
    inc_mgr2 = IncidentManager(db=db2)
    resp_exec2 = ResponseExecutor(db=db2)
    audit2 = AuditLogger(db=db2)

    # Verify incident recovered with timeline and evidence
    recovered_inc = inc_mgr2.get_incident(inc_id)
    assert recovered_inc is not None
    assert recovered_inc.incident_id == inc_id
    assert recovered_inc.risk_score == 85.0
    assert len(recovered_inc.timeline) >= 1
    assert "High attempt rate" in recovered_inc.behavioral_evidence
    assert "Multiple password failures" in recovered_inc.why_evidence

    # Verify active simulated security state recovered
    assert "198.51.100.99" in resp_exec2.blocked_ips
    assert len(resp_exec2.records) >= 1

    # Verify audit logs recovered
    recovered_logs = audit2.list_logs()
    assert len(recovered_logs) >= 1
    assert any(log.actor == "admin_tester" for log in recovered_logs)

def test_restart_does_not_repeat_pending_actions(tmp_path):
    """
    REQ-RECOVERY-002: Pending actions stay pending after restart and are NOT automatically executed.
    """
    db_path = str(tmp_path / "pending_restart.db")
    db1 = DatabaseManager(db_path)
    inc_mgr1 = IncidentManager(db=db1)

    # Create pending approval incident (Tier C)
    inc = inc_mgr1.create_incident(
        event_id="EVT-PENDING",
        threat_category=ThreatCategory.UNUSUAL_DATA_TRANSFER,
        severity=Severity.HIGH,
        risk_score=90.0,
        confidence_score=0.85,
        source_ip="10.0.1.50",
        user_id="user_bob",
        asset_id="finance-db",
        details="Large data transfer",
        recommended_action="ISOLATE_ENDPOINT",
        decision_tier="TIER_C"
    )
    inc_id = inc.incident_id
    assert inc.action_executed is False
    assert inc.status == IncidentStatus.NEW

    # Restart
    db2 = DatabaseManager(db_path)
    inc_mgr2 = IncidentManager(db=db2)
    resp_exec2 = ResponseExecutor(db=db2)

    recovered = inc_mgr2.get_incident(inc_id)
    assert recovered.action_executed is False
    assert "finance-db" not in resp_exec2.isolated_hosts

def test_database_write_failure_fails_closed(tmp_path):
    """
    REQ-FAIL-001: Mandatory safety rule — if audit persistence fails, simulated response action must not execute.
    """
    db = DatabaseManager(str(tmp_path / "fail_closed.db"))
    executor = ResponseExecutor(db=db)

    # Simulate audit persistence failure
    executor.audit_checker = lambda: False

    rec = executor.execute_action(
        incident_id="INC-FAIL-01",
        action_type=ResponseActionType.BLOCK_IP,
        target="10.0.0.1",
        tier=DecisionTier.TIER_B,
        actor="ADMIN"
    )
    assert rec.success is False
    assert rec.status == ActionStatus.DENIED
    assert "Gate 6" in rec.gate_message
    assert "10.0.0.1" not in executor.blocked_ips
