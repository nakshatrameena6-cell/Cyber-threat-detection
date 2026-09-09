import pytest
from backend.response.kill_switch import EmergencyKillSwitch
from backend.response.decision_engine import DecisionEngine
from backend.models.response import DecisionTier, ActionStatus

def test_kill_switch_override():
    # 1. Ensure disabled by default
    EmergencyKillSwitch.disable(actor="test_admin")
    assert EmergencyKillSwitch.is_active() is False

    # Normal Tier C auto-approval
    tier, status, _, _ = DecisionEngine.evaluate_tier(risk_score=90.0, confidence_score=0.90, recommended_action_str="BLOCK_IP")
    assert status == ActionStatus.APPROVED

    # 2. Enable Kill Switch
    EmergencyKillSwitch.enable(actor="test_admin")
    assert EmergencyKillSwitch.is_active() is True

    # Tier C high risk should now drop to PENDING_APPROVAL
    tier, status, _, reason = DecisionEngine.evaluate_tier(risk_score=90.0, confidence_score=0.90, recommended_action_str="BLOCK_IP")
    assert status == ActionStatus.PENDING_APPROVAL
    assert "Kill Switch" in reason

    # Cleanup: restore to disabled
    EmergencyKillSwitch.disable()
