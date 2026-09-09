import pytest
from backend.detection.normalizer import EventNormalizer
from backend.detection.risk_calculator import RiskCalculator
from backend.models.incidents import ThreatCategory, Severity
from backend.models.events import AssetCriticality

def test_risk_calculator_scoring():
    raw_high = {
        "source_ip": "10.0.0.5",
        "user_id": "root",
        "event_type": "BYTES_OUT",
        "asset_id": "core-db",
        "asset_criticality": "HIGH",
        "payload_metric": 950.0
    }
    norm = EventNormalizer.normalize(raw_high)
    risk, conf, action = RiskCalculator.calculate(
        event=norm,
        threat_cat=ThreatCategory.UNUSUAL_DATA_TRANSFER,
        rule_severity=Severity.CRITICAL,
        rule_confidence=0.95,
        ml_score=0.90
    )
    assert risk >= 75.0
    assert conf >= 0.80
    assert action == "ISOLATE_ENDPOINT"

def test_risk_calculator_low_asset():
    raw_low = {
        "source_ip": "10.0.0.99",
        "user_id": "test",
        "event_type": "LOGIN_FAILED",
        "asset_id": "guest-wifi",
        "asset_criticality": "LOW",
        "payload_metric": 3.0
    }
    norm = EventNormalizer.normalize(raw_low)
    risk, conf, action = RiskCalculator.calculate(
        event=norm,
        threat_cat=ThreatCategory.BRUTE_FORCE,
        rule_severity=Severity.MEDIUM,
        rule_confidence=0.75,
        ml_score=0.20
    )
    assert risk < 50.0
    assert action == "BLOCK_IP"
