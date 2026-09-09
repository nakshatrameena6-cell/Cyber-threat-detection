import pytest
from backend.detection.normalizer import EventNormalizer
from backend.detection.rules_engine import RulesEngine
from backend.detection.ml_detector import MLAnomalyDetector
from backend.models.incidents import ThreatCategory, Severity

def test_rules_engine_all_categories():
    ml = MLAnomalyDetector()
    
    # 1. Brute Force
    bf_raw = {"source_ip": "1.1.1.1", "user_id": "u1", "event_type": "LOGIN_FAILED", "payload_metric": 6.0}
    norm_bf = EventNormalizer.normalize(bf_raw)
    cat, sev, conf, _ = RulesEngine.evaluate(norm_bf)
    assert cat == ThreatCategory.BRUTE_FORCE
    assert sev == Severity.HIGH

    # 2. Suspicious Login
    sl_raw = {"source_ip": "2.2.2.2", "user_id": "u2", "event_type": "SUSPICIOUS_LOGIN", "details": "unknown country"}
    norm_sl = EventNormalizer.normalize(sl_raw)
    cat, sev, _, _ = RulesEngine.evaluate(norm_sl)
    assert cat == ThreatCategory.SUSPICIOUS_LOGIN

    # 3. Privilege Escalation
    pe_raw = {"source_ip": "3.3.3.3", "user_id": "u3", "event_type": "SUDO_EXEC", "details": "sudo su root"}
    norm_pe = EventNormalizer.normalize(pe_raw)
    cat, sev, _, _ = RulesEngine.evaluate(norm_pe)
    assert cat == ThreatCategory.PRIVILEGE_ESCALATION

    # 4. Lateral Movement
    lm_raw = {"source_ip": "4.4.4.4", "user_id": "u4", "event_type": "PORT_SCAN", "payload_metric": 30.0}
    norm_lm = EventNormalizer.normalize(lm_raw)
    cat, sev, _, _ = RulesEngine.evaluate(norm_lm)
    assert cat == ThreatCategory.LATERAL_MOVEMENT

    # 5. C2 Activity
    c2_raw = {"source_ip": "5.5.5.5", "user_id": "u5", "event_type": "C2_BEACON", "details": "evil-c2.net"}
    norm_c2 = EventNormalizer.normalize(c2_raw)
    cat, sev, _, _ = RulesEngine.evaluate(norm_c2)
    assert cat == ThreatCategory.C2_ACTIVITY

    # 6. Unusual Data Transfer
    ex_raw = {"source_ip": "6.6.6.6", "user_id": "u6", "event_type": "BYTES_OUT", "payload_metric": 800.0}
    norm_ex = EventNormalizer.normalize(ex_raw)
    cat, sev, _, _ = RulesEngine.evaluate(norm_ex)
    assert cat == ThreatCategory.UNUSUAL_DATA_TRANSFER

def test_ml_detector_anomaly():
    ml = MLAnomalyDetector()
    normal_evt = EventNormalizer.normalize({"event_type": "AUTH_SUCCESS", "payload_metric": 2.0})
    normal_score = ml.predict_anomaly_score(normal_evt)
    assert normal_score <= 0.50

    high_anom_evt = EventNormalizer.normalize({"event_type": "BYTES_OUT", "payload_metric": 900.0})
    anom_score = ml.predict_anomaly_score(high_anom_evt)
    assert anom_score >= 0.75
