# Requirements Specification (REQUIREMENTS.md)

**System:** Suraksha AI - Behavioral Threat Detection & Safe Response System  
**Framework:** Spec-Driven Development (SDD)  
**Phase:** 2  

---

## Requirement Matrix & Traceability

| Requirement ID | Module | Description | Acceptance Criteria | Primary Test Case |
|---|---|---|---|---|
| **REQ-INGEST-001** | `backend/detection/normalizer.py` | Ingest raw event telemetry & normalize to `NormalizedEvent` schema. | Parses JSON/Dict/File inputs; converts timestamps to UTC ISO; validates required fields; handles malformed inputs gracefully. | `tests/test_normalizer.py` |
| **REQ-INGEST-002** | `backend/detection/normalizer.py` | Event Deduplication & Batch Stream Processing. | Filters duplicate events within sliding window; sorts out-of-order event streams by timestamp. | `tests/test_telemetry_stream.py` |
| **REQ-FEAT-001** | `backend/detection/behavioral_engine.py` | Extract rolling behavioral features per user/IP. | Computes 6 rolling metrics: failed logins, login rate, off-hours, unique destinations, privilege changes, data transfer volume. | `tests/test_behavioral_engine.py` |
| **REQ-DET-001** | `backend/detection/rules_engine.py` | Deterministic rule matching for 6 threat categories. | Correctly tags `SUSPICIOUS_LOGIN`, `BRUTE_FORCE`, `PRIVILEGE_ESCALATION`, `LATERAL_MOVEMENT`, `C2_ACTIVITY`, `UNUSUAL_DATA_TRANSFER`. | `tests/test_detection.py::test_rules_engine` |
| **REQ-DET-002** | `backend/detection/ml_detector.py` | ML anomaly detection on network exfiltration and beaconing features. | IsolationForest / Classifier calculates continuous anomaly score [0.0 - 1.0]. | `tests/test_detection.py::test_ml_detector` |
| **REQ-ML-002** | `backend/detection/ml_detector.py` | Behavioral vector anomaly scoring & evidence generation. | Scores 6D behavioral vector; provides list of behavioral anomaly evidence tags. | `tests/test_behavioral_engine.py` |
| **REQ-RISK-001** | `backend/detection/risk_calculator.py` | Composite Risk (0-100) & Confidence Scoring (0.0-1.0). | Risk = `f(RuleWeight, MLScore, AssetCriticality)`; Confidence = `f(RuleCertainty, MLScore)`. | `tests/test_risk_calculator.py` |
| **REQ-INC-001** | `backend/incidents/manager.py` | Incident lifecycle & state persistence with evidence. | Creates unique incident IDs (`INC-XXXX`); attaches behavioral evidence tags and status. | `tests/test_end_to_end.py` |
| **REQ-DEC-001** | `backend/response/decision_engine.py` | Tier A/B/C response decision matrix. | Tier A (Risk <40): Alert; Tier B (40<=Risk<=75): Human Approval; Tier C (Risk >75): Auto Execute (if confidence >= 0.75 & Kill Switch OFF). | `tests/test_response_engine.py` |
| **REQ-RESP-001** | `backend/response/executor.py` | Safe simulated action execution. | Executes `BLOCK_IP`, `SUSPEND_SESSION`, `ISOLATE_ENDPOINT` safely; updates action status to `EXECUTED`. | `tests/test_response_engine.py` |
| **REQ-VERIFY-001** | `backend/response/verifier.py` | Post-response verification check. | Performs post-execution verification check; marks verification as `PASSED` or `FAILED`. | `tests/test_response_engine.py` |
| **REQ-ROLLBACK-001** | `backend/response/executor.py` | Action rollback capability. | Reverses simulated action (`UNBLOCK_IP`, `REACTIVATE_SESSION`, `REJOIN_ENDPOINT`); logs rollback record. | `tests/test_rollback.py` |
| **REQ-KILL-001** | `backend/response/kill_switch.py` | Global Emergency Kill Switch. | When Kill Switch is ACTIVE, all Tier C automated actions revert to Human Approval mode regardless of score. | `tests/test_kill_switch.py` |
| **REQ-AUD-001** | `backend/audit/logger.py` | Tamper-evident Audit Trail. | Logs every pipeline step with timestamp, actor, event ID, action taken, and previous state. | `tests/test_audit.py` |
| **REQ-RBAC-001** | `backend/rbac.py` | Role-Based Access Control. | Enforces `ADMIN` (all), `ANALYST` (view + approve), `AUDITOR` (read-only) permission checks. | `tests/test_rbac.py` |
| **REQ-DASH-001** | `frontend/` + `backend/main.py` | Visual interactive Web Dashboard. | Serves responsive dashboard displaying live feed, incident management, attack simulator, kill switch toggle, and audit viewer. | Integration / UI |
| **REQ-DASH-002** | `frontend/` + `backend/main.py` | Behavioral Telemetry Stream & Evidence Dashboard. | Allows batch stream ingestion, displays Normal vs Abnormal tags, and shows behavioral evidence breakdown. | Integration / UI |
