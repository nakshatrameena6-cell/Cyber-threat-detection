# Requirements Specification (REQUIREMENTS.md)

**System:** Suraksha AI - Risk, Incident Correlation & Safe Response Engine  
**Framework:** Spec-Driven Development (SDD)  
**Phase:** 3  

---

## Requirement Matrix & Traceability

| Requirement ID | Module | Description | Acceptance Criteria | Primary Test Case |
|---|---|---|---|---|
| **REQ-INGEST-001** | `backend/detection/normalizer.py` | Ingest raw event telemetry & normalize to `NormalizedEvent` schema. | Parses JSON/Dict/File inputs; converts timestamps to UTC ISO; validates required fields. | `tests/test_normalizer.py` |
| **REQ-INGEST-002** | `backend/detection/normalizer.py` | Event Deduplication & Batch Stream Processing. | Filters duplicate events within sliding window; sorts out-of-order event streams by timestamp. | `tests/test_telemetry_stream.py` |
| **REQ-FEAT-001** | `backend/detection/behavioral_engine.py` | Extract rolling behavioral features per user/IP. | Computes 6 rolling metrics: failed logins, login rate, off-hours, unique destinations, privilege changes, data transfer volume. | `tests/test_behavioral_engine.py` |
| **REQ-DET-001** | `backend/detection/rules_engine.py` | Deterministic rule matching for 6 threat categories. | Correctly tags `SUSPICIOUS_LOGIN`, `BRUTE_FORCE`, `PRIVILEGE_ESCALATION`, `LATERAL_MOVEMENT`, `C2_ACTIVITY`, `UNUSUAL_DATA_TRANSFER`. | `tests/test_detection.py::test_rules_engine` |
| **REQ-DET-002** | `backend/detection/ml_detector.py` | ML anomaly detection on network exfiltration and beaconing features. | IsolationForest calculates continuous anomaly score [0.0 - 1.0]. | `tests/test_detection.py::test_ml_detector` |
| **REQ-ML-002** | `backend/detection/ml_detector.py` | Behavioral vector anomaly scoring & evidence generation. | Scores 6D behavioral vector; provides list of behavioral anomaly evidence tags. | `tests/test_behavioral_engine.py` |
| **REQ-RISK-001** | `backend/detection/risk_calculator.py` | Composite Risk (0-100) & Confidence Scoring (0.0-1.0). | Risk = `f(RuleWeight, MLScore, AssetCriticality)`; Confidence = `f(RuleCertainty, MLScore)`. | `tests/test_risk_calculator.py` |
| **REQ-RISK-002** | `backend/detection/risk_calculator.py` | Transparent "Why" Evidence Risk Explanation. | Generates human-readable evidence list (`why_evidence`) explaining risk factors without fabricating data. | `tests/test_phase3_end_to_end.py` |
| **REQ-INC-001** | `backend/incidents/manager.py` | Incident lifecycle & state persistence. | Creates unique incident IDs (`INC-XXXX`); attaches behavioral evidence tags and status. | `tests/test_end_to_end.py` |
| **REQ-INC-002** | `backend/incidents/correlation.py` | Deterministic Multi-Event Incident Correlation. | Groups related events (same user, IP, asset, close timestamp) into single correlated incidents. | `tests/test_correlation.py` |
| **REQ-INC-003** | `backend/incidents/manager.py` | Incident Timeline & Strict Lifecycle State Machine. | Enforces valid lifecycle transitions (`NEW` -> `UNDER_INVESTIGATION` -> `MITIGATED` -> `RESOLVED` / `FALSE_POSITIVE`) and builds event timeline. | `tests/test_lifecycle_and_idempotency.py` |
| **REQ-DEC-001** | `backend/response/decision_engine.py` | Tier A/B/C response decision matrix. | Tier A: Auto; Tier B: Human Approval; Tier C: High Risk Auto Execute (if Kill Switch OFF). | `tests/test_response_engine.py` |
| **REQ-DEC-002** | `backend/response/policy_engine.py` | Tier Semantics & Policy Candidate Evaluation. | Tier A candidate only when confidence >= 0.75, scope allowed, kill switch OFF, verifier available. | `tests/test_policy_and_safety_gates.py` |
| **REQ-POLICY-001** | `backend/response/policy_engine.py` | Centralized Response Policy Evaluator. | Evaluates 10-signal tuple (`Threat`, `Risk`, `Confidence`, `Tier`, `Action`, `Target`, `Auth`, `Kill Switch`, `Blast Radius`, `Verification`). | `tests/test_policy_and_safety_gates.py` |
| **REQ-RESP-001** | `backend/response/executor.py` | Safe simulated action execution. | Executes `BLOCK_IP`, `SUSPEND_SESSION`, `ISOLATE_ENDPOINT` safely; updates action status. | `tests/test_response_engine.py` |
| **REQ-RESP-002** | `backend/response/safety_gates.py` | 10 Pre-Execution Safety Gates Enforcement. | Checks Auth, Policy, Kill-Switch, Scope, Blast-Radius, Audit, Pre-State, Idempotency, Timeout, Verification before action run. | `tests/test_policy_and_safety_gates.py` |
| **REQ-VERIFY-001** | `backend/response/verifier.py` | Independent Post-Action Verification Check. | Independently inspects simulated state stores (`blocked_ips`, `suspended_users`, `isolated_hosts`); handles verification failure. | `tests/test_response_engine.py` |
| **REQ-ROLLBACK-001** | `backend/response/executor.py` | Action rollback capability. | Reverses simulated action (`UNBLOCK_IP`, `REACTIVATE_SESSION`, `REJOIN_ENDPOINT`); logs rollback record. | `tests/test_rollback.py` |
| **REQ-ROLLBACK-002** | `backend/response/executor.py` | Pre-State Capture & Idempotency Rollback Protection. | Captures pre-action state; prevents rollback without action or double rollback. | `tests/test_lifecycle_and_idempotency.py` |
| **REQ-KILL-001** | `backend/response/kill_switch.py` | Global Emergency Kill Switch. | When Kill Switch is ACTIVE, all Tier C automated actions revert to Human Approval mode. | `tests/test_kill_switch.py` |
| **REQ-AUD-001** | `backend/audit/logger.py` | Tamper-evident Audit Trail. | Logs every pipeline step with timestamp, actor, event ID, action taken. | `tests/test_audit.py` |
| **REQ-AUD-002** | `backend/audit/logger.py` | Comprehensive Policy, Gate & Correlation Audit Trail. | Audits detection, correlation, risk, policy decisions, blocked safety gates, execution, verification, rollback. | `tests/test_phase3_end_to_end.py` |
| **REQ-RBAC-001** | `backend/rbac.py` | Role-Based Access Control. | Enforces `ADMIN` (all), `ANALYST` (view + approve), `AUDITOR` (read-only) permission checks. | `tests/test_rbac.py` |
| **REQ-DASH-001** | `frontend/` + `backend/main.py` | Visual interactive Web Dashboard. | Serves responsive dashboard displaying live feed, incident management, attack simulator, kill switch toggle, and audit viewer. | Integration / UI |
| **REQ-DASH-002** | `frontend/` + `backend/main.py` | Behavioral Telemetry Stream & Evidence Dashboard. | Allows batch stream ingestion, displays Normal vs Abnormal tags, and shows behavioral evidence breakdown. | Integration / UI |
| **REQ-DASH-003** | `frontend/` + `backend/main.py` | Correlated Incident Timeline & "Why" Evidence UI. | Displays multi-event chronological incident timelines and transparent risk explanation bullets. | Integration / UI |
