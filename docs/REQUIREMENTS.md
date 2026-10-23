# Requirements Specification (REQUIREMENTS.md)

**System:** Suraksha AI - Real-Time Ingestion, SQLite Persistence & Reliability Hardening  
**Framework:** Spec-Driven Development (SDD)  
**Phase:** 4  

---

## Requirement Matrix & Traceability

| Requirement ID | Module | Description | Acceptance Criteria | Primary Test Case |
|---|---|---|---|---|
| **REQ-INGEST-001** | `backend/detection/normalizer.py` | Ingest raw event telemetry & normalize to `NormalizedEvent` schema. | Parses JSON/Dict/File inputs; converts timestamps to UTC ISO; validates required fields. | `tests/test_normalizer.py` |
| **REQ-INGEST-002** | `backend/detection/normalizer.py` | Event Deduplication & Batch Stream Processing. | Filters duplicate events within sliding window; sorts out-of-order event streams by timestamp. | `tests/test_telemetry_stream.py` |
| **REQ-INGEST-003** | `backend/main.py` | Real-time Single-Event Ingestion API (`POST /api/telemetry/event`). | Reuses 9-stage pipeline; normalizes to UTC ISO; returns 201 with structured outcome; deduplicates idempotently. | `tests/test_single_event_and_webhook.py::test_single_event_ingestion_api` |
| **REQ-INGEST-004** | `backend/main.py` | Generic JSON Security Webhook (`POST /api/telemetry/webhook`). | Ingests arbitrary JSON from external security sensors; optional secret authentication; returns 201; handles malformed JSON with 400. | `tests/test_single_event_and_webhook.py::test_generic_webhook_ingestion_api` |
| **REQ-INGEST-005** | `backend/telemetry/syslog_listener.py` | Optional Loopback UDP Syslog-style Ingestion. | Disabled by default (`SURAKSHA_SYSLOG_ENABLED=0`); loopback (127.0.0.1); safe socket lifecycle; feeds common pipeline. | System integration / docs |
| **REQ-FEAT-001** | `backend/detection/behavioral_engine.py` | Extract rolling behavioral features per user/IP. | Computes 6 rolling metrics: failed logins, login rate, off-hours, unique destinations, privilege changes, data transfer volume. | `tests/test_behavioral_engine.py` |
| **REQ-DET-001** | `backend/detection/rules_engine.py` | Deterministic rule matching for 6 threat categories. | Correctly tags `SUSPICIOUS_LOGIN`, `BRUTE_FORCE`, `PRIVILEGE_ESCALATION`, `LATERAL_MOVEMENT`, `C2_ACTIVITY`, `UNUSUAL_DATA_TRANSFER`. | `tests/test_detection.py::test_rules_engine` |
| **REQ-DET-002** | `backend/detection/ml_detector.py` | ML anomaly detection on network exfiltration and beaconing features. | IsolationForest calculates continuous anomaly score [0.0 - 1.0]. | `tests/test_detection.py::test_ml_detector` |
| **REQ-ML-002** | `backend/detection/ml_detector.py` | Behavioral vector anomaly scoring & evidence generation. | Scores 6D behavioral vector; provides list of behavioral anomaly evidence tags. | `tests/test_behavioral_engine.py` |
| **REQ-RISK-001** | `backend/detection/risk_calculator.py` | Composite Risk (0-100) & Confidence Scoring (0.0-1.0). | Risk = `f(RuleWeight, MLScore, AssetCriticality)`; Confidence = `f(RuleCertainty, MLScore)`. | `tests/test_risk_calculator.py` |
| **REQ-RISK-002** | `backend/detection/risk_calculator.py` | Transparent "Why" Evidence Risk Explanation. | Generates human-readable evidence list (`why_evidence`) explaining risk factors without fabricating data. | `tests/test_phase3_end_to_end.py` |
| **REQ-INC-001** | `backend/incidents/manager.py` | Incident lifecycle & state persistence in SQLite. | Creates unique incident IDs (`INC-XXXX`); attaches behavioral evidence tags and status in SQLite. | `tests/test_sqlite_persistence.py` |
| **REQ-INC-002** | `backend/incidents/correlation.py` | Deterministic Multi-Event Incident Correlation. | Groups related events (same user, IP, asset, close timestamp) into single correlated incidents; persists relationships. | `tests/test_correlation.py` |
| **REQ-INC-003** | `backend/incidents/manager.py` | Incident Timeline & Strict Lifecycle State Machine. | Enforces valid lifecycle transitions (`NEW` -> `UNDER_INVESTIGATION` -> `MITIGATED` -> `RESOLVED` / `FALSE_POSITIVE`) and builds event timeline in SQLite. | `tests/test_lifecycle_and_idempotency.py` |
| **REQ-SAFE-001** | `backend/response/policy_engine.py` | Strict Tier A/B/C Semantics. | Tier A: Auto Alert-Only; Tier B: Auto-executes eligible bounded actions with immediate notification; Tier C: Mandatory Human Approval (NEVER auto-executed). | `tests/test_safety_semantics_phase4.py::test_tier_c_never_auto_executed` |
| **REQ-SAFE-002** | `backend/response/policy_engine.py` | ML Anomaly-Only Remediation Constraint. | IsolationForest anomaly score alone must never authorize remediation actions (capped at Alert-Only / Human Review). | `tests/test_safety_semantics_phase4.py::test_anomaly_score_alone_never_authorizes_remediation` |
| **REQ-SAFE-003** | `backend/response/safety_gates.py` | Core and Critical Asset Action Restrictions. | Whitelisting critical assets prohibits disruptive remediation actions (`BLOCK_IP`, `ISOLATE_ENDPOINT`, `SUSPEND_SESSION`). | `tests/test_safety_semantics_phase4.py::test_critical_asset_disruptive_actions_forbidden` |
| **REQ-SAFE-004** | `backend/response/safety_gates.py` | Mandatory Audit Persistence Pre-Check (Gate 6). | Execution aborts (fail closed) if audit storage is unavailable or unwritable. | `tests/test_safety_semantics_phase4.py::test_gate_6_audit_persistence_failure_blocks_execution` |
| **REQ-SAFE-005** | `backend/response/safety_gates.py` | Idempotency & Duplicate State Protection (Gate 8). | Repeated execution and rollback requests do not produce unsafe repeated state changes. | `tests/test_safety_semantics_phase4.py::test_idempotent_repeated_execution` |
| **REQ-DB-001** | `backend/database.py` | SQLite Schema Initialization & Data Access Layer. | Lightweight DAL with parameterized SQL, transactions, WAL mode, and tables for telemetry, incidents, timelines, responses, and audit logs. | `tests/test_sqlite_persistence.py::test_sqlite_schema_initialization` |
| **REQ-DB-002** | `backend/database.py` | Persistent Domain Entity Storage. | Persists telemetry, incidents, relationships, timelines, evidence, responses, and pre-states in SQLite. | `tests/test_sqlite_persistence.py` |
| **REQ-DB-003** | `backend/database.py` | Application-level Audit Immutability. | Append-only audit logging; filterable queries; documented persistence boundary. | `tests/test_sqlite_persistence.py::test_audit_logs_persistence_and_filtering` |
| **REQ-RECOVERY-001** | `backend/main.py` | System Restart Recovery. | Historical incidents, timelines, responses, simulated enforcements, and audit records recovered from real SQLite file on restart. | `tests/test_restart_and_recovery.py::test_restart_recovery_persisted_entities` |
| **REQ-RECOVERY-002** | `backend/main.py` | Safe Restart Defaults. | Does not repeat pending or previously executed actions on startup; configurable kill-switch startup default. | `tests/test_restart_and_recovery.py::test_restart_does_not_repeat_pending_actions` |
| **REQ-FAIL-001** | `backend/main.py` | Database and Ingestion Failure Handling. | Fails closed on audit write errors; returns controlled JSON errors; prevents stack trace leaks. | `tests/test_restart_and_recovery.py::test_database_write_failure_fails_closed` |
| **REQ-DASH-004** | `frontend/` + `backend/main.py` | Real-Time Persistent Dashboard & Simulation Disclaimer. | Displays live monitoring status, persisted events count, SQLite storage badge, and explicit disclaimer that actions are simulated. | `tests/test_dashboard_and_stats_api.py` |
