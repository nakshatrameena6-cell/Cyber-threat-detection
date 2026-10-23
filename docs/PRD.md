# Product Requirements Document (PRD)
## Suraksha AI - Real-Time Telemetry Ingestion, SQLite Persistence & Reliability Hardening

**Project Name:** Suraksha AI - Autonomous Cyber Threat Detection & Safe Response System  
**Target Audience:** Academic Project / College Demonstration & Security Operations Center (SOC) MVP  
**Version:** 4.0.0 (Phase 4)  
**Status:** Approved  

---

## 1. Objective & Problem Statement
Modern enterprise networks generate continuous streams of security telemetry. In addition to multi-event correlation and automated safety enforcement, real-world SOC operations require reliable data persistence, real-time individual telemetry ingestion, resilient recovery across server restarts, and strict fail-closed safety guarantees.

**Suraksha AI Phase 4** hardens the system with:
1. **SQLite Relational Persistence**: Complete application data persistence covering raw telemetry events, incidents, multi-event relationships, chronological timelines, explainable evidence, simulated response execution records, pre-execution states, and audit trails.
2. **Real-Time Single-Event & Webhook Ingestion**: Endpoints for single security event ingestion (`POST /api/telemetry/event`) and generic JSON security webhook ingestion (`POST /api/telemetry/webhook`) with sliding deduplication, UTC normalization, and token-based header authentication.
3. **Optional Local Syslog Ingestion**: Lightweight UDP loopback listener (`127.0.0.1:5514`), disabled by default, feeding raw RFC3164/5424 formatted messages into the normalization pipeline.
4. **Verified Response Policy & Safety Semantics**:
   - **Tier A**: Fully automated execution permitted only for explicitly allowed, bounded actions (`ALERT_ONLY`).
   - **Tier B**: Eligible low-to-medium impact actions execute automatically with immediate audit notification (`BLOCK_IP`, `SUSPEND_SESSION`).
   - **Tier C**: High-impact or high-criticality actions (`ISOLATE_ENDPOINT` or critical asset impact) strictly mandate human review and approval before execution.
   - **IsolationForest Anomaly ML Cap**: High anomaly scores alone without deterministic rule evidence are capped at Tier C (human approval required).
   - **Critical Asset Defense**: Whitelisting a critical asset restricts destructive or disruptive automated actions against it.
5. **Restart Recovery & Fail-Closed Reliability**: Full restoration of incident history, action records, and audit logs upon application restart. If audit persistence to SQLite fails, simulated response actions fail closed and do not execute.

---

## 2. End-to-End Pipeline Workflow
```text
Raw Telemetry (Batch / Single / Webhook / UDP Syslog)
   ↓
Normalization (UTC timestamps, schema validation, deduplication)
   ↓
Hybrid Detection (Rule Engine + Scikit-Learn IsolationForest ML)
   ↓
Risk & Explainable Evidence ("Why" calculation, asset weighting)
   ↓
Incident Correlation (Multi-event sliding window, merged evidence)
   ↓
Response Policy Engine (Tier A / B / C decision logic)
   ↓
10 Pre-Execution Safety Gates (Auth, Scope, Blast Radius, Kill Switch, Idempotency, Verifier, Audit Check)
   ↓
Pre-State Capture & Fail-Closed Audit Verification
   ↓
Simulated Response Execution (BLOCK_IP / SUSPEND_SESSION / ISOLATE_ENDPOINT)
   ↓
Independent State Verifier
   ↓
SQLite Relational Persistence (Transacted storage of events, incidents, actions, audit)
   ↓
SOC Dashboard & Operator Workflow (Live stats, real-time trigger, rollback, human approval)
```

---

## 3. Core Phase 4 Requirements & Capabilities

### 3.1 SQLite Persistence Layer
- Standard library `sqlite3` relational database layer (`DatabaseManager`).
- Configurable database path via `SURAKSHA_DB_PATH` environment variable (defaults to `data/suraksha.db`).
- Relational schema covering: `telemetry_events`, `incidents`, `incident_events`, `incident_timelines`, `incident_evidence`, `incident_threat_categories`, `response_records`, `response_pre_states`, `simulated_security_state`, and `audit_logs`.
- Parameterized SQL queries preventing SQL injection.
- Explicit transacted operations with safe rollback handling on database write failures.

### 3.2 Real-Time Ingestion
- `POST /api/telemetry/event`: Validated single-event ingestion returning `event_id`, `threat_detected`, `category`, and `risk_score`.
- `POST /api/telemetry/webhook`: Generic external security producer endpoint supporting flexible event formatting, optional header authentication (`X-Suraksha-Token`), and full pipeline reuse.
- Sliding deduplication window preventing duplicated processing and preventing duplicate actions for identical event hashes.

### 3.3 Response Policy & Safety Semantics (Workstream A Verification)
- **Tier A (Automated Bounded Notification)**: Executes alert-only response with immediate audit logging.
- **Tier B (Automated Low-to-Medium Actions)**: Executes low-impact remediation (`BLOCK_IP`, `SUSPEND_SESSION`) with instant notification when all gates pass.
- **Tier C (Mandatory Human Approval)**: Severe actions (`ISOLATE_ENDPOINT`) or actions targeting high-criticality assets cannot auto-execute; must be queued in `PENDING_APPROVAL` status until an analyst approves.
- **ML Anomaly Protection**: High ML anomaly scores alone without deterministic rule evidence cannot authorize automated remediation and fail closed into Tier C human review.
- **10 Pre-Execution Safety Gates**: Gate 1 (Authorization), Gate 2 (Policy), Gate 3 (Emergency Kill Switch), Gate 4 (Target Scope & Critical Asset Protection), Gate 5 (Blast Radius Limit $\le 5$), Gate 6 (Mandatory Audit Persistence Check), Gate 7 (Pre-State Capture), Gate 8 (Idempotency Check), Gate 9 (Execution Timeout), Gate 10 (Verifier Availability).
- **Fail-Closed Audit Rule**: If audit log persistence to SQLite fails at Gate 6 or execution time, response execution is immediately aborted and rolled back.

### 3.4 Restart Recovery & Reliable State
- Upon system startup, `DatabaseManager` loads all prior incident records, chronological event linkages, execution records, and audit logs.
- Pending approvals remain pending; no stale or previously completed actions are auto-re-executed.
- Global kill switch defaults to a safe configurable state (`SURAKSHA_KILL_SWITCH_DEFAULT`).

---

## 4. Non-Goals & Boundaries
- Real operating system or hardware network enforcement (all execution remains strictly simulated).
- Distributed message queues (Kafka, RabbitMQ) or distributed key-value stores (Redis).
- Multi-region or enterprise cloud infrastructure dependencies.
- Cryptographically immutable hardware ledgers (SQLite provides persistent relational application storage, not tamper-proof hardware WORM storage).
