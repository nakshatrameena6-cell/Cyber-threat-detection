# Suraksha AI - Autonomous Cyber Threat Detection & Safe Response System

An end-to-end, spec-driven **AI Threat Detection, Real-Time Telemetry Ingestion, SQLite Persistence & Detection Quality Evaluation System (Phase 5 MVP)** for college project demonstration.

---

## 🌟 Core Features & Highlights

- **Spec-Driven Development (SDD)**: Complete traceability matrix mapping requirements (`REQ-*`) to architecture, source code, and automated test cases (**70/70 tests passing, 100% pass rate**).
- **Empirical Detection Quality Evaluation (Phase 5)**:
  - **Hybrid Precision**: **93.3%**
  - **Hybrid Recall**: **93.3%**
  - **Hybrid F1 Score**: **0.9333**
  - **Correlation Grouping Accuracy**: **100.0%**
  - **False Positive Rate**: **11.1%** (Root cause: routine administrative port sweep triggering rule match)
- **Multi-Scenario Labeled Benchmark**: 24-event ground-truth dataset (`data/evaluation_dataset.json`) covering routine operations, benign admin tasks (backups, typos, health checks), 6 attack categories, a 4-stage APT sequence, and edge cases.
- **Leak-Free ML Evaluation**: Independent holdout dataset (seed 101, 200 samples) ensuring zero data leakage with baseline training (seed 42).
- **SQLite Relational Persistence**: Built-in SQLite database layer storing normalized telemetry events, multi-event correlated incidents, chronological timelines, explainable evidence, response execution records, pre-state snapshots, and audit trails.
- **Real-Time Single-Event & Webhook Ingestion**:
  - `POST /api/telemetry/event`: Low-latency single-event ingestion with sliding deduplication.
  - `POST /api/telemetry/webhook`: Generic external security webhook with optional token authentication.
  - Optional UDP loopback Syslog listener (`127.0.0.1:5514`), disabled by default.
- **Restart Recovery & State Resiliency**: Survives crashes and restarts, recovering historical incidents, timelines, pre-states, and audit history from SQLite.
- **Response Policy & Safety Semantics**:
  - **Tier A (Low Risk / Alert-Only)**: Fully automated alert notification.
  - **Tier B (Medium Risk / Low-Impact Remediation)**: Automated bounded actions (`BLOCK_IP`, `SUSPEND_SESSION`) with immediate audit notification when confidence $\ge 0.75$ and all safety gates pass.
  - **Tier C (High Risk / Severe Action)**: High-impact actions (`ISOLATE_ENDPOINT`) or critical asset targets require mandatory human approval.
  - **ML Anomaly Protection**: High ML anomaly scores alone without rule corroboration are capped at Tier C (human approval required).
- **10 Pre-Execution Safety Gates**: Sequential checks (Role Auth, Policy, Kill Switch, Scope, Blast Radius $\le 5$, Gate 6 Audit Check, Pre-State Capture, Idempotency, Timeout, Verifier Availability).
- **Fail-Closed Audit Requirement**: If database audit persistence fails, simulated response actions immediately fail closed and abort execution.
- **Safe Simulated Actions, Verification & Reversal**:
  - `BLOCK_IP`: Dynamic IP block simulation + post-action verification + 1-click unblock rollback.
  - `SUSPEND_SESSION`: User session invalidation + reactivation rollback.
  - `ISOLATE_ENDPOINT`: Host network isolation simulation + network re-join rollback.
- **Global Emergency Kill Switch**: Instant global halt override for automated responses.
- **Role-Based Access Control (RBAC)**: Enforces `ADMIN`, `ANALYST`, and `AUDITOR` permissions.
- **Interactive SOC Dashboard**: Real-time Cyber Attack Simulator, live SQLite persistence telemetry card, simulation disclaimer banner, live pipeline flow animations, incident queue, enforcement monitor, filterable audit trail, and **Detection Evaluation Benchmark Tab**.

---

## 📂 Project Structure

```text
Cyber-threat-detection/
├── docs/
│   ├── PRD.md                       # Product Requirements Document (Phase 5)
│   ├── REQUIREMENTS.md              # SDD Requirement Matrix & Test Traceability
│   ├── ARCHITECTURE.md              # Relational schema diagrams & pipeline flows
│   ├── THREAT_MODEL.md              # STRIDE threat model & IoCs
│   └── DETECTION_EVALUATION.md      # Detailed evaluation methodology & results
├── backend/
│   ├── database.py                  # SQLite Data Access Layer (DatabaseManager)
│   ├── detection/
│   │   ├── normalizer.py            # Telemetry normalization & UTC parsing
│   │   ├── rules_engine.py          # Deterministic rules across 6 threat categories
│   │   ├── ml_detector.py           # IsolationForest ML anomaly detector
│   │   └── risk_calculator.py       # Composite risk & "Why" evidence scoring
│   ├── evaluation/                  # Phase 5 Detection Quality Evaluation
│   │   ├── metrics.py               # Statistical classification & correlation metrics
│   │   ├── ml_evaluator.py          # Leak-free holdout ML model evaluator
│   │   └── eval_runner.py           # Reproducible benchmark runner & reporter
│   ├── incidents/
│   │   ├── correlation.py           # Multi-event 10-minute sliding window correlation
│   │   └── manager.py               # Incident lifecycle store & SQLite sync
│   ├── response/
│   │   ├── policy_engine.py         # Response tier classification (Tier A/B/C)
│   │   ├── decision_engine.py       # Safety decision evaluator
│   │   ├── safety_gates.py          # 10 pre-execution safety gates
│   │   ├── executor.py              # Simulated response execution & rollback
│   │   ├── verifier.py              # Independent post-action state verifier
│   │   └── kill_switch.py           # Global emergency kill switch
│   ├── audit/
│   │   └── logger.py                # Fail-closed SQLite audit logger
│   ├── telemetry/
│   │   └── syslog_listener.py       # Optional loopback UDP syslog listener
│   ├── models/                      # Pydantic domain models & schemas
│   ├── rbac.py                      # RBAC role permissions module
│   └── main.py                      # FastAPI application & REST API routes
├── frontend/
│   ├── index.html                   # SOC Dashboard UI with Evaluation Tab
│   ├── style.css                    # Glassmorphism dark-mode stylesheet
│   └── app.js                       # UI controller, live stats, & attack simulator
├── data/
│   ├── suraksha.db                  # Local SQLite database (auto-created)
│   ├── sample_telemetry.json        # Pre-packaged attack telemetry dataset
│   ├── evaluation_dataset.json      # Phase 5 24-scenario labeled evaluation dataset
│   ├── evaluation_report.json       # Machine-readable evaluation report
│   └── evaluation_summary.md        # Human-readable Markdown summary
├── tests/
│   ├── conftest.py                  # Isolated temporary SQLite database fixture
│   ├── test_normalizer.py
│   ├── test_detection.py
│   ├── test_risk_calculator.py
│   ├── test_response_engine.py
│   ├── test_rollback.py
│   ├── test_kill_switch.py
│   ├── test_audit.py
│   ├── test_rbac.py
│   ├── test_end_to_end.py
│   ├── test_safety_semantics_phase4.py
│   ├── test_sqlite_persistence.py
│   ├── test_single_event_and_webhook.py
│   ├── test_restart_and_recovery.py
│   ├── test_dashboard_and_stats_api.py
│   ├── test_evaluation_metrics.py   # Phase 5 metrics tests
│   ├── test_evaluation_runner.py    # Phase 5 runner tests
│   ├── test_ml_evaluation.py        # Phase 5 ML holdout tests
│   └── test_tier_safety_regression.py # Phase 5 tier safety regression tests
└── README.md
```

---

## ⚙️ Environment Configuration

| Variable | Default Value | Description |
|---|---|---|
| `SURAKSHA_DB_PATH` | `data/suraksha.db` | File path for persistent SQLite database. |
| `SURAKSHA_WEBHOOK_SECRET` | *(empty / none)* | Optional token secret required in `X-Suraksha-Token` header. |
| `SURAKSHA_SYSLOG_ENABLED` | `false` | Enable/disable optional UDP loopback syslog listener on `127.0.0.1:5514`. |
| `SURAKSHA_KILL_SWITCH_DEFAULT` | `false` | Default kill switch state upon startup (`true` = automated actions halted). |

---

## 🚀 Getting Started

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.14)
- `pip` package manager

### 2. Installation
```powershell
# Clone repository and navigate to root directory
cd Cyber-threat-detection

# Install required dependencies
pip install fastapi uvicorn scikit-learn pydantic pytest httpx
```

### 3. Run the Backend Server
```powershell
# Start the FastAPI application on http://localhost:8000
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

### 4. Run the Full Test Suite (70 Tests)
```powershell
# Run the complete test suite (70 tests, 100% passing)
python -m pytest -v
```

### 5. Run the Detection Quality Evaluation Benchmark
```powershell
# Execute the Phase 5 benchmark harness
python -m backend.evaluation.eval_runner
```

---

## 🎓 College Presentation Demo Guide

1. **Demonstrate Phase 5 Detection Quality Benchmark**:
   - Open `http://localhost:8000` in your web browser.
   - Click the **"Detection Evaluation (Phase 5)"** tab in the main panel.
   - Click **"⚡ Run Detection Benchmark"**.
   - Review live metrics: **Hybrid Precision (93.3%)**, **Hybrid Recall (93.3%)**, **F1 Score (0.9333)**, and **Correlation Accuracy (100.0%)**.
   - Review the **Detection Architecture Comparison table** (Rules vs ML vs Hybrid) and the **Per-Category Performance table**.
   - Note the clear banner: `SYNTHETIC BENCHMARK EVALUATION (OFFLINE FIXTURE) - Evaluated in an isolated database environment without altering live incidents`.

2. **Demonstrate Real-Time Telemetry & SQLite Persistence**:
   - Note the top status strip: `DB: data/suraksha.db (ACTIVE)`.
   - Click **"Simulate Real-Time Telemetry"** or **"Send Webhook Event"** in the top-right controls.
   - Observe the live counter increment immediately as the event is persisted into SQLite.

3. **Demonstrate 9-Stage Pipeline Flow & Multi-Event Correlation**:
   - In the Attack Simulator panel, click **"Brute Force Login"** 4 times.
   - Observe that the Correlation Engine groups related events into a single incident with an expanding event timeline.

4. **Demonstrate Automated Remediation (Tier B)**:
   - Click **"C2 Malware Beacon"**.
   - System evaluates Tier B, checks 10 safety gates, captures pre-state, executes `BLOCK_IP`, verifies simulated firewall state, and logs audit record.
   - Switch to the **"Executed Actions"** tab and click **"Rollback"** to unblock and verify reversal.

5. **Demonstrate Tier C Human Approval Gate**:
   - Click **"Data Exfiltration"** (high impact, targets core endpoint with `ISOLATE_ENDPOINT`).
   - Notice that Tier C mandates human approval. The action is held in `PENDING_APPROVAL` status.

6. **Demonstrate Emergency Kill Switch**:
   - Click **"ENGAGE KILL SWITCH"** in the header.
   - Inject any attack event.
   - Automated execution is halted by Gate 3, leaving actions queued safely.

7. **Demonstrate Restart Recovery**:
   - Stop the backend server (`Ctrl+C` in terminal) and restart it.
   - Refresh the dashboard: all previously created incidents, event timelines, execution records, and audit logs are fully restored from `data/suraksha.db`.

---

## 📊 Complete SDD Traceability Matrix (70/70 Tests Passing)

| Requirement | Description | Implementation File | Primary Test File | Status |
|---|---|---|---|---|
| **REQ-INGEST-001** | Batch Telemetry Normalization & UTC parsing | `backend/detection/normalizer.py` | `tests/test_normalizer.py` | Verified (Pass) |
| **REQ-INGEST-002** | Behavioral Feature Extraction | `backend/detection/normalizer.py` | `tests/test_normalizer.py` | Verified (Pass) |
| **REQ-INGEST-003** | Single-Event Telemetry Ingestion API | `backend/main.py` | `tests/test_single_event_and_webhook.py` | Verified (Pass) |
| **REQ-INGEST-004** | Generic JSON Security Webhook API | `backend/main.py` | `tests/test_single_event_and_webhook.py` | Verified (Pass) |
| **REQ-INGEST-005** | Optional Local UDP Syslog Listener | `backend/telemetry/syslog_listener.py` | `tests/test_single_event_and_webhook.py` | Verified (Pass) |
| **REQ-DET-001** | Rules Engine (6 Threat Categories) | `backend/detection/rules_engine.py` | `tests/test_detection.py` | Verified (Pass) |
| **REQ-DET-002** | IsolationForest ML Anomaly Detection | `backend/detection/ml_detector.py` | `tests/test_detection.py` | Verified (Pass) |
| **REQ-RISK-001** | Composite Risk & Confidence Scoring | `backend/detection/risk_calculator.py` | `tests/test_risk_calculator.py` | Verified (Pass) |
| **REQ-RISK-002** | Explainable "Why" Evidence Array | `backend/detection/risk_calculator.py` | `tests/test_risk_calculator.py` | Verified (Pass) |
| **REQ-INC-001** | Multi-Event 10-Minute Incident Correlation | `backend/incidents/correlation.py` | `tests/test_end_to_end.py` | Verified (Pass) |
| **REQ-INC-002** | Incident Lifecycle State Machine | `backend/incidents/manager.py` | `tests/test_end_to_end.py` | Verified (Pass) |
| **REQ-POLICY-001** | Tier A/B/C Response Policy Semantics | `backend/response/policy_engine.py` | `tests/test_tier_safety_regression.py` | Verified (Pass) |
| **REQ-POLICY-002** | ML Anomaly-Only Tier C Capping | `backend/response/decision_engine.py` | `tests/test_ml_evaluation.py` | Verified (Pass) |
| **REQ-SAFE-001** | 10 Pre-Execution Safety Gates Layer | `backend/response/safety_gates.py` | `tests/test_policy_and_safety_gates.py` | Verified (Pass) |
| **REQ-SAFE-002** | Critical Asset Action Restrictions | `backend/response/safety_gates.py` | `tests/test_policy_and_safety_gates.py` | Verified (Pass) |
| **REQ-SAFE-003** | Blast Radius Enforcement ($\le 5$) | `backend/response/safety_gates.py` | `tests/test_policy_and_safety_gates.py` | Verified (Pass) |
| **REQ-SAFE-004** | Execution Idempotency & Repeat Blocking | `backend/response/safety_gates.py` | `tests/test_safety_semantics_phase4.py` | Verified (Pass) |
| **REQ-SAFE-005** | Mandatory Fail-Closed Audit Verification | `backend/response/safety_gates.py` | `tests/test_safety_semantics_phase4.py` | Verified (Pass) |
| **REQ-EXEC-001** | Safe Simulated Remediation Actions | `backend/response/executor.py` | `tests/test_response_engine.py` | Verified (Pass) |
| **REQ-EXEC-002** | Independent State Verification | `backend/response/verifier.py` | `tests/test_response_engine.py` | Verified (Pass) |
| **REQ-EXEC-003** | Rollback & State Reversal | `backend/response/executor.py` | `tests/test_rollback.py` | Verified (Pass) |
| **REQ-KILL-001** | Global Emergency Kill Switch | `backend/response/kill_switch.py` | `tests/test_kill_switch.py` | Verified (Pass) |
| **REQ-RBAC-001** | Role-Based Access Control (`ADMIN`/`ANALYST`/`AUDITOR`) | `backend/rbac.py` | `tests/test_rbac.py` | Verified (Pass) |
| **REQ-AUDIT-001** | Append-Only Fail-Closed Audit Trail | `backend/audit/logger.py` | `tests/test_audit.py` | Verified (Pass) |
| **REQ-DB-001** | SQLite Relational Schema & Indices | `backend/database.py` | `tests/test_sqlite_persistence.py` | Verified (Pass) |
| **REQ-DB-002** | Telemetry, Incident & Action Persistence | `backend/database.py` | `tests/test_sqlite_persistence.py` | Verified (Pass) |
| **REQ-RECOVERY-001** | Crash & Restart Historical State Recovery | `backend/database.py` | `tests/test_restart_and_recovery.py` | Verified (Pass) |
| **REQ-RECOVERY-002** | Safe Restart Defaults (No Auto-Reexecution) | `backend/response/executor.py` | `tests/test_restart_and_recovery.py` | Verified (Pass) |
| **REQ-FAIL-001** | Fail-Closed Safety on Database Failure | `backend/audit/logger.py` | `tests/test_restart_and_recovery.py` | Verified (Pass) |
| **REQ-DASH-004** | Live Persistence Stats & Simulator Display | `frontend/app.js` | `tests/test_dashboard_and_stats_api.py` | Verified (Pass) |
| **REQ-EVAL-001** | Labeled Ground-Truth Evaluation Dataset | `data/evaluation_dataset.json` | `tests/test_evaluation_runner.py` | Verified (Pass) |
| **REQ-EVAL-002** | Event-Level Quantitative Detection Metrics | `backend/evaluation/metrics.py` | `tests/test_evaluation_metrics.py` | Verified (Pass) |
| **REQ-EVAL-003** | Per-Category Detection Evaluation | `backend/evaluation/metrics.py` | `tests/test_evaluation_metrics.py` | Verified (Pass) |
| **REQ-EVAL-004** | Rules vs ML vs Hybrid Holdout Comparison | `backend/evaluation/ml_evaluator.py` | `tests/test_ml_evaluation.py` | Verified (Pass) |
| **REQ-EVAL-005** | Incident Correlation Quality Evaluation | `backend/evaluation/metrics.py` | `tests/test_evaluation_runner.py` | Verified (Pass) |
| **REQ-EVAL-006** | Risk Score Bounds & Explainable Evidence | `backend/detection/risk_calculator.py` | `tests/test_evaluation_runner.py` | Verified (Pass) |
| **REQ-EVAL-007** | Reproducible Evaluation Runner & Reports | `backend/evaluation/eval_runner.py` | `tests/test_evaluation_runner.py` | Verified (Pass) |
| **REQ-EVAL-008** | SOC Dashboard Benchmark Integration | `frontend/` + `backend/main.py` | `tests/test_tier_safety_regression.py` | Verified (Pass) |
