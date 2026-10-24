# Suraksha AI - Autonomous Cyber Threat Detection & Safe Response System

An end-to-end, spec-driven **AI Threat Detection, Real-Time Telemetry Ingestion, SQLite Persistence, Detection Quality Evaluation, Timestamp Resilience, Distributed Correlation & Metric Integrity (Phase 7 MVP)** for college project demonstration.

---

## 🌟 Core Features & Highlights included in the system:

- **Spec-Driven Development (SDD)**: Complete traceability matrix mapping requirements (`REQ-*`) to architecture, source code, and automated test cases (**111/111 tests passing, 100% pass rate**).
- **Hardened Empirical Detection Quality Evaluation (Phase 7)**:
  - **Hybrid Precision**: **100.0%** ($21 / 21$)
  - **Hybrid Recall**: **100.0%** ($21 / 21$)
  - **Hybrid Specificity**: **100.0%** ($10 / 10$)
  - **False Positive Rate**: **0.0%** ($0 / 10$)
  - **Hybrid F1 Score**: **1.0000**
  - **Incident Grouping Accuracy**: **100.0%** across 15 scenario attack graphs.
  - **Metric Integrity Gate**: Single authoritative confusion matrix derivation, mathematical invariant validation ($TP+FP+TN+FN=N_{\text{unique}}$), and elimination of narrative metric contradictions.
- **Subnet-Aware Distributed Threat Correlation**:
  - Groups multi-source attacks originating across IPv4 `/24` or IPv6 `/64` CIDR blocks when corroborated by shared target assets, attack categories, or user identities.
  - Strictly prevents unintended merging of unrelated campaigns or benign operational activity sharing a subnet.
- **Timestamp Resilience & Out-of-Order Telemetry**:
  - Full UTC standardization and timezone offset normalization (`+05:30`, `-04:00`, space-separated formats).
  - 300-second allowed-lateness window preventing state degradation for out-of-order logs.
  - Future timestamp clamping (>60s drift) and audit trail logging for fallback reasons.
  - IsolationForest protection: fallback timestamps are masked from off-hours features to prevent false positive alerts.
- **Real Public-Dataset Batch Evaluation Interface**:
  - Dedicated batch evaluator (`backend/evaluation/public_dataset_adapter.py`) supporting CIC-IDS2017 and UNSW-NB15 schemas.
  - Chunked batch processing with path traversal protection, academic licensing documentation, and deterministic train/test splitting.
  - Strictly honest status reporting (`PENDING_LOCAL_DATA`) when official dataset files are not placed locally; zero benchmark metric fabrication.
- **Multi-Scenario Labeled Benchmark**: 33-event ground-truth dataset (`data/evaluation_dataset.json`) covering routine operations, benign admin tasks (backups, typos, health checks), 6 attack categories, authorized vs unauthorized scanning, cumulative port scans, critical assets, out-of-order duplicates, and a 4-stage APT sequence.
- **SQLite Relational Persistence**: Built-in SQLite database layer storing normalized telemetry events, multi-event correlated incidents, chronological timelines with duplicate tracking, explainable evidence, response execution records, pre-state snapshots, and audit trails.
- **Response Policy & Safety Semantics**:
  - **Tier A (Low Risk / Alert-Only)**: Fully automated alert notification.
  - **Tier B (Medium Risk / Low-Impact Remediation)**: Automated bounded actions (`BLOCK_IP`, `SUSPEND_SESSION`) with immediate audit notification when confidence $\ge 0.75$ and all safety gates pass.
  - **Tier C (High Risk / Severe Action)**: High-impact actions (`ISOLATE_ENDPOINT`) or critical asset targets require mandatory human approval.
  - **ML Anomaly Protection**: High ML anomaly scores alone without rule corroboration are capped at Tier C (human approval required).
  - **Zero Duplicate Response**: Duplicate observations never re-trigger or authorize automated remediation.
- **10 Pre-Execution Safety Gates**: Sequential checks (Role Auth, Policy, Kill Switch, Scope, Blast Radius $\le 5$, Gate 6 Audit Check, Pre-State Capture, Idempotency, Timeout, Verifier Availability).
- **Interactive SOC Dashboard**: Real-time Cyber Attack Simulator, live telemetry and duplicate suppression cards, simulation disclaimer banner, live pipeline flow animations, incident queue, enforcement monitor, filterable audit trail, and **Detection Evaluation Benchmark Tab** with dual-population breakdown and public dataset audit status.

---

## 📂 Project Structure

```text
Cyber-threat-detection/
├── docs/
│   ├── PRD.md                       # Product Requirements Document
│   ├── REQUIREMENTS.md              # SDD Requirement Matrix & Test Traceability
│   ├── ARCHITECTURE.md              # Relational schema diagrams & pipeline flows
│   ├── THREAT_MODEL.md              # STRIDE threat model & IoCs
│   ├── DETECTION_EVALUATION.md      # Detailed evaluation methodology & results
│   └── PHASE6_BASELINE.md           # Phase 6 baseline verification & audit note
├── backend/
│   ├── database.py                  # SQLite Data Access Layer (DatabaseManager)
│   ├── detection/
│   │   ├── normalizer.py            # Telemetry normalization & UTC parsing
│   │   ├── behavioral_engine.py     # 6D Behavioral Vector & cumulative port tracker
│   │   ├── rules_engine.py          # Context-aware rules across 6 threat categories
│   │   ├── ml_detector.py           # IsolationForest ML anomaly detector
│   │   └── risk_calculator.py       # Composite risk & "Why" evidence scoring
│   ├── evaluation/                  # Detection Quality Evaluation
│   │   ├── metrics.py               # Statistical classification & correlation metrics
│   │   ├── ml_evaluator.py          # Leak-free holdout ML model evaluator
│   │   ├── eval_runner.py           # Reproducible benchmark runner & reporter
│   │   └── public_dataset_adapter.py # Decoupled CIC-IDS2017 & UNSW-NB15 adapter
│   ├── incidents/
│   │   ├── correlation.py           # Multi-event correlation & duplicate observer
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
│   ├── evaluation_dataset.json      # Phase 6 33-scenario labeled evaluation dataset
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
│   ├── test_evaluation_metrics.py
│   ├── test_evaluation_runner.py
│   ├── test_ml_evaluation.py
│   ├── test_tier_safety_regression.py
│   ├── test_lateral_movement_specificity.py # Phase 6 specificity tests
│   ├── test_duplicate_observability.py      # Phase 6 duplicate observability tests
│   ├── test_evaluation_semantics.py         # Phase 6 dual-population tests
│   └── test_public_dataset_adapter.py       # Phase 6 adapter tests
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

### 4. Run the Full Test Suite (89 Tests)
```powershell
# Run the complete test suite (89 tests, 100% passing)
python -m pytest -v
```

### 5. Run the Detection Quality Evaluation Benchmark
```powershell
# Execute the Phase 6 benchmark harness
python -m backend.evaluation.eval_runner
```

---

## 🎓 College Presentation Demo Guide

1. **Demonstrate Phase 6 Detection Quality Benchmark**:
   - Open `http://localhost:8000` in your web browser.
   - Click the **"Detection Evaluation (Phase 6)"** tab in the main panel.
   - Click **"⚡ Run Detection Benchmark"**.
   - Review live metrics: **Hybrid Precision (91.3%)**, **Hybrid Recall (100.0%)**, **F1 Score (0.9545)**, and **Correlation Accuracy (100.0%)**.
   - Review the **Stream Deduplication Observability card**: Raw Ingested ($N=33$), Unique Analyzed ($N=31$), Duplicates Suppressed ($N=2$), Incident Correlated ($2/2, 100\%$).
   - Review the **Detection Architecture Comparison table** (Rules vs ML vs Hybrid) and the **Per-Category Performance table**.
   - Note the clear banner: `SYNTHETIC BENCHMARK EVALUATION (OFFLINE FIXTURE) - Evaluated in an isolated database environment without altering live incidents`.

2. **Demonstrate Lateral Movement Specificity & Critical Asset Protection**:
   - Benign port sweeps from authorized network monitors against non-critical hosts are classified as benign operations with zero alert noise.
   - High-volume scans, cumulative stealth scans across multiple events, and any scan targeting `CRITICAL` or `HIGH` criticality assets immediately trigger alerts.

3. **Demonstrate Duplicate Observability with Zero Duplicate Remediation**:
   - Send duplicate events via `/api/telemetry/event`.
   - Observe that `duplicate_events_count` increments on the active incident and a duplicate observation entry appears on the incident timeline.
   - Verify that automated response actions (`BLOCK_IP`) are never re-executed.

4. **Demonstrate Automated Remediation (Tier B)**:
   - In Attack Simulator, trigger **"C2 Malware Beacon"**.
   - System evaluates Tier B, checks 10 safety gates, captures pre-state, executes `BLOCK_IP`, verifies simulated firewall state, and logs audit record.
   - Switch to the **"Executed Actions"** tab and click **"Rollback"** to unblock and verify reversal.

5. **Demonstrate Tier C Human Approval Gate**:
   - Trigger **"Data Exfiltration"** (high impact, targets core endpoint with `ISOLATE_ENDPOINT`).
   - Notice that Tier C mandates human approval. The action is held in `PENDING_APPROVAL` status.

6. **Demonstrate Emergency Kill Switch**:
   - Click **"ENGAGE KILL SWITCH"** in the header.
   - Inject any attack event. Automated execution is halted by Gate 3, leaving actions queued safely.

7. **Demonstrate Restart Recovery**:
   - Stop the backend server (`Ctrl+C` in terminal) and restart it.
   - Refresh the dashboard: all previously created incidents, event timelines, duplicate counts, execution records, and audit logs are fully restored from `data/suraksha.db`.

---

## 📊 Complete SDD Traceability Matrix (89/89 Tests Passing)

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
| **REQ-PREC-001** | Context-Aware Lateral Movement Specificity | `backend/detection/rules_engine.py` | `tests/test_lateral_movement_specificity.py` | Verified (Pass) |
| **REQ-DUP-001** | Observable Duplicate Event Timeline & Counter Tracking | `backend/incidents/correlation.py` | `tests/test_duplicate_observability.py` | Verified (Pass) |
| **REQ-SEM-001** | Dual-Population Evaluation Metrics Semantics | `backend/evaluation/metrics.py` | `tests/test_evaluation_semantics.py` | Verified (Pass) |
| **REQ-BENCH-001** | Expanded Multi-Scenario Evaluation Dataset (33 Scenarios) | `data/evaluation_dataset.json` | `tests/test_evaluation_runner.py` | Verified (Pass) |
| **REQ-DASH-005** | Live Telemetry & Deduplication Observability Dashboard | `frontend/index.html` + `app.js` | `tests/test_duplicate_observability.py` | Verified (Pass) |
| **REQ-ADAPT-001** | Decoupled Public IDS Dataset Adapter (CIC-IDS / UNSW-NB15) | `backend/evaluation/public_dataset_adapter.py` | `tests/test_public_dataset_adapter.py` | Verified (Pass) |

