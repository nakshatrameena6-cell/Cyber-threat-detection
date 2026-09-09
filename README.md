# SentinelAI - Autonomous Cyber Threat Detection & Safe Response System

An end-to-end, spec-driven **AI Threat Detection & Response System (MVP)** for college project demonstration.

---

## 🌟 Core Features & Highlights

- **Spec-Driven Development (SDD)**: Full traceability matrix mapping requirements (`REQ-*`) to code and pytest cases.
- **9-Stage Automated Pipeline**: `Input Logs → Normalize → Detect Threat → Calculate Risk → Create Incident → Decide Response → Execute Safe Action → Verify → Audit`.
- **Hybrid Threat Detection**: Combines deterministic rule matching with a Scikit-Learn `IsolationForest` ML Anomaly Detector covering 6 threat categories:
  1. **Brute Force**
  2. **Suspicious Login**
  3. **Privilege Escalation**
  4. **Lateral Movement**
  5. **C2-like Activity**
  6. **Unusual Data Transfer**
- **Composite Risk & Confidence Scoring**: Risk Score (0-100) & Confidence Score (0.0-1.0) factoring in ML anomaly probability and asset criticality multipliers.
- **Tier A/B/C Decision Logic**:
  - **Tier A (Low Risk, <40)**: Alert log notification.
  - **Tier B (Medium Risk, 40-75)**: Requires Analyst Human Approval.
  - **Tier C (High Risk, >75 & Conf >= 0.75)**: Automated execution of safe simulated response.
- **Safe Simulated Actions, Verification & Reversal**:
  - `BLOCK_IP`: Dynamic IP block simulation + post-action firewall verification + 1-click unblock rollback.
  - `SUSPEND_SESSION`: User session invalidation + reactivation rollback.
  - `ISOLATE_ENDPOINT`: Host network isolation + network re-join rollback.
- **Global Emergency Kill Switch**: Instant global halt override for automated responses.
- **Role-Based Access Control (RBAC)**: Enforces `ADMIN`, `ANALYST`, and `AUDITOR` permissions.
- **Interactive Visual Dashboard**: Real-time Cyber Attack Simulator, live pipeline flow animations, incident queue, enforcement monitor, and filterable audit trail.

---

## 📂 Project Structure

```text
Cyber-threat-detection/
├── docs/
│   ├── PRD.md              # Product Requirements Document
│   ├── REQUIREMENTS.md     # SDD Requirement Matrix & Test Traceability
│   ├── ARCHITECTURE.md     # Pipeline block diagrams & formulas
│   └── THREAT_MODEL.md     # STRIDE threat model & IoCs
├── backend/
│   ├── detection/          # Normalizer, Rules Engine, ML Anomaly Model, Risk Calculator
│   ├── incidents/          # Incident lifecycle store
│   ├── response/           # Tier Decision Engine, Safe Executor, Verifier, Kill Switch
│   ├── audit/              # Append-only tamper-evident audit logger
│   ├── models/             # Pydantic schemas (events, incidents, response, audit)
│   ├── rbac.py             # RBAC role permissions module
│   └── main.py             # FastAPI Web API server
├── frontend/
│   ├── index.html          # Visual Dashboard HTML
│   ├── style.css           # Glassmorphism dark-mode UI stylesheet
│   └── app.js              # Live UI controller & attack simulator script
├── data/
│   └── sample_telemetry.json  # Pre-packaged telemetry attack dataset
├── tests/
│   ├── test_normalizer.py
│   ├── test_detection.py
│   ├── test_risk_calculator.py
│   ├── test_response_engine.py
│   ├── test_rollback.py
│   ├── test_kill_switch.py
│   ├── test_audit.py
│   ├── test_rbac.py
│   └── test_end_to_end.py  # Full 9-stage pipeline integration test
└── README.md
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
Ensure Python 3.10+ is installed.

### 2. Run Test Suite
Verify that all SDD requirement test cases pass:
```bash
python -m pytest -v
```

### 3. Launch Dashboard & API Server
Start the FastAPI server:
```bash
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

Open your browser and navigate to:
👉 **`http://localhost:8000`**

---

## 🎓 College Presentation Demo Guide

1. **Demonstrate 9-Stage Pipeline Flow**:
   - Open `http://localhost:8000`.
   - Click **"Brute Force Login"** under the Attack Simulator panel.
   - Observe the glowing top node animation as the event passes through Ingest $\rightarrow$ Normalize $\rightarrow$ Detect $\rightarrow$ Risk $\rightarrow$ Incident $\rightarrow$ Decide $\rightarrow$ Execute $\rightarrow$ Verify $\rightarrow$ Audit.

2. **Demonstrate Automated Response (Tier C)**:
   - Click **"C2 Malware Beacon"** or **"Data Exfiltration"**.
   - Notice the system assigns High Risk ($>75$) and automatically executes `BLOCK_IP` or `ISOLATE_ENDPOINT` with post-action verification passed.

3. **Demonstrate Emergency Kill Switch**:
   - Click **"ENGAGE KILL SWITCH"** in the top navigation banner.
   - Inject a high-risk attack (e.g. **"Data Exfiltration"**).
   - Notice that automated execution is halted and the action is forced into **PENDING_APPROVAL** mode.
   - Disengage the Kill Switch to restore standard operations.

4. **Demonstrate Action Rollback**:
   - Switch to the **"Executed Actions"** tab.
   - Click **"Rollback"** on any executed `BLOCK_IP` or `ISOLATE_ENDPOINT` action.
   - Verify that the target is unblocked/restored and recorded in the audit trail.

---

## 📊 SDD Traceability Matrix

| Requirement | Description | Module | Test File |
|---|---|---|---|
| **REQ-INGEST-001** | Telemetry Ingestion & Normalization | `backend/detection/normalizer.py` | `tests/test_normalizer.py` |
| **REQ-DET-001** | Rules Engine (6 Threat Categories) | `backend/detection/rules_engine.py` | `tests/test_detection.py` |
| **REQ-DET-002** | ML Anomaly Detector (IsolationForest) | `backend/detection/ml_detector.py` | `tests/test_detection.py` |
| **REQ-RISK-001** | Composite Risk & Confidence Score | `backend/detection/risk_calculator.py` | `tests/test_risk_calculator.py` |
| **REQ-INC-001** | Incident Store & Lifecycle | `backend/incidents/manager.py` | `tests/test_end_to_end.py` |
| **REQ-DEC-001** | Tier A/B/C Decision Logic | `backend/response/decision_engine.py` | `tests/test_response_engine.py` |
| **REQ-RESP-001** | Safe Response Execution | `backend/response/executor.py` | `tests/test_response_engine.py` |
| **REQ-VERIFY-001** | Post-Action Verification | `backend/response/verifier.py` | `tests/test_response_engine.py` |
| **REQ-ROLLBACK-001**| Reversible Action Rollback | `backend/response/executor.py` | `tests/test_rollback.py` |
| **REQ-KILL-001** | Emergency Kill Switch | `backend/response/kill_switch.py` | `tests/test_kill_switch.py` |
| **REQ-AUD-001** | Tamper-Evident Audit Logger | `backend/audit/logger.py` | `tests/test_audit.py` |
| **REQ-RBAC-001** | Role-Based Access Control | `backend/rbac.py` | `tests/test_rbac.py` |
| **REQ-DASH-001** | Visual Web Dashboard | `frontend/` + `backend/main.py` | Integration / UI |
