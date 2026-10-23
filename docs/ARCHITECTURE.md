# System Architecture (ARCHITECTURE.md)

## System: Suraksha AI (Phase 6 Architecture)
### Precision Tuning, Duplicate-Aware Correlation & Evaluation Hardening

Suraksha AI provides an end-to-end autonomous cyber threat detection, incident correlation, explainable risk scoring, safe response simulation, SQLite persistence, and quantitative detection quality evaluation pipeline.

```mermaid
graph TD
    subgraph Ingestion["Ingestion Layer"]
        A1[Batch Telemetry: POST /api/telemetry/ingest]
        A2[Single Event: POST /api/telemetry/event]
        A3[Generic Webhook: POST /api/telemetry/webhook]
        A4[Loopback UDP Syslog: 127.0.0.1:5514]
        A5[Evaluation Dataset: data/evaluation_dataset.json]
        A6[Public Dataset Adapters: CIC-IDS2017 / UNSW-NB15]
    end

    subgraph Processing["Telemetry Normalization & Deduplication"]
        B1[UTC Normalizer & Pydantic Schema Validator]
        B2[Sliding-Window Deduplication Engine: 60s Hash Window]
        B3[Duplicate Suppression Counter & Incident Timeline Correlator]
    end

    subgraph Detection["Behavioral Feature Engine & Hybrid Detection"]
        C[Behavioral Feature Extraction: 8-Dimension BehavioralVector]
        D1[Context-Aware Rules Engine: 6 Categories + Stealth Cumulative Scans]
        D2[Scikit-Learn IsolationForest ML Anomaly Detector]
        E[Composite Risk & Grounded Explainable 'Why' Evidence Engine]
    end

    subgraph Correlation["Incident Correlation & Management"]
        F[Sliding Window Correlation Engine: 10 mins Multi-Stage Merging]
        F2[Duplicate Observation Timeline Association]
        G[Incident Lifecycle State Machine & Duplicate Counter: duplicate_events_count]
    end

    subgraph Response["Response Policy & Safety Gates"]
        H[Response Policy Engine: Tier A / Tier B / Tier C]
        I[10 Pre-Execution Safety Gates Layer: Fail-Closed & Audit-Locked]
        J[Simulated Response Executor: Zero Repeated Remediation on Duplicates]
        K[Independent State Verifier]
        L[Rollback Handler]
    end

    subgraph Evaluation["Evaluation & Benchmarking Engine (Phase 6)"]
        Q1[Evaluation Runner: backend/evaluation/eval_runner.py]
        Q2[Dual-Population Accounting: Raw Stream vs Unique Events]
        Q3[Holdout ML Evaluator: backend/evaluation/ml_evaluator.py]
        Q4[Metrics Calculator: backend/evaluation/metrics.py]
        Q5[Machine-Readable JSON: data/evaluation_report.json]
        Q6[Human-Readable Markdown: data/evaluation_summary.md]
    end

    subgraph Persistence["SQLite Relational Persistence Layer (sqlite3)"]
        M[(Suraksha SQLite DB: data/suraksha.db)]
        M_TEMP[(Isolated Evaluation DB: tempfile)]
    end

    subgraph Presentation["SOC Dashboard & Operator Interface"]
        N[Dark-Mode Glassmorphism SOC Dashboard]
        O[Live Telemetry & Duplicate Stats: GET /api/telemetry/stats]
        P[Evaluation Benchmark Tab: GET /api/evaluation/latest]
    end

    A1 --> B1
    A2 --> B1
    A3 --> B1
    A4 --> B1
    A5 --> Q1
    A6 -.-> Q1
    
    B1 --> B2
    B2 -->|Unique Events| C
    B2 -->|Duplicates Suppressed| B3
    B3 -.->|Timeline Observation & Counter| F2
    F2 -.-> G
    
    C --> D1
    C --> D2
    D1 --> E
    D2 --> E
    E --> F
    F --> G
    G --> H
    H --> I
    I --> J
    J --> K
    J --> L

    Q1 --> Q2
    Q2 --> Q3
    Q2 --> Q4
    Q4 --> Q5
    Q4 --> Q6
    Q1 -.->|Isolated DB Session| M_TEMP
    
    B1 -.->|Telemetry Persistence with is_duplicate| M
    G -.->|Incidents with duplicate_events_count & Timelines| M
    J -.->|Actions & Pre-States| M
    I -.->|Audit Logging| M

    Q5 --> P
    P --> N
    O --> N
```

---

## Component Enhancements in Phase 6

### 1. Context-Aware Lateral Movement Detection
- **Module**: [`backend/detection/rules_engine.py`](file:///c:/Users/NAKSHATRA%20SV/OneDrive/Documents/Cyber-threat-detection/backend/detection/rules_engine.py)
- **Features**:
  - Distinguishes routine low-volume port checks ($< 5.0$ targets) by authorized ops/scanner users on non-critical assets from malicious activity.
  - Critical assets (`CRITICAL` / `HIGH` or identifying hostnames like database/auth gateways) are **never silently exempted**.
  - Cumulative reconnaissance tracker detects stealthy low-volume probes accumulated across sequential events.

### 2. Observable Duplicate Event Management & Idempotency
- **Modules**: [`backend/detection/normalizer.py`](file:///c:/Users/NAKSHATRA%20SV/OneDrive/Documents/Cyber-threat-detection/backend/detection/normalizer.py), [`backend/incidents/correlation.py`](file:///c:/Users/NAKSHATRA%20SV/OneDrive/Documents/Cyber-threat-detection/backend/incidents/correlation.py), [`backend/database.py`](file:///c:/Users/NAKSHATRA%20SV/OneDrive/Documents/Cyber-threat-detection/backend/database.py)
- **Features**:
  - Duplicates are suppressed from triggering detection engines or automated remediation.
  - When an active incident matches the duplicate's entity context, a `DUPLICATE_OBSERVATION` entry is safely appended to the incident timeline.
  - Incidents persist `duplicate_events_count` in SQLite, surviving system restarts.
  - Telemetry statistics API (`GET /api/telemetry/stats`) exposes `total_raw_events`, `total_unique_events`, and `total_duplicates_suppressed`.

### 3. Dual-Population Evaluation Engine
- **Modules**: [`backend/evaluation/eval_runner.py`](file:///c:/Users/NAKSHATRA%20SV/OneDrive/Documents/Cyber-threat-detection/backend/evaluation/eval_runner.py), [`backend/evaluation/metrics.py`](file:///c:/Users/NAKSHATRA%20SV/OneDrive/Documents/Cyber-threat-detection/backend/evaluation/metrics.py)
- **Features**:
  - Population 1 (Unique Normalized Events, $N_{\text{unique}} = 31$): Evaluates Precision (91.3%), Recall (100.0%), and F1 (95.5%) without false-negative penalty for suppressed duplicates.
  - Population 2 (Raw Telemetry Stream, $N_{\text{raw}} = 33$): Tracks raw ingestion, duplicate suppression rate (6.1%), and timeline attachment rate (100.0%).
  - Multi-stage attack scenario grouping achieves 100.0% accuracy across 15 distinct campaigns.

### 4. Decoupled Public Dataset Adapters
- **Module**: [`backend/evaluation/public_dataset_adapter.py`](file:///c:/Users/NAKSHATRA%20SV/OneDrive/Documents/Cyber-threat-detection/backend/evaluation/public_dataset_adapter.py)
- **Features**:
  - Maps external flow records (CIC-IDS2017, UNSW-NB15) into the `NormalizedEvent` schema.
  - Zero fabrication: marks evaluation status as `PENDING_LOCAL_DOWNLOAD` when raw external datasets are not placed in the repository.
