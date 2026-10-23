# System Architecture (ARCHITECTURE.md)

## System: Suraksha AI (Phase 5 Architecture)

Suraksha AI provides an end-to-end autonomous cyber threat detection, incident correlation, explainable risk scoring, safe response simulation, SQLite persistence, and quantitative detection quality evaluation pipeline.

```mermaid
graph TD
    subgraph Ingestion["Ingestion Layer"]
        A1[Batch Telemetry: POST /api/telemetry/ingest]
        A2[Single Event: POST /api/telemetry/event]
        A3[Generic Webhook: POST /api/telemetry/webhook]
        A4[Loopback UDP Syslog: 127.0.0.1:5514]
        A5[Evaluation Dataset Replay: data/evaluation_dataset.json]
    end

    subgraph Processing["Telemetry Normalization & Hybrid Detection"]
        B[Deduplication & UTC Normalizer]
        C[Behavioral Feature Extraction]
        D1[Deterministic Rule Engine: 6 Categories]
        D2[Scikit-Learn IsolationForest ML Detector]
        E[Composite Risk & Explainable 'Why' Evidence Engine]
    end

    subgraph Correlation["Incident Correlation & Management"]
        F[Sliding Window Correlation Engine: 10 mins]
        G[Incident Lifecycle State Machine]
    end

    subgraph Response["Response Policy & Safety Gates"]
        H[Response Policy Engine: Tier A / Tier B / Tier C]
        I[10 Pre-Execution Safety Gates Layer]
        J[Simulated Response Executor]
        K[Independent State Verifier]
        L[Rollback Handler]
    end

    subgraph Evaluation["Evaluation & Benchmarking Engine (Phase 5)"]
        Q1[Evaluation Runner: backend/evaluation/eval_runner.py]
        Q2[Holdout ML Evaluator: backend/evaluation/ml_evaluator.py]
        Q3[Metrics Calculator: backend/evaluation/metrics.py]
        Q4[Machine-Readable JSON: data/evaluation_report.json]
        Q5[Human-Readable Markdown: data/evaluation_summary.md]
    end

    subgraph Persistence["SQLite Relational Persistence Layer (sqlite3)"]
        M[(Suraksha SQLite DB: data/suraksha.db)]
        M_TEMP[(Isolated Evaluation DB: tempfile)]
    end

    subgraph Presentation["SOC Dashboard & Operator Interface"]
        N[Dark-Mode Glassmorphism Dashboard]
        O[Live Monitoring & Stats: GET /api/telemetry/stats]
        P[Evaluation Benchmark Tab: GET /api/evaluation/latest]
    end

    A1 --> B
    A2 --> B
    A3 --> B
    A4 --> B
    A5 --> Q1
    
    Q1 --> B
    B --> C
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
    Q1 --> Q3
    Q3 --> Q4
    Q3 --> Q5
    Q1 -.->|Isolated DB Session| M_TEMP
    
    B -.->|Normal Telemetry Persistence| M
    G -.->|Incidents & Timelines| M
    J -.->|Actions & Pre-States| M
    I -.->|Audit Logging| M

    Q4 --> P
    P --> N
    O --> N
```

---

## Evaluation Engine Architecture (Phase 5)

Implemented in [`backend/evaluation/`](file:///c:/Users/NAKSHATRA%20SV/OneDrive/Documents/Cyber-threat-detection/backend/evaluation/), the Evaluation Engine provides reproducible, isolated statistical benchmarking:

1. **Evaluation Runner ([`backend/evaluation/eval_runner.py`](file:///c:/Users/NAKSHATRA%20SV/OneDrive/Documents/Cyber-threat-detection/backend/evaluation/eval_runner.py))**:
   - Creates a dedicated temporary SQLite database (`tempfile.NamedTemporaryFile`) to guarantee zero contamination of `data/suraksha.db`.
   - Iterates through the 24 labeled evaluation events in [`data/evaluation_dataset.json`](file:///c:/Users/NAKSHATRA%20SV/OneDrive/Documents/Cyber-threat-detection/data/evaluation_dataset.json).
   - Collects predictions from:
     - Deterministic Rules alone
     - Scikit-Learn IsolationForest alone
     - Hybrid Pipeline (Suraksha AI)
2. **Metrics Calculator ([`backend/evaluation/metrics.py`](file:///c:/Users/NAKSHATRA%20SV/OneDrive/Documents/Cyber-threat-detection/backend/evaluation/metrics.py))**:
   - Computes binary confusion matrices (TP, FP, TN, FN).
   - Evaluates Precision, Recall, F1 Score, False Positive Rate (FPR), and Accuracy.
   - Enforces explicit zero-denominator handling policy.
   - Computes One-vs-Rest classification metrics across all 6 threat categories and benign traffic.
   - Evaluates multi-event attack sequence grouping accuracy, split scenarios, and cross-incident contamination.
3. **Leak-Free ML Evaluator ([`backend/evaluation/ml_evaluator.py`](file:///c:/Users/NAKSHATRA%20SV/OneDrive/Documents/Cyber-threat-detection/backend/evaluation/ml_evaluator.py))**:
   - Generates an independent holdout dataset of 200 behavioral vectors (150 normal, 50 anomalous) using random seed `101`, preventing data leakage with the training baseline (seed `42`).
   - Assesses IsolationForest decision function scores and validates the Tier C safety invariant (anomaly score alone never authorizes remediation).
