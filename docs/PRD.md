# Product Requirements Document (PRD)
## Suraksha AI - Detection Quality Evaluation, Attack Replay & Reliability Hardening

**Project Name:** Suraksha AI - Autonomous Cyber Threat Detection & Safe Response System  
**Target Audience:** Academic Project / College Demonstration & Security Operations Center (SOC) MVP  
**Version:** 5.0.0 (Phase 5)  
**Status:** Approved  

---

## 1. Objective & Problem Statement
Moving beyond functional prototype demonstrations, real-world Security Operations Centers (SOCs) require empirical, measurable evidence of detection quality, discriminative accuracy between benign and malicious traffic, attack correlation integrity, and transparent explainability.

**Suraksha AI Phase 5** introduces:
1. **Empirical Detection Quality Evaluation**: Statistical quantification of event-level Precision, Recall, F1 Score, False Positive Rate (FPR), and Accuracy with documented zero-denominator handling.
2. **Realistic Multi-Scenario Ground-Truth Benchmark**: 24-scenario labeled fixture ([`data/evaluation_dataset.json`](file:///c:/Users/NAKSHATRA%20SV/OneDrive/Documents/Cyber-threat-detection/data/evaluation_dataset.json)) covering routine office activity, benign administrative tasks (scheduled backups, health checks, mistyped passwords), attacks across all 6 threat categories, a 4-stage APT sequence, and difficult edge cases (duplicate suppression, missing fields, out-of-order events, unrelated concurrent campaigns).
3. **Leak-Free Machine Learning Evaluation**: IsolationForest anomaly detector evaluation using an independent holdout dataset (seed 101, 200 samples) ensuring zero data leakage with baseline training (seed 42).
4. **Incident Correlation Quality Verification**: Quantitative assessment of multi-stage attack grouping accuracy (100%), split incident rates (0%), and cross-campaign contamination (0%).
5. **Verified Response Policy & Safety Semantics**:
   - **Tier A**: Automated execution permitted only for bounded alert-only actions (`ALERT_ONLY`).
   - **Tier B**: Eligible low-to-medium-impact actions (`BLOCK_IP`, `SUSPEND_SESSION`) execute automatically with immediate audit notification when confidence $\ge 0.75$ and all safety gates pass.
   - **Tier C**: High-impact actions (`ISOLATE_ENDPOINT`) or critical asset targets strictly mandate human review and approval before execution.
   - **ML Anomaly Protection**: High anomaly scores alone without rule corroboration are capped at Tier C (human approval required).
   - **Gate 6 Audit Check**: Response execution fails closed if audit persistence to SQLite fails.
6. **SOC Dashboard Detection Benchmark Integration**: Dedicated dashboard tab displaying live benchmark metrics, architecture comparison (Rules vs ML vs Hybrid), per-category breakdown, and interactive benchmark replay.

---

## 2. End-to-End Pipeline Workflow
```text
Raw Telemetry (Batch / Single / Webhook / UDP Syslog / Benchmark Replay)
   ↓
Normalization & Deduplication (UTC timestamps, sliding deduplication window)
   ↓
Hybrid Detection (Deterministic Rule Engine + Scikit-Learn IsolationForest ML)
   ↓
Risk & Explainable Evidence Engine ("Why" calculation, asset criticality weighting)
   ↓
Incident Correlation (Multi-event sliding window, merged timeline & evidence)
   ↓
Response Policy Engine (Strict Tier A / Tier B / Tier C decision logic)
   ↓
10 Pre-Execution Safety Gates (Role Auth, Scope, Blast Radius <= 5, Kill Switch, Idempotency, Verifier, Gate 6 Audit Check)
   ↓
Simulated Response Execution (BLOCK_IP / SUSPEND_SESSION / ISOLATE_ENDPOINT)
   ↓
Independent State Verifier & Rollback Support
   ↓
SQLite Relational Persistence (Transacted storage of events, incidents, actions, audit)
   ↓
Evaluation Engine & SOC Dashboard (Empirical metrics, architecture comparison, live controls)
```

---

## 3. Core Phase 5 Acceptance Criteria
- **Event-Level Detection Quality**: Hybrid pipeline achieves $\ge 90\%$ Precision, $\ge 90\%$ Recall, and $\le 15\%$ False Positive Rate on labeled benchmark scenarios.
- **Incident Correlation Quality**: Multi-event attack sequences correlate into unified incidents with $\ge 90\%$ grouping accuracy and 0 cross-incident contamination.
- **Explainability Transparency**: All detected threats generate non-empty `why_evidence` bullet points referencing real event attributes without hallucination.
- **Safety Invariant Enforcement**: ML anomaly score alone never authorizes remediation; high-impact endpoint isolation strictly mandates human approval.
- **Zero Test Regressions**: All 53 previous tests and 17 new Phase 5 tests execute and pass (70/70 tests passing, 0 skips, 0 failures).
