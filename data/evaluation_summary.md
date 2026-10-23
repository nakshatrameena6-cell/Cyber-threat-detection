# Suraksha AI — Detection Quality, Distributed Correlation & Metric Integrity Summary (Phase 6 / Phase 7)

**Generated:** 2026-10-23T16:46:22.659793+00:00  
**Dataset:** `data/evaluation_dataset.json` (Synthetic-Hardened-Multi-Scenario-v7)  
**Raw Events Received:** 33  
**Unique Events Analyzed:** 31  
**Duplicate Events Suppressed:** 2  
**Public Dataset Evaluation Status:** `PENDING_LOCAL_DATA` (Official external data not present locally; zero synthetic data fabricated)  
**Mathematical Validation Gate:** PASSED (All invariants TP+FP+TN+FN verified)  
**Database Isolation:** Verified (Isolated SQLite test DB)  

---

## 1. Raw Telemetry Stream & Deduplication Observability (Requirement B & C)

| Stream Metric | Count / Rate | Operational Significance |
|---|---|---|
| **Raw Events Ingested** | **33** | Total unprocessed telemetry events ingested |
| **Unique Events Analyzed** | **31** | Events passed through normalization to detection engine |
| **Duplicates Suppressed** | **2** | Sliding-window duplicate events suppressed from threat generation |
| **Duplicates Correlated to Incidents** | **2** | Duplicate observations appended to active incident timeline without response re-execution |
| **Deduplication Rate / Flood Reduction** | **6.1%** | Percentage of alert flood prevented by normalizer sliding window |
| **Incident Attachment Rate** | **100.0%** | Percentage of suppressed duplicates successfully correlated to incident timelines |

---

## 2. Detection Performance on Unique Normalized Events (Population: N_unique = N_raw - N_dup)

| Detection Metric | Score | Explanation |
|---|---|---|
| **Precision** | **1.0000** (100.0%) | Ratio of true threat detections over all triggered alarms |
| **Recall** | **1.0000** (100.0%) | Ratio of detected threats over total actual unique threats |
| **Specificity** | **1.0000** (100.0%) | True negative rate (benign events correctly ignored) |
| **F1 Score** | **1.0000** | Harmonic mean of Precision and Recall |
| **False Positive Rate** | **0.0000** (0.0%) | False alarms generated per normal operational event |
| **Accuracy** | **1.0000** (100.0%) | Overall correct classification rate on unique events |
| **Balanced Accuracy** | **1.0000** | Average of Recall and Specificity |

### Unique Event Confusion Matrix (Population = 31)
- **True Positives (TP):** 21
- **False Positives (FP):** 0
- **True Negatives (TN):** 10
- **False Negatives (FN):** 0

---

## 3. Detection Engine Comparison (Unique Events Population)

| Detection Engine | Precision | Recall | F1 Score | False Positive Rate |
|---|---|---|---|---|
| **Deterministic Rules Only** | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| **ML IsolationForest Only** | 1.0000 | 0.4762 | 0.6452 | 0.0000 |
| **Hybrid Pipeline (Suraksha AI)** | **1.0000** | **1.0000** | **1.0000** | **0.0000** |

---

## 4. Incident Correlation & Grouping Quality (Requirement B & F)

| Evaluation Metric | Value | Meaning |
|---|---|---|
| **Total Attack Scenarios** | 15 | Evaluated attack campaigns (including duplicate observations) |
| **Correctly Grouped Scenarios** | 15 | Multi-event campaigns mapped to unified incident |
| **Grouping Accuracy** | **100.0%** | Multi-stage correlation success rate |
| **Cross-Contaminated Incidents** | 0 | Unrelated campaigns incorrectly merged |
| **Split Incident Scenarios** | 0 | Related attacks fragmented into multiple incidents |
| **Benign Unintended Incidents** | 0 | Normal events falsely generating incidents |

---

## 5. ML Model Holdout Performance (Zero Data Leakage)
- **Holdout Test Samples:** 200 (150 Normal, 50 Anomalous)
- **Holdout Precision:** 1.0000 | **Holdout Recall:** 1.0000 | **Holdout F1:** 1.0000
- **Safety Invariant:** ML anomaly score alone NEVER authorizes remediation; fails closed to Tier C Human Review.

---

## 6. Risk & Explainability Evaluation
- **Risk Score Range Invariant [0 - 100]:** PASSED
- **Min / Max Risk Observed:** 5.0 / 100.0
- **Confidence Range Invariant [0.0 - 1.0]:** PASSED
- **Explainable Evidence Presence:** 100% Present
