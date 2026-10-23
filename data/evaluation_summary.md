# Suraksha AI — Detection Quality & Deduplication Evaluation Summary (Phase 6)

**Generated:** 2026-10-23T09:44:29.560590+00:00  
**Dataset:** `data/evaluation_dataset.json`  
**Raw Events Received:** 33  
**Unique Events Analyzed:** 30  
**Duplicate Events Suppressed:** 3  
**Database Isolation:** Verified (Isolated SQLite test DB)  

---

## 1. Raw Telemetry Stream & Deduplication Observability (Requirement B & C)

| Stream Metric | Count / Rate | Operational Significance |
|---|---|---|
| **Raw Events Ingested** | **33** | Total unprocessed telemetry events ingested |
| **Unique Events Analyzed** | **30** | Events passed through normalization to detection engine |
| **Duplicates Suppressed** | **3** | Sliding-window duplicate events suppressed from threat generation |
| **Duplicates Correlated to Incidents** | **2** | Duplicate observations appended to active incident timeline without response re-execution |
| **Deduplication Rate / Flood Reduction** | **9.1%** | Percentage of alert flood prevented by normalizer sliding window |
| **Incident Attachment Rate** | **66.7%** | Percentage of suppressed duplicates successfully correlated to incident timelines |

---

## 2. Detection Performance on Unique Normalized Events (Population: N_unique = N_raw - N_dup)

| Detection Metric | Score | Explanation |
|---|---|---|
| **Precision** | **0.9130** (91.3%) | Ratio of true threat detections over all triggered alarms |
| **Recall** | **1.0000** (100.0%) | Ratio of detected threats over total actual unique threats |
| **F1 Score** | **0.9545** | Harmonic mean of Precision and Recall |
| **False Positive Rate** | **0.2222** (22.2%) | False alarms generated per normal operational event |
| **Accuracy** | **0.9333** (93.3%) | Overall correct classification rate on unique events |

### Unique Event Confusion Matrix
- **True Positives (TP):** 21
- **False Positives (FP):** 2
- **True Negatives (TN):** 7
- **False Negatives (FN):** 0

---

## 3. Detection Engine Comparison (Unique Events Population)

| Detection Engine | Precision | Recall | F1 Score | False Positive Rate |
|---|---|---|---|---|
| **Deterministic Rules Only** | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| **ML IsolationForest Only** | 0.8824 | 0.7143 | 0.7895 | 0.2222 |
| **Hybrid Pipeline (Suraksha AI)** | **0.9130** | **1.0000** | **0.9545** | **0.2222** |

---

## 4. Incident Correlation & Grouping Quality (Requirement B & F)

| Evaluation Metric | Value | Meaning |
|---|---|---|
| **Total Attack Scenarios** | 15 | Evaluated attack campaigns (including duplicate observations) |
| **Correctly Grouped Scenarios** | 15 | Multi-event campaigns mapped to unified incident |
| **Grouping Accuracy** | **100.0%** | Multi-stage correlation success rate |
| **Cross-Contaminated Incidents** | 0 | Unrelated campaigns incorrectly merged |
| **Split Incident Scenarios** | 0 | Related attacks fragmented into multiple incidents |
| **Benign Unintended Incidents** | 2 | Normal events falsely generating incidents |

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
