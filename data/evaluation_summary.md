# Suraksha AI — Detection Quality Evaluation Summary (Phase 5)

**Generated:** 2026-10-23T06:34:35.407465+00:00  
**Dataset:** `data/evaluation_dataset.json` (24 events)  
**Database Isolation:** Verified (Isolated evaluation DB)  

---

## 1. Overall Hybrid Detection Performance (Event-Level)

| Metric | Score | Explanation |
|---|---|---|
| **Precision** | **0.9333** (93.3%) | Ratio of true threat detections over all triggered alarms |
| **Recall** | **0.9333** (93.3%) | Ratio of detected threats over total actual threats |
| **F1 Score** | **0.9333** | Harmonic mean of Precision and Recall |
| **False Positive Rate** | **0.1111** (11.1%) | False alarms generated per normal operational event |
| **Accuracy** | **0.9167** (91.7%) | Overall correct classification rate |

### Event-Level Confusion Matrix
- **True Positives (TP):** 14
- **False Positives (FP):** 1
- **True Negatives (TN):** 8
- **False Negatives (FN):** 1

---

## 2. Pipeline Architecture Comparison (Rules vs ML vs Hybrid)

| Detection Engine | Precision | Recall | F1 Score | False Positive Rate |
|---|---|---|---|---|
| **Deterministic Rules Only** | 0.9333 | 0.9333 | 0.9333 | 0.1111 |
| **ML IsolationForest Only** | 0.8889 | 0.5333 | 0.6667 | 0.1111 |
| **Hybrid Pipeline (Suraksha AI)** | **0.9333** | **0.9333** | **0.9333** | **0.1111** |

---

## 3. Incident Correlation Quality (Workstream F)

| Evaluation Metric | Value | Meaning |
|---|---|---|
| **Total Attack Scenarios** | 10 | Evaluated attack campaigns |
| **Correctly Grouped Scenarios** | 10 | Multi-event campaigns mapped to unified incident |
| **Grouping Accuracy** | **100.0%** | Multi-stage correlation success rate |
| **Cross-Contaminated Incidents** | 0 | Unrelated campaigns incorrectly merged |
| **Split Incident Scenarios** | 0 | Related attacks fragmented into multiple incidents |
| **Benign Unintended Incidents** | 1 | Normal events falsely generating incidents |

---

## 4. ML Model Holdout Performance (Workstream D - Zero Data Leakage)
- **Holdout Test Samples:** 200 (150 Normal, 50 Anomalous)
- **Holdout Precision:** 1.0000 | **Holdout Recall:** 1.0000 | **Holdout F1:** 1.0000
- **Safety Control:** ML anomaly score alone NEVER authorizes remediation; fails closed to Tier C Human Review.

---

## 5. Risk & Explainability Evaluation (Workstream E)
- **Risk Score Range Invariant [0 - 100]:** PASSED
- **Min / Max Risk Observed:** 5.0 / 100.0
- **Confidence Range Invariant [0.0 - 1.0]:** PASSED
- **Explainable Evidence Presence:** 100% Present
