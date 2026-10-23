# Suraksha AI — Phase 7 Baseline Audit & Verification Note
**Document Version:** 1.0.0 (Phase 7 Baseline)  
**Verification Date:** 2026-10-23  
**Status:** Verified & Audited  

---

## 1. Executive Baseline Summary

This document establishes the verified baseline of **Suraksha AI** at the start of Phase 7, auditing Phase 6 completion claims, running the full test suite, executing the synthetic benchmark, inspecting dataset availability, and documenting discrepancies.

### Verified Test Suite
- **Total Tests:** 89
- **Passing:** 89 (100%)
- **Failing:** 0
- **Skipped:** 0
- **Execution Command:** `py -m pytest`
- **Result:** Fully green, zero regressions.

---

## 2. Benchmark Baseline & Inconsistency Resolution

### Synthetic Benchmark Ground Truth (`data/evaluation_dataset.json`)
- **Total Raw Events ($N_{\text{raw}}$):** 33
- **Unique Analyzed Events ($N_{\text{unique}}$):** 31
- **Suppressed Duplicates ($N_{\text{dup}}$):** 2
- **Alert Volume Reduction:** 6.06% (2 / 33)
- **Duplicate Incident Attachment Rate:** 100.0% (2 / 2)

### Confusion Matrix on Unique Normalized Events ($N_{\text{unique}} = 31$)
| Metric | Count / Score | Mathematical Formula |
|---|---|---|
| **True Positives (TP)** | **21** | Correctly detected threats |
| **False Positives (FP)** | **2** | Benign events flagged as threats |
| **True Negatives (TN)** | **8** | Correctly ignored benign events |
| **False Negatives (FN)** | **0** | Missed threats (Zero missed!) |
| **Total Population** | **31** | $TP + FP + TN + FN = 21 + 2 + 8 + 0 = 31$ |
| **Precision** | **91.30%** (0.9130) | $TP / (TP + FP) = 21 / 23$ |
| **Recall** | **100.0%** (1.0000) | $TP / (TP + FN) = 21 / 21$ |
| **F1 Score** | **0.9545** | $2 \times (P \times R) / (P + R)$ |
| **False Positive Rate (FPR)** | **20.00%** (0.2000) | $FP / (FP + TN) = 2 / (2 + 8) = 2 / 10 = 0.20$ |
| **Accuracy** | **93.55%** (0.9355) | $(TP + TN) / N = (21 + 8) / 31$ |

### Resolution of Mathematical Discrepancy (Phase 6 Narrative vs Code)
- **Observed Discrepancy:** The Phase 6 text summary in Section 2 mistakenly wrote `"False Positive Rate (FPR): 10.0% (1/10 benign)"`, whereas Section 7 of the same report and all generated artifacts (`data/evaluation_report.json`, `data/evaluation_summary.md`) recorded:
  - $FP = 2$, $TN = 8$
  - $\text{FPR} = 2 / (2 + 8) = 2 / 10 = 20.0\%$
- **Audit Findings:**
  1. The code in `backend/evaluation/metrics.py` implements: `fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0`.
  2. For $FP=2$ and $TN=8$, the code accurately computes $0.2000$ (20.0%).
  3. `data/evaluation_report.json` and `data/evaluation_summary.md` both record `"false_positive_rate": 0.2`.
  4. The "10%" in the Phase 6 completion report text was an editorial transcription error (confusing 1 FP out of 10 with the actual 2 FPs).
- **Correct Authoritative Baseline FPR:** **20.00%** ($2 / 10$).

### Root Cause of the Two Phase 6 False Positives:
1. **`EVAL-NORM-008` (Malformed Timestamp Anomaly)**: Normalizer falls back to current UTC timestamp. While rules did not flag it, IsolationForest flagged the feature vector as an outlier ($FP_1$).
2. **`EVAL-P6-SCAN-004` (Out-of-order Duplicate Sweep)**: In standalone event evaluation without prior ingestion memory, the event was evaluated conservatively ($FP_2$).

---

## 3. External Dataset Availability Audit

- **Files Checked:** Full workspace recursive search for `.csv` files.
- **Findings:** Zero CSV files found. Neither CIC-IDS2017 nor UNSW-NB15 is downloaded locally.
- **Baseline Status:** `PENDING_LOCAL_DATA`.
- **Integrity Guarantee:** Phase 7 will not fabricate scores or mock datasets as public datasets. The public dataset adapter will provide batch processing, schema normalization, and holdout splits, returning `PENDING_LOCAL_DATA` when files are absent.

---

## 4. Key Architectural Limitations to Address in Phase 7

1. **Evaluation Metric Validation (Requirement A)**:
   - Need a single authoritative metric computation pipeline with built-in validation preventing divergent JSON/Markdown/API metric publishing.
   - Enforce invariant $TP + FP + TN + FN == N$.
2. **Public Dataset Batch Interface (Requirement B)**:
   - Extend `PublicDatasetAdapter` to stream/chunk CSVs, map labels to canonical schemas, enforce deterministic splits, avoid memory bloat, and reject unknown labels gracefully.
3. **Timestamp Resilience (Requirement C)**:
   - Distinguish `event_timestamp` from `ingestion_timestamp`.
   - Implement `timestamp_quality` tracking and configurable `allowed_lateness_window_seconds`.
   - Mask/isolate timestamp fallback artifacts from IsolationForest features to prevent false positive $FP_1$ on `EVAL-NORM-008`.
4. **Subnet-Aware Distributed Correlation (Requirement D)**:
   - Correlate multi-source IP events belonging to the same CIDR subnet (e.g. `/24` or `/64`) when corroborating context (same target asset, same threat category, tight time window) exists.
   - Prevent over-eager merging of unrelated traffic in shared subnets.
