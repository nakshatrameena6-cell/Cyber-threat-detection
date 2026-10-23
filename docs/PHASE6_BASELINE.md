# Phase 6 Baseline & Technical Inspection Report (PHASE6_BASELINE.md)

**System:** Suraksha AI — Phase 6 Baseline  
**Date:** 2026-10-23  
**Verified Baseline Test Results:** 70 passed, 0 failed, 0 skipped in 30.53s  
**Status:** Baseline Established & Verified  

---

## 1. Verified Baseline Test Status
The test suite was executed prior to any Phase 6 modifications:
- **Total Test Files**: 24 modules
- **Total Tests Collected**: 70 items
- **Passed**: 70 (100% pass rate)
- **Failed**: 0
- **Skipped**: 0
- **Duration**: 30.53 seconds

---

## 2. Technical Inspection of Pipeline & Identified Issues

### Issue 1: Lateral Movement False Positive (`EVAL-NORM-005`)
- **Code Location**: [`backend/detection/rules_engine.py`](file:///c:/Users/NAKSHATRA%20SV/OneDrive/Documents/Cyber-threat-detection/backend/detection/rules_engine.py) Lines 47–54
- **Existing Logic**:
  ```python
  if event.event_type == EventType.PORT_SCAN or event.payload_metric >= 20.0 and "internal" in event.details.lower():
      return (
          ThreatCategory.LATERAL_MOVEMENT,
          Severity.HIGH,
          0.88,
          f"Internal network probing/port scan across internal hosts ({int(event.payload_metric)} hosts target)."
      )
  ```
- **Flaw**: Because `event.event_type == EventType.PORT_SCAN` is evaluated without context, any routine, low-volume service check (e.g. checking port 80/443 on 2 dev hosts) immediately generates a High Severity lateral movement alert.
- **Root Cause**: Absence of volume thresholds, lack of authorized scanner/subnet context, and no consideration of asset criticality or health-check keywords in the details/metrics.

### Issue 2: Duplicate Event Ambiguity & False Negative Attribution (`EVAL-EDGE-DUP-001`)
- **Code Location**: [`backend/detection/normalizer.py`](file:///c:/Users/NAKSHATRA%20SV/OneDrive/Documents/Cyber-threat-detection/backend/detection/normalizer.py) and [`backend/evaluation/eval_runner.py`](file:///c:/Users/NAKSHATRA%20SV/OneDrive/Documents/Cyber-threat-detection/backend/evaluation/eval_runner.py)
- **Existing Logic**:
  - `EventNormalizer` computes a hash and flags duplicates within a 60s sliding window (`is_dup = True`).
  - In `backend/main.py`, duplicate events return early and write an audit log, but do NOT update active incidents.
  - In `eval_runner.py`, deduplicated events simply append `y_pred = False`, causing suppressed duplicates to be misclassified as detector false negatives (`FN = 1`).
- **Flaw**:
  1. Deduplication is not observable in active incidents (duplicate observations are dropped rather than attached to incident timelines as repeated observations).
  2. The evaluation benchmark conflated *raw ingestion volume* with *unique event detection performance*. Suppressed duplicate events were penalized as missed threats instead of being measured as successful duplicate suppression.

---

## 3. Phase 6 Implementation Plan

1. **Requirement A: Improve Lateral Movement Detection Specificity**:
   - Refactor [`RulesEngine`](file:///c:/Users/NAKSHATRA%20SV/OneDrive/Documents/Cyber-threat-detection/backend/detection/rules_engine.py) to differentiate routine health checks (`payload_metric < 5.0` on non-critical dev/ops assets) from genuine scanning.
   - Introduce configurable thresholds (`MIN_SCAN_TARGETS_THRESHOLD = 5.0`) and authorized scanner subnet awareness without broad loopholes.
   - Detect cumulative port scanning across repeated events.
   - Add grounded `why_evidence`.

2. **Requirement B: Make Duplicate Event Suppression Observable**:
   - Update [`IncidentManager`](file:///c:/Users/NAKSHATRA%20SV/OneDrive/Documents/Cyber-threat-detection/backend/incidents/manager.py) and [`IncidentCorrelationEngine`](file:///c:/Users/NAKSHATRA%20SV/OneDrive/Documents/Cyber-threat-detection/backend/incidents/correlation.py) to record duplicate observations (`duplicate_events_count` and timeline entries) on existing incidents without duplicate response execution.
   - Expose duplicate suppression counters via `/api/telemetry/stats` and SQLite.

3. **Requirement C: Correct Evaluation Semantics**:
   - Update [`metrics.py`](file:///c:/Users/NAKSHATRA%20SV/OneDrive/Documents/Cyber-threat-detection/backend/evaluation/metrics.py) and [`eval_runner.py`](file:///c:/Users/NAKSHATRA%20SV/OneDrive/Documents/Cyber-threat-detection/backend/evaluation/eval_runner.py) to separate:
     - Raw Ingestion Metrics vs Unique Normalized Event Detection Metrics.
     - Deduplication Efficiency (suppression rate).
     - Incident-level correlation metrics.
   - Ensure mathematical consistency across all confusion matrices.

4. **Requirement D: Expand Benchmark Coverage**:
   - Expand [`data/evaluation_dataset.json`](file:///c:/Users/NAKSHATRA%20SV/OneDrive/Documents/Cyber-threat-detection/data/evaluation_dataset.json) to cover cumulative scans, authorized vs unauthorized scanners, duplicates arriving before and after incident creation, and critical assets.
   - Implement an optional public-dataset adapter interface ([`backend/evaluation/public_dataset_adapter.py`](file:///c:/Users/NAKSHATRA%20SV/OneDrive/Documents/Cyber-threat-detection/backend/evaluation/public_dataset_adapter.py)) for CIC-IDS2017/UNSW-NB15 schemas.

5. **Requirement E: Dashboard Integration**:
   - Update the SOC dashboard to display raw events received, unique events analyzed, duplicate events suppressed, deduplication efficiency, and latest tuned benchmark results.
