# Requirement → Spec → Code → Test Traceability Matrix

**Document Version:** 1.0.0  

This document tracks bidirectional traceability across engineering requirements, specifications, codebase components, and test functions.

| Requirement ID | Spec Document | Implementation Component | Test Suite |
| :--- | :--- | :--- | :--- |
| `REQ-ING-001` | `REQUIREMENTS.md#1`, `API_SPEC.md` | `src/ai_threat_detection/ingestion/ingestor.py` | `tests/unit/test_ingestion.py::test_telemetry_ingestion` |
| `REQ-ING-002` | `REQUIREMENTS.md#1` | `src/ai_threat_detection/ingestion/normalizer.py` | `tests/unit/test_ingestion.py::test_event_normalization` |
| `REQ-ING-003` | `REQUIREMENTS.md#1` | `src/ai_threat_detection/ingestion/deduplicator.py` | `tests/unit/test_ingestion.py::test_event_deduplication` |
| `REQ-DET-001` | `REQUIREMENTS.md#2` | `src/ai_threat_detection/detection/detector.py` | `tests/unit/test_detection.py::test_rule_detection` |
| `REQ-DET-002` | `REQUIREMENTS.md#2` | `src/ai_threat_detection/detection/evaluator.py` | `tests/unit/test_detection.py::test_ml_confidence_evaluator` |
| `REQ-COR-001` | `REQUIREMENTS.md#2` | `src/ai_threat_detection/correlation/engine.py` | `tests/unit/test_correlation.py::test_incident_correlation` |
| `REQ-SCO-001` | `REQUIREMENTS.md#3` | `src/ai_threat_detection/scoring/engine.py` | `tests/unit/test_scoring.py::test_risk_score_calculation` |
| `REQ-SCO-002` | `REQUIREMENTS.md#3` | `src/ai_threat_detection/scoring/engine.py` | `tests/unit/test_scoring.py::test_missing_metric_fallback` |
| `REQ-POL-001` | `REQUIREMENTS.md#4`, `PLAYBOOK_SPEC.md` | `src/ai_threat_detection/policy/engine.py` | `tests/unit/test_policy.py::test_policy_tier_routing` |
| `REQ-POL-002` | `REQUIREMENTS.md#4` | `src/ai_threat_detection/policy/engine.py` | `tests/unit/test_policy.py::test_no_autonomous_tier_a_in_mvp` |
| `REQ-PLY-001` | `REQUIREMENTS.md#5`, `PLAYBOOK_SPEC.md` | `src/ai_threat_detection/playbook/runner.py` | `tests/unit/test_playbook.py::test_playbook_execution_flow` |
| `REQ-AUD-001` | `REQUIREMENTS.md#6`, `THREAT_MODEL.md` | `src/ai_threat_detection/audit/logger.py` | `tests/unit/test_audit.py::test_audit_event_logging` |
| `REQ-AUD-002` | `REQUIREMENTS.md#6`, `THREAT_MODEL.md` | `src/ai_threat_detection/audit/logger.py` | `tests/unit/test_audit.py::test_audit_precondition_enforcement` |
| `REQ-SEC-001` | `REQUIREMENTS.md#7` | `src/ai_threat_detection/security/rbac.py` | `tests/unit/test_security.py::test_rbac_permissions` |
| `REQ-SEC-002` | `REQUIREMENTS.md#7` | `src/ai_threat_detection/security/rate_limiter.py` | `tests/unit/test_security.py::test_blast_radius_rate_limiter` |
| `REQ-CON-001` | `REQUIREMENTS.md#8` | `src/ai_threat_detection/connectors/base.py` | `tests/unit/test_connectors.py::test_connector_interface` |
| `REQ-SAF-001` | `REQUIREMENTS.md#9`, `THREAT_MODEL.md` | `src/ai_threat_detection/safety/kill_switch.py` | `tests/unit/test_safety.py::test_kill_switch_engagement` |
| `REQ-VRF-001` | `REQUIREMENTS.md#10` | `src/ai_threat_detection/verification/rollback.py` | `tests/unit/test_verification.py::test_pre_action_state_snapshot` |
| `REQ-MLE-001` | `REQUIREMENTS.md#11` | `src/ai_threat_detection/ml_eval/pipeline.py` | `tests/unit/test_ml_eval.py::test_ml_evaluation_metrics` |
| `REQ-API-001` | `REQUIREMENTS.md#12`, `API_SPEC.md` | `src/ai_threat_detection/api/app.py` | `tests/integration/test_pipeline.py::test_api_endpoints` |
