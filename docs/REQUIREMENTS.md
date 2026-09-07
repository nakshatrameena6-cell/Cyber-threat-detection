# Engineering Requirements Specification

**Document Version:** 1.0.0  
**Status:** Approved  

This document defines the testable engineering requirements for the AI Threat Detection & Response System. Every requirement is identified by a unique `REQ-ID`.

---

## 1. Telemetry Ingestion & Normalization (`REQ-ING`)

* **`REQ-ING-001`**: The Ingestion Engine MUST accept raw telemetry payloads from SIEM, EDR, Network, and Cloud sources.
* **`REQ-ING-002`**: The Normalizer MUST convert raw payloads into a schema-validated `NormalizedEvent` entity with MITRE ATT&CK mapping fields (tactic, technique_id).
* **`REQ-ING-003`**: The Deduplicator MUST reject duplicate events received within a configurable sliding window (default 300 seconds) using payload payload hashing.

---

## 2. Threat Detection & Correlation (`REQ-DET`, `REQ-COR`)

* **`REQ-DET-001`**: The Detection Engine MUST evaluate events against declarative signature rules and ML anomaly scorers.
* **`REQ-DET-002`**: The ML evaluator MUST output confidence scores in the range $[0.0, 1.0]$.
* **`REQ-COR-001`**: The Incident Correlation Engine MUST group related `ThreatAlert` items into a single `CorrelatedIncident` entity based on shared entity identifiers (e.g., host_id, user_id, IP) and temporal proximity.

---

## 3. Risk & Scoring Engine (`REQ-SCO`)

* **`REQ-SCO-001`**: The Scoring Engine MUST compute a composite `RiskScore` incorporating `confidence`, `severity`, and `asset_criticality`.
* **`REQ-SCO-002`**: Risk calculation formula MUST be deterministic:  
  $$\text{RiskScore} = \text{Confidence} \times \text{SeverityWeight} \times \text{AssetCriticality}$$
* **`REQ-SCO-003`**: If any input metric is missing, the engine MUST default to conservative maximum uncertainty and route for human review.

---

## 4. Policy Engine & Response Tiers (`REQ-POL`)

* **`REQ-POL-001`**: The Policy Engine MUST evaluate incident risk scores against tier boundaries:
  - `Tier 0 (Risk < 0.3)`: `ALERT_ONLY`
  - `Tier 1 (0.3 <= Risk < 0.7)`: `HUMAN_REVIEW`
  - `Tier 2 (Risk >= 0.7)`: `CONTAINMENT_PROPOSAL` (Requires human approval in MVP)
* **`REQ-POL-002`**: MVP Policy Engine MUST NEVER authorize autonomous Tier-A/B execution without human authorization.

---

## 5. Playbook Framework (`REQ-PLY`)

* **`REQ-PLY-001`**: Playbooks MUST be defined using schema-validated DSL definitions specifying steps, preconditions, verification checks, and rollback procedures.
* **`REQ-PLY-002`**: The Playbook Runner MUST validate all preconditions prior to step execution.

---

## 6. Audit Logging (`REQ-AUD`)

* **`REQ-AUD-001`**: The Audit System MUST record every system decision, state transition, and playbook step into an immutable `AuditEvent`.
* **`REQ-AUD-002`**: Audit persistence is a **hard precondition** (`audit_persisted == True`). Playbook runner MUST abort if audit write fails.

---

## 7. Security, RBAC & Rate Limiting (`REQ-SEC`)

* **`REQ-SEC-001`**: The RBAC layer MUST enforce permissions (`SOC_ANALYST`, `SECURITY_ADMIN`, `SYSTEM_SERVICE`).
* **`REQ-SEC-002`**: Rate limiters MUST enforce blast-radius constraints, preventing more than $N$ actions per asset within a time window.

---

## 8. Connector Framework (`REQ-CON`)

* **`REQ-CON-001`**: All vendor integration logic MUST implement the abstract `BaseConnector` interface.
* **`REQ-CON-002`**: Vendors MUST NOT pollute domain logic; raw vendor payloads MUST be contained strictly inside connector modules.

---

## 9. Safety Controls & Kill Switch (`REQ-SAF`)

* **`REQ-SAF-001`**: The Global Kill Switch MUST immediately halt all ongoing and pending playbook executions when engaged (`is_engaged == True`).
* **`REQ-SAF-002`**: Kill Switch state MUST be persisted atomically and checked synchronously before every playbook action.

---

## 10. Verification & Rollback Framework (`REQ-VRF`)

* **`REQ-VRF-001`**: Pre-action state MUST be captured in a `PreActionStateSnapshot` before performing any stateful action.
* **`REQ-VRF-002`**: The Rollback Engine MUST restore saved pre-action state if playbook verification fails or if an analyst initiates a rollback.

---

## 11. ML Evaluation Pipeline (`REQ-MLE`)

* **`REQ-MLE-001`**: ML evaluation pipeline MUST measure offline Precision, Recall, and F1 metrics against benchmark datasets.
* **`REQ-MLE-002`**: Models in shadow mode MUST evaluate live telemetry without triggering response policies.

---

## 12. API & Dashboard Foundation (`REQ-API`)

* **`REQ-API-001`**: REST API MUST provide endpoints for Telemetry Ingestion, Incident Querying, Playbook Triggering, and Kill Switch Management.
