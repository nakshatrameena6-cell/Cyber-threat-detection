# Product Requirements Document (PRD)
## Suraksha AI - Risk, Incident Correlation & Safe Response Engine

**Project Name:** Suraksha AI - Autonomous Cyber Threat Detection & Safe Response System  
**Target Audience:** Academic Project / College Demonstration & Security Operations Center (SOC) MVP  
**Version:** 3.0.0 (Phase 3 MVP)  
**Status:** Approved  

---

## 1. Objective & Problem Statement
Modern enterprise networks generate continuous streams of security events. Isolated alert processing leads to SOC alert fatigue, fragmented context, and risky response execution.

**Suraksha AI Phase 3** strengthens the **decision, correlation, and safe response layer**. It normalizes incoming telemetry, deduplicates events, extracts behavioral features, correlates multi-event attack sequences into unified incidents with timeline tracking, evaluates risk using transparent *"Why"* evidence explanations, enforces centralized response policies and 10 pre-execution safety gates (blast radius, kill-switch, scope, authorization, idempotency, verification), executes safe simulated remediation, performs independent post-action verification, supports rollback, and logs tamper-evident audit records.

---

## 2. End-to-End Pipeline Workflow
```text
Telemetry
   ↓
Normalization + Deduplication
   ↓
Rule Detection + Behavioral Detection
   ↓
Risk + Confidence + Evidence ("Why")
   ↓
Incident Correlation (Multi-Event Merge)
   ↓
Response Policy / Tier Decision
   ↓
10 Safety Gates (Authorization + Scope + Blast Radius + Kill Switch + Idempotency)
   ↓
Simulated Response Execution
   ↓
Independent Verification Check
   ↓
Rollback (if requested)
   ↓
Audit Trail & Incident Lifecycle Management
```

---

## 3. Core Phase 3 Requirements & Capabilities

### 3.1 Deterministic Incident Correlation
- Group related events into a single incident based on:
  - Same `user_id`
  - Same `source_ip`
  - Same `asset_id`
  - Close timestamp window (10-minute sliding window)
  - Related behavioral evidence
- Maintain complete event timelines for multi-stage attack scenarios (e.g. 5 failed logins + successful login + privilege escalation + large outbound transfer $\rightarrow$ 1 correlated incident).

### 3.2 Transparent Risk & "Why" Evidence Scoring
- Risk Score: $0–100$, Confidence Score: $0.0–1.0$.
- Human-readable evidence breakdown (`why_evidence`) displaying explicit reasons (e.g. *"8 failed login attempts"*, *"Successful login from unusual source"*, *"Privilege change detected"*, *"850 MB outbound transfer"*, *"Critical endpoint"*).
- Safety Policy constraint: High ML anomaly score without sufficient deterministic evidence is constrained to Tier B (Human Approval).

### 3.3 Response Policy & Tier Semantics
- **Tier A (Fully Automatic)**: Candidate only when confidence $\ge 0.75$, policy permits automation, scope allowed, blast radius within limit, kill switch OFF, and verification available.
- **Tier B (Automatic + Immediate Notification)**: Low-risk / safely bounded actions executed with immediate audit notification.
- **Tier C (Human Approval Required)**: High-impact actions (e.g., `ISOLATE_ENDPOINT`) or high risk require explicit analyst approval. Capped at `ALERT_ONLY / HUMAN_REVIEW` if ambiguity exists.

### 3.4 10 Pre-Execution Safety Gates
Before ANY action is executed, the system enforces:
1. Authorization Check (Role permissions: `ADMIN`, `ANALYST`, `AUDITOR`)
2. Policy Compatibility Check
3. Emergency Kill-Switch Check
4. Target Scope Check (Valid IP, hostname, or user string)
5. Blast-Radius Check (Max 5 active blocked IPs or isolated hosts)
6. Audit Persistence Pre-Check
7. Pre-State Capture
8. Idempotency Check (Prevents duplicate execution/mutations)
9. Execution Timeout Safety Check
10. Independent Verification Check

If any gate fails $\rightarrow$ Execution is blocked, audit entry recorded, incident queued for human review.

### 3.5 Incident Lifecycle State Machine
Strict state machine preventing invalid transitions:
`NEW` $\rightarrow$ `UNDER_INVESTIGATION` $\rightarrow$ `MITIGATED` $\rightarrow$ `RESOLVED` / `FALSE_POSITIVE`

---

## 4. Non-Goals
- Real operating system or network hardware blocking (all remediation remains safely simulated in-memory).
- Enterprise graph databases or external SOAR platforms.
