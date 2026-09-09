# Product Requirements Document (PRD)
## AI Threat Detection & Response System (MVP)

**Project Name:** SentinelAI - Autonomous Cyber Threat Detection & Safe Response System  
**Target Audience:** Academic Project / College Demonstration & Security Operations Center (SOC) MVP  
**Version:** 1.0.0 (MVP)  
**Status:** Approved  

---

## 1. Objective & Problem Statement
Modern enterprise networks generate vast quantities of security telemetry (syslog, web access logs, authentication logs, network flow logs). Manual triage by SOC analysts is slow, prone to alert fatigue, and susceptible to missed critical threats. Existing automated SOAR platforms are often overly complex, costly, and risky if automated actions run without safeguards.

**SentinelAI** provides an autonomous, light-weight, spec-driven threat detection and safe response system. It normalizes incoming security telemetry, runs hybrid detection (deterministic rules + machine learning anomaly scoring), computes composite risk, creates tracked incidents, applies tiered response logic (Tier A/B/C), executes safe simulated remediation actions with post-action verification and rollback capabilities, and maintains a tamper-evident audit trail protected by RBAC and a global Emergency Kill Switch.

---

## 2. Core Workflow
The system strictly executes the 9-stage pipeline:
`Input Logs` → `Normalize` → `Detect Threat` → `Calculate Risk` → `Create Incident` → `Decide Response` → `Execute Safe Action` → `Verify` → `Audit`

---

## 3. High-Level Requirements & Capabilities

### 3.1 Telemetry Ingestion & Normalization
- Support structured JSON, API POST, and log file ingestion.
- Standardize events into unified JSON schema: `timestamp`, `source_ip`, `user_id`, `event_type`, `asset_id`, `payload_metric`, `raw_data`.

### 3.2 Hybrid Threat Detection
Cover 6 key threat categories:
1. **Suspicious Login**: Off-hours access, geolocation jump, disabled account attempts.
2. **Brute Force**: Exceeding failed login thresholds within a rolling window.
3. **Privilege Escalation**: Unauthorized role escalation or unexpected sudo execution.
4. **Lateral Movement**: Internal cross-subnet connection or SMB/RDP probe spikes.
5. **C2-like Activity**: Periodic beaconing patterns or high-frequency query intervals to unknown domains.
6. **Unusual Data Transfer**: Outbound network exfiltration exceeding volumetric baseline.

### 3.3 Risk & Confidence Scoring
- **Risk Score (0–100)**: Derived from rule severity, ML anomaly probability, and target asset criticality multiplier.
- **Confidence Score (0.0–1.0)**: Derived from combined rule match certainty and ML decision threshold.

### 3.4 Tiered Decision Matrix
- **Tier A (Low Risk, <40)**: Alert log only. Status set to `INFO`.
- **Tier B (Medium Risk, 40–75)**: Generate Incident & Request Human Approval for response actions.
- **Tier C (High Risk, >75)**: High Severity & High Confidence ($\ge 0.75$). Auto-trigger safe simulated response action **UNLESS** Emergency Kill Switch is ON.

### 3.5 Safe Response Execution, Verification & Rollback
- **Response Actions (Simulated)**:
  - `BLOCK_IP`: Simulated firewall dynamic rule injection & state tracking.
  - `SUSPEND_SESSION`: Simulated user session token invalidation.
  - `ISOLATE_ENDPOINT`: Simulated host network adapter isolation.
- **Verification**: Automatically check post-action state (e.g., mock ping/reachability check).
- **Rollback**: Support 1-click or automated reversal of any executed action.

### 3.6 Safeguards, RBAC & Audit
- **Emergency Kill Switch**: Global toggle halting automated response execution across all tiers instantly.
- **RBAC**: Roles `ADMIN` (Full control), `ANALYST` (View & Approve responses), `AUDITOR` (Read-only logs & metrics).
- **Audit Logging**: Append-only log recording every ingestion, detection, tier evaluation, manual approval, execution, and rollback.

---

## 4. Non-Goals
- Real host/network destruction or actual operating system kernel/firewall modifications (all actions are safely simulated with realistic state transitions).
- Complex microservices / Kubernetes deployments (monolithic clean modular architecture for college demo simplicity).
- Continuous online ML retraining infrastructure.
