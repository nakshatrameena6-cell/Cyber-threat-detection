# Product Requirements Document (PRD)
## Suraksha AI - Behavioral Threat Detection & Safe Response System

**Project Name:** Suraksha AI - Autonomous Cyber Threat Detection & Safe Response System  
**Target Audience:** Academic Project / College Demonstration & Security Operations Center (SOC) MVP  
**Version:** 2.0.0 (Phase 2 MVP)  
**Status:** Approved  

---

## 1. Objective & Problem Statement
Modern enterprise networks generate continuous, high-volume streams of security telemetry (syslog, web access logs, authentication logs, network flow logs). Manual triage by SOC analysts is slow, prone to alert fatigue, and susceptible to missed critical threats. Existing automated SOAR platforms are often overly complex, costly, and risky if automated actions run without safeguards.

**Suraksha AI** provides an autonomous, light-weight, spec-driven threat detection and safe response system. It normalizes incoming security telemetry streams, deduplicates redundant events, extracts rolling behavioral features, runs hybrid detection (deterministic rules + machine learning behavioral anomaly scoring), computes composite risk, creates tracked incidents with behavioral evidence, applies tiered response logic (Tier A/B/C), executes safe simulated remediation actions with post-action verification and rollback capabilities, and maintains a tamper-evident audit trail protected by RBAC and a global Emergency Kill Switch.

---

## 2. Core Workflow
The system strictly executes the 9-stage pipeline:
`Input Logs / Stream` → `Deduplicate & Normalize` → `Extract Behavioral Features` → `Detect Threat (Rules + ML Anomaly)` → `Calculate Risk` → `Create Incident with Evidence` → `Decide Response` → `Execute Safe Action` → `Verify & Audit`

---

## 3. High-Level Requirements & Capabilities (Phase 1 & Phase 2)

### 3.1 Telemetry Ingestion, Deduplication & Normalization
- Support structured JSON, batch stream files, API POST, and sequential event arrays.
- Sliding window deduplication filtering out identical event hashes within a 60-second window.
- Automatic sorting of out-of-order event timestamps.
- Standardized JSON schema: `timestamp`, `source_ip`, `user_id`, `event_type`, `asset_id`, `payload_metric`, `raw_data`.

### 3.2 Behavioral Feature Engine (Phase 2)
Stateful rolling window tracking per user and IP:
- `failed_login_count`: Rolling 5-minute window counter.
- `login_frequency`: Login rate per minute.
- `off_hours_flag`: Access outside standard business hours (08:00 - 18:00 UTC).
- `unique_destinations`: Count of distinct internal subnets/hosts accessed.
- `privilege_change_events`: Count of sudo/admin escalation attempts.
- `data_transfer_volume_mb`: Cumulative outbound transfer volume.
- `connection_frequency`: High-frequency network/C2 connection rate.

### 3.3 Hybrid Threat Detection
Cover 6 key threat categories:
1. **Suspicious Login**: Off-hours access, geolocation jump, disabled account attempts.
2. **Brute Force**: Exceeding failed login thresholds within a rolling window.
3. **Privilege Escalation**: Unauthorized role escalation or unexpected sudo execution.
4. **Lateral Movement**: Internal cross-subnet connection or SMB/RDP probe spikes.
5. **C2-like Activity**: Periodic beaconing patterns or high-frequency query intervals to unknown domains.
6. **Unusual Data Transfer**: Outbound network exfiltration exceeding volumetric baseline.

### 3.4 Risk & Confidence Scoring
- **Risk Score (0–100)**: Derived from rule severity, ML behavioral anomaly probability, and target asset criticality multiplier.
- **Confidence Score (0.0–1.0)**: Derived from combined rule match certainty and ML decision threshold.

### 3.5 Tiered Decision Matrix
- **Tier A (Low Risk, <40)**: Alert log only. Status set to `INFO`.
- **Tier B (Medium Risk, 40–75)**: Generate Incident & Request Human Approval for response actions.
- **Tier C (High Risk, >75)**: High Severity & High Confidence ($\ge 0.75$). Auto-trigger safe simulated response action **UNLESS** Emergency Kill Switch is ON.

### 3.6 Safe Response Execution, Verification & Rollback
- **Response Actions (Simulated)**:
  - `BLOCK_IP`: Simulated firewall dynamic rule injection & state tracking.
  - `SUSPEND_SESSION`: Simulated user session token invalidation.
  - `ISOLATE_ENDPOINT`: Simulated host network adapter isolation.
- **Verification**: Automatically check post-action state (e.g., mock ping/reachability check).
- **Rollback**: Support 1-click or automated reversal of any executed action.

### 3.7 Safeguards, RBAC & Audit
- **Emergency Kill Switch**: Global toggle halting automated response execution across all tiers instantly.
- **RBAC**: Roles `ADMIN` (Full control), `ANALYST` (View & Approve responses), `AUDITOR` (Read-only logs & metrics).
- **Audit Logging**: Append-only log recording every ingestion, detection, tier evaluation, manual approval, execution, and rollback.

---

## 4. Non-Goals
- Real host/network destruction or actual operating system kernel/firewall modifications (all actions are safely simulated with realistic state transitions).
- Complex microservices / Kubernetes deployments (monolithic clean modular architecture for college demo simplicity).
- Deep learning neural network dependencies.
