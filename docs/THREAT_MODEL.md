# Threat Model & Risk Analysis (THREAT_MODEL.md)

## System: Suraksha AI (Phase 6 Security & Hardened Threat Analysis)

## 1. Threat Categories & Detection Mapping

| Threat Category | Attack Vector Description | Example IoC / Context | Detection Method | Recommended Mitigation Action |
|---|---|---|---|---|
| **Suspicious Login** | Login from unapproved geolocation or off-hours access. | Geolocation jump within 5 mins or login at 03:00 AM UTC. | Rule Engine + Behavioral Off-Hours Feature | `SUSPEND_SESSION` |
| **Brute Force** | Rapid credential stuffing / brute-force password guessing. | $>5$ failed logins within rolling window. | Rule Engine + Rolling Failed Login Counter | `BLOCK_IP` |
| **Privilege Escalation** | Low-privilege user attempting unauthorized admin/sudo access. | `sudo su` execution by non-wheel user or unauthorized API role request. | Rule Engine + Privilege Change Feature | `SUSPEND_SESSION` |
| **Lateral Movement** | Host scanning or unauthorized internal SMB/SSH pivot. | Internal port scan (volume $\ge 15.0$, or probe targeting `CRITICAL` asset, or cumulative stealth probes $\ge 5.0$). | Context-Aware Rule Engine + Cumulative Target Tracking | `ISOLATE_ENDPOINT` |
| **C2-like Activity** | Malware beaconing to command & control servers. | Periodic HTTP GET requests every exactly 10s to unknown domain. | ML Behavioral Anomaly Detector + Rule Engine | `BLOCK_IP` / `ISOLATE_ENDPOINT` |
| **Unusual Data Transfer** | Exfiltration of sensitive enterprise assets. | Outbound data size $> 500 \text{MB}$ in a single request or high cumulative volume. | ML Anomaly Detector (IsolationForest) | `ISOLATE_ENDPOINT` |

---

## 2. STRIDE Threat Analysis (Phase 6 Hardened)

| Threat Type | Potential Vulnerability / Attack Vector | Phase 6 Mitigation & Architecture Control |
|---|---|---|
| **Spoofing** | 1. Adversary injects fake telemetry to cover tracks or exhaust SOC analysts.<br>2. Adversary spoofs benchmark evaluation fixtures to falsify metrics. | 1. Generic webhook enforces secret token verification (`X-Suraksha-Token`).<br>2. UDP Syslog listener binds strictly to loopback `127.0.0.1:5514`.<br>3. Evaluation datasets feature immutable file hashes and schema validation. |
| **Tampering** | 1. Adversary attempts to clear or modify SQLite audit records.<br>2. Adversary poisons evaluation dataset labels to hide low detection rates. | 1. Parameterized SQL queries prevent SQL injection.<br>2. Append-only audit logger raises exceptions on failure.<br>3. Pre-execution Gate 6 halts response execution if database writes fail.<br>4. Evaluation benchmark runs in an isolated database environment, preventing test tampering of live operational data. |
| **Repudiation** | Operator denies approving a response action or tampering with benchmark metrics. | 1. All manual approvals, rollbacks, and benchmark runs log actor ID, role, timestamp, and details into the append-only SQLite audit table.<br>2. Benchmark reports record UTC generation timestamps and dataset file paths. |
| **Information Disclosure** | Unauthorized users view restricted incidents, topologies, or benchmark holdout data. | 1. Strict RBAC checking (`ADMIN`, `ANALYST`, `AUDITOR`).<br>2. Webhook secret tokens are read from environment variables and never logged.<br>3. Public API responses mask stack traces behind structured HTTP 400/500 errors. |
| **Denial of Service (DoS)** | 1. Attacker spams duplicate events to flood correlation engine or re-trigger remediation.<br>2. Attacker games single-event scan thresholds with slow cumulative probes.<br>3. Attacker triggers automated response runaway on critical internal hosts.<br>4. Benchmark execution exhausts server CPU or locks database. | 1. Sliding-window deduplication suppresses identical events.<br>2. Duplicate events correlate to incident timelines but **never authorize or re-trigger response execution**.<br>3. Cumulative reconnaissance tracking aggregates low-volume scans across sequential events.<br>4. Emergency Kill Switch halts automated responses immediately.<br>5. Blast Radius Gate restricts active blocks to $\le 5$.<br>6. Critical asset protection prevents destructive isolation of core servers.<br>7. ML anomaly scores alone are capped at Tier C (human approval required).<br>8. Benchmark runs operate in isolated temporary databases without table locking on `data/suraksha.db`. |
| **Elevation of Privilege** | Low-privilege user executes high-impact response actions (e.g., `ISOLATE_ENDPOINT`). | 1. Tier C enforces mandatory human approval with verified `ADMIN` or `ANALYST` authorization.<br>2. Strict state machine prevents unauthorized incident lifecycle jumps. |

---

## 3. Lateral Movement Reconnaissance Defense & Exemption Specificity

### 3.1 Threshold-Gaming Prevention (Cumulative Stealth Scans)
Adversaries often attempt to evade detection rules by fragmenting port reconnaissance into low-volume events (e.g., 2 ports scanned per minute to remain under a static threshold of 5).
- **Control**: Suraksha AI maintains an in-memory cumulative tracker (`v.cumulative_scan_targets` and `v.port_scan_count`) per entity in the Behavioral Engine. When cumulative probed targets reach the minimum threshold across multiple events, a high-severity `LATERAL_MOVEMENT` alert is triggered.

### 3.2 Strict Critical Asset Protection Boundary
Authorized scanner exemptions ($< 5.0$ targets) apply **exclusively** to non-critical development and sandbox environments.
- **Control**: Any probe targeting an asset designated `CRITICAL` or `HIGH` (or identifying infrastructure like `db`, `auth`, `prod`, `domain controller`) immediately bypasses benign exemptions and triggers immediate detection.

### 3.3 Zero Remediation on Duplicate Telemetry
Duplicate events could be weaponized to cause response runaway or re-trigger rate-limiting blocks.
- **Control**: If an event is marked `is_duplicate = True`, it is appended to the active incident timeline as an observable duplicate count, but `process_telemetry_pipeline` terminates with `threat_detected = False` and `response_record = None`. Zero automated actions or state mutations can be induced by duplicate observations.
