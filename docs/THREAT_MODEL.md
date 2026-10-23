# Threat Model & Risk Analysis (THREAT_MODEL.md)

## System: Suraksha AI (Phase 4 Security Analysis)

## 1. Threat Categories & Detection Mapping

| Threat Category | Attack Vector Description | Example Indicator of Compromise (IoC) | Detection Method | Recommended Mitigation Action |
|---|---|---|---|---|
| **Suspicious Login** | Login from unapproved geolocation or off-hours access. | Geolocation jump within 5 mins or login at 03:00 AM UTC. | Rule Engine + Behavioral Off-Hours Feature | `SUSPEND_SESSION` |
| **Brute Force** | Rapid credential stuffing / brute-force password guessing. | $>5$ failed logins within rolling window. | Rule Engine + Rolling Failed Login Counter | `BLOCK_IP` |
| **Privilege Escalation** | Low-privilege user attempting unauthorized admin/sudo access. | `sudo su` execution by non-wheel user or unauthorized API role request. | Rule Engine + Privilege Change Feature | `SUSPEND_SESSION` |
| **Lateral Movement** | Host scanning or unauthorized internal SMB/SSH pivot. | Internal port scan (22/445) across multiple RFC1918 subnets. | Rule Engine + Unique Destination Counter | `ISOLATE_ENDPOINT` |
| **C2-like Activity** | Malware beaconing to command & control servers. | Periodic HTTP GET requests every exactly 10s to unknown domain. | ML Behavioral Anomaly Detector + Rule Engine | `BLOCK_IP` / `ISOLATE_ENDPOINT` |
| **Unusual Data Transfer** | Exfiltration of sensitive enterprise assets. | Outbound data size $> 500 \text{MB}$ in a single request or high cumulative volume. | ML Anomaly Detector (IsolationForest) | `ISOLATE_ENDPOINT` |

---

## 2. STRIDE Threat Analysis (Phase 4 Hardened)

| Threat Type | Potential Vulnerability / Attack Vector | Phase 4 Mitigation & Architecture Control |
|---|---|---|
| **Spoofing** | Adversary sends fake telemetry or unauthorized webhook requests to distract analysts or exhaust resources. | 1. Generic webhook supports secret token verification (`X-Suraksha-Token`).<br>2. Optional UDP Syslog listener binds strictly to loopback (`127.0.0.1:5514`), preventing external network injection.<br>3. RBAC role verification on all state-altering endpoints (`ADMIN`, `ANALYST`, `AUDITOR`). |
| **Tampering** | Adversary attempts to modify SQLite database rows, clear audit history, or alter incident timelines. | 1. Parameterized SQL queries prevent SQL injection.<br>2. Audit logger enforces append-only writing.<br>3. Gate 6 pre-execution safety check halts all response actions if database writes or audit logging fail.<br>4. *Note on Security Boundary*: SQLite is an application database running under host OS permissions. It is not an immutable hardware WORM device or cryptographically distributed ledger. Operating system file-level permissions must restrict SQLite database file access. |
| **Repudiation** | Operator or adversary claims an automated action or approval was unauthorized or never occurred. | 1. Every response decision, pre-state capture, execution outcome, verification, and rollback writes an immutable audit record containing actor ID, role, target, and timestamp.<br>2. Fail-closed architecture prevents execution without prior audit log persistence. |
| **Information Disclosure** | Unauthorized users access incident details, network topology, or secret webhook tokens. | 1. RBAC permissions restrict administrative endpoints.<br>2. Webhook secret tokens are read from environment variables (`SURAKSHA_WEBHOOK_SECRET`) and are never exposed in log files or error traces.<br>3. Stack traces are masked behind standard HTTP 400/500 responses. |
| **Denial of Service (DoS)** | 1. Attacker spams duplicate events to flood correlation engine.<br>2. Attacker spoofing critical infrastructure IPs to trigger automated host isolation or IP blocking. | 1. Sliding window deduplication identifies and suppresses identical events.<br>2. Emergency Kill Switch instantly halts all automated remediation.<br>3. Blast Radius Gate limits concurrent active blocks/isolations to a maximum of 5.<br>4. Critical asset protection prevents automated isolation of core infrastructure.<br>5. High ML anomaly scores alone without deterministic evidence are capped at Tier C (human approval required). |
| **Elevation of Privilege** | Low-privilege user (or compromised analyst account) executes high-impact response actions (e.g. `ISOLATE_ENDPOINT`). | 1. Tier C enforces mandatory human approval with verified `ADMIN` or `ANALYST` authorization.<br>2. Strict state machine prevents unauthorized incident lifecycle jumps. |

---

## 3. Operational Security Boundaries

1. **Simulated Execution**: All remediation actions (`BLOCK_IP`, `SUSPEND_SESSION`, `ISOLATE_ENDPOINT`) operate on simulated firewall/network state objects in-memory and in SQLite. No modifications to real host operating system network adapters, iptables, or Windows Firewall rules are performed.
2. **Persistence Boundary**: The SQLite database provides crash-resilient application persistence. It protects against application restarts and transient runtime failures. Host-level access control, full disk encryption, and periodic external backups are recommended for enterprise production deployment.
