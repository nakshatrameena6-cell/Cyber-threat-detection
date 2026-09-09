# Threat Model & Risk Analysis (THREAT_MODEL.md)

## System: Suraksha AI

## Threat Categories & Mapping

| Threat Category | Attack Vector Description | Example Indicator of Compromise (IoC) | Detection Method | Recommended Mitigation Action |
|---|---|---|---|---|
| **Suspicious Login** | Login from unapproved geolocation or off-hours access. | Geolocation jump within 5 mins or login at 03:00 AM UTC. | Rule Engine + Behavioral Off-Hours Feature | `SUSPEND_SESSION` |
| **Brute Force** | Rapid credential stuffing / brute-force password guessing. | $>5$ failed logins within rolling window. | Rule Engine + Rolling Failed Login Counter | `BLOCK_IP` |
| **Privilege Escalation** | Low-privilege user attempting unauthorized admin/sudo access. | `sudo su` execution by non-wheel user or unauthorized API role request. | Rule Engine + Privilege Change Feature | `SUSPEND_SESSION` |
| **Lateral Movement** | Host scanning or unauthorized internal SMB/SSH pivot. | Internal port scan (22/445) across multiple RFC1918 subnets. | Rule Engine + Unique Destination Counter | `ISOLATE_ENDPOINT` |
| **C2-like Activity** | Malware beaconing to command & control servers. | Periodic HTTP GET requests every exactly 10s to unknown domain. | ML Behavioral Anomaly Detector + Rule Engine | `BLOCK_IP` / `ISOLATE_ENDPOINT` |
| **Unusual Data Transfer** | Exfiltration of sensitive enterprise assets. | Outbound data size $> 500 \text{MB}$ in a single request or high cumulative volume. | ML Anomaly Detector (IsolationForest) | `ISOLATE_ENDPOINT` |

---

## Threat Modeling (STRIDE Analysis for Suraksha AI)

1. **Spoofing Telemetry**: Adversary attempts to inject fake clean events to cover tracks.
   - *Mitigation*: API Key / Token Authentication and event HMAC checksum verification.
2. **Tampering with Audit Logs**: Adversary attempts to clear or modify response records.
   - *Mitigation*: Append-only in-memory audit store with hash-chaining verification.
3. **Repudiation**: Analyst denies executing a manual response action or overriding Tier B.
   - *Mitigation*: Audit logs record actor `user_id`, `role`, timestamp, and precise action parameters.
4. **Information Disclosure**: Unauthorized analyst views restricted system endpoints.
   - *Mitigation*: Strict RBAC checking (`ADMIN`, `ANALYST`, `AUDITOR`).
5. **Denial of Service (DoS) via Automated Response Runaway**: Malicious attacker spoofing internal IP to trigger automated `BLOCK_IP` or `ISOLATE_ENDPOINT`.
   - *Mitigation*: Emergency Kill Switch halts auto-execution; Tier B requires Human Approval for medium risk; Whitelisted critical subnets.
6. **Elevation of Privilege**: Attacker bypasses decision tier to execute high-impact commands.
   - *Mitigation*: Strict schema validation, immutability of decision rules, and safe simulated execution wrappers.
