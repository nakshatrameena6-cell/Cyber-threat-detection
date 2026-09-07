# STRIDE Threat Model & Safety Control Specification

**Document Version:** 1.0.0  

---

## 1. Overview & Threat Boundaries

The AI Threat Detection & Response System is a security control plane. It must be protected against adversarial manipulation, telemetry poisoning, privilege escalation, audit bypass, and rogue automated execution.

---

## 2. STRIDE Threat Analysis

| Threat Category | Threat Scenario | Mitigation / Safety Control | REQ Mapping |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Adversary injects forged telemetry to trigger fake alerts or exhaust system resources. | HMAC verification, mandatory source authentication in Connectors, signature validation. | `REQ-ING-001`, `REQ-SEC-002` |
| **Tampering** | Malicious insider modifies or deletes audit logs to conceal malicious actions. | Immutable audit logger with cryptographic hash chain; hard precondition check before execution (`audit_persisted == True`). | `REQ-AUD-001`, `REQ-AUD-002` |
| **Repudiation** | Operator denies initiating an emergency kill switch or playbook trigger. | RBAC enforcement with mandatory user ID tagging on all API calls and audit records. | `REQ-SEC-001`, `REQ-AUD-001` |
| **Information Disclosure** | Vendor payloads leak sensitive credentials or PII into core domain engine logs. | Strict vendor isolation in Connectors; field anonymization & sanitization during normalization. | `REQ-CON-002`, `REQ-ING-002` |
| **Denial of Service** | Telemetry storm or automated response loop exhausts API endpoints or lock assets. | Rate limiting per asset/source; sliding deduplication window; global kill switch circuit breaker. | `REQ-ING-003`, `REQ-SAF-001`, `REQ-SEC-002` |
| **Elevation of Privilege** | An unprivileged user triggers a high-severity remediation playbook. | Fine-grained RBAC matrix (`SOC_ANALYST` vs `SECURITY_ADMIN`); policy check before playbook instantiation. | `REQ-SEC-001`, `REQ-POL-001` |

---

## 3. Safety Controls & Fail-Closed Behavior

### 3.1 Global Emergency Kill Switch
* The Global Kill Switch is an in-memory & file-backed circuit breaker (`config/kill_switch.yaml`).
* When activated (`is_engaged = True`), all pending and active playbook executions are instantly aborted (`KillSwitchEngagedException`).
* Engagement can be triggered via API (`/api/v1/safety/kill-switch`) or CLI.

### 3.2 Audit Hard Precondition
* Before any playbook action is executed, an audit record must be written to disk/store.
* If audit write fails or times out, execution MUST FAIL SAFE and terminate immediately.

### 3.3 Rollback Guarantee
* Before executing any stateful containment/remediation action, a `PreActionStateSnapshot` MUST be generated.
* If post-execution verification fails, the Rollback Manager reverts the asset state automatically.
