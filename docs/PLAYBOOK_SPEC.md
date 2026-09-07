# Playbook Specification & Response Tiers

**Document Version:** 1.0.0  

---

## 1. Playbook Schema & Lifecycle

Playbooks represent structured remediation and containment workflows. Each playbook is defined declaratively and adheres to strict lifecycle phases.

```
 +-------------+     +-------------+     +--------------+     +-------------+
 | PRE-CHECKS  | --> | AUDIT LOG   | --> | PRE-ACTION   | --> | STEP        |
 | (Preconds)  |     | PERSISTENCE |     | SNAPSHOT     |     | EXECUTION   |
 +-------------+     +-------------+     +--------------+     +-------------+
                                                                     |
                                                                     v
                                                             +-------------+
                                                             | VERIFY &    |
                                                             | ROLLBACK IF |
                                                             | FAILED      |
                                                             +-------------+
```

---

## 2. Response Tiers

| Tier | Name | Risk Threshold | Authorized Actions | Human Approval |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 0** | `ALERT_ONLY` | $< 0.30$ | SIEM Tagging, Slack/Email Notification | No |
| **Tier 1** | `HUMAN_REVIEW` | $0.30 \le Risk < 0.70$ | Ticket Generation, Enrichment, Context Gathering | No |
| **Tier 2** | `CONTAINMENT_PROPOSAL` | $\ge 0.70$ | IP Block Proposal, User Suspend Proposal | **Mandatory** (MVP) |

---

## 3. Sample Playbook DSL Schema (YAML)

```yaml
id: pb-isolate-host-proposal-v1
name: Isolate Host Proposal Playbook
target_entity_type: host
risk_tier: TIER_2
steps:
  - name: verify_preconditions
    action: check_asset_criticality
    args:
      max_criticality: High

  - name: notify_soc_team
    action: connector.slack.send_message
    args:
      channel: "#soc-alerts"
      message: "Proposed containment for host {{incident.target_host}}"

  - name: log_audit_precondition
    action: audit.log_intent
    args:
      action_name: propose_host_isolation

  - name: snapshot_host_state
    action: safety.snapshot_state
    args:
      target: "{{incident.target_host}}"

  - name: propose_containment
    action: connector.edr.propose_isolation
    args:
      host_id: "{{incident.target_host}}"
      require_human_approval: true
```
