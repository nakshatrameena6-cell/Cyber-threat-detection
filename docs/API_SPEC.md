# REST API & Interface Specification

**Document Version:** 1.0.0  
**Base URL:** `/api/v1`  

---

## Endpoints Summary

| Method | Endpoint | Description | Auth Required | REQ ID |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/telemetry/ingest` | Ingest raw telemetry batch | Yes (`SYSTEM_SERVICE`) | `REQ-ING-001` |
| `GET` | `/api/v1/incidents` | Query correlated incidents | Yes (`SOC_ANALYST`) | `REQ-COR-001` |
| `GET` | `/api/v1/incidents/{id}` | Fetch incident details & risk score | Yes (`SOC_ANALYST`) | `REQ-SCO-001` |
| `POST` | `/api/v1/playbooks/execute` | Trigger playbook execution | Yes (`SECURITY_ADMIN`) | `REQ-PLY-001` |
| `GET` | `/api/v1/audit/logs` | Fetch system audit logs | Yes (`SECURITY_ADMIN`) | `REQ-AUD-001` |
| `GET` | `/api/v1/safety/kill-switch` | Get global kill switch status | Yes (`SOC_ANALYST`) | `REQ-SAF-001` |
| `POST` | `/api/v1/safety/kill-switch` | Toggle global kill switch | Yes (`SECURITY_ADMIN`) | `REQ-SAF-001` |

---

## Key Data Contracts

### 1. Ingestion Request Payload
```json
{
  "source_id": "siem-splunk-01",
  "vendor": "Splunk",
  "events": [
    {
      "raw_payload": "{\"event_id\": 4625, \"user\": \"admin\", \"ip\": \"192.168.1.50\"}",
      "timestamp": "2026-09-07T14:00:00Z"
    }
  ]
}
```

### 2. Kill Switch Response Payload
```json
{
  "is_engaged": false,
  "engaged_by": null,
  "reason": null,
  "last_updated": "2026-09-07T14:30:00Z"
}
```
