# System Architecture (ARCHITECTURE.md)

## System: Suraksha AI (Phase 3 Architecture)

```mermaid
graph TD
    A[Raw Telemetry Ingestion / Stream API] --> B[Deduplication & Normalizer]
    B --> C[Behavioral Feature Engine]
    C --> D[Hybrid Detection Engine]
    D --> D1[Deterministic Rules Engine]
    D --> D2[ML Behavioral Anomaly Detector]
    D1 --> E[Composite Risk & "Why" Evidence Calculator]
    D2 --> E
    E --> F[Deterministic Incident Correlation Engine]
    F --> G[Centralized Response Policy Engine]
    G --> H[10 Pre-Execution Safety Gates Layer]
    H -->|Gate 1: Auth Role Check| Gate2
    H -->|Gate 2: Policy Rules Check| Gate3
    H -->|Gate 3: Kill Switch Check| Gate4
    H -->|Gate 4: Target Scope Check| Gate5
    H -->|Gate 5: Blast Radius Check| Gate6
    H -->|Gate 6: Audit Persistence Check| Gate7
    H -->|Gate 7: Pre-State Capture| Gate8
    H -->|Gate 8: Idempotency Check| Gate9
    H -->|Gate 9: Execution Timeout Safety| Gate10
    H -->|Gate 10: Independent Verification| J[Simulated Response Executor]
    H -->|Any Gate Fails| I[Block Action & Queue Human Approval]
    J --> K[Independent State Verifier]
    K --> L[Audit Trail Logger]
    I --> L
    J -->|Rollback Requested| M[Action Rollback Handler]
    M --> L
```

---

## Phase 3 Component Specifications

### 1. Incident Correlation Engine (`backend/incidents/correlation.py`)
- Groups related events into unified multi-stage incidents using a 10-minute sliding window.
- Correlation Key: matching `user_id`, `source_ip`, or `asset_id`.
- Merges event IDs, threat categories list, aggregates behavioral evidence, re-evaluates risk score, and appends timeline events.

### 2. Risk & "Why" Evidence Engine (`backend/detection/risk_calculator.py`)
$$ \text{Risk Score} = \min\left(100, (\text{RuleSeverityWeight} \times 0.55 + \text{MLAnomalyScore} \times 45) \times \text{AssetCriticality} \right) $$
- Generates human-readable evidence array (`why_evidence`) explicitly documenting the factors driving the risk score.

### 3. Response Policy Engine (`backend/response/policy_engine.py`)
Evaluates 10-signal decision tuple:
- `Tier A`: Candidate for auto-execution only if confidence $\ge 0.75$, policy permits, scope allowed, blast radius within limit, kill switch OFF.
- `Tier B`: Low-risk / safely bounded auto-execution + immediate notification.
- `Tier C`: High-impact actions (e.g. `ISOLATE_ENDPOINT`) require explicit analyst approval.

### 4. 10-Gate Pre-Execution Safety Enforcement (`backend/response/safety_gates.py`)
Enforces 10 sequential checks before executing ANY action:
1. Authorization Role Check
2. Response Policy Compatibility Check
3. Emergency Kill-Switch Check
4. Target Scope Format Validation
5. Blast-Radius Limit Check (max 5 active blocks/isolations)
6. Audit Persistence Pre-Check
7. Pre-State Capture
8. Idempotency Check (prevents redundant mutations)
9. Execution Timeout Safety Check
10. Independent Verification Check

### 5. Strict Incident Lifecycle State Machine (`backend/incidents/manager.py`)
Enforces valid state transitions:
`NEW` $\rightarrow$ `UNDER_INVESTIGATION` $\rightarrow$ `MITIGATED` $\rightarrow$ `RESOLVED` / `FALSE_POSITIVE`
Rejects invalid jumps (e.g. `RESOLVED` $\rightarrow$ `NEW`).
