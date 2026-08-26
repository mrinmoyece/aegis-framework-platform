# Layer 3 failure modes

| Failure | Fail-closed behavior | Durable owner | Qualification |
|---|---|---|---|
| Stale aggregate writer | Expected-version conflict; no event/cursor/outbox commit | Application ledger | unit + PostgreSQL |
| Duplicate request/signal/activity | Fingerprint/inbox/event ID returns same fact or rejects conflict | Application database | unit + eval |
| Event/outbox insert race | Whole transaction rolls back | PostgreSQL | unit + integration |
| Event mutation/reorder/delete | Runtime privilege/trigger rejects mutation; hash verification fails | PostgreSQL ledger | integration |
| Tenant cursor race | Locked tenant cursor produces contiguous commit order | PostgreSQL | integration |
| Projection corruption/loss | Rebuild from verified events; projection is never source truth | Application reducer | unit + eval |
| Tampered/wrong cursor | HMAC/tenant/run binding rejects cursor | Application API | unit/API |
| Cross-tenant ledger/API read | Current policy and forced RLS hide object | Policy/PostgreSQL | unit/integration |
| Outbox worker crash | Claim expires and another worker reclaims | Application outbox | unit |
| Repeated delivery failure | Fifth failure becomes explicit dead letter | Application outbox | unit |
| Temporal unavailable | Intent/outbox remain pending; API stays queued, never claims completion | Application database | documented/dispatcher test |
| Duplicate Temporal start | Stable workflow ID and conflict policy reuse current execution | Application + Temporal | adapter/integration |
| Worker absent/crashes | Temporal retains work; compatible worker replays and resumes | Temporal | integration |
| Activity transient failure | Temporal retries up to three attempts with same operation/budget IDs | Temporal + application idempotency | integration/eval |
| Activity poison/framework defect | Non-retryable typed failure; worker process survives | Activity adapter | unit |
| Activity heartbeat timeout | Temporal retries bounded attempt | Temporal | configuration/integration boundary |
| Workflow timer expiry | `timed_out` application event; no silent success | Temporal timer + application event | integration |
| Duplicate resume signal | Workflow set and inbox suppress duplicate command | Temporal + application inbox | integration/unit |
| Forged signal payload | Signal reference is reloaded from inbox and current signaller reauthorized | Application authority | unit/eval |
| Policy revoked during wait | Resume Activity denies; workflow fails safely | Current policy | eval |
| Cancellation/result race | Persisted cancel transition rejects stale graph result | Application aggregate state machine | unit/eval |
| Temporal history loss | Reconcile pending application intent using same workflow/message IDs; never infer completion | Application ledger | documented boundary |
| LangGraph checkpoint loss | Bounded graph Activity may rerun under stable operation/budget; checkpoint is not truth | LangGraph + application idempotency | eval/documented |
| Workflow code incompatibility | Replay test fails release; patch/version strategy required | Temporal deployment | integration |
| Oversized/malformed payload | Pydantic/codec rejects before handler; no unbounded allocation | Application converter | unit |
| Evidence tenant/hash mismatch | Activity fails before LangGraph | Application evidence validation | inherited unit tests |
| Budget exhausted | Authorization Activity records fail-closed outcome before evidence/graph | Application budget | eval |
| Audit/ledger unavailable | Operation cannot be represented as durable success | PostgreSQL | fail-closed adapter |
| OTel/Langfuse unavailable | Product truth unaffected; export remains optional | Observability adapter | non-authoritative |

## Retry rules

The application dispatcher retries command delivery. Temporal retries whole Activities.
LangGraph owns graph checkpoints but not a second retry loop. Connector/provider retries
must be disabled or included in the Activity attempt. No framework retry converts an
at-least-once external operation into exactly-once behavior.

## Operator rules

- Never edit an immutable event, idempotency row, or inbox fact.
- Never report Temporal `COMPLETED` as product completion without the application event.
- Never bypass current policy/budget to recover availability.
- Never switch silently to memory persistence.
- Treat hash failure, cross-tenant access, stale results, and framework defects as
  platform/security incidents.
