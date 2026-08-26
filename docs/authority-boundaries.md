# Layer 3 authority and retry ownership

## Ownership matrix

| Fact or mechanic | Authoritative owner | Framework copy allowed? | Recovery source |
|---|---|---:|---|
| Current identity/tenant/grants | Application identity store | Opaque references only | Identity repository |
| Run/checkpoint-read authorization | `PolicyPort` current evaluation | Decision may be observed, never reused as grant | Current policy/grants |
| Budget reservation | PostgreSQL quota reservation | Reservation reference only | Application database |
| Application intent/outcome | Append-only application events | Reference only | Event ledger |
| Tenant/aggregate order and integrity | Ledger heads/cursors/hash chains | No | Event ledger |
| Command idempotency | Application idempotency/inbox | IDs may route messages | Application database |
| Delivery retry/DLQ | Application outbox claim record | Temporal also retries Activities, not command delivery facts | Application database |
| Cross-process schedule/timer/signal | Temporal history | Yes | Temporal |
| Activity result fact | Application event after Activity | Temporal return reference only | Event ledger |
| Cognitive node progress | LangGraph checkpoint | Yes | LangGraph saver |
| Hypothesis/proposal | Domain result with citations | Yes, non-authoritative candidate | Application result event |
| API status/timeline | Rebuildable application projection | Temporal query is convenience only | Event replay |
| Audit | Application PostgreSQL audit/ledger | No | Application database |
| Approval/effect/fencing/receipt | Not implemented in Layer 3 | Never | Future application layer |

## Retry matrix

| Boundary | Retry owner | Limit/idempotency |
|---|---|---|
| HTTP durable command | Caller may retry | Tenant/request fingerprint returns the same run |
| Outbox to Temporal | Application dispatcher | Five claims, stable workflow/message ID, DLQ |
| Workflow task | Temporal | Deterministic replay; no application fact inferred |
| Activity | Temporal | Three attempts, timeout/heartbeat, stable operation ID |
| Evidence connector call | Activity only | Connector SDK retries disabled or counted inside Activity limit |
| LangGraph run | One Activity attempt | No Temporal per-node retry and no graph retry loop |
| Signal | Temporal may redeliver | Workflow command-reference set + application inbox |
| Projection | Application replay | Cursor/hash checkpoint; deterministic reducer |

## Non-negotiable call order

1. Establish `IdentityContext` at delivery.
2. Authorize current command.
3. Persist idempotency, event, projection, and outbox atomically.
4. Dispatch using a tenant-scoped claim.
5. Resolve opaque references and reauthorize immediately before every Activity.
6. Reserve budget before evidence or graph work; retry reuses the run reservation.
7. Persist Activity intent before I/O and result/failure afterward.
8. Serve status/timeline only from authorized application projections.

A Temporal signal, workflow query, history event, LangGraph checkpoint, model output, or
trace cannot change this order or grant authority.
