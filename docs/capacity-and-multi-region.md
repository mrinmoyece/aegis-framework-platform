# Capacity, scaling, and bounded multi-region

## Capacity and backpressure

`CapacityPlan` fails when configured PostgreSQL pools exceed guarded connections after
30% headroom. Each task queue has explicit replica, workflow/activity concurrency,
activity rate, and task-queue rate bounds. API and worker HPAs scale slowly down.
Temporal schedule-to-start latency, not CPU alone, is the primary worker saturation
signal; queue-specific scaling needs an authenticated low-cardinality metric adapter.

No queue may create a second retry authority. Provider SDK retry is disabled; Temporal
Activity attempts, application intent/idempotency, and reconciliation remain bounded.
On saturation: stop accepting low-priority work, preserve reserved budgets, reduce
connector/provider concurrency, honor `Retry-After`, open circuits, and keep
remediation/sandbox cleanup capacity isolated. Do not increase all HPA, DB pool, and
Temporal concurrency limits simultaneously.

Tenant partitions are explicit deployment configuration, sorted, unique, and owned by
one worker group at a time. High-volume tenants require a reviewed dedicated partition,
quota, queue, and DB budget. No global exact spend or fairness claim is made.

Temporal sticky queues/cache improve workflow latency but are disposable. A worker
drain removes readiness, stops new polls through the enterprise bootstrap, allows up to
90 seconds, then Temporal reschedules tasks. LangGraph checkpoints and model results
still require application compatibility/fences.

## Multi-region

Normal operation has one home-region RDS writer and one monotonic deployment
generation. Regional API edges/workers are stateless and route commands to the home
region. Every writer/effect claim is checked against current generation/fence.
Temporal uses one namespace per region; only the active namespace receives new
application outbox starts. Existing workflows in another namespace are reconciled from
application intent, never copied as audit truth.

Failover requires:

1. approved incident/change and residency-compatible target;
2. source ingress and writer fenced;
3. backup/replica promoted into an isolated target and dual ledger chains/sequences
   verified;
4. new generation committed before target writes;
5. projections/vector indexes/LangGraph checkpoints rebuilt from ledger/object data;
6. Temporal outbox/workflows/schedules reconciled without blind duplicate starts;
7. ambiguous effects/provider calls/sandbox cleanup reconciled;
8. routing changed only after readiness and safety gates.

Failback is a new failover with a new generation. Never lower/reuse a generation.
Split-brain, stale DNS, delayed clients, clock skew, KMS/secret residency, and network
partitions are deny conditions. Active-active ledger writes, conflict-free tenant
merging, cross-region synchronous budget order, and exact global cost are not designed.

