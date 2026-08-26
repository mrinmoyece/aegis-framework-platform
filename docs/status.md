# Layer 3 qualification status

## Delivered

- immutable additive application events with aggregate sequence, tenant cursor, dual
  hash chains, expected-version concurrency, legacy upcast, and deterministic rebuild;
- tenant-scoped idempotency, inbox/outbox, lease claims, retries, dead-letter state,
  projection checkpoints, and redacted cursor API;
- Temporal SDK 1.31.0 workflow around one bounded LangGraph Activity lifecycle;
- durable wait/resume/cancel/timeout, duplicate signal handling, Activity heartbeat and
  retry bounds, workflow patch marker, payload limits, and replay test;
- current policy checks at commands and immediately before every Activity;
- forced RLS/non-bypass runtime role for all Layer 3 PostgreSQL tables;
- optional digest-pinned Temporal 1.29.1 Compose server and CI integration job;
- provider-neutral worker runtime that drains explicitly configured trusted tenant
  partitions; it is an embeddable runtime rather than a production CLI because live
  evidence/model adapters are deliberately deferred;
- manual OTel/optional Langfuse privacy boundary with no payload export.

## Qualification snapshot

- 138 deterministic tests pass with 91.61% branch coverage;
- 13 deterministic evals pass;
- four local PostgreSQL integration tests pass;
- two local Temporal integration tests cover no-worker recovery, Activity retry,
  duplicate signal, cancellation, timeout, replay, and the real application
  outbox/Activity/projection path;
- one Keycloak compatibility test remains environment-gated.

Counts are refreshed by the final release run and recorded in
`comparison/layer3-metrics.json`.

## Not proven

Production Temporal HA/upgrade/failover, PostgreSQL HA/PITR/restore, multi-region order,
load/capacity, WORM witnessing, retention/erasure execution, live IdP rotation, live
evidence/model credentials, approvals/effects/fencing/reconciliation, sandbox tools,
memory/RAG, UI/BFF, MCP/A2A, and deployment admission remain unproven.
