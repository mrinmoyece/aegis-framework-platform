# Bounded performance and chaos qualification

## Performance

`qualification/performance-profiles.json` defines eight local real-path drivers and
four environment gates. Local drivers use at least 20 fixed serial samples and report
p50/p95/p99, serial iterations per second and error rate. The rate is the inverse of
mean serial latency, not concurrent throughput. Budgets are CI regression limits, not
SLOs or production capacity estimates. Samples exclude network latency, process
startup, noisy neighbors, managed-service quotas and scaling.

Fresh PostgreSQL/pgvector, Temporal, browser/UI and logical restore evidence must use
their named commands. Production capacity additionally requires representative data
volume, tenant mix, concurrency, provider quotas, storage growth and saturation/
recovery curves.

## Chaos

`qualification/chaos-matrix.json` covers all existing deterministic fault points:
intent/effect/result, projection/outbox, Activity/signal/timer/heartbeat, LangGraph
checkpoint, provider/connector/action/sandbox, embedding/index/cache. Every scenario
requires convergence, zero unauthorized effects, bounded duplicates, tenant
isolation, complete audit and cleanup; ambiguous effect cuts require reconciliation.

Repository cases additionally exercise policy/protocol revocation, telemetry outage,
replay convergence and stale work. PostgreSQL transient failure, real worker loss,
network partitions, sandbox orphan processes and region generation fencing still
require environment/live chaos. The generated report explicitly sets
`production_chaos_claim` to false. Its convergence/count fields come from the existing
deterministic fault contract model and are labeled `contract_model_simulation`; the
listed real-path eval cases are the regression signal.
