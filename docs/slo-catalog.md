# Layer 11 SLI/SLO catalog

The machine-readable source is `src/aegis_framework/slos.py`; Prometheus rules are in
`observability/prometheus/rules/aegis-slos.yaml`.

| SLO | Objective / window | Good event | Runbook |
|---|---|---|---|
| API availability | 99.9% / 28d | authorized response is success/deny/validation within 2s | [API](runbooks/api-availability.md) |
| Safe execution | 100% / 28d | approval, fence, idempotency and receipt all validate | [Safety](runbooks/safety-violation.md) |
| Durable freshness | 99.9% / 28d | accepted command projected within 30s | [Durability](runbooks/durable-freshness.md) |
| Evidence completeness | 99.5% / 28d | query completes with valid provenance/citations | [Evidence](runbooks/evidence-health.md) |
| Model gateway | 99.0% / 28d | validated structured result or explicit abstention | [Gateway](runbooks/model-gateway.md) |
| Approval/effect convergence | 99.9% / 28d | terminal state reconciles to durable receipt | [Approval/effect](runbooks/approval-effect.md) |
| Sandbox cleanup | 99.9% / 28d | terminal sandbox is cleaned within 15m | [Sandbox](runbooks/sandbox-cleanup.md) |
| Memory retrieval | 99.0% / 28d | cited context or explicit empty result within 1s | [Memory](runbooks/memory-retrieval.md) |
| Evaluation health | 99.0% / 28d | current deterministic suite finishes before expiry | [Evaluation](runbooks/evaluation-health.md) |

Fast burn is 14.4x on both 5m and 1h windows. Slow burn is 6x on both 30m and
6h windows. Error-budget exhaustion freezes reliability-risking releases. Safety,
tenant isolation, unauthorized effects, integrity, and cleanup violations page
immediately and are not availability tradeoffs.

Layer 14 adds operational release gates rather than new product SLO claims:

- Temporal queue schedule-to-start objective below 30 seconds;
- PostgreSQL guarded connection use below 70%;
- zero unverified/mutable-image admissions;
- restore drill objective RPO 5 minutes and RTO 60 minutes;
- sandbox cleanup and stale-generation violations remain non-budgetable.

These are objectives/configuration until measured in an operated environment. Local
rules, mock plans, and deterministic drills do not establish SLO performance or on-call
readiness.
