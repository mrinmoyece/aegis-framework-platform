# ADR 016: Provider-neutral observability and ledger replay

- Status: Accepted
- Date: 2026-08-17

## Context

Layers 1-10 already emit fixed manual OTel/Langfuse observations and preserve
application facts independently of Temporal and LangGraph. Enterprise operation needs
one stable vocabulary, bounded metrics and logs, SLOs, dashboards, authenticated
support views, and deterministic debugging without turning telemetry into authority.

Langfuse offers useful self-hostable model/graph trace UX and sanitized evaluation
publication. LangSmith provides close LangGraph integration but its commercial
self-hosted control plane and automatic capture conflict with the repository privacy
boundary. Neither product should become application truth.

## Decision

1. Aegis owns versioned neutral semantic conventions, attribute allowlists, sampling,
   propagation, links, metric definitions, SLOs, and replay contracts.
2. OTel is the portable signal boundary. Prometheus stores neutral metrics and Grafana
   renders provisioned dashboards. Exporters are optional and bounded.
3. Langfuse remains an opt-in trace/evaluation UX through manual sanitized adapters.
   Automatic LangGraph/LangChain tracing stays disabled. LangSmith is not added.
4. Trace references may be stored durably only as validated opaque coordinates. They
   are navigation hints, never authorization, approval, audit, fencing, or receipts.
5. The application ledger is replay truth. Temporal history and LangGraph checkpoints
   remain framework recovery mechanisms, not sources for application reconstruction.
6. Replay validates tenant cursor, aggregate sequence, schema version, both hash
   chains, and record hashes before deriving state. It never invokes models,
   connectors, sandboxes, tools, or effects.
7. Safety violations page immediately and never consume availability error budget.

## Consequences

- Telemetry outages produce degraded operations visibility but cannot block or alter
  correctness decisions.
- New dimensions require semantic-version review, tests, and cardinality-budget review.
- Operators must authenticate and authorize support/replay reads; privileged reads are
  audited and anti-enumerating.
- Compose is a local qualification topology, not evidence of managed-backend,
  production SLO, or on-call readiness.

## Escape and replacement

Any OTLP backend can replace Langfuse. Any Prometheus-compatible metrics store and
Grafana-compatible dashboard workflow can replace the local services. Replacements
must preserve redaction, stable dimensions, bounded queues/retries, failure containment,
and ledger-grounded replay. Removing Temporal or LangGraph does not change replay truth.
