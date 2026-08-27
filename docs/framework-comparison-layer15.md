# Framework Layer 15 versus custom Aegis Layer 16

Comparison basis: framework release `4f4b8924247367f959c910f8261baea3337967d6`
on parent `60b120c6c6348044e716a2cc79e679b6bd29b758`; custom
`mrinmoyece/aegis-agent-platform` PR 18 at
`1cccd9363fec83f7f4b2748b0e913be3a123d5ce`. Measurements use physical lines
including comments/blanks and are not code-efficiency ratios.

The custom baseline reports an 11-stage, 203-event, nine-stream journey, 127 eval
cases, 17 chaos branches, 12 local performance profiles, 24 readiness categories, six
hard gates, eleven open risks and twelve compliance mappings. Its Layer 16
qualification runtime is 1,557 physical Python lines. Its repository uses 14 direct
runtime dependencies, PostgreSQL/pgvector and Redis, with no orchestration framework.

Framework Layer 15 deliberately reuses the existing 58 real cross-layer cases and
application services rather than copying 127 custom cases or manufacturing event-count
parity. Its comparable output has 17 fault points and 12 capacity profiles; four are
environment-gated. Counts are disclosed, not manipulated.

## Where frameworks accelerated

- Temporal replaces custom queue lease, heartbeat, timer, signal and workflow recovery
  mechanics.
- LangGraph replaces generic bounded fanout/fanin/checkpoint scheduling.
- FastAPI, Pydantic, OTel, MCP/A2A SDKs and React/TanStack supply protocol, validation,
  delivery and UI mechanics.

## Where frameworks increased complexity

- Temporal Cloud adds namespace, payload-codec, mTLS/API key, retention, versioning,
  capacity, cost and failover qualification.
- LangGraph checkpoints introduce compatibility/migration state that cannot become
  authority.
- Official SDK dependency trees increase supply-chain and upgrade surface.
- Framework and application retry/state ownership must be kept explicit.

Identity/RLS, application events, budgets, evidence/provenance/citations, approval,
fencing, effects, reconciliation, sandbox policy, memory lifecycle, protocol trust,
telemetry redaction and release evidence remain application-owned in both designs.

## Lock-in and escape

Escape requires versioned neutral contracts, PostgreSQL event export, ledger-grounded
rebuild without Temporal/LangGraph objects, replay compatibility, outage fail-closed
tests and an operated migration rehearsal. Current live export/replacement rehearsal
is still required; local application-ledger replay proves the architectural seam, not
production portability.
