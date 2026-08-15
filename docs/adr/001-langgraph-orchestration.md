# ADR 001: Use LangGraph for bounded investigation orchestration

- Status: accepted
- Date: 2026-08-15

## Context

Layer 1 needs typed state, a fixed coordinator, parallel telemetry/change specialists,
a synchronized critic, deterministic tests, and checkpoint visibility. It does not
need model-selected topology or an unbounded conversational agent.

## Decision

Use LangGraph 1.2.11 with a statically declared graph and JSON-compatible state.
Use `InMemorySaver` only for network-free demo/tests and provide a PostgreSQL saver
adapter. Keep policy, tenant authority, budget, evidence access, idempotency,
approval, audit, and effects outside LangGraph behind application protocols. Layer 4
structured nodes use `GatewayStructuredModel`; model policy, catalog, reservation,
routing, usage, and provider adapters remain outside graph state.

## Consequences

LangGraph removes custom scheduler, fan-out/join, reducer, and checkpoint traversal
code. We accept its Pregel-style super-step semantics, saver schema, state API, and
upgrade surface. Reducers explicitly sort output. The graph has no loop and uses a
secondary recursion bound.

Checkpoint state is not authorization, approval, audit, or exactly-once execution.
Value streaming is not enabled because official guidance notes private channels are
included unless outputs are filtered.

## Escape

`OrchestratorPort` returns domain `InvestigationResult`. Only `graph.py` and
`postgres.py` import LangGraph. A replacement engine must pass the same evals and
checkpoint/idempotency tests.
