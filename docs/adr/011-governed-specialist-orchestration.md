# ADR 011: Use LangGraph for governed fixed-role specialist orchestration

- Status: accepted
- Date: 2026-08-16

## Context

Layer 6 needs four independent specialist assessments, synchronized critic review,
proposal-only remediation planning, verification planning, deterministic replay, and
bounded failure containment. Reimplementing parallel super-steps, joins, reducers,
routing, and checkpoint traversal would duplicate graph-engine mechanics. A framework
must not become authority for identity, roles, capabilities, artifacts, audit, approval,
or production effects.

LangGraph 1.2.11, `langgraph-checkpoint` 4.2.0, PostgreSQL saver 3.1.2, and
LangChain Core 1.5.5 were rechecked against current official docs/package metadata.
`StateGraph`, typed reducers, conditional edges, checkpoints, state history, and
`recursion_limit` are stable public APIs. `Send`, `Command`, subgraphs, and
`interrupt()` are stable, but are not needed by this fixed topology. `DeltaChannel` and
the Temporal LangGraph plugin are beta/experimental and are not used.

## Decision

Use a statically declared `StateGraph` with explicit fan-out to telemetry, change,
runtime, and knowledge specialists and list-edge fan-in to one critic. Use a
commutative/deterministically sorted reducer for findings, errors, and artifacts.
Conditional routing sends accepted cited hypotheses through a remediation planner and
verification-plan node; all other outcomes go directly to the coordinator decision.

The application defines immutable artifact envelopes, eight fixed roles, role write
capabilities, allowed artifact transitions, fan-out/iteration/artifact/context bounds,
confidence and citation gates, graph version `6.0.0`, deterministic ordinals/digests,
and complete/abstain/escalate terminal semantics. No schema supports peer free chat,
dynamic role creation, approval, credentials, policy mutation, or effect execution.

PostgreSQL application facts record run intent, task dispatch before model work,
attempt-scoped fenced task result, artifacts, decisions, and projection rebuild. A
reconciliation transition rotates the fence so an abandoned worker cannot overwrite it.
Concurrent first-run intent uses conflict-safe insert plus locked reread. Forced RLS
scopes all rows.
Checkpoint transactions and orchestration-ledger writes use separate bounded pools so
parallel specialist writes cannot wait behind a connection held for the graph run.
LangGraph checkpoints are tenant/run bound and compatible only when graph version and
input digest match. They remain disposable framework state.

Temporal owns the long-running workflow, Activity retry/heartbeat, signals,
cancellation, and replay. It invokes one bounded graph Activity. LangGraph node retry is
disabled; provider retry remains disabled. The experimental Temporal LangGraph plugin
is rejected for this layer because it would partition nodes into Temporal Activities and
overlap the existing application intent/result boundary.

Cancellation is an independent application flag: it blocks new task/artifact results
without erasing an already recorded cognitive decision. A cancellation racing the graph
returns an explicit cancelled result and never fabricates a completed workflow outcome.

## Consequences

LangGraph removes custom DAG scheduling, synchronized join, reducer execution,
conditional routing, checkpoint serialization, and state-history traversal. It adds
Pregel super-step semantics, saver schema, node-name compatibility, dependency upgrade,
and checkpoint migration/retention work. Renaming/removing a node can strand an
in-flight checkpoint; releases retain graph version compatibility and replay fixtures.

The custom Layer 7 comparison remains candid: role policy, artifact schemas/transitions,
tenant RLS, dispatch/result facts, fencing, budgets, citations, redaction, projection
rebuild, Temporal ownership, and effect separation are still application code.

## Escape

`OrchestratorPort`, neutral `GovernanceArtifact` JSON, application orchestration facts,
and deterministic evals isolate LangGraph. Rebuild projections from application facts,
discard framework checkpoints, implement the same fixed DAG behind the port, and pass
the fan-out/order/replay/version/tenant/cancellation/critic suite. No authorization,
audit, cost, artifact, or decision truth must be extracted from LangGraph first.
