# ADR 002: Defer Temporal until durable effects

- Status: superseded for the Layer 3 lifecycle by ADR 007
- Date: 2026-08-15

## Context

Temporal Python 1.31.0 provides durable workflow replay across process failures and
long waits. Operating it also requires a Temporal Server cluster and datastore.
Layer 1 has a short investigation, no production activity, and no long-lived approval
decision.

## Decision

Do not run Temporal in Layer 1. LangGraph owns investigation node/checkpoint
orchestration. Introduce Temporal when approval, controlled execution, verification,
and reconciliation must survive process/service/deployment boundaries.

The future shape is:

1. Temporal workflow owns incident lifecycle and durable wait;
2. a bounded investigation Activity calls LangGraph;
3. separate idempotent Activities request approval, execute with fencing, and verify;
4. application audit records authoritative transitions.

Do not let Temporal retry individual LangGraph nodes, and do not let LangGraph retry a
Temporal effect workflow.

## Consequences

Layer 1 avoids an unjustified cluster and overlapping retry owner. It does not claim
crash-resilient external workflows. Temporal Activities remain at-least-once in
practice and will still require idempotency/fencing; workflow replay is not effect
exactly-once.

## Revisit trigger

Revisit when Layer 2 adds a real approval wait or an effect spans processes, exceeds
the HTTP request lifetime, or must resume after a deployment.

Layer 3 met the process/deployment recovery, timer, and signal portion of this trigger
without adding effects. [ADR 007](007-temporal-durable-workflow.md) adopts Temporal
around the bounded investigation while preserving the no-effect boundary.
