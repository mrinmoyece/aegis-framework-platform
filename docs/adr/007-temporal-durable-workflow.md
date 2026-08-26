# ADR 007: Adopt Temporal for the cross-process investigation lifecycle

- Status: accepted
- Date: 2026-08-15
- Supersedes: ADR 002 for Layer 3 lifecycle scheduling

## Context

Layer 3 must survive worker/process loss, own bounded Activity retry/backoff, wait on a
durable timer, receive duplicate signals, recover after deployment, and replay workflow
code deterministically. Implementing these mechanics with database leases and a custom
queue is possible but recreates a workflow engine. LangGraph checkpoints do not provide
cross-process timers, Activity heartbeat/cancellation, or durable message history.

Official sources refreshed on 2026-08-15 identify Temporal Python SDK 1.31.0 as the
current stable SDK with Python 3.10-3.14 support. Temporal Server 1.31.0 is current, but
the official Docker Compose reference remains `auto-setup:1.29.1`. The SDK/server pair
is within Temporal's supported compatibility window for the APIs used here.

## Decision

Use exact-pinned `temporalio[opentelemetry,pydantic]==1.31.0`. The optional local server
is `temporalio/auto-setup:1.29.1` pinned to multi-architecture digest
`sha256:5b3502a3b685f9eff1b925af90c57c9e3dbeccbef367cc28a2a9712c63379312`.

Temporal owns the bounded cross-process lifecycle, timers, signals, Activity
retry/timeout/heartbeat, and workflow replay. One Activity invokes the existing
LangGraph graph. PostgreSQL application events remain status/audit/idempotency truth.
Every Activity reauthorizes current application identity/policy and uses stable
operation IDs. Signals are references to persisted commands, not trusted authority.

Workflow payloads use strict Pydantic conversion plus a 64 KiB codec bound and contain
only opaque references. Tenant routing is authenticated-encrypted with a separately
injected application key; actor/request references are hash-derived. No tenant ID or
other sensitive value is indexed as a search attribute. The sandbox remains enabled.
`workflow.patched` establishes the first replay version; representative histories are
replayed in integration CI.

## Retry and history decisions

Temporal retries whole Activities at most three times. LangGraph has no overlapping
retry loop. Provider SDK retry must be disabled or included in the Activity budget.
The bounded one-investigation/32-signal/two-day workflow does not justify
continue-as-new. Revisit only from measured history growth.

## Consequences

Temporal removes custom scheduler, poller, timer, heartbeat, signal-history,
retry/backoff, and worker-recovery code. It adds a second stateful service, schema
operations, upgrade/replay qualification, task-queue capacity, and operational
monitoring. Activities remain at-least-once and application idempotency is still
required. Temporal history is not application audit or external-effect truth.

## Escape

`ActivityOperations`, opaque typed messages, and the transactional application outbox
form the escape hatch. A replacement must consume the same application intent and pass
the recovery/retry/signal/timer/replay suite. Application events/projections require no
Temporal export to remain usable.
