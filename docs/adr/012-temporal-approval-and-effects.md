# ADR 012: Use Temporal for approval waits and controlled effects

- Status: accepted
- Date: 2026-08-16

## Context

Layer 7 introduces an exact-scope human approval that can wait hours, receive duplicate
or forged commands, expire or be revoked, and then coordinate preflight, one external
effect, reconciliation, verification, cancellation, and compensation across worker
loss and deployments. Recreating durable timers, signal history, Activity heartbeat,
retry/backoff, cancellation delivery, and deterministic recovery in PostgreSQL would be
a second workflow engine. LangGraph checkpoints do not provide these mechanics and must
never approve or execute a remediation.

Temporal Activities remain at-least-once. Temporal history is not a policy decision,
approval, fencing token, audit fact, effect receipt, or verification record.

## Decision

Extend the selected Temporal Python SDK 1.31.0 with
`AegisRemediationWorkflow` (`aegis.remediation.v1`). The workflow:

1. records an approval request through an application Activity;
2. durably waits for an opaque approval-command reference with a bounded timer;
3. reloads the immutable decision and current identity, role, policy, quota, exact plan,
   action, target, and digest bindings from PostgreSQL;
4. schedules preflight/dry-run, execution, ambiguous-outcome reconciliation, fresh
   verification, cancellation, and compensation Activities;
5. returns only opaque references and operational status.

Signals carry only command references. Activities reauthorize immediately before an
effect. Application code persists requested intent before I/O and a receipt or explicit
ambiguity afterward. Temporal owns three-attempt Activity retry, timeouts, heartbeat,
cancellation delivery, workflow replay, and the `aegis-remediation-lifecycle-v1` patch
marker. The action adapter owns no retry loop. Observe-before-retry and read-after-write
are application controls.

PostgreSQL application contracts remain authoritative: immutable plans, approval
requests and decisions, effect facts/receipts, verification records, tenant-scoped
idempotency and fences, quotas, and rebuildable projections. `ActionPort` isolates
external providers. The only production-shaped adapter is a disabled-by-default,
fixed-shape official Kubernetes client operation for an exact Deployment rollout
restart. It cannot accept a shell command, arbitrary URL, kubeconfig exec plugin, object
kind, namespace, name, UID, resource version, or patch body from a model.

## Consequences

Temporal eliminates custom approval pollers, durable sleep/timer state, signal
deduplication history, Activity scheduling, retry/backoff, heartbeat, cancellation
delivery, crash recovery, and workflow replay. It adds a stateful service, task-queue and
namespace operations, history retention, replay/Worker Versioning qualification, and
signal/history lock-in.

Most security-sensitive code remains application-owned: exact-scope digests, current
policy, maintenance windows, allowlists, risk/blast thresholds, quota, evidence/critic
gates, SoD/quorum, anti-enumeration, immutable audit, idempotency, fencing, ambiguous
outcomes, reconciliation, verification, rollback policy, RLS, and redaction. No
exactly-once effect claim is made.

## Rejected alternatives

- LangGraph `interrupt()` is not an approval store, identity boundary, timer service, or
  effect ledger; using it would let cognitive state appear authoritative.
- A PostgreSQL/Redis approval poller would duplicate workflow scheduling and recovery.
- The experimental Temporal LangGraph plugin would split graph nodes into Activities and
  overlap existing retry/intent ownership.
- CrewAI, AutoGen, or another workflow/agent framework would overlap LangGraph/Temporal
  without removing enterprise controls.
- Shell, `kubectl`, arbitrary Kubernetes patch, generic HTTP webhook, MCP, or A2A effect
  adapters are outside the exact action contract and remain deferred.

## Escape

The application outbox, opaque workflow/activity messages, `RemediationActivityOperations`,
`ActionPort`, immutable SQL facts, and pure `reduce_remediation` fold form the escape
path. Rebuild application projections from PostgreSQL, replace Temporal with a scheduler
that passes wait/timer/signal/retry/heartbeat/cancellation/crash/replay equivalence, and
discard Temporal history. No approval or effect truth must be extracted from Temporal
first.
