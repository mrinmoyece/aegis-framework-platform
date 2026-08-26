# Layer 7 approval and controlled-effect runbook

This runbook operates the application approval/effect lifecycle. It does not authorize
enabling live Kubernetes credentials. The official-client adapter is disabled by
default; local tests use deterministic doubles and no cluster or network.

## Non-negotiable authority order

1. Establish current `IdentityContext` at the API boundary.
2. Authorize the proposal/request/decision/read command.
3. Persist the immutable plan and current policy decision.
4. Open an exact-digest approval outside LangGraph.
5. Require distinct current human approvers, SoD, role/purpose, bounded rationale,
   expiry, optional no-self-approval, and configured quorum.
6. Reload plan, action, approval, target, policy, role and quota revisions immediately
   before effect; any change invalidates approval.
7. Reserve tenant effect quota and persist effect intent before I/O.
8. Observe target, perform mandatory dry-run, fence the worker attempt, then execute one
   fixed action through `ActionPort`.
9. Persist success, failure, or ambiguity; never infer success from Temporal or API
   acceptance.
10. Verify from fresh evidence and postconditions. Roll back only through the separately
    bound compensation contract; otherwise escalate.

## Approval investigation

- Use the authenticated `/v1/approvals/{approval_id}` view. It exposes opaque plan and
  approval references, status, quorum/count, expiry, and canonical digests. It omits
  tenant, actor, rationale, evidence, target, and receipt details.
- A missing, unauthorized, or cross-tenant approval is always `404`.
- Do not edit an approval or decision. A role, policy, plan, action, target fingerprint,
  digest, or expiry change requires a new approval request.
- Duplicate command ID with identical content is a replay. A changed decision under the
  same command ID is a security/idempotency conflict.
- One human can contribute at most one decision. A deny is terminal. Revocation is an
  additive fact and must reach the workflow before execution.

## Stuck approval wait

1. Read the application projection and immutable decisions under tenant RLS.
2. Inspect Temporal only for operational scheduling. Its `waiting_for_approval` query is
   not approval truth.
3. Confirm the decision command was persisted before signalling.
4. Re-send the same opaque command reference if delivery is uncertain; do not create a
   second decision.
5. If the timer expired, preserve `approval_expired`; do not extend it in place.
6. If history is lost, restart from application intent with the same workflow/command
   identities or escalate. Never reconstruct approval from history.

## Ambiguous external effect

An Activity timeout, worker crash, or transport error after request delivery can mean the
effect occurred. Treat it as `execution_ambiguous`.

1. Block automatic retry and fallback.
2. Verify tenant, plan/action/approval/policy digests and the current fence.
3. Observe the exact target using provider read APIs and the stable idempotency key.
4. If read-after-write proves the requested state, append `reconciliation_resolved` and
   continue to fresh verification.
5. If observation proves no application and preconditions still hold, an operator may
   authorize a bounded retry under the same idempotency key and a new fenced attempt.
6. If observation conflicts or remains unknown, append `escalated`. Do not claim
   exactly-once behavior.

## Verification failure and rollback

- API acceptance or a Deployment patch response is not recovery.
- Verification must occur after the effect receipt and cite fresh evidence. Evaluate the
  immutable postconditions in application code.
- On failure, append `verification_failed`. If the plan has an independently approved,
  exact compensation contract, persist rollback intent, fence the attempt, execute, and
  verify recovery.
- A rollout restart has no intrinsic inverse. The production-shaped adapter therefore
  rejects rollback unless a separately designed fixed revision action exists. The
  deterministic fake demonstrates compensation mechanics only.
- Failed or ambiguous compensation is `escalated`, never success.

## Cancellation and stale workers

Persist cancellation intent before signalling Temporal. Activities heartbeat and check
cancellation at boundaries. Cancellation cannot undo an already completed effect.
Reject any result whose attempt, claim token, fence, action digest, approval digest, or
policy digest does not match the current application record.

## Projection rebuild

Verify immutable fact sequence and previous-digest chain, fold with
`reduce_remediation`, compare the rebuilt projection, record a tenant-scoped rebuild
fact, then swap. Never rebuild from Temporal history, LangGraph checkpoints, Kubernetes
events, traces, or logs.

## Escalate immediately

Treat cross-tenant visibility, forged/replayed decisions, digest mismatch, approval
self-grant, stale fence acceptance, duplicate conflicting receipt, RLS bypass, immutable
row mutation, unexplained external state, or trace payload leakage as security/platform
incidents. Redact tenant/actor/request IDs, evidence locators, credentials, payloads,
approval rationale, and provider receipts from tickets and telemetry.
