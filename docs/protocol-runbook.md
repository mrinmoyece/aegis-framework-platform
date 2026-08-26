# MCP and A2A interoperability runbook

## Activation gate

Network interoperability is disabled unless all of these are true:

1. the peer has a current reviewed tenant registry revision;
2. owner, environment, tier, expiry, classifications, risks, capabilities, origin,
   card/schema/certificate/key digests, and quotas match the request;
3. OIDC/workload issuer, audience, scopes, tenant reference, purpose, proof and replay
   checks pass current application RBAC;
4. mTLS, distributed token replay, secret brokerage, DNS/egress, Temporal, PostgreSQL,
   and audit readiness probes are healthy;
5. no quarantine, revocation, expiry, drift, or emergency disable is active.

No operator action here approves or executes remediation.

## Peer onboarding and review

Create a pending registry revision from out-of-band partner evidence. Fetch no URL from
peer/model content. Verify the A2A detached JWS with an explicit ES256/PS256 allowlist,
then pin the neutral card digest and key/certificate digests. Review exact capabilities,
schema, risk, classification, egress, timeout, quota, and expiry.

In the operator workspace, type `TRUST PEER_ID`. Any changed digest creates a new
pending revision; it does not inherit approval.

## Quarantine, revoke, emergency disable

- Quarantine on schema/card/certificate/key drift, forged artifact, invalid citation,
  Unicode/schema bomb, MIME/URL violation, tenant mismatch, or repeated malformed data.
  Type `QUARANTINE PEER_ID`.
- Revoke after confirmed compromise, ownership termination, or unacceptable behavior.
  Type `REVOKE PEER_ID`.
- Emergency disable for active exploitation or denial-of-wallet. Type
  `DISABLE PEER_ID`.

All transitions advance registry revision. In-flight Activities reauthorize. Stale
results fail fencing and move to reconciliation/quarantine; never treat disable as proof
that external work stopped.

## Ambiguous network outcome

1. Confirm application `invocation_requested` and `invocation_claimed` facts precede I/O.
2. Do not resend. Preserve request/trust/policy/idempotency/fence digests.
3. For A2A, poll `GetTask` or snapshot-first subscribe under the same registered peer and
   task reference. For MCP, use the application-owned status handle; protocol sessions
   are not authority.
4. Append reconciled success/failure only after bounded observation. Otherwise retain
   `reconciliation-required` and escalate.
5. Quarantine conflicting task/artifact/card/capability provenance.

## Security incident

Never put raw messages, tool descriptions, artifacts, URLs, tenant/actor/request IDs,
tokens, secrets, or evidence locators in traces or tickets. Preserve digest-only facts,
registry revisions, status/error codes, count/byte buckets, and approved evidence
references. Rotate secret/certificate/key revisions out of band and require new review.

Public federation, production PKI/token brokerage, partner qualification, deployment,
and independent conformance/security certification are not provided by this runbook.
