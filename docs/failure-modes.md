# Failure modes

| Failure | Layer 2 behavior | Authority owner | Test/eval |
|---|---|---|---|
| Missing/malformed bearer | Generic `401`; no repository or graph authority | Authenticator | API tests |
| Unknown issuer/audience/algorithm/key | Fail authentication closed | OIDC verifier | JWT attack tests |
| Expired/future/long token | Fail authentication within explicit skew/lifetime | OIDC verifier | JWT attack tests |
| JWKS unavailable/oversized/malformed | No stale success; identity unavailable | JWKS adapter | identity tests |
| Rotated signing key | Cooldown-bounded refresh then verify current key | JWKS adapter | rotation test |
| Stale/revoked grant version | Fail authentication before policy | Principal/grant repository | identity tests |
| Missing role/purpose/risk grant | Deny before graph; audit denial | Policy | policy/service/API tests |
| Cross-tenant resource | Generic `404` before object lookup | Delivery policy | API anti-enumeration tests |
| Tenant mismatch from evidence adapter | Raise explicit isolation error; mark run failed | Application service | service test |
| Budget exhausted | Deterministic abstention; zero checkpoints/model calls | Budget | eval |
| Duplicate completed request | Reauthorize, return stored result, no new graph run | Idempotency | graph/service tests |
| Duplicate in progress | Conflict, never start another run | Idempotency | service test |
| Failed attempt retried | Same budget reservation; next explicit attempt may run | Idempotency/budget | service test |
| No evidence | Specialists and critic abstain | Evidence/critic | graph test |
| Malformed structured output | Named node abstention | Model adapter/critic | graph test |
| Declared provider outage | Named node abstention | Model adapter/critic | graph test |
| Unexpected framework/adapter defect | Raise `OrchestrationFailure`, audit failed | Orchestrator adapter | graph/service test |
| Forged/missing citation | Critic rejects all hypotheses/proposal | Critic | graph test |
| Invalid evidence-derived action target | Keep cited hypothesis, omit proposal, abstain safely | Critic | graph test |
| Specialist contradiction | Abstain, return reasons, no proposal | Critic | eval |
| Prompt injection in evidence | Drop untrusted text, flag, abstain, no proposal | Evidence projection/critic | eval |
| Checkpoint process loss in demo | State is lost; do not claim durability | Saver selection | documented limitation |
| PostgreSQL unavailable | Readiness/authenticated governance fail closed; no memory fallback | Repository/operator | readiness test |
| Runtime role can bypass RLS | Pool configuration fails | PostgreSQL adapter | integration policy |
| Tenant context remains after transaction | Connection is rejected/reset, not returned as success | Pool adapter | PostgreSQL integration |
| Optimistic version changed | Explicit concurrency conflict | Repository | governance tests |
| Quota race | Serialized row update; durable winner/denials | Quota repository | PostgreSQL integration |
| Audit mutation | Privilege and trigger reject update/delete | Audit repository | PostgreSQL integration |
| Cross-tenant checkpoint | RLS hides read; owner uniqueness rejects rebinding | Checkpoint repository | graph/PostgreSQL tests |
| Langfuse unavailable | Default runtime unaffected because external export is opt-in | Observability operator | adapter is non-authoritative |
| Audit adapter unavailable | Operation must not be represented as fully audited | Audit operator | production gap |
| Approval/effect requested | No decision endpoint; effect adapter raises | Approval/effect boundary | service test |

## Retry ownership

LangGraph may retry/replay nodes according to graph/checkpoint configuration. Layer 2
does not attach external effects to nodes. The application idempotency record owns
whole-run duplicate suppression. A future Temporal workflow will own long-running
approval/effect retries. Provider SDK retries must be bounded and observable when
introduced; they must not overlap invisibly with graph or workflow retry policy.

## Operator responses

- Treat citation rejection, contradiction, injection, and budget exhaustion as safe
  abstentions requiring human investigation.
- Treat `OrchestrationFailure`, evidence isolation, audit failure, or saver failure as
  platform incidents, not empty successful investigations.
- Never bypass policy, budget, approval, or audit to recover availability.
- Never switch silently from PostgreSQL to memory checkpoints in a durable
  deployment.
