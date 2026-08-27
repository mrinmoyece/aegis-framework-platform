# Framework verdicts and defensible narrative

The detailed machine-readable verdicts live in
[`layer16-final.json`](../comparison/layer16-final.json). Each decision asks what
code disappeared, what authority remained, what must be operated, how upgrades
fail, and how to leave.

| Framework | Verdict | Removed | Never replaced |
|---|---|---|---|
| LangGraph | Adopt, bounded | fan-out/fan-in, reducers, routing, checkpoints | roles, citations, policy, approval, audit, effects |
| Temporal | Adopt for durable waits/recovery | leases, heartbeats, timers, signals, activity retry/replay | outbox, authorization, intent, fencing, receipts, reconciliation |
| Langfuse | Optional/contained | trace and experiment UX | audit, replay, release gates, SLO policy |
| FastAPI/Pydantic | Adopt at delivery | routing, OpenAPI, parsing, validation | identity, authorization, tenant policy, idempotency |
| Official SDKs | Adopt behind ports | wire/object/auth mechanics | egress, quotas, retry ownership, provenance, target binding |
| pgvector | Adopt as derived state | separate vector service/protocol | acceptance, ACL, retention, citations, erasure |
| React/TanStack/Zod | Adopt for derived UX | rendering/router/cache/table/parsing | server policy, CSRF, approval, tenant teardown |
| MCP/A2A | Contain as untrusted adapters | protocol/card/transport mechanics | workload identity, trust, tenancy, approval, effects |
| Infrastructure tooling | Adopt as reference | rollout/state/build/signing mechanics | release approval, fencing, restore acceptance, compliance |

## Upgrade and rejection rule

Adopt only when exact-pinned dependencies, deterministic fakes, privacy tests,
failure/replay tests, operated capacity, and a neutral exit are cheaper than the
custom mechanics removed. Reject or postpone when a framework requires opaque
authoritative state, automatic sensitive capture, hidden retries, self-asserted
tenant authority, unsupported hosting/data policy, or a major upgrade cannot
rebuild identical application projections.

## Employer/interview narrative

> I used frameworks for mechanics, not enterprise authority. Temporal owns durable
> scheduling; LangGraph owns a bounded cognitive topology; FastAPI/Pydantic and
> official SDKs own delivery and wire mechanics; pgvector and UI caches are derived;
> Langfuse is optional. Identity, tenant policy, immutable application events,
> budgets, cited evidence, approvals, fencing, receipts, reconciliation, audit and
> release decisions remain explicit application ports. I proved denial, replay,
> framework outage, projection rebuild and protocol/UI bypass behavior locally, and
> I distinguish that evidence from live identity, managed recovery, sandbox,
> provider, capacity and organizational go-live gates. The exit test is simple:
> remove framework history/checkpoints/traces/indexes and rebuild the same
> application truth.

This narrative is defensible because each clause links to executable evidence in
the [readiness manifest](../qualification/release-readiness.json), not to an
aggregate maturity score.
