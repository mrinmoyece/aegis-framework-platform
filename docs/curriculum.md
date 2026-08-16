# Layer 6 curriculum

## Learning outcomes

After this layer, an engineer should be able to:

1. separate authentication identity from current application authorization;
2. explain why verified token roles still are not authoritative tenant grants;
3. implement JWT BCP defenses for issuer, audience, algorithm, key ID and time;
4. design bounded JWKS refresh and fail-closed rotation;
5. model human and workload principals with immutable purpose-bound grants;
6. evaluate deny-by-default tenant, action, purpose and risk policy;
7. use PostgreSQL forced RLS with a non-bypass runtime role;
8. prevent transaction/pool tenant context leakage;
9. distinguish application audit and quota from framework checkpoints;
10. test cross-tenant, concurrency, mutation and exporter attacks deterministically.
11. distinguish application ledger truth from Temporal history and LangGraph state;
12. design dual aggregate/tenant integrity chains and commit-safe cursors;
13. place idempotency, inbox/outbox and projections in one transaction;
14. explain Temporal workflow determinism, replay, patching and Activity at-least-once;
15. assign retry ownership without overlapping workflow, graph and provider retries;
16. reauthorize commands/signals/Activities against current policy;
17. recover worker/history/checkpoint failures without fabricating application outcome.
18. design neutral model message/tool/schema/usage/pricing/error contracts;
19. enforce tenant model policy, catalog capabilities, pricing and secret references;
20. reserve worst-case token/cost budget before provider intent and reconcile ambiguity;
21. assign SDK, gateway and Temporal retry ownership without multiplication;
22. contain malformed/hostile output with schema, tool and citation allowlists;
23. distinguish immutable usage facts from derived provider health and framework traces.
24. design tenant/source/query/page/provenance/citation/bundle contracts and digests;
25. enforce SSRF, DNS, redirect, response, pagination and secret-reference boundaries;
26. record connector page intent/result without overlapping Temporal/SDK retries;
27. canonicalize, scan, redact, deduplicate and quarantine untrusted documents;
28. correlate timelines/conflicts deterministically without causal claims;
29. rebuild forced-RLS evidence projections and expose redacted status/cursor APIs;
30. critically compare narrow official clients with broad loader/connector frameworks.
31. design immutable typed reasoning artifacts with provenance and canonical digests;
32. enforce fixed role capabilities and artifact transitions without peer free chat;
33. use LangGraph fan-out/fan-in/reducers while keeping authority in application ports;
34. bind checkpoint replay to tenant/run/input/graph version and rebuild from ledger facts;
35. assign Temporal, LangGraph, gateway and application-ledger retry ownership;
36. compare Framework Layer 6 candidly with custom Aegis Layer 7.

## Suggested sequence

| Module | Read | Lab | Qualification question |
|---|---|---|---|
| Identity boundary | ADR 005, `identity.py` | Forge algorithm/audience/time claims | Which token claims may establish authority? |
| Grant governance | `access.py`, `authorization.py` | Revoke a grant/version and retry | Why reload grants on every authentication? |
| Delivery | `api.py` | Attempt tenant enumeration and oversized bodies | Why is readiness separate from liveness? |
| PostgreSQL tenancy | ADR 006, migration | Run RLS and pool leakage probes | Why is `FORCE ROW LEVEL SECURITY` required? |
| Quota | `PostgresRepository.reserve` | Race ten reservations for five units | Which lock owns retries? |
| Audit | audit migration/repository | Attempt update/delete and verify chain | Why is a checkpoint not audit evidence? |
| Graph boundary | `service.py`, `graph.py` | Attempt cross-tenant thread rebinding | Can graph output change current policy? |
| Privacy | `safety.py`, exporter tests | Inject identifiers/secrets into attributes | Where must redaction occur? |
| Event ledger | ADR 008, `durability.py`, migration 0002 | Race expected-version appends and verify both chains | Why is tenant cursor assigned at commit? |
| Transactional delivery | `durable_postgres.py` | Crash a claimant and reclaim the outbox row | Which record proves delivery intent? |
| Temporal lifecycle | ADR 007, `temporal.py` | Run no-worker recovery, retry, timer and replay | What may workflow code do deterministically? |
| Activity authority | `activity_runtime.py` | Revoke a signaller during wait | Why is a signal payload never authority? |
| Projection API | durable API/timeline tests | Rebuild and tamper with a cursor | Why can Temporal query not serve product status? |
| Model contracts | ADR 009, `model_gateway.py` | Attempt vendor-shape/tool/policy injection | Which fields may a model create? |
| Routing and resilience | `ModelGateway` | Trigger fallback, circuit, timeout and cancellation | Why is ambiguous billing not retried by default? |
| Provider adapters | `provider_adapters.py` | Verify both SDKs use zero retries and fake clients | What remains vendor-specific? |
| Model ledger | migration 0003, `model_postgres.py` | Race reservations and rebuild projections | Which fact owns usage/cost? |
| Evidence contracts | ADR 010, `evidence.py` | Tamper source/query/provenance/citation digests | Which fields bind a citation? |
| Connector security | `connector_adapters.py` | Probe DNS/private IP/redirect/MIME/size/rate limit | Which library control is insufficient? |
| Durable pagination | `evidence_temporal.py`, `evidence_runtime.py` | Crash after page intent and reconcile | Why may an Activity retry not repeat I/O? |
| Safe ingestion | `ingestion.py` | Submit injection, token, malformed YAML and ZIP bomb | Which records reach graph state? |
| Correlation | `correlation.py`, `graph.py` | Reverse input and add conflicts/stale sources | Why is proximity never cause? |
| Evidence persistence/API | migration 0004, `evidence_postgres.py`, `api.py` | Rebuild and cross-tenant query/cursor reads | Which ledger facts rebuild status? |
| Framework comparison | `framework-selection.md`, Layer 5 metrics | Compare custom Layer 6 LOC/deps/runtime | What code did frameworks actually remove? |
| Governed artifacts | ADR 011, `orchestration.py` | Forge role, transition, provenance and digest | Which artifact fields can grant authority? |
| Specialist graph | `graph.py` | Reverse branch completion and inject node failure | What does LangGraph remove versus retain? |
| Replay and ledger | migration 0005, orchestration repository | Lose/tamper checkpoint then rebuild projection | Which state is disposable? |

## Practical exercises

1. Add a second trusted issuer without using token data to construct a JWKS URL.
2. Add a low-risk read-only purpose and prove an incident grant cannot use it for
   writes.
3. Advance a principal grant version and show that an old signed token fails.
4. Remove `FORCE ROW LEVEL SECURITY` in a disposable branch and explain which role
   could observe rows.
5. Add a saver table in a simulated framework upgrade and update the RLS
   qualification test.
6. Design—but do not implement—a Vault resolver that cannot expose values to graph
   state or observability.
7. Add an event schema v2 with an explicit v1 upcaster and prove old replay.
8. Kill a worker between Activity attempts and explain why budget is not charged twice.
9. Remove an Activity policy check in a disposable branch and identify the confused
   deputy path.
10. Propose a Temporal-to-alternative migration using only outbox messages and
    application events.
11. Add a model route with an unknown price and prove the provider adapter is not called.
12. Crash after model call intent, prove the cost is reported ambiguous, and reconcile it.
13. Revoke model policy during a fake provider call and prove the billed output is stale.
14. Replace the fake provider adapter without changing graph/domain/ledger contracts.
15. Add a fake paginated source and prove cursor/query/tenant binding.
16. Rotate a source credential revision during a page call and prove stale rejection.
17. Add a scanner hook and prove blocking findings create quarantine metadata only.
18. Add contradictory evidence in reverse order and prove identical non-causal output.
19. Attempt dynamic role creation and an illegal artifact transition; prove denial.
20. Leave task dispatch intent unresolved and prove retry does not duplicate the model call.
21. Change graph version/input digest under an existing thread and prove replay fails closed.
22. Rebuild the artifact projection without reading LangGraph state.

## Assessment rubric

- **Pass:** all deterministic unit/eval gates and local PostgreSQL integration pass;
  the engineer correctly identifies every authority owner.
- **Strong pass:** adds an attack case with a fail-closed implementation and explains
  retry, tenant, replay/versioning, ledger integrity and redaction semantics.
- **Not qualified:** treats IdP roles, LangGraph checkpoints, traces, or API payloads
  as current authorization/audit truth; treats Temporal completion as application
  truth; overlaps retry owners; or claims production evidence from local profiles.
