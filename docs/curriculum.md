# Layer 14 curriculum

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
37. design immutable exact-scope plan/action/approval/effect/verification contracts;
38. implement current-policy invalidation, SoD, distinct-human quorum and anti-enumeration;
39. explain why Temporal signals/history are mechanics rather than approval/audit truth;
40. assign at-least-once effect retry, idempotency, claim and fencing ownership;
41. reconcile ambiguous external outcomes with observe-before-retry and read-after-write;
42. require fresh independent evidence/postconditions instead of API acceptance;
43. constrain a Kubernetes official-client adapter to one exact operation without shell;
44. compare Temporal Layer 7 candidly with custom Aegis Layer 8.
45. bind a memory candidate to accepted/redacted evidence, current chunker/embedder
    versions, and an explicit `MemoryAcceptance` human/policy decision before appending
    any candidate/scan/chunk/embed/index fact;
46. keep the derived vector/lexical index and cache rebuildable and never authoritative
    for tenancy, retention or audit, including the live `hybrid_candidates` SQL query,
    which returns scored candidates only, never a final authorized context;
47. frame retrieved memory as untrusted LangGraph state via a fixed instruction boundary,
    never as an instruction or effect trigger;
48. gate `tombstone_and_erase` on current legal hold and treat crypto-erasure callbacks
    as contract points rather than qualified KMS/blob integrations;
49. distinguish immutable memory ledger facts, the live pgvector `hybrid_candidates` query
    (store-tested, not yet wired into the serving path), and digest-only
    `MemoryOperationFact` retrieval/context-build facts (a separate, purpose-built ledger
    from the primary `MemoryFact` lifecycle ledger);
50. compare Framework Layer 9 candidly with custom Aegis Layer 10, including what the
    live pgvector-query implementations now share and what still differs (application
    wiring into the serving path, final MMR/bounds ownership).
51. distinguish immutable evaluation release evidence from runtime authorization,
    approval, audit, effect receipt, production verification and SLO evidence;
52. design canonical suite/dataset/case/scorer/result/baseline/comparison/waiver/report
    contracts with deterministic clocks, seeds, IDs, ordering and shards;
53. enforce non-waivable hard safety, reviewed baselines, scoped expiring waivers,
    missing/new/tamper detection and synthetic dataset lifecycle;
54. inject named faults around intent/effect/result/framework cut points and assert
    convergence without duplicate, stale or unauthorized effects;
55. compare Framework Layer 10 candidly with custom Aegis Layer 11 by catalog breadth,
    LOC/dependencies/services, removed framework mechanics, retained governance and
    hosted escape.
56. design stable semantic conventions, units, buckets and low-cardinality dimensions;
57. propagate and link hostile-boundary-safe trace context without making it authority;
58. separate logical-operation, retry, replay and redelivery metric counting;
59. define measurable SLOs and non-budgetable safety alerts;
60. debug and rebuild application state only from a verified ledger;
61. compare optional Langfuse with LangSmith and preserve an OTLP/ledger escape;
62. compare Framework Layer 11 candidly with pinned custom Aegis Layer 12.
63. design a BFF authorization-code boundary without browser bearer storage;
64. distinguish deny-default RBAC affordances from server authorization;
65. tear down tenant cache, cancellation, polling and session state on tenant change;
66. review exact digests/quorum/SoD/expiry while keeping approval server-owned;
67. model stale, offline, conflict, denial and ambiguity without success fallbacks;
68. build WCAG 2.2 AA semantic tables/forms/live regions and test them with axe/browser
    journeys while retaining a manual audit checklist;
69. enforce central XSS, URL, download, CSV, clipboard, redaction, CSP and no-analytics
    policy;
70. compare Framework Layer 12 candidly with pinned custom Aegis Layer 13.
71. distinguish official MCP/A2A transport mechanics from application authority;
72. design a versioned trust registry with card/schema/certificate/key drift invalidation;
73. bind workload identity audience/scope/tenant/purpose/proof/replay to current RBAC;
74. persist protocol intent before network and reconcile at-least-once ambiguity;
75. reject protocol poisoning, confused-deputy escalation, SSRF, forged artifacts,
    schema bombs, Unicode attacks, URL exfiltration and denial-of-wallet;
76. compare official SDK code removal with the custom security controls that remain.
77. choose Kustomize over Helm for a fixed security-sensitive topology and explain the
    distribution trigger that would revisit the decision;
78. separate Temporal Cloud availability/history from application ledger recovery,
    namespace policy, payload encryption, replay, and reconciliation;
79. design pinned Worker Deployment/build ID rollouts with queue isolation, rate bounds,
    schedule-to-start monitoring, drain, replay, and rollback;
80. apply expand-contract migrations to application and LangGraph saver schemas while
    preserving RLS, old-code reads, and event replay;
81. budget DB pools, Temporal concurrency, provider quotas, HPAs, and tenant partitions
    without creating retry storms or noisy-neighbor bypass;
82. verify backup integrity, rebuild projections/vector/checkpoints, discard caches, and
    reconcile Temporal/outbox/effects without treating framework state as truth;
83. design one home-region writer with monotonic generation fencing, residency-aware
    routing, failover, and failback while rejecting active-active claims;
84. verify SBOM, provenance, keyless signatures, vulnerability/license/secret gates,
    immutable promotion, admission, and rollback evidence;
85. map deployment evidence to compliance objectives without claiming certification;
86. compare Framework Layer 14 with pinned custom Aegis Layer 15 across LOC,
    dependencies, runtime services, managed Temporal tradeoffs, retained controls,
    lock-in/escape, cost, and unproven operation.

## Suggested sequence

| Module | Read | Lab | Qualification question |
|---|---|---|---|
| Identity boundary | ADR 005, `identity.py` | Forge algorithm/audience/time claims | Which token claims may establish authority? |
| Operator BFF | ADR 017, `operator_api.py` | Replay state, forge Origin/CSRF, switch tenant | Why can no browser claim establish authority? |
| Accessible workspace | `ui/src`, accessibility checklist | Keyboard/axe/injection/ambiguity journey | Which state is derived and disposable? |
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
| Exact contracts | `remediation.py`, ADR 012 | Change one digest/target/policy revision | Why must approval be reopened? |
| Human approval | approval API/service | Race two decisions; try self/workload/replay | Which fact satisfies quorum? |
| Temporal remediation | `remediation_temporal.py` | Wait, expire, signal, cancel and replay | What does Temporal simplify? |
| Controlled action | `action_adapters.py` | Attempt arbitrary patch/shell/target change | Why is the client not authority? |
| Ambiguity and fencing | effect service/repository | Crash after request; submit stale result | What can fencing not undo? |
| Verification/rollback | verification contracts/runbook | Fail postcondition and compensate | Why is API acceptance insufficient? |
| Layer 7 persistence | migration 0006 | Probe RLS, immutable decision and atomic claim | Which rows are mutable mechanics? |
| Memory contracts | `memory.py`, ADR 014 | Submit a quarantined-evidence candidate and prove rejection | Which fields may a memory fact never carry? |
| Memory retrieval/context | `InMemoryHybridIndex`, `LangGraphMemoryContextBuilder` | Rebuild the index and diff retrieval before/after | Why is retrieved memory framed as untrusted state? |
| Memory persistence | migration 0008, `memory_postgres.py` | Probe forced RLS and run `hybrid_candidates` against a wrong-tenant/classification query | What would wiring the SQL query into the serving path require? |
| Memory lifecycle/Temporal | `memory_temporal.py`, memory runbook | Hold, attempt erase, release, then erase | Which fact blocks crypto-erasure? |
| Evaluation contracts | ADR 015, `evaluation.py` | Tamper suite/dataset/baseline/scorer | Which mismatch blocks promotion? |
| Adversarial/recovery packs | `evals/suite.json`, Layer 10 tests | Reverse, shard, inject every fault point | Why are sleeps and random crashes insufficient evidence? |
| Baseline governance | evaluation runbook | Expire/over-broaden a waiver | Which findings can never be waived? |
| Framework comparison | Layer 10 metrics | Compare pinned custom Layer 11 | Which evaluator/governance code remains custom? |
| Semantic/privacy boundary | `telemetry.py`, ADR 016 | Inject IDs, URLs, secrets and malformed context | Which dimensions may leave the process? |
| SLOs and dashboards | SLO catalog, Prometheus rules, dashboards | Validate fast/slow burn and safety alerts | Why is safety not an error-budget tradeoff? |
| Replay debugging | `replay.py`, observability runbook | Tamper hash/sequence, compare and rebuild | Why are traces/checkpoints not truth? |
| Framework comparison | Layer 11 metrics | Compare pinned custom Layer 12 | Which telemetry/replay security remains custom? |
| Protocol contracts | ADR 018, `interoperability.py` | Forge authority fields and raw ledger content | Why can a peer message never grant authority? |
| MCP adapter | `mcp_interop.py`, `protocol_adapters.py` | Negotiate modern/legacy versions; poison tools and cursors | Which mechanics does MCP 2.0 remove? |
| A2A adapter | `a2a_interop.py`, compatibility guide | Forge card/artifact/task provenance | What does card JWS not prove? |
| Trust operations | migration 0009, protocol runbook, operator UI | Review, drift, quarantine, revoke, disable | Why must in-flight work reauthorize? |
| Protocol recovery | `interoperability_temporal.py` | Crash after intent and reconcile | What can fencing not undo? |

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
23. Forge a plan/action/approval digest and prove the effect adapter is never called.
24. Race high-risk grants, reuse one approver and attempt self/workload approval.
25. Expire and revoke approval while the Temporal workflow waits.
26. Crash before and after a fake effect; prove intent, ambiguity and reconciliation.
27. Return a stale worker fence and prove PostgreSQL rejects completion.
28. Make provider API acceptance succeed while postconditions fail; prove no recovery claim.
29. Attempt shell/arbitrary Kubernetes patch input and show no contract field accepts it.
30. Delete a remediation projection and rebuild only from immutable application facts.
31. Change one sandbox spec or policy digest after approval and prove provider I/O is absent.
32. Attempt shell/interpolation, mutable image, host path/socket, privilege and capability add.
33. Feed traversal, symlink, device, duplicate-case and compression-bomb archives.
34. Race two sandbox claims, expire one, and prove only an advancing fenced attempt completes.
35. Simulate ambiguous Kubernetes create/delete and reconcile by exact labels and UID.
36. Exercise timeout, OOM, violation, cancellation, output overflow and quarantine terminals.
37. Remove RuntimeClass, admission, CNI or workload-identity readiness and prove fail-closed.
38. Request exact DNS egress without an enforcing proxy and explain why NetworkPolicy is insufficient.
39. Rebuild sandbox projection from immutable facts without Temporal or Kubernetes history.
40. Compare the framework layer with custom Layer 9 by LOC, dependencies, mechanics removed,
    controls retained, runtime, lock-in, escape, and unproven live-isolation claims.
41. Submit a quarantined-disposition evidence item as a memory candidate and prove `ingest`
    rejects it before any candidate fact is appended.
42. Reuse a stale chunker/embedder version on an existing record and prove `IntegrityFailure`
    is raised before any embed/index fact.
43. Delete the derived index/cache and rebuild it from `memory_facts` via `reduce_memory`
    only, then diff retrieval results before and after.
44. Attempt `tombstone_and_erase` under an open legal hold, then release the hold and erase;
    prove the injected `erase_blob` callback is only invoked after the hold clears.
45. Attempt to feed a `MemoryContext` snippet back into the graph as an instruction and show
    the fixed `instruction_boundary` marks it as untrusted data only.
46. Run `PostgresMemoryStore.hybrid_candidates` for a wrong-tenant/wrong-classification
    query and prove it returns zero candidates; compare its scoring/prefilter design with
    custom Aegis Layer 10's live pgvector query and explain what wiring it into the
    production serving path would require.
47. Attempt network and process escape from a fake evaluation executor and verify a
    redacted evaluator failure with no destination or tenant value in the reports.
48. Divide the corpus into four shards, reverse input order, and prove exact union,
    disjointness, stable ordering, and byte-identical replay.
49. Add a soft metric regression with a valid waiver, then expire it and attempt the
    same waiver against a hard safety scorer.
50. Change one governed fixture byte without updating provenance and verify loading
    fails before application code runs.

## Assessment rubric

- **Pass:** all deterministic unit/eval gates and local PostgreSQL integration pass;
  the engineer correctly identifies every authority owner.
- **Strong pass:** adds an attack case with a fail-closed implementation and explains
  retry, tenant, replay/versioning, ledger integrity and redaction semantics.
- **Not qualified:** treats IdP roles, LangGraph checkpoints, traces, or API payloads
  as current authorization/audit truth; treats Temporal completion as application
  truth; overlaps retry owners; or claims production evidence from local profiles.
