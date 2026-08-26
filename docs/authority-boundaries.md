# Layer 10 authority and retry ownership

## Ownership matrix

| Fact or mechanic | Authoritative owner | Framework copy allowed? | Recovery source |
|---|---|---:|---|
| Current identity/tenant/grants | Application identity store | Opaque references only | Identity repository |
| Run/checkpoint-read authorization | `PolicyPort` current evaluation | Decision may be observed, never reused as grant | Current policy/grants |
| Budget reservation | PostgreSQL quota reservation | Reservation reference only | Application database |
| Application intent/outcome | Append-only application events | Reference only | Event ledger |
| Tenant/aggregate order and integrity | Ledger heads/cursors/hash chains | No | Event ledger |
| Command idempotency | Application idempotency/inbox | IDs may route messages | Application database |
| Delivery retry/DLQ | Application outbox claim record | Temporal also retries Activities, not command delivery facts | Application database |
| Cross-process schedule/timer/signal | Temporal history | Yes | Temporal |
| Activity result fact | Application event after Activity | Temporal return reference only | Event ledger |
| Cognitive node progress | LangGraph checkpoint | Yes | LangGraph saver |
| Model policy/catalog/pricing | Application PostgreSQL policy/catalog | Route/model name may enter adapter | Current model policy/catalog |
| Model token/cost reservation | Application model reservation | Reservation/call reference only | Application database |
| Provider call/usage outcome | Immutable model call facts | SDK response is untrusted input | Application settlement/reconciliation |
| Provider health | Derived application projection | Framework health is advisory only | Model call fact rebuild |
| Evidence source/config/trust | Current application source registry | Source ID/digest/reference only | Current source policy |
| Evidence query/page intent and outcome | Application event ledger | Opaque query/cursor/result references | Event replay |
| Connector pagination cursor | Tenant-bound encrypted application cursor | Opaque cursor reference only | Application projection/reconciliation |
| Evidence metadata/provenance/quarantine | Immutable application facts | Bounded accepted projection only | Application events + retained object reference |
| Evidence bundle/citation | Application evidence bundle | LangGraph/model receives cited allowlisted facts | Bundle/member facts |
| Correlation timeline/link/conflict | Deterministic application reducer | May enter graph context; never causal authority | Accepted cited evidence |
| Hypothesis/proposal | Domain result with citations | Yes, non-authoritative candidate | Application result event |
| Specialist role/capability | Closed application role/transition policy | Role label only | Application code/version |
| Task dispatch/result | Immutable application orchestration fact with fence | Checkpoint may mirror progress | Application ledger |
| Reasoning artifact/decision | Immutable application artifact fact/projection | Graph state may hold a copy | Application ledger rebuild |
| API status/timeline | Rebuildable application projection | Temporal query is convenience only | Event replay |
| Audit | Application PostgreSQL audit/ledger | No | Application database |
| Remediation plan/action digest | Immutable application contract | Opaque reference only | PostgreSQL plan |
| Approval request/decision/quorum | Application approval service + immutable decisions | Command reference/status only | PostgreSQL approval facts |
| Effect intent/idempotency/fence | Application ledger and atomic claim | Activity operation reference | PostgreSQL effect attempt |
| External operation mechanics | `ActionPort` adapter | Provider receipt is untrusted input | Observe/reconcile through provider API |
| Effect receipt/verification/rollback | Immutable application facts | Result reference only | PostgreSQL replay + fresh evidence |
| Sandbox request/spec/policy/approval | Immutable application contracts and current authority | Opaque references/digests only | PostgreSQL request/policy/approval |
| Sandbox quota/idempotency/claim/fence | Application PostgreSQL control rows | Activity operation reference | PostgreSQL claim/replay |
| Sandbox provider lifecycle | `SandboxBackend` observation | Temporal/Kubernetes may schedule and observe | Application reconciliation |
| Sandbox artifact/manifest/attestation | Immutable scanned application facts | Provider output is untrusted input | PostgreSQL artifact facts/object reference |
| Sandbox cleanup/orphan ownership | Application cleanup claim plus exact provider UID | Temporal schedules redrive | PostgreSQL cleanup claim |
| Memory record/fact/projection | Immutable application ledger (`memory_facts`) | Opaque references/digests only | PostgreSQL memory facts |
| Memory acceptance decision | `MemoryAcceptance` (human/policy `reviewer_kind`, disposition, reason code, digest) | No; required before any candidate/scan/chunk/embed/index fact | PostgreSQL `candidate_accepted`/`candidate_rejected` facts |
| Derived vector/lexical index and cache, and `hybrid_candidates` SQL scoring | `InMemoryHybridIndex` / Postgres `memory_chunks`/`memory_cache` / `PostgresMemoryStore.hybrid_candidates` | Never authority; always rebuildable/purgeable; SQL returns scored, bounded candidates only, never a final context | Rebuild from ledger facts |
| Retrieval/context-build operation record | `MemoryOperationFact` (digest-only, `RETRIEVE_REQUESTED`/`RETRIEVE_COMPLETED`/`CONTEXT_BUILT`) | Observational audit trail only; never a retrieval authorization grant | PostgreSQL `memory_operation_facts` (immutable) / in-memory ledger |
| Retrieved memory context | `MemoryContext` with fixed `instruction_boundary` | LangGraph state only; never instructions or authority | Re-derived from current retrieval |
| Memory retention/legal hold/erasure | `RetentionBinding` + `MemoryProjection.legal_hold_count` | No | PostgreSQL memory facts |
| Erasable blob reference | `ErasableBlobReference` on the immutable record | Reference only; erasure via injected callback, not authority | PostgreSQL memory record |

## Retry matrix

| Boundary | Retry owner | Limit/idempotency |
|---|---|---|
| HTTP durable command | Caller may retry | Tenant/request fingerprint returns the same run |
| Outbox to Temporal | Application dispatcher | Five claims, stable workflow/message ID, DLQ |
| Workflow task | Temporal | Deterministic replay; no application fact inferred |
| Activity | Temporal | Three attempts, timeout/heartbeat, stable operation ID |
| Evidence connector call | Activity only | Connector SDK retries disabled or counted inside Activity limit |
| Connector page | Temporal Activity + application page intent | Three Activity deliveries; unresolved intent blocks another network call pending reconciliation |
| LangGraph run | One Activity attempt | No Temporal per-node retry and no graph retry loop |
| Specialist node | No framework retry | Application dispatch intent/result and model-call identity suppress duplicates |
| Provider SDK | None | `max_retries=0`; one network intent per durable attempt ID |
| Structured repair/fallback | Application gateway | Policy bound; no ambiguous-billing fallback by default |
| Signal | Temporal may redeliver | Workflow command-reference set + application inbox |
| Approval signal | Temporal may redeliver | Persisted decision command + workflow reference set |
| Effect Activity | Temporal | Three attempts; observe-before-retry + stable tenant key + fence |
| Kubernetes client | None | One fixed request per claimed attempt; no client retry |
| Ambiguous effect | Operator/application reconciler | Observe exact target; retry only after proof |
| Verification | Application | Fresh evidence after receipt; no API-acceptance shortcut |
| Sandbox workflow | Temporal | Stable opaque request/operation IDs; application facts remain truth |
| Kubernetes Job client | None | Observe-before-create, request/fence labels and UID-bound delete |
| Sandbox artifact capture | Temporal Activity + application bounds | One manifest per exact execution; quarantine on conflict |
| Sandbox cleanup/orphan redrive | Temporal Activity + application cleanup claim | Observe exact UID before delete; ambiguity never success |
| Projection | Application replay | Cursor/hash checkpoint; deterministic reducer |
| Memory ingest Activity | Temporal `aegis.memory.v1` + application fact expected-version | Resume at next expected fact type; never re-append a completed fact |
| Memory compact/purge/rebuild | Temporal Activity + application ledger | Fold `reduce_memory` in ordinal order; no blind retry of ambiguous erasure |

## Non-negotiable call order

1. Establish `IdentityContext` at delivery.
2. Authorize current command.
3. Persist idempotency, event, projection, and outbox atomically.
4. Dispatch using a tenant-scoped claim.
5. Resolve opaque references and reauthorize immediately before every Activity.
6. Reserve budget before evidence or graph work; retry reuses the run reservation.
7. Persist Activity intent before I/O and result/failure afterward.
8. Serve status/timeline only from authorized application projections.
9. Before a provider call, recheck model policy/catalog, reserve worst-case cost, and
   append call intent.
10. Settle billed/not-billed/ambiguous outcome, reject stale policy/cancellation results,
    and serve only RLS-filtered redacted usage/catalog/health projections.
11. Record evidence query/page intent before connector I/O; recheck current source,
    credential revision, policy and cancellation before accepting a page.
12. Canonicalize/scan/quarantine before graph projection; expose only authorized,
    redacted query and cursor status from forced-RLS projections.
13. Persist the fixed task dispatch before a model call and accept the result only under
    the current run/task fence.
14. Validate role, artifact transition, provenance, citation, confidence, graph version,
    and input digest before recording the final application artifact/decision facts.
15. Convert only an accepted cited proposal into an immutable exact-scope plan; the graph
    cannot open or decide approval.
16. Recheck current allowlists, maintenance window, risk/blast thresholds, quota,
    evidence/critic status and plan/action/target/policy/role digests.
17. Persist approval commands before signalling; require current human SoD/quorum and
    reject self, duplicate, stale, expired, revoked or forged decisions.
18. Reserve effect quota and persist effect intent before I/O; dry-run and observe exact
    target, then execute under the current claim/fence.
19. Persist receipt or ambiguity, reconcile by observation, and verify with fresh cited
    evidence. Rollback requires its own exact compensation contract.
20. Bind sandbox request to the exact Layer 7 approval, current sandbox policy and
    immutable spec; reserve quota and claim before provider I/O.
21. Observe deterministic provider identity before create, persist result afterward, and
    reject stale attempts/fences or ambiguous outcomes.
22. Capture only expected bounded outputs, scan/redact/quarantine as untrusted data,
    persist manifest/attestation, then clean up by exact provider UID.
23. Bind a memory candidate to accepted/redacted evidence, current chunker/embedder
    versions, and an explicit human/policy `MemoryAcceptance` decision before any
    scan/chunk/embed/index fact is appended.
24. Persist intent-before-effect memory facts in fixed order; never re-append a fact type
    the ledger has already advanced past.
25. Treat the derived vector/lexical index, cache, and `hybrid_candidates` SQL scoring as
    always-rebuildable and never authoritative for tenancy, retention, or audit; treat
    digest-only retrieval/context-build operation facts as an audit record, never a
    retrieval authorization grant.
26. Frame every retrieved memory snippet with the fixed `instruction_boundary` literal;
    it is LangGraph state, never an instruction, approval, or effect trigger.
27. Block `tombstone_and_erase` on current legal hold before purging the derived index and
    invoking the injected erase-blob callback.

A Temporal signal, workflow query, history event, LangGraph checkpoint, model output, or
trace cannot change this order or grant authority.
A Layer 10 suite, dataset, baseline, waiver, score, comparison, report, trace
reference, Langfuse record, pytest result, or CI status is release evidence only.
None authorizes a run/checkpoint read, grants tenant access, approves an action,
fences an effect, proves reconciliation, verifies production recovery, or becomes
an audit record.
