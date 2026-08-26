# Glossary

**Evidence source** — Current tenant-owned configuration binding source kind, exact
resources, trust, classification, region, policy revision and secret reference/version.

**Page intent** — Immutable application fact recorded before one connector page I/O. An
intent without result is ambiguous and requires reconciliation.

**Evidence provenance** — Immutable tenant/incident/run/source/query/page/locator/time/
trust/classification/retention and raw-hash binding for a normalized record.

**Quarantine** — Fail-closed disposition that prevents malformed, active, oversized,
secret-bearing, injection-bearing or scanner-rejected content from entering graph/model
context.

**Non-causal correlation** — Deterministic timeline/shared-fact relationship that
explicitly does not assert one event caused another.

**Governance artifact** — Immutable schema-versioned neutral envelope binding tenant,
incident, run, task, producer role, typed payload, provenance and canonical digest.

**Specialist dispatch intent** — Application-ledger fact written before model work. A
result is accepted only with the matching task fence; unresolved intent requires
reconciliation.

**Graph version binding** — Compatibility check joining a checkpoint to the exact
tenant/run/request, canonical input digest and graph contract version.

**Abstention**
A deliberate non-answer when evidence, budget, validation, or corroboration is
insufficient. It is not a successful empty investigation.

**A2A**
Agent-to-Agent protocol work, deferred until official stable SDKs can be placed behind
identity and capability controls.

**Approval boundary**
An application-owned service that turns a proposal into a separately governed
pending/approved/rejected record. Graph output cannot cross it by assignment.

**Checkpoint**
Framework persistence of graph state at execution boundaries. Useful for resumption;
not authorization, audit, idempotency, or an effect receipt.

**Citation**
The evidence ID, locator, and content hash attached to a finding/hypothesis and
validated against evidence collected for the run.

**Critic**
The deterministic join node that checks injection flags, specialist availability,
citations, contradictions, and corroboration before producing a proposal.

**Effect**
A mutation of an external/production system. Layer 3 has no enabled effect.

**Enterprise-owned control**
Policy, tenant isolation, budget, idempotency, approval, effect fencing, verification,
reconciliation, or audit whose authority cannot be delegated to an agent framework.

**Evidence projection**
Conversion of untrusted source records into a minimal, allowlisted structured view for
a model adapter.

**Fencing token**
A monotonically governed token proving an effect worker still owns authority. It
prevents stale workers acting after a lease/approval changes; deferred.

**Framework-owned state**
Node progress, intermediate channels, checkpoint metadata, trace data, and other
mechanics managed by LangGraph/Langfuse/Temporal.

**Idempotency**
Application behavior ensuring retries/duplicates with the same tenant/request/input do
not duplicate work, while conflicting input is rejected.

**Grant version**
Monotonic principal authority revision carried by a token and matched against current
application storage. A mismatch makes a signed but stale token unusable.

**IdentityContext**
Immutable application projection created at delivery after JWT verification and
current principal/grant resolution. It contains tenant, issuer/subject, principal
kind, purpose-bound grant bindings, request and trace references.

**JWKS rotation cache**
Bounded cache of configured-issuer signing keys with key-count/ID limits, TTL and
unknown-key refresh cooldown. It is unavailable rather than stale-successful after a
required refresh failure.

**Langfuse**
The selected optional framework trace/eval backend. Layer 3 uses manual minimized
observations rather than automatic graph capture.

**LangGraph**
The selected bounded investigation graph framework, using static topology,
super-steps, reducers, and checkpoints.

**LangSmith**
LangChain's commercial tracing/evaluation platform. Its client is transitive, but the
platform is not configured because it would duplicate Langfuse.

**Application replay**
Deterministic read-only validation and projection from application ledger events. It is
distinct from Temporal workflow replay and LangGraph checkpoint recovery.

**SLI / SLO**
An allowlisted measurable service-level indicator and its objective/window. Safety
violations are hard alerts and never consume availability error budget.

**Trace reference**
Validated opaque W3C trace/span coordinates used only for navigation and causal links.
It is not authorization, audit, approval, fencing, or proof of effect.

**MCP**
Model Context Protocol. Tool interoperability is deferred until identity, capability,
and effect boundaries can govern it.

**Pregel / super-step**
LangGraph's bulk-synchronous execution model: runnable parallel nodes execute within a
super-step and joins proceed after required branch updates arrive.

**Proposal**
Non-authoritative suggested remediation. It always requires separate approval.

**Reconciliation**
Independent comparison of intended and observed external state after an effect;
deferred.

**RLS**
PostgreSQL row-level security. Required for production tenant data, not supplied by
framework checkpoints.

**Purpose binding**
Requirement that one current grant permit an action for the exact declared business
purpose. Permissions from unrelated purposes cannot be combined.

**Runtime role**
The `aegis_runtime` PostgreSQL group role used after connection setup. It is neither
superuser nor `BYPASSRLS`; migrations and saver setup use a separate administrative
connection.

**Secret reference**
Tenant-bound provider URI/name stored instead of secret material. Layer 3 does not
resolve it and never places values in graph, API, audit or trace state.

**Structured model port**
Provider-neutral interface that accepts a typed specialist task and returns output
that must pass domain validation.

**Model gateway**
Application-owned policy and accounting boundary that converts neutral model requests
into one or more provider adapter calls (each with a distinct durable attempt ID for
reservation, resilience, and settlement). It owns routing, reservation, resilience,
settlement and stale-result rejection; it is not a hosted vendor gateway.

**Model catalog**
Tenant-authorized declaration of exact provider/model/region capabilities, context/output
limits, tokenizer limitations, pricing version and secret reference. Unknown data denies.

**Billing ambiguity**
A durable state where provider acceptance or charging cannot be proven after timeout,
cancellation or crash. It blocks an exactly-once claim and requires reconciliation.

**Provider health projection**
Rebuildable aggregate of observed application call outcomes. It is an availability hint,
not authorization, billing truth, provider SLA, or audit.

**Temporal**
A durable workflow engine deferred until long-running approvals/effects need replay
across process boundaries.

**Tenant bucket**
A bounded hash bucket exported for aggregate telemetry instead of a tenant identifier.

**Verification**
Evidence-based check that a controlled effect achieved its intended outcome. Layer 3
does not execute this journey stage.

**Application event**
Immutable tenant-scoped domain fact with aggregate sequence, tenant cursor, schema
version, opaque actor/correlation references, bounded payload and dual integrity hashes.

**Activity**
Temporal's side-effect/I/O boundary. Layer 3 Activities reauthorize current application
policy and are at-least-once, bounded, heartbeating, and idempotent by operation ID.

**Dead letter**
Explicit outbox state after the bounded claim/delivery attempt limit. It requires an
audited operator decision; immutable intent is never rewritten.

**Inbox / outbox**
Application-owned transactional records that deduplicate incoming commands and publish
committed intent to a framework boundary without dual writes.

**Projection**
Derived, rebuildable read model. It is served by the API but can always be recreated
from verified application events.

**Tenant cursor**
Contiguous per-tenant commit order assigned in the same transaction as the event. It is
for replay/pagination and does not grant access.

**Workflow history**
Temporal's deterministic scheduling/replay record. It is operational framework state,
not authorization, application audit, or product status truth.

**MemoryRecord**
The immutable versioned memory record contract: tenant/ACL/classification, evidence
binding, embedder/chunker version, retention/legal-hold state, and an optional
`ErasableBlobReference`. It is truth for what a memory candidate is bound to, never a
container for raw text.

**MemoryFact**
An append-only ledger entry (`MemoryFactType`) for one memory's lifecycle transition.
Banned fields: raw text, query text, prompt, completion, tenant ID, locator. Ingest,
supersession, legal hold, and tombstone/erasure are ledger-audited here; a separate,
purpose-built `MemoryOperationFact` ledger now covers retrieval/context-build (see
`RETRIEVE_REQUESTED`/`RETRIEVE_COMPLETED`/`CONTEXT_BUILT` below).

**MemoryAcceptance**
An explicit, digested human-or-policy decision record (`disposition` accept/reject,
`reviewer_kind` human/policy, policy ID/revision/digest, reason code) bound by
tenant/memory ID. `MemoryLifecycleService.ingest` validates it before appending any
candidate/scan/chunk/embed/index fact; a missing or mismatched acceptance raises
`IntegrityFailure`. Memory can never become durable from evidence disposition alone.

**MemoryOperationFact**
A digest-only, sequenced ledger entry (`RETRIEVE_REQUESTED`=1, `RETRIEVE_COMPLETED`=2,
`CONTEXT_BUILT`=3 per operation ID) recorded by `MemoryRetrievalService` around every
retrieval and context build, carrying only `policy_digest`/`query_digest`/
`result_digest` — never raw query text. Appended to `InMemoryMemoryOperationLedger` or
the durable, immutable `aegis.memory_operation_facts` table with idempotent replay and
strict-sequence enforcement. A separate class/table from `MemoryFact`, though both share
the `MemoryFactType` enum's fact-type values.

**MemoryProjection**
The rebuildable read model folded by `reduce_memory` from ordered `MemoryFact`s:
status, indexed/tombstoned flags, hold count, derived-purged/blob-erased flags, and
chunk count. Never a source of truth independent of the facts.

**Derived hybrid index**
`InMemoryHybridIndex` (and the durable PostgreSQL `memory_chunks`/cache tables):
lexical/vector/recency/quality-weighted, MMR-diversified, tenant-scoped, and always
rebuildable from `memory_facts`. Never authoritative for tenancy, retention, or audit.

**instruction_boundary**
The fixed literal `MemoryContext` prefixes onto every retrieved snippet, marking it as
untrusted LangGraph state. It exists precisely so retrieved memory can never be treated
as an instruction, approval, or effect trigger.

**Legal hold (memory)**
A `RetentionBinding`/`MemoryProjection.legal_hold_count` state that blocks
`tombstone_and_erase` until released, regardless of retention expiry or operator intent.

**Crypto-erasure callback**
The injected `erase_blob` function invoked by `tombstone_and_erase` only after legal
hold clears and the derived index is purged. A contract point, not a qualified KMS or
blob-storage integration.

**Live pgvector hybrid query**
`PostgresMemoryStore.hybrid_candidates`: a single forced-RLS SQL query combining cosine
ANN distance (`embedding <=> %s::vector`), lexical `ts_rank_cd`, recency/quality scoring,
and ACL/classification/time/retention prefilters into one deterministic weighted score,
with a stable tie-break order and a bounded candidate count. Implemented and
integration-tested at the store layer, including a cross-tenant/classification isolation
assertion; not yet wired into `MemoryRetrievalService`/`InMemoryMemoryControl` or
`/v1/memories/retrieve` — production retrieval still serves from `InMemoryHybridIndex`
until that wiring lands.
**Evaluation baseline**
A reviewed immutable set of suite/dataset/case/scorer digests, directions,
thresholds and tolerances. It is release evidence, not runtime policy.

**Hard safety invariant**
A deterministic scorer threshold that cannot be averaged away or waived.

**Evaluation waiver**
A reviewed exception for one non-safety scorer and exact cases, owner, reason and
expiry. Expiry or scope mismatch fails closed.

**Fault cut point**
A named deterministic boundary where the evaluator injects failure and asserts
convergence, fencing, reconciliation, cleanup, audit and isolation without sleeps.
