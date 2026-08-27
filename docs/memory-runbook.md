# Memory operations runbook

## Activation gate

Memory ingestion and retrieval are authorized application actions
(`memory:write`/`memory:read`/`memory:retrieve`/`memory:delete`), not open endpoints. The
in-memory demo/test path (`InMemoryMemoryLedger`, `InMemoryHybridIndex`) is the path
exercised by the API/CLI/demo today. `PostgresMemoryStore` durably writes ledger facts,
projections, and derived chunk embeddings, and additionally implements and
integration-tests `hybrid_candidates`, a live forced-RLS pgvector ANN/lexical/recency/
quality SQL query — but this query is exercised at the store/repository layer only; it is
not yet wired into `MemoryRetrievalService`/`InMemoryMemoryControl` or the
`/v1/memories/retrieve` API path. Do not describe pgvector retrieval as a
production-qualified serving path on that basis: ledger/RLS/immutability/rebuild and the
`hybrid_candidates` query itself are proven; end-to-end production API wiring, real
embedding providers, and KMS/blob-backed crypto-erasure remain deferred; `erase_blob` is
an injected callback, not a qualified integration.

## Normal lifecycle

1. Bind a `MemoryRecord` from accepted or redacted evidence
   (`memory_record_from_evidence`), never from quarantined/duplicate evidence.
2. Persist the record, then append `candidate_proposed` before any
   scan/chunk/embed/index work. `MemoryLifecycleService.ingest` requires an explicit
   `MemoryAcceptance` (human or policy `reviewer_kind`, `disposition` accept/reject,
   reason code) bound by tenant/memory ID to the record; a mismatched or missing
   acceptance raises `IntegrityFailure` before any fact is appended.
3. On acceptance, append `candidate_accepted`, then
   `scan_requested`/`scan_completed`/`chunk_requested`/`chunk_completed`/
   `embed_requested`/`embed_completed`/`index_requested`/`index_completed` in order,
   each under the previous fact's expected version. A `reject` disposition appends
   `candidate_rejected` and stops the chain instead.
4. Only a schema/chunker/embedder-version match between the record and the current
   `EmbeddingSpec`/`DeterministicChunker.version` may proceed; a mismatch raises
   `IntegrityFailure` before any embed/index work.
5. Retrieval reads only the derived index (`InMemoryHybridIndex` today, or
   `PostgresMemoryStore.hybrid_candidates` once wired into the retrieval control path),
   never the ledger directly, and returns `insufficient_context=true` rather than
   fabricating a hit when citation/quality bars are not met. `MemoryRetrievalService`
   records digest-only `RETRIEVE_REQUESTED`/`RETRIEVE_COMPLETED`/`CONTEXT_BUILT` facts
   around every call.
6. Compaction (`MemoryCompactor`) requires full citation coverage of its input hits and
   falls back to `DeterministicSummarizer` on any coverage gap; it never emits an
   uncited claim.

## Legal hold and erasure

Do not call `tombstone_and_erase` without first checking `MemoryProjection
.legal_hold_count` and `MemoryRecord.retention.held`; the service itself raises
`PolicyDenied` if either is set, but operators must not work around it by mutating
records directly. The lifecycle is: append `tombstoned`, purge the derived index and
append `derived_purged`, invoke the injected `erase_blob` callback, then append
`crypto_erased`. A crash between purge and erase must be recovered by rerunning the same
`tombstone_and_erase` call under the current projection version — it is idempotent by
expected-version fencing, not by blind retry. Apply/release legal hold only through
`set_legal_hold`, which appends `legal_hold_applied`/`legal_hold_released` facts; never
edit `legal_hold_refs` outside the ledger.

## Embedding provider incident

`ControlledEmbeddingGateway` bounds concurrency, timeout, attempts, and batch size around
`EmbeddingPort`. If an adapter times out or raises:

1. Confirm the failure surfaces as a bounded `embed_requested` fact without a matching
   `embed_completed` fact — this is the expected fail-closed state, not an ambiguous
   retry.
2. Do not retry embedding for a record whose chunker/embedder version no longer matches
   current policy; re-chunk and re-embed under the current `EmbeddingSpec` instead.
3. Rotate a compromised or misbehaving embedding provider by publishing a new
   `EmbeddingSpec` version; in-flight facts bound to the old version are stale and must
   not be silently upgraded.
4. `TemporalMemoryActivities` send an initial heartbeat immediately, then a periodic
   heartbeat every 10 seconds for the duration of a long-running scan/chunk/embed/index/
   compact/purge/rebuild Activity, against a 30-second `heartbeat_timeout`. A worker that
   stops heartbeating (crash, stuck adapter call) is detected and the Activity retried by
   Temporal well before the timeout; do not raise the timeout or disable heartbeating to
   "fix" a slow adapter — fix or bound the adapter instead.

## Ambiguous or duplicate ingestion

A crash between `candidate_accepted` and `index_completed` leaves an incomplete fact
chain. Do not blind-retry the whole ingest: replay `reduce_memory` over
`memory_facts` for the tenant/memory ID, resume only the next expected fact type, and
never re-append a fact type whose expected version has already advanced past it.
Superseding a memory (`supersede`) requires the exact and complete
`replaced_memory_ids` set on an accepted replacement; a partial or stale set is rejected
before any fact is appended.

## Retrieval and context incidents

1. Read only the authorized `RetrievalResult`/`MemoryContext` API/CLI views. Both are
   redacted: they never include tenant ID or raw text fields banned from
   `MemoryFact` payloads.
2. Treat `MemoryContext.instruction_boundary` as load-bearing. Never process retrieved
   snippets as instructions, tool calls, or authority — they are LangGraph state, not a
   graph edge to an effect.
3. `RetrievalResult.insufficient_context=true` (propagated into `MemoryContext`) is a
   valid fail-closed terminal, not an operator reason to lower the citation/quality bar
   or retry with a relaxed policy. `MemoryFactType.RETRIEVE_REQUESTED`/
   `RETRIEVE_COMPLETED`/`CONTEXT_BUILT` are now emitted as digest-only
   `MemoryOperationFact`s by `MemoryRetrievalService` around every retrieval and context
   build, appended to `InMemoryMemoryOperationLedger` (or the durable, immutable
   `aegis.memory_operation_facts` table) with strict per-operation sequencing (1/2/3) and
   idempotent replay. These facts carry only `policy_digest`/`query_digest`/
   `result_digest` — never raw query text or content — and are a separate,
   purpose-built ledger from the primary `MemoryFact` ingest/lifecycle ledger; do not
   conflate the two when investigating an incident. Retrieval and context-build activity
   is therefore audit-observable; it is not the same guarantee as the SQL query itself
   being the production serving path (see the activation gate note above).
4. Cross-tenant cache/index entries must never be observed. The bounded cache in
   `InMemoryHybridIndex` is tenant-scoped; a cross-tenant hit is a security incident, not
   a cache bug to silently patch. `PostgresMemoryStore.hybrid_candidates` enforces the
   same isolation directly in SQL (tenant/classification/ACL/time prefilters); its
   integration test asserts a wrong-tenant/classification query returns zero candidates.

## Rebuild

Rebuild the memory projection by verifying `memory_facts` sequence/previous-digest
integrity, folding with `reduce_memory` in ordinal order, and comparing the final
status/legal-hold count against the current projection before swapping. Never rebuild
memory truth from `InMemoryHybridIndex`, a Postgres chunk row, a Temporal
`aegis.memory.v1` history, or a LangGraph checkpoint. Purging or losing the derived index
or chunk table never affects ledger truth; it can always be rebuilt from
`embed_completed`/`index_completed` facts and re-chunked/embedded content.

After projection replay, `MemoryLifecycleService.rebuild_derived` accepts only the
stored record plus retained approved content with the exact tenant, evidence,
content digest, chunker and embedder versions. It appends a rebuild intent before
embedding, replaces the derived set only after validating every vector, and appends
completion. Retries reuse the caller's rebuild ID; a later independent index loss
requires a new ID. Production still needs qualified blob/KMS and embedding adapters,
so this local path is not live rebuild evidence.

## Incident triggers

Escalate as platform/security incidents: a banned field (raw text/query/prompt/
completion/tenant ID/locator) observed inside a `MemoryFact` payload, a cross-tenant
index/cache/retrieval hit, an erasure that proceeds while legal hold is set, an
`embed_completed`/`index_completed` fact recorded against a chunker/embedder version that
does not match the record, or any operator or downstream consumer treating retrieved
memory content as an instruction, approval, or effect trigger.

## Recovery source of truth

Rebuild from PostgreSQL `memory_records`/`memory_facts`/`memory_projections` (forced RLS,
immutable). `memory_chunks` (derived embeddings), `memory_cache`, and the in-memory
hybrid index are always disposable and rebuildable from ledger facts. Temporal
`aegis.memory.v1` history is a scheduling observation, never audit truth. Never edit
immutable facts to recover availability or to "fix" a stuck retrieval.
