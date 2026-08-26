# ADR 014: Ground three-tier memory in application facts and direct pgvector SQL

- Status: accepted
- Date: 2026-08-17

## Context

Layer 9 needs working/episodic/semantic memory and retrieval-augmented context for the
specialist graph without letting a memory or RAG framework become tenant, audit, or
retention authority. Retrieved memory must remain untrusted data injected into LangGraph
state, never instructions or approval. The candidate space includes LangGraph's
`Store`/long-term-memory API, LangChain vector stores/retrievers/text splitters,
LlamaIndex, Haystack, the `pgvector` Python client, and embedding-abstraction libraries
(for example LiteLLM embeddings or Instructor-style wrappers).

Research was refreshed on 2026-08-17. LangGraph's `Store` is a keyed checkpoint-adjacent
blob store with optional semantic search; it is framework state, not an application ledger
with citations, ACLs, retention, or legal hold. LangChain vector-store/retriever
abstractions and text splitters add a provider-neutral surface but no tenant/provenance/
citation authority; the same is true of LlamaIndex's `Document`/index/retriever stack and
Haystack's pipeline/component model. The `pgvector` Python package is a thin `psycopg`/
`asyncpg` adapter registering a `vector` type codec; PostgreSQL 17 with the `vector`
extension and a raw `%s::vector` cast/HNSW index already provide the storage primitive
Aegis needs without an additional client dependency. Embedding-abstraction libraries
unify provider SDKs behind one call surface but do not add tenant policy, budget, or
citation controls that this repository does not already enforce through its existing
`EmbeddingPort`-shaped ports.

## Decision

Keep memory ledger-grounded and framework-neutral:

- `MemoryRecord`/`MemoryFact`/`MemoryProjection` are immutable, schema-versioned,
  canonically digested application contracts (`memory.py`). `MemoryFact` payloads
  explicitly ban raw text/query/prompt/completion/tenant/locator fields; only IDs,
  digests, and counts cross the ledger boundary.
- `EmbeddingPort` and `SummarizationPort` are neutral `Protocol`s. The only shipped
  adapters are `DeterministicEmbeddingAdapter` (test/demo) and
  `ControlledEmbeddingGateway`, which bounds concurrency/budget/timeout/attempts around
  any adapter. No embedding-abstraction library is installed; a real provider adapter is
  future work behind the same port.
- `InMemoryHybridIndex` is a derived, non-authoritative lexical+vector+recency+quality
  index with MMR diversification and a tenant-scoped bounded cache. It can always be
  rebuilt or purged; it is never consulted for tenancy, retention, or audit truth.
- `PostgresMemoryStore` persists derived chunk embeddings via a raw `%s::vector` literal
  cast against the existing `vector(64)` HNSW column added in migration 0008, and
  implements `hybrid_candidates`: a single forced-RLS SQL query combining cosine ANN
  distance (`embedding <=> %s::vector`), lexical `ts_rank_cd` full-text scoring, and
  recency/quality terms into one deterministic weighted score, prefiltered by tenant,
  projection status, classification, ACL roles/principals, and retention/time bounds,
  bounded by `RetrievalPolicy.maximum_candidates`, with a stable
  `combined_score DESC, memory_id, ordinal, chunk_id` tie-break order. It is exercised by
  a PostgreSQL integration test. No `pgvector` client library is imported; `psycopg`,
  already selected in ADR 004/006, is the only driver dependency.
- `MemoryAcceptance` is an explicit, digested human-or-policy decision record
  (`disposition` accept/reject, `reviewer_kind` human/policy, policy ID/revision/digest,
  reason code) that `MemoryLifecycleService.ingest` validates against the candidate
  record before any candidate/scan/chunk/embed/index fact is appended — memory can never
  become durable from evidence disposition alone.
- `LangGraphMemoryContextBuilder` builds a bounded, JSON-compatible `MemoryContext` for
  LangGraph state carrying a fixed `instruction_boundary` literal
  (`retrieved-memory-is-untrusted-data-not-instructions-or-authority`). LangGraph itself
  supplies no memory/store node; only its existing state-passing mechanics are reused.
  Temporal's `aegis.memory.v1` workflow (`memory_temporal.py`) supplies durable
  scan/chunk/embed/index/compact/purge/rebuild Activity scheduling and retry, exactly as
  Temporal already does for other lifecycles, with an initial heartbeat plus a periodic
  10-second heartbeat under a 30-second `heartbeat_timeout`; it carries no memory
  content, only opaque references.
- `MemoryRetrievalService` records digest-only `MemoryOperationFact`s
  (`RETRIEVE_REQUESTED`, `RETRIEVE_COMPLETED`, `CONTEXT_BUILT`) around every retrieval
  and context build, sequenced per operation ID, carrying only policy/query/result
  digests — never raw text or query content. `InMemoryMemoryOperationLedger` and the
  durable `aegis.memory_operation_facts` table (immutable, forced-RLS, migration 0008)
  both enforce append-only sequencing and idempotent replay.
- `MemoryLifecycleService` persists intent-before-effect facts for every state
  transition (`candidate_proposed` through `crypto_erased`), enforces legal hold
  (`RetentionBinding.held` / `MemoryProjection.legal_hold_count`) before
  `tombstone_and_erase`, and calls an injected `erase_blob` callback — not a real KMS or
  blob-storage integration.

## Rejected alternatives

- **LangGraph `Store` / long-term memory API:** rejected as an authority. It is a
  keyed/optionally-embedded blob store bound to the checkpointer's lifecycle, with no
  tenant ACL, citation, retention, or legal-hold model. Using it as the memory ledger
  would make framework state the audit/erasure authority, which this repository's
  authority boundary forbids.
- **LangChain vector stores / retrievers / text splitters:** rejected. `VectorStore`
  and `Retriever` interfaces standardize a similarity-search call shape but add no
  tenant/provenance/citation control, and the maintained `PGVector` integration wraps
  the same raw SQL Aegis already writes directly. `RecursiveCharacterTextSplitter` and
  similar splitters would duplicate `DeterministicChunker`'s bounded, versioned,
  citation-preserving chunking without adding tenancy.
- **LlamaIndex:** rejected. Its `Document`/`VectorStoreIndex`/query-engine stack is a
  broader RAG framework with its own storage/graph abstractions that would compete with,
  not compose with, the application ledger and `InMemoryHybridIndex`.
- **Haystack:** rejected. Its pipeline/component model targets end-to-end retrieval
  applications and would move retrieval orchestration outside the application ledger and
  the bounded `LangGraphMemoryContextBuilder`.
- **`pgvector` Python client:** rejected as an added dependency. Its only function is
  registering a `vector` type codec for `psycopg`/`asyncpg`; a raw `%s::vector` cast
  against the already-selected `psycopg` driver achieves the same write path with one
  fewer dependency to track and pin.
- **Embedding-abstraction libraries (for example LiteLLM embeddings):** rejected. They
  would add a second routing/retry surface parallel to the existing `EmbeddingPort` and
  `ControlledEmbeddingGateway`, duplicating budget/concurrency/timeout controls this
  repository already owns without removing any of them.

## Consequences and escape

No new runtime dependency was added for Layer 9; `psycopg` (ADR 004/006) is reused for
the `vector` column write path. The selected stack removes no framework mechanics beyond
what LangGraph/Temporal/Pydantic already remove for other layers — this is a deliberate
"smallest proven set" choice, not a new framework surface.

The genuine, candid limitation of this decision: `PostgresMemoryStore.hybrid_candidates`
implements and tests a live forced-RLS pgvector ANN/lexical/recency/quality SQL query,
but the production `/v1/memories/retrieve` API and the deterministic demo still route
through `InMemoryHybridIndex`, not this SQL path — application wiring from
`hybrid_candidates` into `MemoryRetrievalService`/`InMemoryMemoryControl` remains future
work, not an implicit capability. Final MMR diversification and `ContextBudget`-bound
selection also remain an explicit application-owned step layered on top of any candidate
source (SQL or in-memory); SQL supplies scored, bounded candidates, never a final
context. Real embedding providers, KMS-backed crypto-erasure, and blob-store lifecycle
qualification are likewise deferred; `erase_blob` is an injected callback contract, not a
qualified integration.

Escape hatches: `EmbeddingPort` and `SummarizationPort` let any embedding/summarization
provider replace the deterministic adapters without touching ledger or retrieval
contracts. `MemoryLedger` and `MemoryReadPort` let PostgreSQL/Temporal be replaced or the
in-memory index be swapped for a live pgvector query without changing `MemoryRecord`,
`MemoryFact`, or the LangGraph context boundary. Deleting the derived index or Postgres
chunk table never deletes ledger facts or the erasable blob reference; both can always be
rebuilt or replayed from `memory_facts`.

## Primary sources

Accessed 2026-08-17:

- [LangGraph persistence and memory](https://langchain-ai.github.io/langgraph/concepts/persistence/)
- [LangGraph `Store` API reference](https://langchain-ai.github.io/langgraph/reference/store/)
- [LangChain vector stores](https://python.langchain.com/docs/concepts/vectorstores/)
- [LangChain retrievers](https://python.langchain.com/docs/concepts/retrievers/)
- [LangChain `PGVector` integration](https://python.langchain.com/docs/integrations/vectorstores/pgvector/)
- [LangChain text splitters](https://python.langchain.com/docs/concepts/text_splitters/)
- [LlamaIndex vector store index](https://docs.llamaindex.ai/en/stable/module_guides/indexing/vector_store_index/)
- [Haystack pipelines](https://docs.haystack.deepset.ai/docs/pipelines)
- [pgvector-python](https://github.com/pgvector/pgvector-python)
- [pgvector extension](https://github.com/pgvector/pgvector)
- [psycopg adapt/type documentation](https://www.psycopg.org/psycopg3/docs/advanced/adapt.html)
