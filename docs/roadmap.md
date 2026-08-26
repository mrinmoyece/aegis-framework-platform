# Roadmap across the 16 Aegis capabilities

| Layer | Capability | Layer 9 status | Framework-first direction |
|---:|---|---|---|
| 1 | Platform foundation | **Delivered** | Strict Python, contracts, deterministic slice, CI/container/docs |
| 2 | Tenant identity and authorization | **Delivered** | OIDC/JWT current grants, purpose/risk policy, forced RLS, quota, secret refs, audit |
| 3 | Durable PostgreSQL event ledger | **Delivered** | Immutable envelopes, dual chains, cursor, expected version, inbox/outbox, projections/rebuild |
| 4 | Distributed worker runtime | **Delivered for investigation lifecycle** | Temporal scheduling, timers, signals, Activity retry/recovery; no effects |
| 5 | Provider-neutral model gateway | **Delivered offline/adapter boundary** | Official SDK adapters, neutral contracts, policy/catalog, routing, budget/usage ledger, structured safety; live qualification deferred |
| 6 | Durable evidence connectors and correlation | **Delivered offline/adapter boundary** | Durable page intent/cursor, secure disabled adapters, ingestion/provenance/quarantine and deterministic correlation; live qualification deferred |
| 7 | Governed durable specialist orchestration | **Delivered offline/adapter boundary** | Fixed eight roles, typed artifacts, critic/planner/verification gates, application ledger and bounded LangGraph inside one Temporal Activity |
| 8 | Approval-gated remediation actions | **Delivered offline/adapter boundary** | Exact approvals, Temporal waits, fixed action, fencing/idempotency/reconciliation, verification and compensation |
| 9 | Hardened sandbox execution | **Delivered offline/adapter boundary** | Approval-bound immutable contracts, Temporal lifecycle, forced-RLS ledger, safe artifacts, hardened Kubernetes Job/RuntimeClass adapter; live isolation qualification deferred |
| 10 | Event-grounded memory and pgvector RAG | **Delivered offline/adapter boundary** | Immutable three-tier ledger, deterministic chunk/embed/compact pipeline, live forced-RLS pgvector hybrid SQL query (store-tested), digest-only retrieval/context ledger facts, explicit `MemoryAcceptance` decision contract, LangGraph-bounded untrusted context; production wiring of the SQL query into the serving path, real embedding providers, and KMS/blob erasure remain deferred |
| 11 | Deterministic enterprise evaluation gates | Partial | Twenty-one hermetic evals plus PostgreSQL/Temporal integration; live/load datasets pending |
| 12 | Observability and replay | Partial | Redacted OTel/Langfuse, ledger rebuild, workflow replay; SLOs pending |
| 13 | Secure operator workspace and BFF | Partial | Authenticated redacted APIs; browser session/CSRF/review UX deferred |
| 14 | Secure MCP and A2A interoperability | Planned | Capability/tool/effect policies |
| 15 | Production deployment foundations | Partial | Digest images and CI; IaC/KMS/admission/HA/DR pending |
| 16 | Final enterprise qualification | Partial | Threat/limitations/review gates; chaos/load/legal/privacy sign-off pending |

## Next layer boundary

Layer 9 delivers event-grounded three-tier memory, a live forced-RLS pgvector hybrid
retrieval query, and derived-index retrieval bounded into LangGraph state. The next
framework work is closing the remaining memory adapter-boundary gaps: wiring
`PostgresMemoryStore.hybrid_candidates` into the production retrieval control path
(`MemoryRetrievalService`/`InMemoryMemoryControl`, `/v1/memories/retrieve`), a real
embedding provider, and qualified KMS/blob-backed crypto-erasure. Full operator UI,
MCP/A2A, production deployment/IaC and live provider/runtime qualification remain
explicitly deferred. Do not add CrewAI, AutoGen, a memory/RAG framework (LangChain
vector stores, LlamaIndex, Haystack), or another overlapping orchestration/workflow
framework.

Live connector/provider qualification remains blocked on credential brokering, regional
data policy, private network/CA/egress operations, source scopes, parser isolation,
retention execution, model/version approval, tokenizer/pricing validation, and capacity
tests.

Layer 8 provides application-owned SoD/quorum decisions, immutable digests, fencing,
idempotency, verification, reconciliation and durable facts with deterministic/offline
adapters. Live cluster credentials, workload identity, Kubernetes RBAC, production
Temporal/PostgreSQL, chaos/load, external witnessing and operational sign-off remain
qualification gaps. Sandbox live Kata/gVisor, admission, CNI, CSI, egress-proxy and
workload-identity qualification is also pending. Layer 9 provides application-owned
memory ledger facts, an explicit `MemoryAcceptance` human/policy decision contract,
retention/legal-hold enforcement, digest-only retrieval/context ledger facts, a live
forced-RLS pgvector hybrid SQL query (proven at the store layer), and a derived retrieval
index with a fixed untrusted-data boundary; wiring the SQL query into the production
serving path, real embedding/summarization providers, and KMS/blob-qualified erasure
remain qualification gaps. No graph edge or Temporal signal may shortcut the controls.
