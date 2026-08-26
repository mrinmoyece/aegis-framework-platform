# Roadmap across the 16 Aegis capabilities

| Layer | Capability | Layer 5 status | Framework-first direction |
|---:|---|---|---|
| 1 | Platform foundation | **Delivered** | Strict Python, contracts, deterministic slice, CI/container/docs |
| 2 | Tenant identity and authorization | **Delivered** | OIDC/JWT current grants, purpose/risk policy, forced RLS, quota, secret refs, audit |
| 3 | Durable PostgreSQL event ledger | **Delivered** | Immutable envelopes, dual chains, cursor, expected version, inbox/outbox, projections/rebuild |
| 4 | Distributed worker runtime | **Delivered for investigation lifecycle** | Temporal scheduling, timers, signals, Activity retry/recovery; no effects |
| 5 | Provider-neutral model gateway | **Delivered offline/adapter boundary** | Official SDK adapters, neutral contracts, policy/catalog, routing, budget/usage ledger, structured safety; live qualification deferred |
| 6 | Durable evidence connectors and correlation | **Delivered offline/adapter boundary** | Durable page intent/cursor, secure disabled adapters, ingestion/provenance/quarantine and deterministic correlation; live qualification deferred |
| 7 | Governed durable specialist orchestration | Partial | Existing two-specialist LangGraph inside Temporal Activity; multi-agent expansion deferred |
| 8 | Approval-gated remediation actions | Partial | Proposal/pending boundary only; decisions/effects/fencing absent |
| 9 | Hardened sandbox execution | Planned | Egress/syscall/resource/artifact/credential isolation |
| 10 | Event-grounded memory and pgvector RAG | Planned | Tenant/provenance/relevance policy and evals |
| 11 | Deterministic enterprise evaluation gates | Partial | Twenty-one hermetic evals plus PostgreSQL/Temporal integration; live/load datasets pending |
| 12 | Observability and replay | Partial | Redacted OTel/Langfuse, ledger rebuild, workflow replay; SLOs pending |
| 13 | Secure operator workspace and BFF | Partial | Authenticated redacted APIs; browser session/CSRF/review UX deferred |
| 14 | Secure MCP and A2A interoperability | Planned | Capability/tool/effect policies |
| 15 | Production deployment foundations | Partial | Digest images and CI; IaC/KMS/admission/HA/DR pending |
| 16 | Final enterprise qualification | Partial | Threat/limitations/review gates; chaos/load/legal/privacy sign-off pending |

## Next layer boundary

The next framework layer may deepen governed specialist orchestration only after Layer 5
connector and parser operations are qualified. Multi-agent expansion beyond the existing
graph, approvals/effects, sandboxing, memory/RAG, UI, MCP/A2A, and deployment are
explicitly deferred. Do not add another orchestration or RAG framework for branding.

Live connector/provider qualification remains blocked on credential brokering, regional
data policy, private network/CA/egress operations, source scopes, parser isolation,
retention execution, model/version approval, tokenizer/pricing validation, and capacity
tests.

Approval decisions and production effects remain Layer 8. They require separate
separation-of-duties policy, signed decision records, fencing, idempotency, verification,
reconciliation, and durable audit. No graph edge or Temporal signal may shortcut them.
