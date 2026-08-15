# Roadmap across the 16 Aegis capabilities

| Layer | Capability | Layer 3 status | Framework-first direction |
|---:|---|---|---|
| 1 | Platform foundation | **Delivered** | Strict Python, contracts, deterministic slice, CI/container/docs |
| 2 | Tenant identity and authorization | **Delivered** | OIDC/JWT current grants, purpose/risk policy, forced RLS, quota, secret refs, audit |
| 3 | Durable PostgreSQL event ledger | **Delivered** | Immutable envelopes, dual chains, cursor, expected version, inbox/outbox, projections/rebuild |
| 4 | Distributed worker runtime | **Delivered for investigation lifecycle** | Temporal scheduling, timers, signals, Activity retry/recovery; no effects |
| 5 | Provider-neutral model gateway | Partial | `StructuredModelPort`; live adapters/credentials/routing deferred |
| 6 | Durable evidence connectors and correlation | Partial | Tenant/hash validation and durable snapshot; live signed connectors deferred |
| 7 | Governed durable specialist orchestration | Partial | LangGraph cognitive graph inside Temporal Activity; richer specialists deferred |
| 8 | Approval-gated remediation actions | Partial | Proposal/pending boundary only; decisions/effects/fencing absent |
| 9 | Hardened sandbox execution | Planned | Egress/syscall/resource/artifact/credential isolation |
| 10 | Event-grounded memory and pgvector RAG | Planned | Tenant/provenance/relevance policy and evals |
| 11 | Deterministic enterprise evaluation gates | Partial | Thirteen evals plus PostgreSQL/Temporal integration; broader datasets/load pending |
| 12 | Observability and replay | Partial | Redacted OTel/Langfuse, ledger rebuild, workflow replay; SLOs pending |
| 13 | Secure operator workspace and BFF | Partial | Authenticated redacted APIs; browser session/CSRF/review UX deferred |
| 14 | Secure MCP and A2A interoperability | Planned | Capability/tool/effect policies |
| 15 | Production deployment foundations | Partial | Digest images and CI; IaC/KMS/admission/HA/DR pending |
| 16 | Final enterprise qualification | Partial | Threat/limitations/review gates; chaos/load/legal/privacy sign-off pending |

## Next layer boundary

Layer 4 work should not add another queue/retry owner. It should qualify Temporal worker
operations: authenticated namespaces, task-queue routing, worker versioning, autoscaling,
backpressure, HA/backup/restore, capacity and chaos tests. Live evidence/model providers
remain blocked on credential brokering and data policy.

Approval decisions and production effects remain Layer 8. They require separate
separation-of-duties policy, signed decision records, fencing, idempotency, verification,
reconciliation, and durable audit. No graph edge or Temporal signal may shortcut them.
