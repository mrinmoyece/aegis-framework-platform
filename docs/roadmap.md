# Roadmap across the 16 Aegis capabilities

The custom Aegis program is organized as 16 cumulative capabilities. This repository
uses the same conceptual progression so comparisons remain honest; it does not copy
the custom implementation.

| Layer | Capability | Layer 1 parity | Framework-first direction |
|---:|---|---|---|
| 1 | Platform foundation | **Delivered** | Strict Python, contracts, deterministic slice, CI/container/docs |
| 2 | Tenant identity and authorization | Partial | Replace trusted headers/local role policy with workload/user identity, RBAC/ABAC, tenant RLS |
| 3 | Durable PostgreSQL event ledger | Partial | PostgreSQL checkpoint adapter exists; add application-owned durable audit/idempotency schemas |
| 4 | Distributed worker runtime | Planned | Introduce explicit queue/work ownership only when scaling evidence/model work |
| 5 | Provider-neutral model gateway | Partial | `StructuredModelPort` + fake exist; add official OpenAI/Anthropic adapters, quotas, routing, schema/version policy |
| 6 | Durable evidence connectors and correlation | Partial | Replace fake telemetry/GitHub/runbook data with signed, tenant-scoped connectors and provenance |
| 7 | Governed durable specialist orchestration | Partial | LangGraph fan-out/join exists; add PostgreSQL mode, pause/resume, policies, richer specialists |
| 8 | Approval-gated remediation actions | Partial | Pending approval boundary and disabled effect exist; add separation of duties, signed decisions, fencing |
| 9 | Hardened sandbox execution | Planned | Isolate tools/effects with egress, syscall, resource, artifact, and credential policies |
| 10 | Event-grounded memory and pgvector RAG | Planned | Add tenant-filtered, provenance-preserving retrieval only after relevance/isolation evals |
| 11 | Deterministic enterprise evaluation gates | Partial | Five core evals exist; add regression datasets, quality thresholds, adversarial suites, release gates |
| 12 | Observability and replay | Partial | Redacted OTel/Langfuse and graph checkpoints exist; add durable audit replay and operational SLOs |
| 13 | Secure operator workspace and BFF | Planned | FastAPI is only a thin API; add React/TypeScript BFF, CSRF/session security, accessible review UX |
| 14 | Secure MCP and A2A interoperability | Planned | Add official stable SDKs behind identity, capability, evidence, and effect policies |
| 15 | Production deployment foundations | Partial | Non-root digest image and CI exist; add IaC, KMS, policy admission, RLS, backups, rollout/rollback |
| 16 | Final enterprise qualification | Partial | Threat/limits/review gates exist; add load/chaos/DR/security/legal/privacy qualification |

## Next layer

Layer 2 should make identity and tenancy real before adding a live model:

1. authenticated human/workload principals and signed claims;
2. tenant-scoped PostgreSQL schemas with RLS tests;
3. application-owned durable idempotency and audit tables;
4. PostgreSQL LangGraph saver wired through runtime configuration without fallback;
5. authorization on API, evidence, checkpoints, approvals, and audit reads;
6. migration, backup, erasure, and retention policy.

Only after those controls should Layer 5 add credentialed providers. Temporal remains
deferred until Layer 8 introduces durable approval/effect workflows.
