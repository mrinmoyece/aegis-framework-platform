# Roadmap across the 16 Aegis capabilities

The custom Aegis program is organized as 16 cumulative capabilities. This repository
uses the same conceptual progression so comparisons remain honest; it does not copy
the custom implementation.

| Layer | Capability | Layer 2 parity | Framework-first direction |
|---:|---|---|---|
| 1 | Platform foundation | **Delivered** | Strict Python, contracts, deterministic slice, CI/container/docs |
| 2 | Tenant identity and authorization | **Delivered** | OIDC/JWT humans/workloads, current grants, purpose/risk policy, forced RLS, quotas, secret references, durable audit |
| 3 | Durable PostgreSQL event ledger | Partial | Application audit is durable; add generalized domain event ledger, durable idempotency, retention and replay |
| 4 | Distributed worker runtime | Planned | Introduce explicit queue/work ownership only when scaling evidence/model work |
| 5 | Provider-neutral model gateway | Partial | `StructuredModelPort` + fake and tenant quota exist; add official adapters, credential broker, routing and schema/version policy |
| 6 | Durable evidence connectors and correlation | Partial | Replace fake telemetry/GitHub/runbook data with signed, tenant-scoped connectors and provenance |
| 7 | Governed durable specialist orchestration | Partial | LangGraph fan-out/join and tenant PostgreSQL saver exist; add pause/resume and richer specialists |
| 8 | Approval-gated remediation actions | Partial | Pending approval boundary and disabled effect exist; add separation of duties, signed decisions, fencing |
| 9 | Hardened sandbox execution | Planned | Isolate tools/effects with egress, syscall, resource, artifact, and credential policies |
| 10 | Event-grounded memory and pgvector RAG | Planned | Add tenant-filtered, provenance-preserving retrieval only after relevance/isolation evals |
| 11 | Deterministic enterprise evaluation gates | Partial | Eight core evals and JWT/RLS attacks exist; add regression datasets, quality thresholds and release gates |
| 12 | Observability and replay | Partial | Redacted OTel/Langfuse, checkpoints and durable audit exist; add replay tooling and operational SLOs |
| 13 | Secure operator workspace and BFF | Partial | Authenticated FastAPI governance exists; add React/TypeScript BFF, session/CSRF security and review UX |
| 14 | Secure MCP and A2A interoperability | Planned | Add official stable SDKs behind identity, capability, evidence, and effect policies |
| 15 | Production deployment foundations | Partial | Non-root digest image, RLS and CI exist; add IaC, KMS, admission, backups and rollout/rollback |
| 16 | Final enterprise qualification | Partial | Threat/limits/review gates exist; add load/chaos/DR/security/legal/privacy qualification |

## Next layer

Layer 3 should generalize the application-owned durable ledger without treating
LangGraph checkpoints as event history:

1. durable tenant idempotency and domain events beyond audit;
2. replay projections and integrity verification;
3. retention, legal hold, erasure exception and export policies;
4. backup/restore and failure-injection evidence;
5. partitioning/capacity measurements and migration rollback strategy.

Live model providers remain blocked on tenant credential brokering and data policy.
Temporal remains deferred until Layer 8 introduces durable approval/effect workflows.
