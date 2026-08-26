# ADR 019: Kustomize on AWS with a managed Temporal boundary

- Status: accepted for Layer 14 reference foundations
- Date: 2026-08-18

## Context

Layer 14 needs reproducible production packaging, infrastructure, supply-chain,
database lifecycle, recovery, and bounded multi-region controls without turning a
framework service into application authority. The repository already has a single
application image, a same-origin BFF/UI, PostgreSQL/pgvector truth, Temporal workflow
history, LangGraph checkpoints, and an isolated Kubernetes sandbox adapter.

## Decision

1. Use **Kustomize**, not Helm. The workload topology is fixed and security-sensitive.
   Base resources plus reviewable overlays avoid a chart template/value language,
   uncontrolled value combinations, and chart lifecycle coupling. A separate chart is
   justified only if a real distribution requirement appears.
2. Use private EKS and Multi-AZ RDS PostgreSQL 17 with pgvector as the AWS reference.
   Terraform `1.13.3` and AWS provider `6.10.0` are exact-pinned and direct resources
   are used rather than external modules. EKS Pod Identity, KMS, Secrets Manager, ECR,
   S3, AWS Backup vault lock, ACM/Route53, AMP, private endpoints, and native S3 state
   locking are reference boundaries, not evidence of an applied account.
3. Select **Temporal Cloud through AWS PrivateLink** as the reference Temporal
   topology. It removes server persistence/visibility databases, shard sizing, schema
   upgrade, replication, and control-plane patching from this repository. It does not
   remove namespace policy, task queues, payload encryption, mTLS/API-key handling,
   Worker Deployment Versioning, workflow replay, capacity, retention, or
   application reconciliation.
4. Isolate outbox, reconciliation, investigation lifecycle, cognitive LangGraph,
   evidence, remediation, memory, sandbox, and MCP/A2A work by explicit task queue.
   Production bootstraps are discovered through one attested entry point and fail
   closed when enterprise adapters are absent. No deterministic fake may become a
   production fallback.
5. PostgreSQL application events remain recovery and audit truth. Temporal history is
   workflow recovery; LangGraph checkpoints are cognitive recovery; both are
   reconstructible or reconcilable from application intent. Redis is not introduced.
6. Use one ledger writer region and monotonic generation fencing. Regional API edges
   and compatible workers may be stateless. There are no active-active ledger writes,
   global exactly-once, or exact global spend claims.
7. Build multi-architecture images, generate SPDX SBOMs, scan vulnerabilities,
   licenses, and secrets, keyless-sign immutable digests, attach provenance/SBOM
   attestations, and verify them before environment approval. The Sigstore admission
   policy is a prerequisite and must fail closed. A GitHub workflow run or signature
   is release evidence, never application authorization.

## Temporal Cloud versus self-hosted

| Concern | Temporal Cloud reference | Self-hosted alternative |
|---|---|---|
| Persistence/visibility | Managed by Temporal; retention and export contract required | Separate HA persistence and visibility databases, schema tooling, capacity, backup, and replication owned here |
| Upgrade/failover | Vendor-operated service; namespace/SDK/replay compatibility remains ours | Server, schema, Elasticsearch/OpenSearch if selected, replication, failover, and rollback all become platform duties |
| Network/auth | PrivateLink, TLS server-name verification, API key and optional mTLS refs | Private frontend, server mTLS, cert rotation, admin tools, and inter-service auth |
| Data/residency | Region/vendor/DPA/retention/backup terms must be qualified | Greater data-plane control, materially larger operational surface |
| Cost/lock-in | Usage-based managed cost and namespace API coupling | Infrastructure/on-call cost and deeper server operational coupling |
| Recovery | Application ledger still reconciles missing/unavailable histories | Server backups may recover histories, but still cannot replace application truth |

Self-hosting remains an escape only after a measured service/cost requirement and a
qualified server topology, persistence/visibility backup, schema upgrade, replication,
and failover program exist.

## Consequences

The repository gains a renderable Kubernetes topology, direct AWS reference, strict
production contracts, additive migration, deterministic restore/failover evidence, and
signed promotion gates. It also adds EKS/RDS/PrivateLink/GitHub Actions reference
coupling. Standard OCI, Kustomize, SQL, OTel, Sigstore, Temporal SDK contracts, neutral
ports, and application-ledger replay preserve escape routes.

The checked-in application digest is an offline render fixture derived from the Layer
13 base, not a published artifact. Promotion must replace it with a verified registry
digest. Real cloud apply, managed failover, production PKI, live worker bootstrap,
provider/connector credentials, SLO/on-call, load, chaos, penetration, accessibility,
and compliance certification remain release gates.

