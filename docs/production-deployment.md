# Layer 14 production deployment reference

This layer is an executable **reference foundation**, not evidence of an operated
production service. `make deployment-check`, `make kubernetes-render`,
`make terraform-check`, and `make restore-drill` validate local structure and
deterministic contracts without cloud credentials or paid resources.

## Topology and authority

| Workload | Replicas | Temporal queue / purpose | Authority boundary |
|---|---:|---|---|
| API | 3-12 | none | Establishes `IdentityContext`; reads application projections |
| Operator BFF/UI | 3-8 | none | Same-origin session/CSRF boundary; production readiness still requires live OIDC exchange and shared sessions |
| Outbox | 2 | `aegis-production-outbox-v1` | Delivers committed application intent; never creates truth |
| Reconciler | 2 | `aegis-production-reconciler-v1` | Resolves ambiguous framework/provider state into new application facts |
| Investigation | 3-20 | `aegis-production-investigation-v1` | Temporal lifecycle only |
| Cognitive | 3-20 | `aegis-production-cognitive-v1` | One bounded LangGraph run; no approval/effect edge |
| Evidence | 3-20 | `aegis-production-evidence-v1` | Current source policy, page intent, provenance, quarantine |
| Remediation | 2-8 | `aegis-production-remediation-v1` | Reloads exact application approval/fence before effects |
| Memory | 2-12 | `aegis-production-memory-v1` | Derived pgvector/checkpoint work; ledger remains truth |
| Sandbox controller | 2 | `aegis-production-sandbox-v1` | Creates only fixed hardened Jobs in the dedicated namespace |
| Protocol gateway | 3-16 | `aegis-production-protocol-gateway-v1` bootstrap coordination | Inbound MCP/A2A Host/origin/identity boundary; fails closed without enterprise bootstrap |
| Protocol worker | 3-16 | `aegis-production-protocol-v1` | MCP/A2A durable translation through current trust/policy |
| OTel gateway | 2 | none | Redacted operational signals only |

The production worker command loads exactly one installed
`aegis_framework.production_worker` entry point named `aegis`. Missing wiring,
Temporal TLS/API-key or mTLS material, codec key, non-default namespace, build ID, or
PostgreSQL DSN fails closed. Startup/readiness/liveness files contain no payload or
identity data; preStop removes readiness and requests a 90-second drain.

## Kubernetes controls

`deployment/kubernetes/base` and `overlays/production` render with `kubectl
kustomize`. Every long-running Pod has an explicit service account, non-root UID/GID,
read-only root, drop-all capabilities, no escalation, RuntimeDefault seccomp, bounded
tmpfs, requests/limits, probes, preStop, 120-second termination, PDB, zone/host spread,
anti-affinity, and zero-unavailable rolling updates. HPAs use slow scale-down to avoid a
retry storm. No workload uses host namespaces, hostPath, sockets, devices, privileged
mode, or an automatically mounted service-account token.

The sandbox is a separate restricted namespace with a tokenless service account,
Kata `RuntimeClass`, dedicated node label/taint, quota, limits, network default deny,
bounded CSI/emptyDir admission, and the existing exact Job policy. A namespace is not a
hostile-code boundary. Kata nodes, guest/kernel images, CNI, admission, CSI,
workload identity, PID enforcement, cleanup, escape tests, and an approved egress
proxy must be qualified before readiness.

## Network and secret boundaries

Both namespaces default deny ingress and egress. Explicit policies permit:

- internal ingress-controller traffic to API/operator;
- CoreDNS;
- PostgreSQL/pgvector only through a labeled data boundary;
- Temporal frontend only through a labeled private endpoint;
- OIDC, approved providers/connectors, OTLP, and protocol peers only through labeled
  boundary proxies.

Standard NetworkPolicy cannot enforce DNS names and does not consistently identify a
managed Kubernetes API endpoint. Platform overlays must provide enforcing CNI and
boundary proxies/private endpoints; direct Internet or broad RFC1918 egress is not
claimed. The sandbox controller uses a one-hour, audience-bound projected Kubernetes
token rather than automatic token mounting.

Secrets are names only in manifests. AWS Secrets Manager and EKS Pod Identity are the
reference. An External Secrets/CSI operator may materialize `aegis-runtime-secrets`,
`aegis-migration-secrets`, and `aegis-telemetry-secrets` only after its own RBAC,
rotation, deletion, outage, and redaction qualification.

## Deploy and rollback order

1. Qualify the cluster, Kata nodes, admission/CNI/proxies, workload identity, secret
   sync, DNS/TLS, RDS, Temporal namespace/private endpoint, telemetry, and backups.
2. Verify source gates, multi-arch digest, SBOM, vulnerabilities/licenses/secrets,
   keyless signature, provenance, and admission identity.
3. Take and verify a pre-migration backup. Run the additive PreSync migration Job;
   checksum drift or advisory-lock failure stops deployment.
4. Deploy old/new compatible workers first with a new Temporal deployment/build ID.
   Replay retained representative histories, then route new workflows gradually.
5. Deploy outbox/reconciler, API, protocol, and operator. Production BFF readiness must
   remain `503` until live OIDC exchange and durable shared sessions exist.
6. Hold a canary/soak. Block promotion on safety violations, tenant isolation,
   reconciliation/cleanup failures, fast burn, exhausted error budget, queue
   schedule-to-start, DB saturation, or migration drift.
7. Roll back stateless code to a previously verified digest while leaving additive
   schema in place. Route workflows to a replay-compatible worker. Never reverse a
   destructive migration or infer success from framework status.
8. Reconcile outbox, workflows, ambiguous provider calls/effects, sandbox cleanup,
   and application projections before declaring the change converged.

GitHub Environments record staged approvals for the same immutable digest. A GitOps
repository/controller remains deployment authority; the promotion workflow emits a
verified digest-only candidate rather than directly applying a cluster. Protected
branch enforcement and commit signing are not proven by repository files.

## Observability, UI, protocol, and compliance

The in-cluster Collector repeats the fixed attribute allowlist, memory limiter, batch,
bounded queue/retry, and no-debug-exporter policy. Automatic LangGraph/LangChain tracing
stays disabled. Managed Prometheus/log resources are Terraform references only.
Telemetry cannot grant readiness for correctness or replace the ledger.

TLS ingress supplies force-redirect, HSTS, body/rate/connection/time limits. Live BFF
OIDC/session readiness, trusted proxy header behavior, browsers, assistive technology,
and independent penetration testing remain unproven. Protocol egress remains disabled
without reviewed peer routes, mTLS/PKI, distributed replay/quota, and partner
qualification.

Evidence can map to control objectives in
[compliance evidence](compliance-evidence.md), but no certification, legal opinion,
production verification, or operated SLO follows from these assets.
