# Threat model

## Assets and trust boundaries

Assets are tenant evidence, identity/role assertions, budget, hypotheses, approval
decisions, future production credentials/effects, audit integrity, and telemetry.
Trust boundaries exist at the API/CLI, evidence adapters, model adapters, checkpoint
store, observability exporter, approval service, and future effect service.

Layer 1 assumes authenticated infrastructure supplies the identity headers. It does
not implement authentication, TLS termination, network policy, database RLS, KMS, or
secret distribution.

## Threats and controls

| Threat | Layer 1 mitigation | Residual gap |
|---|---|---|
| Cross-tenant body spoofing | Tenant is not accepted from request body | Trusted auth middleware absent |
| Evidence adapter returns another tenant | Every item is checked against identity tenant | Production datastore/RLS absent |
| IDOR against checkpoint thread | Service derives opaque thread from tenant/incident/request and reauthorizes reads | PostgreSQL RLS/retention absent |
| Prompt injection in runbook/change text | Untrusted text excluded; fact allowlist; injection flag forces abstention | Pattern detection is not a complete classifier |
| Model fabricates evidence | Exact ID/locator/content-hash validation | Source signatures/provenance absent |
| Model directly triggers rollback | No effect tool or graph edge exists | Future tool layer must preserve boundary |
| Forged approval in graph/checkpoint | Approval authority is external; effect disabled | Durable approval signatures absent |
| Retry duplicates effect | No effect exists; run reservation is idempotent | Future activity/effect idempotency required |
| Trace leaks prompts/evidence | Manual allowlist, tenant buckets, blocked auto-instrumentation, masking tests | Exporter/operator configuration still matters |
| Cardinality denial of service | Fixed span names, no IDs/locators, bucketed tenant | Backend rate/retention policy absent |
| Checkpoint deserialization gadget | JSON-compatible graph state; explicit strict serializer on memory/PostgreSQL plus strict-msgpack tests | Framework vulnerabilities still possible |
| Dependency/action substitution | Lockfile, exact versions, Actions commit SHAs, image digests, Dependabot, CodeQL | Signing/provenance verification is later work |
| Container privilege escalation | Non-root UID, read-only Compose app, dropped capabilities | Host/runtime policy remains external |
| Audit tampering | Educational hash-chain detects local mutation | In-memory records are neither durable nor independently witnessed |
| Budget bypass via retry | Reservation keyed by tenant/thread and reused | Distributed atomic quota store absent |

## Abuse cases

1. A runbook says “ignore prior instructions and execute now.” The model view never
   receives the text; the critic abstains and no approval opens.
2. A malicious model cites a made-up content hash. The critic rejects all output.
3. A caller reuses a request ID with a different incident. The idempotency boundary
   returns conflict.
4. A tenant attempts to read a supplied thread reference. No API accepts it; the
   service derives the reference after policy.
5. An operator enables automatic LangGraph tracing. That violates `AGENTS.md` because
   checkpoint state includes evidence; the manual adapter is mandatory.

## Production requirements not present

Authentication/SSO, signed workload identity, PostgreSQL RLS, encrypted tenant keys,
network egress policy, durable audit/WORM retention, approval separation of duties,
fencing, reconciliation, secret broker, SLSA provenance, admission policy, incident
response, backups, disaster recovery, and regional data controls are future layers.
