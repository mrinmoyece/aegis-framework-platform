# Layer 2 limitations

- Production mode can build OIDC/JWT identity and PostgreSQL governance from explicit
  environment configuration. Missing configuration fails readiness closed. The
  deterministic static authenticator is available only in explicit demo/test mode.
- JWT attacks and deterministic two-key rotation are tested. A local,
  environment-gated Keycloak token test exists, but live IdP rotation, outage,
  revocation latency, HA, realm administration, and production traffic are unproven.
- PostgreSQL integration tests prove the migration, non-bypass runtime role, forced
  RLS, transaction/pool reset, audit mutation prevention, quota concurrency, and
  checkpoint isolation. They do not prove HA, backup/restore, PITR, failover,
  cross-region latency, capacity, retention, or erasure operations.
- The local Keycloak Compose profile contains no users, client secrets, or realm
  credentials. Operators must supply bootstrap credentials and configure a local
  client/claim mapper before the gated live test.
- `SecretReference` prevents values entering domain/API/graph/audit data. Layer 2 does
  not resolve Vault/KMS secrets, broker short-lived credentials, rotate them, or prove
  provider isolation.
- The production investigation route remains unavailable until future production
  evidence and model adapters exist. This avoids silently using deterministic fixtures
  with production identity. The authenticated governance routes are production-shaped.
- Evidence and model fixtures remain deterministic. No live OpenAI, Anthropic,
  telemetry, GitHub, or runbook credentials/network calls exist.
- Injection detection demonstrates minimization and abstention, not universal
  prompt-injection classification. Content hashes do not prove source authenticity.
- Durable audit is application-owned, immutable to the runtime, tenant hash-chained,
  and redacted. It is not externally witnessed, signed by HSM/KMS, WORM-retained, or
  legally qualified.
- LangGraph saver tables are protected by an application RLS overlay. Saver upgrades
  must be requalified against table/schema changes. Checkpoints remain neither audit
  nor authorization.
- Policy is explicit immutable RBAC plus purpose/risk/current grant checks. There is no
  delegated administration UI, policy simulation service, Cedar/Casbin/OPA adapter, or
  formal policy proof.
- API anti-enumeration normalizes status/details but timing behavior has not been
  load-tested. TLS, ingress, WAF, session/BFF/CSRF behavior, and browser UX are absent.
- There is no approval decision endpoint, effect execution, fencing, independent
  verification, reconciliation, or rollback.
- Temporal, MCP, A2A, sandbox execution, vector retrieval, memory, distributed workers,
  and human workflow remain deferred.
- Local runtime measurements are not reliability, throughput, load, or cost
  benchmarks. Dependency advisory checks require current advisory network access.

These are deliberate boundaries, not implied framework or enterprise capabilities.
