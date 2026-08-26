# Layer 4 limitations

- The optional Temporal Compose service is a single local `auto-setup:1.29.1` process
  backed by the local PostgreSQL service. It proves SDK 1.31.0 compatibility for the
  used APIs, not production topology, auth/TLS, HA, upgrades, failover, capacity, or DR.
- The SDK test supports a preinstalled time-skipping test-server binary. Tests never
  download it implicitly. CI uses the digest-pinned Compose server instead.
- Temporal workflow payloads are bounded and opaque but not encrypted by this layer.
  A production payload codec/KMS and Temporal mTLS/namespace policy remain required.
- No custom search attributes are used, avoiding tenant/PII indexing. Operational
  filtering is correspondingly limited.
- Workflow patching is demonstrated by one patch marker and history replay. Production
  Worker Versioning rollout/rollback and long-lived historical fixture retention are
  not qualified.
- Continue-as-new is deliberately absent because history is bounded. If the lifecycle
  grows, history size must be measured before adding it.
- The application event hash chains detect local mutation/reordering but are unsigned,
  not externally witnessed, and not WORM/legal records.
- PostgreSQL integration proves forced RLS, non-bypass runtime role, immutable facts,
  ledger/outbox atomicity, projection rebuild, and tenant isolation. It does not prove
  HA, PITR, backup/restore, partitioning, regional ordering, retention, or erasure.
- The commit-order tenant cursor/hash chain intentionally serializes all event appends
  for one tenant on one cursor row. This favors deterministic integrity/rebuild over
  maximum write throughput; capacity and partitioning alternatives are unmeasured.
- In-memory durability is a deterministic reference/test adapter only. Production must
  use the PostgreSQL adapter and cannot fall back to memory.
- The durable API demo records/reads application intent but does not start a production
  worker. Official OpenAI/Anthropic adapters exist, but production wiring is deliberately
  unavailable without qualified credentials, model policy/catalog, and worker deployment.
- Evidence snapshots in application events are tenant-scoped and API-redacted. Source
  signatures, retention classification, connector credentials, and live provenance
  remain deferred.
- Activity failures and retries are bounded, but external side effects would still need
  separate intent/result, approval validation, fencing, idempotency, verification, and
  reconciliation. Layer 3 performs no production effect.
- Cancellation stops the workflow lifecycle and rejects stale results; it cannot undo
  already completed external I/O. There are no effect Activities.
- Temporal queries are operational only. If the application ledger is unavailable, the
  product API fails closed rather than returning framework state.
- OpenTelemetry's Temporal interceptor is optional. Application allowlists do not
  control arbitrary operator-added interceptors/exporters; new exporters require
  redaction tests.
- Local timing measures deterministic in-process behavior, not Temporal/PostgreSQL
  throughput or a cross-repository load benchmark.
- Live IdP rotation, KMS/Vault, approvals/effects, sandbox, memory/RAG, UI/BFF, MCP/A2A,
  and deployment remain deferred.
- OpenAI 3.1.0 and Anthropic 0.122.0 adapter shape tests use fake SDK clients. No live
  credentials, network, provider retention policy, regional processing, model snapshot,
  abuse-filter, tokenizer, latency, rate-limit, or billing behavior is qualified.
- Conservative byte-based token estimation can over-reserve and cannot prove provider
  context fit for every tokenizer. Catalog limits/prices are declared inputs, not a live
  price feed; unknown declarations fail closed.
- A provider can bill a request when the client sees timeout/cancellation/crash. Pending
  intent and ambiguous settlement reserve the ceiling and block silent duplicate calls.
  Provider reconciliation is required; exactly-once billing is not claimed.
- In-process circuit/rate/concurrency state is availability control, not durable truth or
  distributed global enforcement. Production multi-worker limits need a qualified
  application-owned coordination adapter without creating another retry authority.
- Model usage and provider health are RLS-filtered projections rebuilt from immutable call
  facts. Health is observed history, not a provider SLA or permission to route.
- PostgreSQL model reservation/reconciliation integration is environment-gated. It does
  not qualify HA, multi-region budget order, price updates during long runs, or high-volume
  ledger partitioning.

These are explicit non-production boundaries, not implied capabilities.
