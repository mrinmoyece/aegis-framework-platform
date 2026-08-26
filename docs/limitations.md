# Layer 10 limitations

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
- Dynatrace, GitHub App, Kubernetes, and runbook adapters are production-shaped but
  disabled by default and tested only with deterministic transports/SDK doubles. No live
  account, scope, token rotation, regional endpoint, latency, rate-limit, pagination, or
  provider-version behavior is qualified.
- HTTPX origin/DNS/IP checks reduce SSRF risk but cannot eliminate DNS rebinding between
  resolution and connection. Production requires deny-by-default egress, approved DNS,
  TLS inspection policy where applicable, and no environment proxy inheritance.
- GitHub has no official Python SDK and Dynatrace has no general official Python REST
  SDK. Direct HTTPX means Aegis retains endpoint/shape maintenance. The official
  Kubernetes client adds a large requests/urllib3/WebSocket/OAuth dependency subtree and
  must track cluster/client compatibility.
- GitHub installation-token caching across workers, Dynatrace OAuth client-credential
  flows, private enterprise origins/CAs, Kubernetes watch/relist, webhook verification,
  and distributed connector rate limiting are not implemented.
- Cursor values are AES-GCM encrypted in application storage, but production KMS key
  rotation, envelope encryption, cryptographic erasure, and cross-region key availability
  are not qualified.
- The default parser accepts UTF-8 text/Markdown, JSON, safe YAML, and bounded ZIP only.
  PDF, DOCX, XML, HTML, images, OCR, macros, active content, and broad loader frameworks
  are intentionally absent. Parsing runs in-process; a resource-isolated parser service
  is required before admitting complex formats.
- Secret/PII/injection scanners are deterministic hooks, not proof of complete detection.
  Quarantine storage, reviewer workflow, retention deletion, legal hold, and encrypted
  raw-object lifecycle remain operational work.
- Evidence metadata and bundles have forced-RLS schema and deterministic projection
  rebuild. Capacity, partitioning, object storage, WORM witnessing, PITR/restore,
  retention/erasure execution, and high-volume cursor cleanup are unproven.
- Temporal evidence workflow code carries only opaque references and is environment-gated.
  It does not prove live connector reconciliation. A crash after a read can remain
  permanently ambiguous when the source has no stable request/audit identifier.
- Deterministic correlation links time/shared facts and preserves conflict but cannot
  prove causality, clock correctness, semantic equivalence, or source truth. Missing or
  stale required sources cause abstention; operators must not reinterpret proximity as
  cause.
- The eight-role graph is fixed and incident-specific. It does not support dynamic role
  creation, peer free chat, open-ended delegation, unbounded debate, or autonomous tools.
- LangGraph checkpoint compatibility is enforced by graph/input version binding, but
  long-lived production checkpoint migrations, pruning, restore, node renames, and
  multi-version worker rollout remain unqualified.
- The in-memory orchestration ledger is test/demo only. PostgreSQL schema/repository
  integration is environment-gated; HA, partitioning, retention and load remain unproven.
- The verification agent produces a plan only. Approval service/effects, effect fencing,
  and production execution remain outside LangGraph. Layer 7 adds separate application
  approval/effect services; the agent itself still cannot approve or execute.
- Approval decisions are immutable and exact-scope but are not cryptographically signed
  by external human keys, externally witnessed, WORM/legal records, or integrated with a
  production change-management system.
- SoD and quorum rely on current application identities and distinct actor references.
  They do not prevent two compromised human accounts, organizational collusion, or an
  administrator/DBA outside the runtime role.
- The Kubernetes rollout-restart adapter is production-shaped but disabled by default and
  tested only with SDK doubles. No live cluster, RBAC, workload identity, admission,
  policy engine, service-account rotation, API compatibility, rate, latency or failure
  behavior is qualified.
- A Deployment rollout restart has no safe inverse. The official adapter intentionally
  rejects generic compensation; the deterministic fake demonstrates rollback lifecycle.
  A fixed image rollback needs a separate action contract and approval.
- At-least-once Activities, client/server timeouts and crash windows can leave external
  state ambiguous. Fencing protects application acceptance, not a provider request
  already delivered by a stale worker. Exactly-once effects are not claimed.
- Reconciliation depends on provider-observable state and stable target identity. It can
  remain inconclusive and require operator escalation.
- Verification uses deterministic postconditions and fresh cited evidence in tests.
  Production source freshness, independence, lag, false results and causal recovery are
  not qualified. API acceptance is never sufficient.
- Temporal remediation history uses signals, timers and a patch marker, but production
  Worker Versioning, multi-day history growth, signal throughput, task-queue isolation,
  mTLS, HA, failover and disaster recovery remain unqualified.
- PostgreSQL Layer 7 schema/repository provides forced RLS, immutable decisions/facts/
  receipts, quotas, fenced claims and rebuilds. Capacity, partitioning, HA/PITR, external
  witnessing, retention/erasure and multi-region claim order remain unproven.
- Approval/effect API is deliberately narrow and redacted. A reviewer UI, secure browser
  session, CSRF controls, notification delivery and accessibility are deferred.
- Kubernetes Job adapter tests prove manifest and reconciliation logic with SDK doubles,
  not host-kernel, gVisor, Kata, CNI, admission, CSI, workload-identity, node, or cluster
  isolation. No live cluster or tenant code is used in tests.
- Kubernetes namespaces and ordinary containers are not claimed as hostile-code
  isolation. Production activation requires a separately qualified RuntimeClass; Kata is
  recommended for mutually distrustful tenants and gVisor needs its own compatibility and
  escape review.
- Standard Kubernetes NetworkPolicy cannot enforce FQDN destinations. Network-none is the
  complete adapter path. Exact destinations require a separately operated enforcing proxy
  and policy-registration adapter; neither is implemented, so execution fails closed.
- PID limits are policy contracts and must be enforced by the selected runtime/admission/
  node configuration; the Kubernetes Job API has no portable per-Pod PID field.
- Content-addressed input/output CSI drivers, malware/DLP scanners, object encryption,
  legal hold, retention deletion, and quarantine reviewer operations are contracts and
  interfaces, not deployed services in this repository.
- AppArmor annotations and RuntimeDefault seccomp depend on node/runtime/admission support.
  Readiness declarations must be backed by operator probes; application unit tests cannot
  prove enforcement.
- Kubernetes Jobs are at-least-once and can start duplicate Pods in rare controller/node
  failures. Application idempotency and fencing protect acceptance but cannot undo code
  already executed in an isolated runtime.
- E2B and Modal are credible managed alternatives but remain optional/documented pending
  tenant, region, retention, private-network, idempotency, attestation, DPA, SLA, and
  incident-response review. Daytona requires renewed vendor review after its public core
  moved private. No managed adapter is shipped.
- Docker socket/SDK, local subprocess, RestrictedPython, and raw Firecracker wrappers are
  deliberately absent: they do not provide the selected durable hostile-tenant boundary
  without substantial additional platform controls.
- `PostgresMemoryStore.hybrid_candidates` implements and integration-tests a live
  forced-RLS pgvector query combining cosine ANN distance (`<=>`), lexical `ts_rank_cd`,
  recency/quality scoring, and ACL/classification/time/retention prefilters with
  deterministic tie-break ordering. This is proven at the store/repository layer,
  including a cross-tenant/classification isolation assertion; it is not yet wired into
  `MemoryRetrievalService`/`InMemoryMemoryControl` or the `/v1/memories/retrieve` API, so
  production retrieval still serves from `InMemoryHybridIndex` today. Final MMR
  diversification and `ContextBudget` selection also remain an explicit application-owned
  step regardless of candidate source; index-tuning/relevance benchmarking against the
  SQL path remains future work.
- `EmbeddingPort`/`SummarizationPort` ship only a deterministic hash-based adapter and a
  budget/concurrency/timeout-bounded gateway. No real embedding or summarization
  provider is wired; live embedding-provider latency, rate limits, drift, and cost are
  unqualified.
- Retrieval and context-build now append digest-only `MemoryOperationFact`s
  (`RETRIEVE_REQUESTED`/`RETRIEVE_COMPLETED`/`CONTEXT_BUILT`) via `MemoryRetrievalService`,
  with strict per-operation sequencing and idempotent replay, to an in-memory or the
  durable, immutable `aegis.memory_operation_facts` table — a separate, purpose-built
  ledger from the primary `MemoryFact` ingest/lifecycle ledger. These facts carry only
  policy/query/result digests, never raw query text or content.
- Memory crypto-erasure calls an injected `erase_blob` callback after legal-hold checks
  and derived-index purge. It is a contract point, not a qualified KMS or blob-storage
  integration; key rotation, envelope encryption, and cross-region erasure durability
  remain unqualified.
- The deterministic memory demo/eval scenarios exercise one tenant, one incident, and a
  small fixed corpus. Corpus-scale relevance quality, drift over time, and multi-tenant
  concurrent-write throughput on the derived index are unmeasured.
- Full operator UI/BFF, MCP/A2A, production deployment/IaC, and live provider/runtime
  qualification remain explicitly deferred.
- The governed suite executes 44 existing real cross-layer deterministic cases and
  separately meta-tests 17 named fault cuts. It is smaller than custom Aegis Layer 11's
  pinned 91-case/22-cut catalog and does not claim catalog-count parity.
- Deterministic scorers deliberately make all required safety dimensions fail when a
  canonical case fails. They do not yet model nullable case-specific metric
  applicability, confidence intervals, statistical drift, or human-label agreement.
- The hermetic guard denies common Python network/process entry points and required cases
  contain no native untrusted code. It is not an OS sandbox against malicious native
  extensions or direct syscalls.
- Environment-gated evaluation mode checks configuration while PostgreSQL/pgvector and
  Temporal behavior is qualified by the repository's dedicated integration suites. An
  offline report never claims those services ran.
- The optional model-judge contract is disabled and has no implementation. Production
  model/connector qualification, independent penetration/human labeling, observability/
  SLOs, UI, MCP/A2A, deployment, and final load/chaos certification remain deferred.

These are explicit non-production boundaries, not implied capabilities.
# Layer 11 observability limitations

- Local Collector, Prometheus and Grafana Compose services prove configuration and
  bounded smoke behavior only; no managed backend, retention, HA, capacity, regional,
  mTLS, alert delivery, silence/escalation, live SLO or on-call evidence is claimed.
- The four dashboards cover all implemented component families but are starter
  operational views, not a UI/BFF or production incident workspace.
- Langfuse remains optional and manually sanitized. LangSmith is not added. No live
  trace backend or credential is exercised in tests.
- Trace references can be missing after sampling/export failure and cannot prove an
  event or effect. Replay remains ledger-grounded.
- The projection rebuild API covers the investigation run projection; other layer
  rebuilders retain their existing capability-specific procedures.
- UI, MCP/A2A, deployment/IaC, live model/connector/memory qualification, penetration,
  human labeling, load/chaos and managed telemetry remain deferred.

# Layer 12 operator limitations

- The OIDC authorization-code/PKCE/state/nonce boundary is deterministic fake behavior.
  No live token exchange, refresh rotation, provider logout, key rotation, distributed
  session persistence, or cross-node revocation is delivered; production readiness is
  intentionally false.
- Polling provides bounded validated generation-watermark refresh. There is no durable
  SSE transport or server cursor/resume contract.
- The canonical checkout workspace uses synthetic BFF view models. It demonstrates all
  screens and invariants but does not claim production provider, cluster, audit-store,
  or effect integration.
- Automated axe/jsdom and Chromium journeys do not replace manual keyboard, VoiceOver,
  NVDA, JAWS, zoom/reflow, contrast, forced-colors, or independent WCAG audit.
- The production bundle is 440,439 uncompressed JavaScript bytes. TanStack reduces
  authored lifecycle/router/table code but is larger than the pinned custom Layer 13
  bundle; see `comparison/layer12-metrics.json`.
- Live browser/IdP/TLS proxy qualification, penetration testing, deployment/IaC,
  managed analytics/telemetry, load/chaos and compliance certification remain
  deferred.

# Layer 13 interoperability limitations

- Official SDK adapters are implemented and tested with in-process/fake transports; no
  live external peer, credential, certificate, partner endpoint or public registry is
  contacted.
- Production readiness intentionally fails closed without distributed token replay,
  mTLS/certificate verification, secret brokerage and deny-by-default egress.
- MCP `2026-07-28` Tasks are experimental and absent from SDK 2.0.0. Aegis uses
  application-owned opaque handles/status/cancel instead.
- The MCP SDK supplies modern/legacy compatibility. Legacy `2025-11-25` is accepted only
  for an explicit registration; deprecated HTTP+SSE is not activated.
- A2A Agent Card JWS covers the card, not task messages or artifacts. Aegis provenance
  is a custom neutral contract/extension and has not been independently standardized.
- A2A push notification webhooks are not enabled. Polling and snapshot-first subscribe
  are the qualified deterministic reconciliation paths.
- DNS/IP validation cannot close DNS resolution/connect TOCTOU without a production
  egress proxy. Exact origins and redirect denial reduce but do not eliminate that risk.
- The SDK dependency closure is materially larger. Upgrade compatibility, CVE response,
  protocol conformance and transitive supply-chain review remain ongoing obligations.
- Forced-RLS SQL and Temporal workflow definitions are environment-gated; local unit
  tests do not prove PostgreSQL/Temporal HA, multi-region ordering, capacity or DR.
- Public federation, production PKI/token brokerage, partner qualification, deployment,
  and independent conformance/security certification are explicitly deferred.
