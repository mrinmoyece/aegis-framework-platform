# Layer 11 qualification status

## Delivered

- immutable additive application events with aggregate sequence, tenant cursor, dual
  hash chains, expected-version concurrency, legacy upcast, and deterministic rebuild;
- tenant-scoped idempotency, inbox/outbox, lease claims, retries, dead-letter state,
  projection checkpoints, and redacted cursor API;
- Temporal SDK 1.31.0 workflow around one bounded LangGraph Activity lifecycle;
- durable wait/resume/cancel/timeout, duplicate signal handling, Activity heartbeat and
  retry bounds, workflow patch marker, payload limits, and replay test;
- current policy checks at commands and immediately before every Activity;
- forced RLS/non-bypass runtime role for all Layer 3 PostgreSQL tables;
- optional digest-pinned Temporal 1.29.1 Compose server and CI integration job;
- provider-neutral worker runtime that drains explicitly configured trusted tenant
  partitions; it is an embeddable runtime rather than a production CLI because live
  connector/model qualification and credential brokering are deliberately deferred;
- manual OTel/optional Langfuse privacy boundary with no payload export;
- immutable provider-neutral message/content/tool/schema/safety/usage/pricing/error
  contracts with canonical digests and tenant/run/purpose bindings;
- deny-by-default tenant model policy/catalog, deterministic routing, exact capability and
  price declarations, worst-case reservation, stable call intent, billing reconciliation,
  fallback/circuit/rate/concurrency controls, and stale-result rejection;
- deterministic fake plus official OpenAI 3.1.0 and Anthropic 0.122.0 adapters with SDK
  retries disabled and secret references only;
- strict Pydantic structured generation in LangGraph nodes, evidence framing, bounded
  repair, exact tool allowlists, citation rejection, and safe abstention;
- forced-RLS model policy/catalog/reservation/call/usage/health tables and authorized
  redacted model operations APIs.
- immutable versioned source/query/page/cursor/provenance/evidence/citation/bundle
  contracts with tenant/incident/run/time/trust/policy/credential/retention bindings;
- disabled-by-default Dynatrace and GitHub App HTTPX adapters, official Kubernetes
  client adapter, and neutral trusted-runbook adapter;
- exact origins/resources, tenant secret references, DNS/IP/redirect/proxy, timeout,
  response byte/MIME/schema, page/record, cancellation and rate-limit controls;
- opaque Temporal evidence-query workflow/Activities with page intent/result,
  heartbeat, cancellation, retry ownership, cursor checkpoints, stale-result rejection
  and reconciliation-required outcomes;
- safe JSON/YAML/text/ZIP ingestion with canonical hashes, tenant/incident deduplication,
  secret/PII/injection scanner hooks, redaction, classification, quarantine and retention
  references;
- deterministic non-LLM timeline/shared-fact/conflict/freshness/missing-source
  correlation integrated into LangGraph specialist context and extended citations;
- forced-RLS evidence source/query/cursor/metadata/quarantine/bundle/rebuild tables,
  authorized redacted query/cursor endpoints, and application-ledger projection rebuild;
- fixed-name OTel/Langfuse evidence observations containing only source kind,
  status/counts and reconciliation flags.
- immutable typed reasoning artifacts and fixed-role capability/transition policy;
- four-specialist LangGraph fan-out/fan-in, critic/planner/verification routing,
  graph-version replay binding, deterministic duplicate suppression and safe terminals;
- application-ledger run/task/artifact/decision facts, fencing, forced-RLS projections,
  deterministic rebuild and authorized redacted cursor reads;
- one Temporal-owned bounded graph Activity with no graph/provider retry overlap;
- fixed-name redacted graph-node and model observations.
- immutable exact-scope remediation/action/approval/effect/verification contracts and
  canonical digests with citations, policy snapshots and compensation bindings;
- deny-by-default allowlist/window/risk/blast/quota/evidence/critic/digest policy;
- authenticated SoD/quorum approval service and redacted anti-enumerating API;
- Temporal durable approval wait, timer, opaque signals, effect/reconciliation/
  verification/rollback Activities, heartbeat/cancellation and replay version marker;
- provider-neutral `ActionPort`, deterministic fake and fixed-shape disabled Kubernetes
  Deployment rollout-restart official-client adapter;
- at-least-once idempotency, observe-before-retry, ambiguity, reconciliation, fencing,
  read-after-write, fresh verification, rollback and escalation;
- forced-RLS Layer 7 plans/policies/quotas/approvals/immutable decisions/facts/receipts/
  verification/rebuild tables and atomic effect claims;
- redacted CLI demonstrations for success, denial, expiry, ambiguity/reconciliation,
  verification failure and rollback.
- immutable versioned sandbox spec/request/result/attestation/artifact contracts with exact
  Layer 7 approval, policy, tenant/run/task/remediation/action, OCI digest, argv,
  content-addressed input, mount/env/secret, network, resource, security, output,
  idempotency/retry/cleanup, and canonical-digest binding;
- deny-default sandbox policy for images/registries/commands/purposes/mounts/resources/
  output/egress/secrets/concurrency/risk/lifetime with policy/spec change invalidation;
- additive request through reconciliation/cleanup/quarantine application facts, pure
  replay, tenant claims/fencing, forced-RLS PostgreSQL projections/quotas/artifacts/
  attestations/cleanup ownership, and redacted status/artifact APIs;
- `aegis.sandbox.v1` Temporal workflow/Activities for provision, wait/heartbeat/cancel,
  capture, attest, cleanup, ambiguous create/delete reconciliation and orphan redrive;
- provider-neutral backend, deterministic fake and disabled official Kubernetes Job
  adapter requiring RuntimeClass/admission/CNI/workload identity and enforcing non-root,
  read-only root, drop-all, no-escalation, RuntimeDefault, AppArmor, no service token,
  no host namespaces/path/socket, immutable image, limits and UID-bound cleanup;
- network-none adapter and exact-destination abstraction; execution fails closed because
  external proxy policy registration is not implemented, with no false FQDN claim;
- bounded atomic archive staging and output allowlists with hashing, scanning, redaction,
  quarantine, retention references and provenance.
- immutable versioned memory record/fact/projection contracts with citations, ACL,
  classification/trust, embedder/chunker version binding, retention/legal-hold, and an
  erasable blob reference, plus banned raw-text/query/prompt/completion/tenant/locator
  fields in every ledger fact payload;
- intent-before-effect ingest lifecycle (candidate through scan/chunk/embed/index) gated
  by an explicit `MemoryAcceptance` human/policy decision record (disposition, reviewer
  kind, policy digest, reason code), with expected-version fencing, deterministic bounded
  chunking, and neutral `EmbeddingPort`/`SummarizationPort` ports behind a
  budget/concurrency/timeout-bounded gateway;
- derived, rebuildable `InMemoryHybridIndex` (lexical/vector/recency/quality/MMR) with a
  tenant-scoped bounded cache, plus a durable PostgreSQL pgvector chunk-storage adapter
  under forced RLS and immutability triggers, and a live forced-RLS `hybrid_candidates`
  SQL query combining cosine ANN distance, lexical `ts_rank_cd`, recency/quality scoring
  and ACL/classification/time/retention prefilters with deterministic tie-break ordering,
  exercised by a PostgreSQL integration test including cross-tenant isolation;
- digest-only `MemoryOperationFact`s (`RETRIEVE_REQUESTED`/`RETRIEVE_COMPLETED`/
  `CONTEXT_BUILT`) recorded by `MemoryRetrievalService` around every retrieval and context
  build, appended to an in-memory or durable immutable ledger with strict sequencing and
  idempotent replay, carrying only policy/query/result digests;
- `LangGraphMemoryContextBuilder` producing bounded JSON-compatible context with a fixed
  untrusted-data instruction boundary, and a citation-enforcing compactor with a
  deterministic extractive fallback;
- `aegis.memory.v1` Temporal workflow for ingest/compact/purge/rebuild Activities carrying
  only opaque references, with an initial heartbeat plus a periodic 10-second heartbeat
  under every long-running Activity, plus legal-hold-gated tombstone/crypto-erase
  lifecycle through an injected erase-blob callback;
- authorized redacted memory status/retrieval API endpoints and a deterministic
  `memory-demo` CLI scenario under the same tenant/policy authorization boundary as every
  other Layer 2+ action.
- frozen neutral evaluation suite/scenario/case/dataset/scorer/result/baseline/
  comparison/waiver/report contracts with canonical digests, provenance,
  fingerprints, fixed seed/clock/IDs, bounded trace references and strict limits;
- hermetic execution of all 44 real cross-layer cases with denied network/process
  helpers, hard timeout, stable order/filter/shard/replay behavior and separate
  environment-gated PostgreSQL/pgvector/Temporal qualification;
- adversarial taxonomy covering injection, Unicode/bidi/schema/citation, tenant/role/
  approval/confused-deputy, SSRF/path/archive/shell/secret/output, replay/fencing/
  idempotency/wallet, malicious adapter and framework-state poisoning;
- all 20 named deterministic fault cut points with convergence, authorization,
  duplicate/stale-effect, reconciliation, cleanup, audit and isolation assertions;
- reviewed exact baseline, non-waivable hard safety, scoped expiring waivers,
  missing/new/tamper detection, governed synthetic dataset lifecycle, deterministic
  JSON/Markdown/JUnit, six CLI operations, five dedicated CI eval gates, and optional
  sanitized Langfuse dataset/report publication.
- versioned neutral semantic conventions, strict propagation/baggage/sampling/links,
  bounded structured logs, cardinality-guarded Prometheus metrics and telemetry
  failure containment;
- nine measurable SLOs, multi-window burn-rate recording/alerts, hard safety alerts,
  hardened OTel Collector, Prometheus/Grafana provisioning and validated dashboards;
- authenticated audited operations readiness/SLO/support/rebuild APIs and
  deterministic ledger replay CLI with hash/sequence/version/state/compare/causal
  validation that never executes an external operation;
- six deterministic observability evals covering causal coverage, retry counting,
  secret absence, telemetry outage correctness, replay convergence and safety alerts.

## Qualification snapshot

- 386 deterministic tests pass with 90.07% meaningful branch coverage;
- 50 deterministic evals pass, including pagination, poisoning, source revocation,
  deterministic non-causal correlation, private-destination rejection, and memory
  retrieval/tenant-cache/context/retention cases;
- eleven local PostgreSQL integration tests cover forced RLS/tenant isolation,
  immutable audit/events/model/evidence/orchestration/sandbox/memory facts, quota/model
  races, checkpoint isolation, dedicated-pool concurrency, crash ambiguity/reconciliation,
  the live pgvector `hybrid_candidates` query with cross-tenant/classification isolation,
  and deterministic rebuild;
- six local Temporal integration tests cover no-worker recovery, Activity retry,
  duplicate signal, cancellation, timeout, replay, opaque evidence pagination, the
  real application outbox/Activity/projection path, sandbox provision/capture/
  attestation/cleanup replay, and memory ingest retry/fencing/completion/replay;
- one Keycloak compatibility test remains environment-gated.

Counts are refreshed by the final release run and recorded in
`comparison/layer11-metrics.json`.

## Not proven

Production Temporal HA/upgrade/failover, PostgreSQL HA/PITR/restore, multi-region order,
load/capacity, WORM witnessing, retention/erasure execution, live IdP rotation, live
connector/model credentials and provider qualification, production DNS/egress,
complex-document parser isolation, live Kubernetes credentials/RBAC/admission,
independent production verification, live Kata/gVisor/admission/CNI/CSI/egress-proxy/
workload-identity sandbox qualification, UI/BFF, MCP/A2A and deployment admission remain
unproven. For memory specifically: `PostgresMemoryStore.hybrid_candidates` is implemented
and integration-tested at the store layer, and retrieval/context-build now emit
digest-only ledger facts — but wiring that SQL query into the production retrieval
control path (`MemoryRetrievalService`/`InMemoryMemoryControl`, `/v1/memories/retrieve`),
a real embedding/summarization provider, and KMS/blob-qualified crypto-erasure are not
proven. Final MMR diversification and `ContextBudget` selection also remain an
application-owned step regardless of candidate source.
Production model/connector qualification, independent penetration testing and human
labeling, UI, MCP/A2A, deployment, managed telemetry backends, live SLO/on-call
evidence, and final load/chaos certification are explicitly deferred.
