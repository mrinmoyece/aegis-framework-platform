# Aegis Framework Platform

[![CI](https://github.com/mrinmoyece/aegis-framework-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/mrinmoyece/aegis-framework-platform/actions/workflows/ci.yml)
[![CodeQL](https://github.com/mrinmoyece/aegis-framework-platform/actions/workflows/codeql.yml/badge.svg)](https://github.com/mrinmoyece/aegis-framework-platform/actions/workflows/codeql.yml)

A framework-first educational implementation of durable enterprise incident
investigation. It uses LangGraph for one bounded cognitive graph, Temporal for
cross-process workflow/timer/retry/signal recovery, and PostgreSQL for application-owned
tenant facts, immutable events, delivery records, projections, and audit.

**Layer 13 adds secure MCP and A2A interoperability through the current official
`mcp==2.0.0` and `a2a-sdk==1.1.2` adapters. A tenant trust registry, workload identity,
capability/schema/card/certificate pins, SSRF and content bounds, quotas, digest-only
intent-before-network facts, Temporal reconciliation, forced-RLS projections, and exact
operator trust transitions surround every peer. External content remains untrusted;
destructive requests become Layer 7 proposals only and can never approve or execute.**

**Layer 12 adds a secure accessible React/TypeScript operator workspace and same-origin
FastAPI BFF over those authorities: runtime-validated bounded views, deterministic
checkout demo, fail-closed OIDC/session readiness, tenant cache teardown, safe approval
review, explicit ambiguity, polling, CSP, axe, Playwright, dependency/license/audit and
bundle gates. Live IdP/session-store and production browser qualification remain
deferred.**

**Layer 8 adds approval-bound ephemeral sandbox execution through hardened Kubernetes
Jobs while keeping policy, ledger, claims, artifacts, and attestations outside Temporal,
Kubernetes, and LangGraph.**

**Layer 9 adds event-grounded three-tier memory and pgvector-backed retrieval-augmented
generation: an immutable ledger of memory facts, a derived rebuildable hybrid index, a
live forced-RLS pgvector hybrid SQL query proven at the store layer, digest-only
retrieval/context ledger facts, an explicit `MemoryAcceptance` decision contract, and
LangGraph-bounded untrusted context — with production wiring of the SQL query into the
retrieval-serving path, a real embedding provider, and KMS-qualified erasure still
deferred.**

**Layer 10 adds governed deterministic enterprise evaluation: immutable neutral
suite/dataset/scorer/result/baseline/waiver/report contracts, a hermetic runner over
all 44 real Layers 1-9 cases, adversarial and 17-point fault packs, non-waivable
safety baselines, deterministic JSON/Markdown/JUnit, dedicated CI gates, and an
optional sanitized Langfuse publisher. Evaluation remains release evidence, never
runtime authority or production certification.**

## Delivered Layer 8

- additive strict application events with aggregate sequence, commit-order tenant
  cursor, expected-version concurrency, aggregate/tenant hash chains, legacy upcast,
  immutable runtime privileges/triggers, and deterministic rebuild;
- transactional tenant-scoped idempotency, inbox/outbox, race-safe lease claims,
  retries, explicit dead-letter state, and projection checkpoints;
- application run/timeline projections with current authorization, payload redaction,
  and tenant/run-bound HMAC cursor pagination;
- Temporal Python SDK 1.31.0 workflow for start, current authorization/budget reserve,
  evidence collection, one bounded LangGraph run, wait/resume/cancel, timeout,
  completion/failure, Activity heartbeat/retry, and worker recovery;
- strict Pydantic Temporal conversion plus a 64 KiB codec bound and opaque references;
- application policy checks at the command and immediately before every Activity;
- stale-result rejection, duplicate start/signal/activity handling, and poison
  framework-defect containment;
- forced PostgreSQL RLS for every Layer 3 table under a non-superuser,
  non-`BYPASSRLS` runtime role;
- digest-pinned optional Temporal Server 1.29.1 Compose profile and replay integration;
- OpenTelemetry/optional Langfuse counts/status telemetry without payload export.
- immutable neutral model messages/content/tools/schemas/safety/usage/pricing/errors with
  tenant/run/purpose binding, strict bounds, and canonical digests;
- tenant model policy/catalog, exact capability/context/region/classification/price
  declarations, deterministic routes, worst-case token/cost reservation, immutable call
  intent/settlement, explicit billing ambiguity, and rebuildable usage/health views;
- bounded structured repair, fallback, circuit, rate/concurrency controls, cancellation
  and policy-revocation stale-result rejection, with SDK and graph retries disabled;
- deterministic fake plus official OpenAI 3.1.0 and Anthropic 0.122.0 adapters; all tests
  use fake clients and no network/credentials;
- authorized redacted catalog, usage, and derived-health APIs under forced PostgreSQL RLS.
- immutable evidence source/query/page/cursor/provenance/citation/bundle contracts;
- disabled-by-default Dynatrace/GitHub HTTPX, official Kubernetes, and trusted-runbook
  adapters with exact allowlists, tenant secret references, SSRF/DNS/redirect,
  pagination, timeout, rate-limit, response and cancellation controls;
- application-ledger page intent/result, encrypted cursor checkpoints, opaque Temporal
  pagination, stale policy/credential rejection and explicit reconciliation ambiguity;
- bounded JSON/safe-YAML/text/ZIP canonicalization, hashing, deduplication, scanning,
  redaction, classification, quarantine and retention references;
- deterministic non-LLM timeline/link/conflict/freshness/missing-source correlation with
  non-causal links and provenance-bound graph/model citations;
- forced-RLS evidence projections/rebuild and authorized redacted query/cursor APIs.
- immutable schema-versioned plan, task, evidence-assessment, hypothesis/alternative,
  contradiction/critique, timeline/causal-reference, proposal-only remediation,
  verification-plan, coordinator-decision, and final-assessment artifacts;
- fixed coordinator, telemetry/change/runtime/knowledge specialists, critic,
  remediation planner, and verification agent with code-enforced capabilities and
  artifact transitions—no peer chat, dynamic roles, or self-granted authority;
- static LangGraph `StateGraph` fan-out/fan-in with deterministic reducers, critic
  routing, eight checkpoint super-steps, recursion/iteration/fan-out bounds, duplicate
  suppression, graph-version binding, and safe complete/abstain/escalate outcomes;
- application-ledger dispatch intent, fenced task result, artifact and decision facts
  with forced-RLS PostgreSQL projections/rebuild, while Temporal retains one bounded
  graph Activity and owns cross-process retry/cancellation;
- authorized redacted artifact cursor API plus fixed-name OTel/Langfuse graph-node and
  model spans that export counts/status only.
- immutable versioned remediation plan/action/approval/effect/verification contracts
  binding exact plan/action digests, tenant/run/target fingerprint, risk/blast radius,
  pre/postconditions, dry-run, retry/timeouts, idempotency, compensation, citations and
  current policy snapshot;
- additive application-ledger facts and pure replay across proposal, approval,
  preflight, execution, ambiguity/reconciliation, cancellation, verification and
  rollback; Temporal history is never audit truth;
- deny-by-default current action policy for exact targets, maintenance windows,
  risk/blast thresholds, quotas, evidence/critic gates, role/purpose and immutable
  digests; policy/role/plan changes invalidate approval;
- authenticated redacted approval API with SoD, distinct humans, two-person high-risk
  quorum, expiry/revocation, optimistic concurrency, replay protection and
  anti-enumeration;
- `aegis.remediation.v1` Temporal workflow for long approval waits, timers, opaque
  signals, Activity heartbeat/cancellation/retry, crash recovery, ambiguity and
  reconciliation, verification and compensation;
- provider-neutral `ActionPort`, deterministic fake, and one disabled-by-default
  fixed-shape official Kubernetes Deployment rollout-restart adapter with exact UID,
  resourceVersion and target binding—no shell or arbitrary command/patch surface;
- forced-RLS PostgreSQL plans, policies, quotas, approvals, immutable decisions/facts/
  receipts/verifications, fenced atomic effect claims and projection rebuild records.
- immutable sandbox spec/request/execution/result/artifact/attestation contracts binding
  tenant, run, task, Layer 7 remediation, approval, policy, image digest, resources,
  network, mounts, secrets, outputs, idempotency, retry, cleanup, and fencing;
- strict rejection of shell strings/interpolation, mutable images, unsafe paths,
  host/device/socket/namespace privilege, unknown capabilities, secret literals,
  malicious archives, output overflow, and exact-egress execution until external proxy
  policy registration is implemented;
- additive application-ledger sandbox lifecycle and pure replay, forced-RLS PostgreSQL
  policy/request/quota/claim/fact/artifact/attestation/cleanup/projection tables, and
  authorized redacted status/artifact APIs;
- `aegis.sandbox.v1` Temporal workflow for provision/wait/capture/attest/cleanup,
  cancellation, ambiguous create/delete reconciliation, orphan redrive, bounded retries,
  heartbeat, and stable operation IDs;
- provider-neutral `SandboxBackend`, deterministic fake, and disabled-by-default official
  Kubernetes Job adapter requiring RuntimeClass, admission, NetworkPolicy enforcement,
  workload identity, non-root/read-only/drop-all/no-escalation/RuntimeDefault security,
  no service token or host namespaces/path/socket, UID-bound cleanup, and immutable image;
- safe content-addressed CSI input/output references, atomic bounded ZIP staging,
  deterministic output allowlists, scanning/redaction/quarantine, retention references,
  and provenance digests. Sandbox output remains untrusted data.

## Delivered Layer 9

- immutable versioned memory record/fact/projection contracts with citations, ACL,
  classification/trust, embedder/chunker version binding, retention/legal-hold, and an
  erasable blob reference, banning raw text/query/prompt/completion/tenant/locator from
  every ledger fact payload;
- intent-before-effect ingest lifecycle gated by an explicit `MemoryAcceptance`
  human/policy decision, with expected-version fencing, deterministic bounded chunking,
  and neutral `EmbeddingPort`/`SummarizationPort` ports behind a
  budget/concurrency/timeout-bounded gateway;
- derived, rebuildable `InMemoryHybridIndex` (lexical/vector/recency/quality/MMR) with a
  tenant-scoped bounded cache, plus a durable PostgreSQL pgvector chunk-storage adapter
  under forced RLS and immutability triggers, and a live forced-RLS `hybrid_candidates`
  SQL query (cosine ANN + lexical + recency/quality + ACL/classification/time/retention
  prefilters, deterministic tie-break ordering) proven by a PostgreSQL integration test
  including cross-tenant isolation;
- digest-only `MemoryOperationFact`s (`RETRIEVE_REQUESTED`/`RETRIEVE_COMPLETED`/
  `CONTEXT_BUILT`) recorded around every retrieval and context build, with strict
  sequencing and idempotent replay;
- `LangGraphMemoryContextBuilder` producing bounded context with a fixed untrusted-data
  instruction boundary, and a citation-enforcing compactor with deterministic fallback;
- `aegis.memory.v1` Temporal workflow for ingest/compact/purge/rebuild Activities with
  periodic 10-second heartbeating, plus legal-hold-gated tombstone/crypto-erase through
  an injected erase-blob callback;
- authorized redacted memory status/retrieval APIs and a deterministic `memory-demo` CLI
  scenario under the same tenant/policy authorization boundary as every other action.
- **Candid gaps**: `hybrid_candidates` is proven at the store/integration-test layer but
  not yet wired into `MemoryRetrievalService`/`InMemoryMemoryControl` or
  `/v1/memories/retrieve`, so production retrieval still serves from
  `InMemoryHybridIndex`; final MMR/context-budget selection remains application-owned
  regardless of candidate source; no real embedding/summarization provider is wired;
  `erase_blob` is a callback, not a
  qualified KMS/blob integration. See [status](docs/status.md) and
  [limitations](docs/limitations.md).

  `comparison/layer10-metrics.json` pins custom Aegis Layer 11 at
  `d17447f016cfd335ad9ff9900e9478b9d25844ea` and records LOC, dependencies,
  incremental effort, required services, framework facilities removed, remaining
  custom evaluation/governance, hosted escape, catalog/fault/meta counts, and the
  200-run equivalent deterministic evaluation scenario. The comparison does not
  claim latency parity because the custom runtime was not executed under the same
  interpreter.

## Delivered Layer 10

- immutable, strict, schema-versioned neutral evaluation contracts and canonical
  digests for suites, scenarios, cases, datasets, scorers, results, baselines,
  comparisons, waivers, reports, provenance, fingerprints, bounds and trace refs;
- hermetic deterministic execution of 44 real cross-layer cases, stable filtering/
  sharding/replay, hard timeouts, dataset hash and secret/PII validation, and no
  required network, process, credential, production data or model judge;
- eight outcome classes, broad adversarial taxonomy, 17 named fault cut points,
  multidimensional deterministic scorers, non-waivable hard safety, reviewed
  baselines, scoped expiring waivers and missing/new/tamper detection;
- deterministic bounded JSON/Markdown/JUnit reports, optional sanitized Langfuse
  dataset/report publishing, and dedicated safety/adversarial/recovery/baseline/meta
  CI gates;
- candid pinned comparison with custom Aegis Layer 11. Framework Layer 10 is
  smaller and reuses real Layers 1-9 scenarios, but has a narrower catalog and less
  granular case-specific scoring than the custom implementation.

## Delivered Layer 11

- versioned provider-neutral semantic conventions and fixed spans across API, ledger,
  outbox, Temporal, LangGraph, models, connectors, approvals/effects, sandbox, memory
  and evaluation, with strict low-cardinality allowlists and explicit units/buckets;
- strict W3C propagation, hostile-context rejection, baggage allowlist, deterministic
  sampling, bounded fan-out/retry/redelivery links, and safe durable trace references;
- bounded JSON logging, Prometheus metrics with logical-operation deduplication,
  exporter failure containment, neutral OTel Collector pipelines, multi-window SLO
  rules and four provisioned Grafana dashboards covering every implemented layer;
- authenticated, purpose-authorized, anti-enumerating and audited SLO/readiness/support/
  projection APIs, plus deterministic read-only ledger replay and CLI with dual-chain,
  sequence, schema, compare, causal-chain and bounded support-report validation;
- nine measurable SLOs and non-budgetable safety alerts. Langfuse remains optional
  trace/evaluation UX; OTel and the application ledger preserve portability and truth.
  live OIDC/session persistence/browser qualification, deployment, and live
  managed telemetry/SLO/on-call evidence remain deferred.

## Ownership

| Owner | Responsibility | Not authoritative for |
|---|---|---|
| PostgreSQL application ledger | Events, idempotency, inbox/outbox, run/timeline/audit facts | Framework scheduling/checkpoints |
| Temporal | Cross-process schedule, approval waits, Activities, timers, signals, retry/replay/recovery | Tenant grants, policy, approval truth, audit, effect receipts |
| LangGraph | Fixed cognitive topology, fan-out/join, reducers, routing, graph checkpoints | Roles/capabilities, approval, authorization, audit, effects |
| Action adapter | One exact provider operation and observation | Policy, approval, fencing, idempotency, audit, verification |
| Sandbox backend | One ephemeral provider execution and observation | Authorization, approval, policy, ledger, artifact trust, cluster-isolation claim |
| Official provider SDKs | OpenAI/Anthropic wire protocol and decoding | Model policy, routing, budget, pricing, usage, safety, retry truth |
| Connector libraries | HTTPX transport, Kubernetes decoding, PyYAML syntax | Tenant/source policy, SSRF, secrets, provenance, pagination truth, quarantine |
| Memory ledger/lifecycle | Immutable `memory_facts`/`MemoryLifecycleService` | Derived index/cache, retrieval quality, framework state |
| Derived memory index/cache | `InMemoryHybridIndex` + PostgreSQL `memory_chunks`/cache | Tenancy, retention, legal hold, audit — never authority |
| OTel/Prometheus/Grafana/Langfuse | Portable signals, alert evaluation, dashboards and optional trace UX | Application truth, authorization, approval, audit, fencing, effect receipts |

A framework history, checkpoint, trace, prompt, completion, message, or tool result is
never an authorization, tenant grant, quota receipt, approval, audit record, fencing
token, or effect receipt.

## Quick start

Prerequisites: [uv 0.12.5](https://docs.astral.sh/uv/), Python 3.14.7, and Docker.

```bash
make bootstrap
make ci
make eval
docker compose config --quiet
uv run aegis-framework remediation-demo --scenario success
uv run aegis-framework remediation-demo --scenario ambiguity
uv run aegis-framework remediation-demo --scenario rollback
uv run aegis-framework memory-demo
uv run aegis-framework eval list
uv run aegis-framework eval replay
uv run aegis-framework eval compare
```

Run the deterministic API:

```bash
AEGIS_MODE=demo make serve

curl --fail-with-body \
  -H 'Content-Type: application/json' \
  -H 'Authorization: ******' \
  -H 'X-Request-ID: durable-readme-001' \
  --data @examples/investigation-request.json \
  http://127.0.0.1:8000/v1/investigations
```

The durable command body omits the demo `scenario` property:

```bash
curl --fail-with-body \
  -H 'Content-Type: application/json' \
  -H 'Authorization: ******' \
  -H 'X-Request-ID: durable-readme-002' \
  --data '{
    "incident_id":"checkout-20260815-001",
    "alert":{
      "signal":"checkout_failure_rate",
      "service":"checkout-api",
      "region":"eu-west-1",
      "observed_at":"2026-08-15T00:00:00Z",
      "failure_rate":0.42,
      "threshold":0.05
    },
    "wait_for_signal":true
  }' \
  http://127.0.0.1:8000/v1/durable-investigations
```

`202` means application intent is durable, not that Temporal or LangGraph completed.
The demo exposes projection behavior but does not start a production worker.

## Local PostgreSQL and Temporal qualification

```bash
export AEGIS_POSTGRES_ADMIN_PASSWORD="$(openssl rand -hex 24)"
export AEGIS_POSTGRES_RUNTIME_PASSWORD="$(openssl rand -hex 24)"
docker compose --profile temporal up -d postgres temporal

export AEGIS_TEST_POSTGRES_ADMIN_DSN="postgresql://aegis_admin:${AEGIS_POSTGRES_ADMIN_PASSWORD}@127.0.0.1:55432/aegis"
export AEGIS_TEST_POSTGRES_RUNTIME_DSN="postgresql://aegis_app:${AEGIS_POSTGRES_RUNTIME_PASSWORD}@127.0.0.1:55432/aegis"
make integration

AEGIS_TEST_TEMPORAL_ADDRESS=127.0.0.1:57233 make temporal-integration
```

The eight PostgreSQL tests prove forced RLS/pool reset, immutable audit/events/artifacts,
quota/model races, checkpoint isolation, ledger/outbox atomicity, projection rebuild,
and tenant isolation. The Temporal test proves no-worker recovery, Activity retry, duplicate
signal, cancellation signal, timer timeout, completion, and deterministic replay.

Production delivery additionally requires a private
`AEGIS_CURSOR_SIGNING_KEY` of at least 32 bytes. It signs opaque pagination cursors and
`AEGIS_REFERENCE_ENCRYPTION_KEY` of at least 32 bytes encrypts tenant routing
references before Temporal history. Both must come from deployment secret injection,
never the repository or workflow history.

## Selected stack

| Concern | Exact selection | Application boundary |
|---|---|---|
| Identity | PyJWT 2.13.0 + cryptography 50.0.0 | Current principal/grants/policy |
| API/contracts | FastAPI 0.141.1 + Pydantic 2.13.4 | Delivery/validation only |
| Cognitive graph | LangGraph 1.2.11 | `OrchestratorPort`, no authority |
| Workflow | Temporal Python SDK 1.31.0 | `ActivityOperations`, outbox, application facts |
| Local Temporal | Server `auto-setup:1.29.1` digest | Optional compatibility profile |
| Application state | PostgreSQL 17 + Psycopg 3.3.4 | SQL schema, forced RLS, ledger/audit |
| Graph saver | `langgraph-checkpoint-postgres` 3.1.2 | Tenant owner/RLS overlay |
| Telemetry | OpenTelemetry 1.44.0 | Fixed names/allowlisted attributes |
| Optional model trace/eval | Langfuse 4.14.4 | Counts/status only |
| Provider adapters | OpenAI 3.1.0 + Anthropic 0.122.0 | `ModelProviderAdapter`; retries disabled |
| Evidence adapters | HTTPX 0.28.1 + Kubernetes 36.0.3 + PyYAML 6.0.3 | Neutral ports; disabled by default |
| Memory storage | PostgreSQL 17 + Psycopg 3.3.4 + pgvector extension | Raw `vector` cast write path plus live `hybrid_candidates` hybrid SQL query (store-tested; not yet wired into the serving path) |

## Qualification status

- 415 deterministic tests pass at 90%+ meaningful branch coverage, 44 evals pass — including
  governed Layer 10 evaluation with JUnit/Markdown/JSON report artefacts, immutable
  canonical digest chains, baseline/waiver/comparison contracts, hermetic runtime, and all
  cross-layer scenario coverage — and eleven PostgreSQL plus six Temporal integration tests
  pass locally;
- one Keycloak compatibility test remains environment-gated;
- tests/evals use no live credentials, real models, real embedding providers, or cloud
  services.

See [status](docs/status.md) and [limitations](docs/limitations.md) before interpreting
these as production evidence.

## Framework comparison

`comparison/layer8-metrics.json` pins custom Aegis Layer 9 and records LOC,
dependencies, incremental effort, retained controls, operational cost and escape paths.
The 200-run in-memory sandbox benchmark measures approval-bound fake lifecycles separately
from the custom async event-repository path. It is not an isolation or service benchmark
and excludes PostgreSQL, Temporal, Redis, Kubernetes, CSI, CNI, runtime, network, and
process boundaries. The conclusion is deliberately critical: Temporal and Kubernetes
remove workflow/Job mechanics, not policy, approval, tenant controls, artifacts, fencing,
reconciliation, cleanup, or live-isolation qualification.

`comparison/layer9-metrics.json` pins custom Aegis Layer 10 and records the equivalent
memory/RAG comparison: LOC, dependencies, the 200-run deterministic demo benchmark,
framework code removed, retained controls, and lock-in/escape. Both implementations now
implement a live pgvector hybrid SQL query; the candid remaining difference is that this
framework's `hybrid_candidates` query is proven at the store/integration-test layer but
not yet wired into its own production retrieval-serving path — this framework does not
independently verify the custom target's serving-path wiring, and retrieval-quality
parity is not measured by either benchmark.

## Commands

| Command | Purpose |
|---|---|
| `make lint` / `make type` / `make test` | Strict deterministic gates |
| `make eval` | Complete governed 44-case deterministic suite |
| `make eval-safety` | Non-waivable safety gates |
| `make eval-adversarial` | Adversarial attack pack |
| `make eval-recovery` | Recovery and deterministic fault gates |
| `make eval-baseline` | Reviewed baseline comparison |
| `make eval-meta` | Evaluator repeatability/governance meta-tests |
| `make integration` | Configured PostgreSQL/Keycloak tests |
| `make temporal-integration` | Configured Temporal workflow/replay test |
| `make docs` | Documentation, parity, pin, and measurement checks |
| `make security` | Bandit and dependency audit |
| `make container` | Digest-pinned non-root image |
| `make measure` | Refresh Layer 10 comparison metrics |

Start with [architecture](docs/architecture.md),
[authority boundaries](docs/authority-boundaries.md),
[ADR 007](docs/adr/007-temporal-durable-workflow.md),
[ADR 010](docs/adr/010-secure-evidence-connectors.md),
[ADR 011](docs/adr/011-governed-specialist-orchestration.md),
[ADR 012](docs/adr/012-temporal-approval-and-effects.md),
[ADR 013](docs/adr/013-kubernetes-job-sandbox.md),
[ADR 014](docs/adr/014-pgvector-sql-event-grounded-memory.md),
[connector runbook](docs/connector-runbook.md), [runbook](docs/runbook.md),
[approval/effect runbook](docs/approval-effect-runbook.md),
[sandbox runbook](docs/sandbox-runbook.md),
[memory runbook](docs/memory-runbook.md),
[threat model](docs/threat-model.md), and
[limitations](docs/limitations.md).

Licensed under the [MIT License](LICENSE).
