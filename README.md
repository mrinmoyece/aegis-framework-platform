# Aegis Framework Platform

[![CI](https://github.com/mrinmoyece/aegis-framework-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/mrinmoyece/aegis-framework-platform/actions/workflows/ci.yml)
[![CodeQL](https://github.com/mrinmoyece/aegis-framework-platform/actions/workflows/codeql.yml/badge.svg)](https://github.com/mrinmoyece/aegis-framework-platform/actions/workflows/codeql.yml)

A framework-first educational implementation of durable enterprise incident
investigation. It uses LangGraph for one bounded cognitive graph, Temporal for
cross-process workflow/timer/retry/signal recovery, and PostgreSQL for application-owned
tenant facts, immutable events, delivery records, projections, and audit.

**Layer 6 adds governed fixed-role specialist orchestration and typed reasoning
artifacts. It still cannot approve, execute, or verify a production effect.**

## Delivered Layer 6

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

## Ownership

| Owner | Responsibility | Not authoritative for |
|---|---|---|
| PostgreSQL application ledger | Events, idempotency, inbox/outbox, run/timeline/audit facts | Framework scheduling/checkpoints |
| Temporal | Cross-process schedule, Activities, timers, signals, replay/recovery | Tenant grants, policy, audit, API status, effects |
| LangGraph | Fixed cognitive topology, fan-out/join, reducers, routing, graph checkpoints | Roles/capabilities, artifacts, dispatch/result facts, authorization, audit, effects |
| Official provider SDKs | OpenAI/Anthropic wire protocol and decoding | Model policy, routing, budget, pricing, usage, safety, retry truth |
| Connector libraries | HTTPX transport, Kubernetes decoding, PyYAML syntax | Tenant/source policy, SSRF, secrets, provenance, pagination truth, quarantine |

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

## Qualification status

- 226 deterministic tests pass at 90.01% meaningful branch coverage;
- 31 deterministic evals cover cognitive/model safety, durable recovery,
  routing, budgets, malformed output, fallback/circuit, timeout/cancellation, duplicate
  and ambiguous billing, revocation, tenant isolation, connector pagination, poisoning,
  source revocation, non-causal correlation and SSRF;
- eight PostgreSQL and three Temporal integration tests pass locally;
- one Keycloak compatibility test remains environment-gated;
- tests/evals use no live credentials, real models, or cloud services.

See [status](docs/status.md) and [limitations](docs/limitations.md) before interpreting
these as production evidence.

## Framework comparison

`comparison/layer6-metrics.json` pins custom Aegis Layer 7 at `dce0054` and records LOC,
dependencies, incremental effort, retained controls, operational cost and escape paths.
The 200-run in-memory specialist benchmark measured the framework path separately from
the custom async event-repository path; it is not a service benchmark and excludes
PostgreSQL, Temporal, Redis, networks, and process boundaries. The conclusion is
deliberately critical: LangGraph removes scheduler/fan-in/checkpoint mechanics, not
governance, tenant controls, artifact facts, citations, or recovery policy.

## Commands

| Command | Purpose |
|---|---|
| `make lint` / `make type` / `make test` | Strict deterministic gates |
| `make eval` | Twenty-six deterministic evals |
| `make integration` | Configured PostgreSQL/Keycloak tests |
| `make temporal-integration` | Configured Temporal workflow/replay test |
| `make docs` | Documentation, parity, pin, and measurement checks |
| `make security` | Bandit and dependency audit |
| `make container` | Digest-pinned non-root image |
| `make measure` | Refresh Layer 6 comparison metrics |

Start with [architecture](docs/architecture.md),
[authority boundaries](docs/authority-boundaries.md),
[ADR 007](docs/adr/007-temporal-durable-workflow.md),
[ADR 010](docs/adr/010-secure-evidence-connectors.md),
[ADR 011](docs/adr/011-governed-specialist-orchestration.md),
[connector runbook](docs/connector-runbook.md), [runbook](docs/runbook.md),
[threat model](docs/threat-model.md), and
[limitations](docs/limitations.md).

Licensed under the [MIT License](LICENSE).
