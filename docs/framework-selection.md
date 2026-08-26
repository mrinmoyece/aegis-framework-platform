# Framework selection report

Research was refreshed from official package/project sources on **2026-08-15**.
Installed dependencies and Actions are exact-pinned; container images use digests.

## Selected and deferred stack

| Candidate | Version | Operational dependency | What it removes | What remains application-owned | Decision/escape |
|---|---:|---|---|---|---|
| Python | 3.14.7; CI 3.13.15 | Runtime/toolchain | Language/runtime | Types, controls, lifecycle | Select |
| LangGraph | 1.2.11 | Embedded + saver | Graph scheduler, fan-out/join, reducers, checkpoint API | Policy, evidence tenancy, citations, application facts | Select behind `OrchestratorPort` |
| LangGraph PostgreSQL saver | 3.1.2 | PostgreSQL | Saver SQL/state history | Owner registry, forced RLS, retention | Select, replace through `OrchestratorPort` |
| Temporal Python SDK | 1.31.0 | Temporal Server | Workflow replay, timers, signals, Activity retry/heartbeat/cancel, worker recovery | Event ledger, policy, budget, idempotency, outbox, projections, audit | Select behind `ActivityOperations` + outbox |
| Temporal Server | 1.29.1 local digest | Server + PostgreSQL | Local compatibility runtime | Auth/TLS, namespaces, HA, upgrades, DR, capacity | Optional Compose only |
| FastAPI/Pydantic | 0.141.1 / 2.13.4 | ASGI runtime | Routing/OpenAPI/validation | Identity, policy, body bounds, anti-enumeration | Delivery adapter |
| PostgreSQL/Psycopg | PG 17 / 3.3.4 | Stateful DB | Transactions, locks, pooling | Schema, RLS, event/hash/idempotency/delivery semantics | Repository ports + SQL export |
| PyJWT/cryptography | 2.13.0 / 50.0.0 | IdP/JWKS | JOSE/JWK/signature/registered claims | Issuer/cache bounds/current principal/grants | `AuthenticatorPort` |
| OpenTelemetry | 1.44.0 | Exporter/backend optional | Span/metric transport APIs | Redaction, cardinality, sampling, SLO | Canonical telemetry |
| Langfuse | 4.14.4 | Hosted/self-hosted backend | Optional model/graph trace/eval UI | Payload minimization, retention | Optional behind `ObservabilityPort` |
| Keycloak | 26.7.1 local digest | JVM + database | Local OIDC compatibility | Realm/client/grants/production operations | Optional |
| Redis/Valkey | Not installed | Additional state service | Queue primitives | Leases, truth, retry, tenancy still custom | Reject: Temporal owns workflow queue |
| OpenAI/Anthropic | Deferred | Credentials/network | Provider calls | Data policy, routing, quotas, schema | `StructuredModelPort` |
| pgvector/RAG | Deferred | Extension/index | Vector search | Tenant/provenance/relevance | `EvidencePort` |
| UI, MCP/A2A, sandbox | Deferred | New runtimes/services | N/A | Session/tool/effect security | Later layers |

## Why Temporal now

ADR 002 deferred Temporal while the product had a short request-bound investigation.
Layer 3 explicitly requires process-independent scheduling, a durable wait/timer,
signals, cancellation delivery, bounded Activity retry/heartbeat, worker recovery, and
workflow replay. Those are workflow-engine requirements; reproducing them with
PostgreSQL/Redis pollers would create a custom engine.

The SDK's workflow sandbox prohibits common nondeterministic operations. Pydantic
conversion is supported by the official extra. SDK 1.31.0 moved payload warning limits
to `Client.connect`; the application adds a stricter codec that rejects payload items
over 64 KiB. Built-in `WorkflowEnvironment.start_time_skipping()` is supported but
downloads a test server unless a path is supplied, so tests require a preinstalled
binary. CI uses the digest-pinned local server instead.

Temporal does **not** provide:

- current tenant identity, grants, purpose/risk policy, or quota;
- an application event/audit ledger or authorized API projection;
- exactly-once Activities or external effects;
- application inbox/outbox/idempotency/fencing;
- payload privacy, retention, or low-cardinality policy;
- deterministic LangGraph/model semantics.

## Temporal and LangGraph ownership

LangGraph stays inside one Activity and owns only the bounded cognitive graph. Temporal
retries the Activity, not individual nodes. LangGraph has no independent retry loop.
Provider SDK retries must be disabled or included inside the Activity attempt. This
keeps one visible retry owner per boundary.

Temporal workflow history can resume mechanics but is not an authorization, tenant
grant, audit record, application outcome, approval, fencing token, or effect receipt.
The API reads PostgreSQL projections only.

## Server compatibility choice

The current stable SDK and server are 1.31.0. The official
`temporalio/docker-compose` reference still pins `auto-setup:1.29.1`. The used core
workflow/Activity APIs are within Temporal's documented SDK/server compatibility
window. Local integration verifies the exact pair:

- `temporalio==1.31.0`;
- `temporalio/auto-setup:1.29.1@sha256:5b3502a3b685f9eff1b925af90c57c9e3dbeccbef367cc28a2a9712c63379312`.

This is not a recommendation to deploy `auto-setup` in production. Production must use
a qualified server topology and schema upgrade process.

## Framework comparison against custom Aegis

Pinned custom targets:

- Layer 3 durable ledger: `87cefe58adbf62e6a419d38e57e0928581b7003c`;
- Layer 4 worker runtime: `171fa485819334a892684544c0a993a6e2fc4ace`.

Custom Layer 3 uses 3,765 production LOC and 2,239 test LOC. Its change from Layer 2 is
3,901 additions across 42 files. Custom Layer 4 grows to 7,452 production LOC and
3,687 test LOC; the worker layer adds 6,301 lines across 47 files and introduces Redis
Streams plus PostgreSQL-authoritative leases/fencing.

Temporal removes custom poller/scheduler, retry/backoff, heartbeat, timer, signal
history, and crash-recovery machinery. It does not remove application event envelopes,
expected versions, RLS, idempotency, inbox/outbox, stale-result controls, projections,
authorization, audit, or redaction. It adds one operational control plane and workflow
history/versioning lock-in. The exact framework branch measurements are in
`comparison/layer3-metrics.json`.

## Versioning and lock-in

Workflow code records `aegis-investigation-lifecycle-v1` with
`workflow.patched`. Release replay uses `Replayer`. Future deployments use patch
add/deprecate/remove or current Worker Versioning—not the removed pre-2026 experimental
scheme. Continue-as-new is deferred until measured history size justifies it.

Escape hatches:

- Temporal: application outbox + opaque typed messages + `ActivityOperations`;
- LangGraph: `OrchestratorPort` + JSON-compatible domain results;
- PostgreSQL: repository ports + canonical SQL/JSON export;
- PyJWT/IdP: `AuthenticatorPort` + standard JWT/JWK/OIDC;
- Langfuse: `ObservabilityPort` + OpenTelemetry.

## Primary sources

Accessed 2026-08-15:

- [Temporal Python SDK releases/changelog](https://github.com/temporalio/sdk-python/blob/main/CHANGELOG.md)
- [Temporal Python workflows](https://docs.temporal.io/develop/python/core-application)
- [Temporal testing and replay](https://docs.temporal.io/develop/python/testing-suite)
- [Temporal workflow versioning](https://docs.temporal.io/develop/python/versioning)
- [Temporal data handling](https://docs.temporal.io/develop/python/converters-and-encryption)
- [Temporal cancellation](https://docs.temporal.io/develop/python/cancellation)
- [Temporal Server 1.31.0](https://github.com/temporalio/temporal/releases/tag/v1.31.0)
- [Official Temporal Docker Compose](https://github.com/temporalio/docker-compose)
- [LangGraph persistence](https://docs.langchain.com/oss/python/langgraph/persistence)
- [PyJWT API](https://pyjwt.readthedocs.io/en/stable/api.html)
- [JWT BCP RFC 8725](https://www.rfc-editor.org/rfc/rfc8725)
- [PostgreSQL version policy](https://www.postgresql.org/support/versioning/)
- [OpenTelemetry](https://opentelemetry.io/docs/)
- [Langfuse repository/license](https://github.com/langfuse/langfuse)

Package metadata is the source for exact SDK pins. Production service/license/security
qualification remains an organizational responsibility.
