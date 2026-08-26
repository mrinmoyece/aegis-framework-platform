# Framework selection report

Research was refreshed from official package/project sources on **2026-08-16**.
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
| OpenAI SDK | 3.1.0 | Provider network when enabled | OpenAI Responses protocol/decoding | Policy, routing, budget, pricing, usage, safety | Optional behind `ModelProviderAdapter` |
| Anthropic SDK | 0.122.0 | Provider network when enabled | Anthropic Messages protocol/decoding | Policy, routing, budget, pricing, usage, safety | Optional behind `ModelProviderAdapter` |
| HTTPX | 0.28.1 | Connector network when enabled | HTTP pooling, timeout and streamed response mechanics | Origin/DNS/IP/redirect policy, auth, schema, limits, retry truth | Select behind `HttpTransport` |
| Kubernetes Python client | 36.0.3 | Kubernetes API when enabled | Official API object/wire decoding | Static safe configuration, RBAC, namespace/resource policy, pagination truth | Optional behind `KubernetesApi` |
| PyYAML | 6.0.3 | Embedded | YAML syntax parsing | Input/structure bounds, schema, trust, redaction | Select narrowly with `safe_load` |
| Keycloak | 26.7.1 local digest | JVM + database | Local OIDC compatibility | Realm/client/grants/production operations | Optional |
| Redis/Valkey | Not installed | Additional state service | Queue primitives | Leases, truth, retry, tenancy still custom | Reject: Temporal owns workflow queue |
| LiteLLM | 1.98.0 evaluated, not installed | Proxy/SDK and broad dependencies | Unified provider API/routing | Enterprise controls still remain | Reject: OpenAI 3 conflict, overlap, footprint |
| Instructor | 1.16.0 evaluated, not installed | Validation/retry wrapper | Structured parsing/repair | Policy/budget/ledger still remain | Reject: version/retry overlap |
| LangChain provider interfaces | 1.5.1 evaluated, not installed | LangChain messages/tracing/tokenizer | Provider runnable wrappers | Enterprise controls still remain | Reject: coupling without control removal |
| Portkey/OpenRouter | Not installed | External gateway/SaaS | Hosted routing/retry/cost UI | Application truth and privacy controls | Reject: external authority/trace/retry plane |
| pgvector/RAG | Deferred | Extension/index | Vector search | Tenant/provenance/relevance | `EvidencePort` |
| PyGithub | 2.9.1 evaluated, not installed | Requests/urllib3/PyNaCl | GitHub object/pagination wrappers | All Layer 5 controls remain | Reject: non-official and obscures call controls |
| githubkit | 0.16.1 evaluated, not installed | HTTPX/cache/generated schemas | GitHub generated API | All Layer 5 controls remain | Reject: non-official and excess surface |
| LangChain community loaders | 0.4.2 evaluated, not installed | Broad loader/network stack | Loader dispatch | Trust/provenance/sandbox remain | Reject: sunset/overlap |
| LangChain Unstructured | 1.0.1 evaluated, not installed | External API or parser stack | Document extraction | Trust/provenance/sandbox remain | Reject: Python-range/privacy/footprint |
| LlamaIndex readers / Unstructured | Evaluated, not installed | Overlapping ingestion/RAG stack | Broad format parsing | All enterprise controls remain | Reject: overlap without control removal |
| UI, MCP/A2A, sandbox | Deferred | New runtimes/services | N/A | Session/tool/effect security | Later layers |
| CrewAI / AutoGen | Not installed | Additional agent runtime | Agent chat/delegation abstractions | All Aegis authority/artifact/ledger controls | Reject: overlaps LangGraph and expands dynamic authority surface |

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

## Layer 4 model framework decision

Official package metadata checked on 2026-08-15 reports `openai==3.1.0` and
`anthropic==0.122.0` as current stable releases supporting the repository Python range.
Both expose retry disablement through `max_retries=0`. Aegis uses their protocol clients
only in `provider_adapters.py`; neutral messages, tools, structured schemas, errors,
usage, pricing, policy, reservations, ledger, and health live in application contracts.

LiteLLM 1.98.0 requires OpenAI `<3`, carries boto3/tiktoken/aiohttp and multiple
retry/routing/telemetry axes. Instructor 1.16.0 also requires OpenAI `<3`, its Anthropic
extra pins 0.93.0, and Tenacity duplicates bounded repair. `langchain-openai==1.5.1`
would fit `langchain-core==1.5.5` but adds LangChain message/tiktoken coupling and tracing
risk without removing enterprise code. Portkey/OpenRouter place retry, model catalog,
cost, and potentially prompt/completion observation in another control plane.

The selected pair increases direct optional dependencies and adapter code. It does not
reduce policy, budget, ledger, resilience, safety, or evaluation code. Official SDKs
remove only provider wire-protocol maintenance.

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
- Layer 4 worker runtime: `171fa485819334a892684544c0a993a6e2fc4ace`;
- Layer 5 model gateway: `7c22d380a66f57aad943fe926ffff3ca8fc06ed6`.

Custom Layer 3 uses 3,765 production LOC and 2,239 test LOC. Its change from Layer 2 is
3,901 additions across 42 files. Custom Layer 4 grows to 7,452 production LOC and
3,687 test LOC; the worker layer adds 6,301 lines across 47 files and introduces Redis
Streams plus PostgreSQL-authoritative leases/fencing.

Temporal removes custom poller/scheduler, retry/backoff, heartbeat, timer, signal
history, and crash-recovery machinery. It does not remove application event envelopes,
expected versions, RLS, idempotency, inbox/outbox, stale-result controls, projections,
authorization, audit, or redaction. It adds one operational control plane and workflow
history/versioning lock-in. The exact framework branch measurements are in
`comparison/layer4-metrics.json`.

Custom Layer 5 has 11,079 production LOC and 5,479 test LOC (16,558 total); its Layer 5
increment adds 6,568 lines across 55 files. Framework Layer 4 has 12,136 production LOC
and 5,463 test LOC (17,599 total). Framework use therefore increases production LOC by
1,057 and total LOC by 1,041. Official SDKs eliminate wire protocol code but none of the
enterprise controls.

On the same arm64/Python 3.14.7 machine, 50 equivalent in-process fake calls covering
catalog route, reservation and settlement measured 0.348 ms median/0.510 ms p95 for
Framework Layer 4 and 0.166/0.206 ms for custom Layer 5. These are not service benchmarks:
they exclude PostgreSQL, Temporal, Redis, provider network, serialization and process
boundaries.

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
- OpenAI/Anthropic: `ModelProviderAdapter` + neutral `ModelRequest`/`ProviderResult`.

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
- [OpenAI Python SDK](https://github.com/openai/openai-python)
- [Anthropic Python SDK](https://github.com/anthropics/anthropic-sdk-python)
- [LiteLLM routing](https://docs.litellm.ai/docs/routing)
- [Instructor retry behavior](https://python.useinstructor.com/concepts/retrying/)
- [Portkey AI Gateway](https://portkey.ai/docs/product/ai-gateway)

Package metadata is the source for exact SDK pins. Production service/license/security
qualification remains an organizational responsibility.

## Layer 5 connector framework decision

No general official Dynatrace REST SDK or official GitHub Python Octokit exists.
`oneagent-sdk` is instrumentation, not an API client. Direct HTTPX therefore keeps exact
API paths, tokens, redirect denial, page semantics, response limits, and exceptions
visible. Existing PyJWT signs GitHub App JWTs; installation tokens are narrowed to the
configured repositories and permissions.

The official Kubernetes client is selected only for Kubernetes and configured directly
from a fixed HTTPS server plus tenant-bound service-account token. Aegis does not load
arbitrary kubeconfig, exec credential plugins, auth providers, Secrets, ConfigMaps, or
mutating APIs. List `_continue` values are encrypted application cursors; `410 Gone`
requires explicit relist/reconciliation.

PyYAML removes syntax parsing only. Aegis still applies byte/node/depth/schema bounds and
projects scalar allowlisted facts. Markdown/text/JSON and bounded ZIP are handled
narrowly. PDF, DOCX, XML, HTML, macros, active content, Unstructured, LlamaIndex, and
LangChain loaders remain absent. This is intentionally less framework-heavy: secure
connectors gained little from loader ecosystems and would inherit more supply-chain and
metadata risk.

## Framework Layer 5 versus custom Aegis Layer 6

Pinned custom Layer 6 is
`mrinmoyece/aegis-agent-platform@7a685bc52772e1c92467baba58a1c668646e9bf7`.
It contains 17,119 production LOC, 8,780 test LOC, 25,899 total LOC, and 204 test
functions. Its one-commit increment from custom Layer 5 is 10,954 additions, 123
deletions across 50 files. Framework Layer 5 measurements are generated in
`comparison/layer5-metrics.json`.

The custom layer uses 12 broad runtime dependencies with version ranges and keeps its
Redis worker plane. Framework Layer 5 has 12 exact runtime dependencies, seven optional
dependencies, 131 locked packages, PostgreSQL plus Temporal, and no new stateful service.
The official Kubernetes client adds a notable `requests`/`urllib3`/YAML/WebSocket/OAuth
dependency subtree. HTTPX and PyYAML were already transitive but are now direct pins.

For 200 equivalent in-process three-record non-causal correlations on the same
arm64/Python 3.14.7 machine, custom Layer 6 measured 0.015 ms median/p95 and Framework
Layer 5 measured 0.048/0.049 ms. The framework path is roughly 3x slower at microsecond
scale because of strict Pydantic construction. This is not a service benchmark: it
excludes ingestion, PostgreSQL, Temporal, Redis, connector networks, serialization, and
process boundaries.

Frameworks eliminate HTTP connection/stream mechanics, Kubernetes wire/object decoding,
JWT cryptography, YAML syntax parsing, Temporal scheduling/retry/heartbeat/cancellation,
and LangGraph scheduling/checkpoint plumbing. They do **not** eliminate tenant/source
policy, secret references, SSRF/DNS/redirect controls, response/schema limits, durable
intent, ambiguity/reconciliation, cursor encryption, canonicalization, scanning,
redaction, quarantine, retention, provenance, RLS, deterministic correlation, citation
validation, observability privacy, or authorized APIs. Secure connector work remains
mostly custom.

Operationally, Framework Layer 5 trades the custom Redis worker for Temporal and adds the
official Kubernetes client's dependency/upgrade matrix. Escape paths are `HttpTransport`,
`KubernetesApi`, `EvidenceConnector`, `EvidenceControlStore`, opaque Temporal messages,
application events/SQL export, and canonical JSON/text. Loader lock-in is avoided.

## Framework Layer 6 versus custom Aegis Layer 7

The custom target is
`mrinmoyece/aegis-agent-platform@dce0054a40c34ab4cc9d515aa753bc71d73fab57`.
It has 21,581 production LOC, 9,975 test LOC, 31,556 total LOC, 221 test functions,
12 runtime and six optional dependencies. Its Layer 7 increment from custom Layer 6 is
6,749 additions and 177 deletions across 41 files in three commits.

Framework Layer 6 keeps exact `langgraph==1.2.11`, transitive
`langgraph-checkpoint==4.2.0`, `langgraph-checkpoint-postgres==3.1.2`, and
`langchain-core==1.5.5`; it adds no new dependency or stateful service above Layer 5.
Stable public APIs used are `StateGraph`, `TypedDict` state with annotated reducers,
static parallel edges/list-edge fan-in, conditional edges, `InMemorySaver`/
`PostgresSaver`, `get_state`, `get_state_history`, and invocation `recursion_limit`.
Stable but unnecessary `Send`, `Command`, subgraphs, and `interrupt()` are deliberately
absent. Beta `DeltaChannel` and the experimental `temporalio.contrib.langgraph` plugin
are rejected.

LangGraph eliminates custom DAG scheduler, synchronized fan-in, reducer engine,
conditional router, checkpoint serialization and history traversal. Remaining custom
controls are the majority of security-sensitive behavior: identity/policy/budget,
fixed role capabilities, artifact schemas/transitions/digests, dispatch/result fencing,
model/evidence safety, citation/confidence/critic gates, tenant RLS, immutable facts,
projection rebuild, Temporal retry ownership, redaction, approval separation and effect
absence.

The 200-run local equivalent benchmark measured 25.922 ms median/29.305 ms p95 for the
custom async coordinator/event-repository path. Framework values are generated in
`comparison/layer6-metrics.json`. The methods are not identical: custom creates an event
loop per sample and exercises its in-memory event repository; framework exercises strict
Pydantic artifacts plus LangGraph checkpoints. Neither includes PostgreSQL, Temporal,
Redis, model/connector networks, or process boundaries, so the figures are implementation
cost indicators—not service throughput.

Checkpoint lock-in includes Pregel super-step semantics, node names, channel reducers,
saver schema/serialization, error behavior and upgrade testing. Escape is explicit:
retain/rebuild from application orchestration facts and neutral artifact JSON, discard
framework checkpoints, replace `OrchestratorPort`, and pass the same deterministic
fan-out/order/replay/version/tenant/cancellation/critic suite.

## Framework Layer 7 versus custom Aegis Layer 8

The custom target is
`mrinmoyece/aegis-agent-platform@0ce9368d60f3b2fce7b805d7d7699d585f13cef2`
on `mrinmoyece-aegis-remediation-approvals`, one commit above custom Layer 7
`dce0054`. Measured with the same non-blank/non-comment Python rule, custom Layer 8 has
28,056 production LOC, 14,031 test LOC, 42,087 total LOC and 275 test functions. Its
increment is 12,030 additions, 162 deletions across 48 files. Framework Layer 7 has
24,193 production LOC, 10,600 test LOC and 34,793 total LOC; its Layer 7 increment is
recorded in `comparison/layer7-metrics.json`.

Both implement immutable exact-scope plan/action/approval/effect/verification contracts,
deny-by-default action policy, two-person high-risk SoD, expiry/revocation, intent before
effect, stable idempotency, fencing, ambiguity/reconciliation, fresh verification,
compensation lifecycle, forced-RLS projections and one fixed Kubernetes rollout restart.
Both retain the same security-sensitive application controls. The official Kubernetes
client removes request/object mechanics only.

The primary difference is durable workflow machinery. Custom Layer 8 implements its own
asynchronous remediation lifecycle over PostgreSQL application state and the existing
Redis Streams delivery plane. Framework Layer 7 uses the already selected Temporal
service for long approval waits, timers, opaque signals, Activity scheduling,
retry/backoff, heartbeat, cancellation delivery, worker recovery and deterministic
workflow replay. No extra agent or workflow framework is added above Temporal and
LangGraph.

Temporal therefore eliminates custom poller/scheduler/timer/signal/retry/heartbeat/
recovery code, but not exact authorization, decisions, audit, idempotency, claims,
fencing, reconciliation, verification or rollback. Operationally, Framework Layer 7
requires PostgreSQL plus Temporal Server; custom Layer 8 requires PostgreSQL plus Redis
Streams. Temporal brings namespace/task-queue/history/schema/Worker Versioning
operations and server-side history lock-in. Custom code brings more queue/lease/lifecycle
maintenance but avoids Temporal history and server operations.

The 200-run equivalent checkout scenario uses a high-risk exact-target rollout restart,
two distinct approvals, dry-run, deterministic fake effect and verification, with no
network, credentials or stateful service. On the same arm64/Python 3.14.7 machine,
Framework Layer 7 measured 0.953 ms median/1.220 ms p95; custom Layer 8 measured
5.983/7.210 ms. The methods are not identical: custom is async and exercises its
in-memory event repository/lease machinery; framework is synchronous and exercises
strict Pydantic contracts and pure ledger replay. The numbers exclude PostgreSQL,
Temporal, Redis, Kubernetes, serialization and process boundaries, so they are
implementation-path indicators—not service throughput or a reason to choose a framework.

Temporal lock-in includes workflow/activity names, deterministic code, signal semantics,
history format, retry behavior, patch markers and deployment replay qualification.
Escape remains explicit: retain PostgreSQL application facts, rebuild projections,
consume opaque commands through another scheduler implementing
`RemediationActivityOperations`, keep `ActionPort`, and pass the wait/timer/signal/
retry/heartbeat/cancellation/crash/replay equivalence suite. Framework history is
discardable; application decisions and receipts are not.
