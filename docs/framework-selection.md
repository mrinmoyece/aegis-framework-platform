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
| pgvector (PostgreSQL extension) | 0.8.x local digest | PostgreSQL extension | `vector` column type/cast, distance operators | Retrieval scoring/prefilters, tenant/provenance scoping, application wiring | Select: raw SQL write path plus live `hybrid_candidates` query; not yet wired into serving path |
| LangGraph `Store`/long-term memory | 1.2.11 evaluated, not installed | Embedded checkpointer-adjacent store | Namespaced key/value put/search helpers | Retention, legal hold, citations, tenancy, erasure, audit | Reject: framework store as authority for durable memory |
| LangChain vector stores/retrievers/text splitters | 1.5.1/0.4.x evaluated, not installed | Broad abstraction + provider-specific stores | Generic `VectorStore`/`Retriever`/splitter interfaces | Tenant/citation/retention/erasure controls still remain | Reject: overlap without control removal; opaque splitter/store semantics |
| LlamaIndex (index/query engine) | 0.14.x evaluated, not installed | Broad indexing/query framework + optional hosted services | Index construction/query-engine orchestration | All enterprise controls remain | Reject: overlap without control removal; heavy dependency surface |
| Haystack | 2.x evaluated, not installed | Pipeline/component framework + optional hosted services | Pipeline/component orchestration for RAG | All enterprise controls remain | Reject: overlap with LangGraph/application ports without control removal |
| pgvector-python client | 0.4.x evaluated, not installed | psycopg/asyncpg adapter registration | Vector type adaptation convenience | Raw `%s::vector` cast already sufficient; no new control removed | Reject: unnecessary dependency for a two-line cast |
| Embedding abstraction libraries (e.g. provider-agnostic embedding SDKs) | Evaluated, not installed | Additional provider abstraction layer | Unified embed-call surface | `EmbeddingPort` already provides this seam; no real provider shipped either way | Reject: no control removed while adding a dependency and a second abstraction over the same port |
| pgvector/RAG | Selected | Extension/index | Durable embedding write path plus live forced-RLS hybrid SQL query (store-tested) | Serving-path wiring, tenant/provenance/relevance benchmarking at scale, legal hold | `EmbeddingPort`/`MemoryReadPort`; see ADR 014 |
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
- pgvector/memory: `EmbeddingPort`/`SummarizationPort`/`MemoryReadPort` + immutable
  `memory_facts` replay; the raw `vector` cast is portable PostgreSQL, not a vendor SDK.

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
# Layer 8 sandbox framework decision

The selected production-shaped adapter is the official Kubernetes Python client creating
one-shot Jobs behind neutral `SandboxBackend`. `RuntimeClass` permits a separately
qualified Kata VM boundary (recommended for mutually distrustful tenants) or gVisor
userspace-kernel profile without placing vendor types in contracts. Kubernetes supplies
Job lifecycle, scheduling, deadlines, resources, RBAC integration, and official API
mechanics; Temporal supplies durable Activity retry/heartbeat/cancellation/replay.

This does not claim that Kubernetes namespaces or ordinary containers isolate hostile
tenants. Kubernetes documents the weaker shared-kernel boundary and recommends sandboxing
or VMs for untrusted workloads. NetworkPolicy is CNI-dependent L3/L4 and is not an FQDN
firewall. The adapter therefore implements network none and rejects exact-destination
execution; an external proxy plus policy-registration adapter remains future work.

| Option | Useful mechanics | Decision |
|---|---|---|
| Kubernetes Jobs + RuntimeClass | Official client, immutable digests, Job deadlines/state, quotas/RBAC, injectable SDK doubles | Selected; disabled until live runtime/admission/CNI/CSI/identity qualification |
| Kata Containers | VM-isolated container runtime through RuntimeClass | Recommended production profile; not qualified by repository tests |
| gVisor | Userspace-kernel interception with lower overhead | Optional separately qualified profile; not equivalent to a VM |
| E2B | Managed Firecracker sandbox, lifecycle and egress controls | Credible optional future adapter; vendor/tenant/region/retention/idempotency review required |
| Modal | Managed gVisor sandbox, mature Python lifecycle/network APIs | Credible optional future adapter; outbound/image/UID/beta domain-policy tradeoffs |
| Daytona | Managed container/VM classes, snapshots and network controls | Deferred; renewed review required after public core moved private |
| Docker SDK/socket | Mature image/container APIs | Rejected for hostile tenancy; daemon access is host-privileged |
| Raw Firecracker wrappers | Strong KVM primitive | Deferred; would recreate scheduling, networking, jailer, image and lifecycle platform |
| RestrictedPython | Python language restriction | Rejected; maintainers explicitly state it is not a sandbox |
| Local subprocess | Standard process lifecycle | Rejected; no independent kernel/filesystem/network/tenant boundary |

Primary references: [Kubernetes multi-tenancy](https://kubernetes.io/docs/concepts/security/multi-tenancy/#sandboxing-containers),
[RuntimeClass](https://kubernetes.io/docs/concepts/containers/runtime-class/),
[Kubernetes Jobs](https://kubernetes.io/docs/concepts/workloads/controllers/job/),
[Kubernetes images](https://kubernetes.io/docs/concepts/containers/images/#image-names),
[NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/),
[Kata](https://katacontainers.io/), [gVisor security](https://gvisor.dev/docs/architecture_guide/security/),
[E2B sandbox lifecycle](https://docs.e2b.dev/sandbox),
[Modal sandboxes](https://modal.com/docs/guide/sandboxes),
[Daytona sandboxes](https://www.daytona.io/docs/en/sandboxes/),
[Docker daemon security](https://docs.docker.com/engine/security/#docker-daemon-attack-surface),
[Firecracker production setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md),
and [RestrictedPython](https://restrictedpython.readthedocs.io/en/latest/).

## Framework Layer 8 versus custom Aegis Layer 9

The pinned custom comparison is
`mrinmoyece/aegis-agent-platform@ed16fb8bb62ca6d18bc53ec8ee4e0191ed6caa63`
on `mrinmoyece-aegis-layer-9-sandbox`. Custom Layer 9 has 35,980 production LOC,
18,558 test LOC and 54,538 total LOC, with 12 runtime, seven optional and no declared
development dependencies. Its one-commit sandbox increment from custom Layer 8 is 14,283
additions and 95 deletions across 53 files.

Framework Layer 8 currently measures 27,964 production LOC, 12,603 test LOC and 40,567
total LOC, with 12 runtime, seven optional, eight development and 131 locked packages. Its
working Layer 8 increment from the Layer 6 comparison anchor is recorded transparently in
`comparison/layer8-metrics.json`; that Git proxy includes accumulated later-layer changes
and must not be read as isolated sandbox authoring effort.

Temporal removes a custom durable sandbox scheduler, wait loop, retry/backoff, heartbeat
timeout, signal history, cancellation delivery, crash recovery and replay implementation.
The official Kubernetes client and Job controller remove custom Kubernetes wire/object
mechanics, Job scheduling/state/deadline handling and basic resource placement. They do
not remove exact contracts, current approval/policy, tenant RLS, quotas, idempotency,
claims/fencing, observe-before-create, ambiguous reconciliation, safe workspace/archive
handling, output scanning/redaction/quarantine, attestation, cleanup ownership, privacy,
or operational readiness controls. Those remain application code in both implementations.

The equivalent 200-run deterministic fake lifecycle measured Framework Layer 8 at
0.219 ms median/0.249 ms p95 and custom Layer 9 at 4.055 ms median/4.552 ms p95 on the
same machine. This is not a throughput, isolation or distributed-system result: the custom
path includes its async event repository/orchestrator while the framework path includes
strict Pydantic contracts, three application facts and a fake backend. Neither includes
PostgreSQL, Temporal, Redis, Kubernetes, CSI, CNI, runtime isolation, serialization,
network, node scheduling or process startup.

Framework lock-in is real: Temporal histories/task queues/versioning and Kubernetes Job,
RuntimeClass, admission, CNI, CSI and operational semantics become dependencies. Escape is
explicit: preserve neutral `SandboxBackend`, opaque workflow messages, immutable
PostgreSQL facts and pure replay; replace Temporal/Kubernetes only after the new scheduler
or managed service passes equivalent waits/retry/heartbeat/cancel/crash/replay, exact
identity/idempotency, policy, egress, artifact, attestation, cleanup and privacy tests.

E2B and Modal can remove much of the cluster/runtime operations burden but add remote
availability, vendor image/build identity, network-policy semantics, region/retention/DPA,
attestation, SLA and incident-response dependencies. Daytona needs renewed diligence
after its public core moved private. None is represented as a drop-in production security
claim, and no live managed-service benchmark is presented.

# Layer 9 memory framework decision

The selected production-shaped adapter is direct pgvector SQL (raw `%s::vector` casts,
forced RLS, immutability triggers over `memory_facts`/`memory_chunks`) plus the already
selected LangGraph (bounded context building only), Temporal (`aegis.memory.v1` durable
ingest/compact/purge/rebuild Activities) and Pydantic (immutable `MemoryRecord`/`MemoryFact`
contracts). No new memory/RAG framework or vector-store abstraction is added. Full
rationale, rejected alternatives and primary sources are in
[ADR 014](adr/014-pgvector-sql-event-grounded-memory.md).

| Option | Useful mechanics | Decision |
|---|---|---|
| Direct pgvector SQL (`vector` column, raw cast) | Durable embedding storage, forced RLS, immutability triggers, no ORM/abstraction indirection, plus a live `hybrid_candidates` hybrid-scoring query | Selected; store-level query implemented and integration-tested, not yet wired into the serving path |
| LangGraph `Store`/long-term memory | Namespaced key/value put/search helpers | Rejected: framework store as durable authority for tenancy, retention, legal hold, citations, erasure |
| LangChain vector stores/retrievers/text splitters | Generic `VectorStore`/`Retriever`/splitter interfaces | Rejected: overlap without control removal; opaque store/splitter semantics; still requires all enterprise controls |
| LlamaIndex | Index construction/query-engine orchestration | Rejected: overlap without control removal; heavy dependency surface |
| Haystack | Pipeline/component framework for RAG | Rejected: overlap with LangGraph/application ports without control removal |
| pgvector-python client | Vector type adaptation convenience for psycopg/asyncpg | Rejected: unnecessary dependency for a two-line raw cast already covered by psycopg |
| Embedding abstraction libraries | Unified embed-call surface across providers | Rejected: `EmbeddingPort` already provides this seam; no real provider ships either way |

This does not claim a qualified, production-serving live pgvector retrieval path.
`PostgresMemoryStore.hybrid_candidates` implements and integration-tests a live
forced-RLS SQL query combining cosine ANN distance, lexical `ts_rank_cd`, and
recency/quality scoring with ACL/classification/time/retention prefilters, including a
cross-tenant/classification isolation assertion — but it is proven at the store layer
only. `MemoryRetrievalService`/`InMemoryMemoryControl` and `/v1/memories/retrieve` still
serve from `InMemoryHybridIndex`; wiring `hybrid_candidates` into that live path remains
explicit future work rather than an implicit capability.

Primary references (accessed 2026-08-17): [LangGraph persistence/Store](https://docs.langchain.com/oss/python/langgraph/persistence),
[LangChain vector stores](https://python.langchain.com/docs/concepts/vectorstores/),
[LangChain retrievers](https://python.langchain.com/docs/concepts/retrievers/),
[LangChain PGVector integration](https://python.langchain.com/docs/integrations/vectorstores/pgvector/),
[LangChain text splitters](https://python.langchain.com/docs/concepts/text_splitters/),
[LlamaIndex](https://docs.llamaindex.ai/en/stable/),
[Haystack](https://docs.haystack.deepset.ai/docs/intro),
[pgvector-python](https://github.com/pgvector/pgvector-python),
[pgvector extension](https://github.com/pgvector/pgvector),
[psycopg adapt](https://www.psycopg.org/psycopg3/docs/advanced/adapt.html).

## Framework Layer 9 versus custom Aegis Layer 10

The pinned custom comparison is
`mrinmoyece/aegis-agent-platform@c9474184af756ce93d19d86360c339541e8263fb`
on `mrinmoyece-aegis-layer-10-memory-rag`, one commit above custom Layer 9
`ed16fb8b`. Custom Layer 10 has 44,117 production LOC, 22,194 test LOC and 66,311 total
LOC, with 395 test functions, 12 runtime and seven optional dependencies (no lock file).
Its one-commit memory/RAG increment from custom Layer 9 is 13,545 additions and 104
deletions across 58 files.

Framework Layer 9 currently measures 31,501 production LOC, 14,110 test LOC and 45,611
total LOC, with 12 runtime, seven optional, eight development and 131 locked packages —
unchanged dependency counts from Layer 8, confirming no new dependency was added for
pgvector/memory (the existing `psycopg` connection is reused for the raw `vector` cast
and the `hybrid_candidates` query). Its working Layer 9 increment is recorded
transparently in `comparison/layer9-metrics.json`; that Git proxy includes accumulated
later-layer changes and must not be read as isolated memory authoring effort.

Both implementations independently avoid LangChain, LlamaIndex, Haystack and
`pgvector-python`, choosing raw SQL over pgvector instead. Neither adds a new dependency
for memory. The prior material asymmetry has narrowed: custom Layer 10's
`memory/postgres.py` implements a live pgvector cosine ANN query (`embedding <=> %s::vector`
in a combined lexical+vector `ORDER BY` clause) exercised by its own retrieval path, and
this framework's `PostgresMemoryStore.hybrid_candidates` now implements an equivalent live
forced-RLS query (cosine ANN distance, lexical `ts_rank_cd`, recency/quality scoring,
ACL/classification/time/retention prefilters, deterministic tie-break ordering), proven by
a PostgreSQL integration test including a cross-tenant/classification isolation
assertion. The remaining, candid difference: this framework's query is proven at the
store/repository layer only — `MemoryRetrievalService`/`InMemoryMemoryControl` and
`/v1/memories/retrieve` still serve from `InMemoryHybridIndex`, so wiring
`hybrid_candidates` into the production retrieval path remains explicit future work. This
comparison does not independently verify whether custom Layer 10's query is wired into
its own production serving path.

Temporal removes a custom durable memory-lifecycle scheduler, retry/backoff, and replay
implementation for ingest/compact/purge/rebuild; this framework's Activities additionally
send a periodic 10-second heartbeat (beyond an initial heartbeat) under a 30-second
timeout so a stalled worker is detected promptly. LangGraph's role is unchanged from
earlier layers: bounded context assembly only, never authority. Neither framework removes
exact contracts, tenancy, legal hold/retention, citation enforcement, banned-field
discipline, the fact-chain ledger, or final MMR/context-budget selection; those remain
application code in both implementations. This framework additionally now requires an
explicit `MemoryAcceptance` human/policy decision before any candidate can be ingested,
and records digest-only `MemoryOperationFact`s around every retrieval/context build.

The 200-run equivalent demo scenario measured Framework Layer 9 at 0.849 ms median/
0.944 ms p95 and custom Layer 10 at 10.285 ms median/11.88 ms p95 on the same arm64/
Python 3.14.7 machine (custom repo measured in its own isolated virtual environment).
This is not a throughput or retrieval-quality result: the custom path exercises its own
async event/index machinery including the live SQL-shaped ANN scoring path, while the
framework's demo scenario exercises strict Pydantic contracts and the in-memory hybrid
index only — it does not call the separately store-tested `hybrid_candidates` query,
which requires a live PostgreSQL connection and is exercised only by the PostgreSQL
integration test, not this in-memory benchmark. Neither run includes PostgreSQL, Temporal,
a real embedding provider, network, or process startup. Retrieval-quality parity
(precision/recall on an equivalent corpus) is not measured by either benchmark and
remains a candid gap in this comparison.

Framework lock-in is limited: the raw pgvector SQL cast, forced RLS and immutability
triggers are portable PostgreSQL/psycopg mechanics, not a vendor abstraction. Temporal
history/task-queue/versioning lock-in from earlier layers applies unchanged to the memory
workflow. Escape remains explicit: preserve immutable `memory_facts`, the neutral
`EmbeddingPort`/`SummarizationPort`/`MemoryReadPort` seams, and pure `reduce_memory`
replay; replace the derived index or embedding provider only after the new implementation
passes the same tenancy/citation/legal-hold/erasure/instruction-boundary equivalence
suite.
## Layer 10 evaluation tool decision

Required evaluation remains neutral Python contracts plus pytest. It executes
offline and publishes nothing unless an operator explicitly selects the sanitized
Langfuse adapter.

| Tool | Decision | Enterprise rationale |
|---|---|---|
| pytest | Selected | Existing exact-pinned runner, strict assertions/JUnit/coverage, no hosted service, and Temporal's recommended Python test harness |
| Hypothesis | Comparison/future additive use | Strong local generation and shrinking; generated failures still need reviewed promotion into the immutable corpus, so Layer 10 does not add it solely to restate finite cases |
| Temporal `WorkflowEnvironment` | Selected, environment-gated | Time skipping and replay are proven SDK mechanics; `test_server_existing_path` prevents an implicit binary download and Compose provides the pinned CI path |
| Langfuse datasets/evals | Selected only as optional publisher | MIT core and self-hosting are available, but deterministic gates stay local; no code-evaluator dispatcher, hosted dataset authority, or automatic graph capture |
| LangSmith | Rejected | Self-hosting is an Enterprise add-on and brings a proprietary evaluation/control plane; automatic LangGraph capture conflicts with the repository privacy boundary |
| DeepEval | Rejected for CI | Most built-in metrics are LLM-as-judge; using only custom deterministic metrics duplicates the neutral scorer contracts |
| Ragas | Rejected for CI | Core RAG/agent metrics are judge-driven; BLEU/ROUGE/string metrics do not establish tenant, citation, approval, effect, or recovery safety |
| promptfoo | Rejected | Adds Node, subprocess/provider configuration, and another test DSL; its main multi-provider value requires network/model calls |
| OpenAI eval tooling | Rejected | Provider/network dependent; the hosted Evals platform is read-only from 2026-10-31 and scheduled to shut down on 2026-11-30 |

Primary references: [LangSmith evaluation concepts](https://docs.langchain.com/langsmith/evaluation-concepts),
[LangSmith self-hosting](https://docs.langchain.com/langsmith/self-hosted),
[Langfuse datasets](https://langfuse.com/docs/evaluation/experiments/datasets),
[Langfuse SDK experiments](https://langfuse.com/docs/evaluation/experiments/experiments-via-sdk),
[Langfuse licensing](https://langfuse.com/self-hosting/license-key),
[DeepEval metrics](https://deepeval.com/docs/metrics-introduction),
[Ragas metrics](https://docs.ragas.io/en/stable/concepts/metrics/available_metrics/),
[promptfoo deterministic assertions](https://www.promptfoo.dev/docs/configuration/expected-outputs/deterministic/),
[OpenAI evals](https://developers.openai.com/api/docs/guides/evals),
[Hypothesis](https://hypothesis.readthedocs.io/en/latest/), and
[Temporal Python testing](https://docs.temporal.io/develop/python/best-practices/testing-suite).

The full decision and authority boundary are in
[ADR 015](adr/015-governed-deterministic-evaluation.md).
