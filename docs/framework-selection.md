# Framework selection report

Research was refreshed from official project/package sources on **2026-08-15**.
Versions are exact pins where installed. Candidate versions that are deliberately
deferred are recorded so the decision can be reproduced.

## Selected and deferred stack

| Candidate | Version | Maturity/license | Operational dependency | Known limitation | Exit strategy | Decision |
|---|---:|---|---|---|---|---|
| Python | 3.14.7; supports 3.13 | Stable, PSF | Runtime/toolchain | Newer ecosystem wheels can lag | CI keeps 3.13 compatibility | Select 3.14.7 |
| LangGraph | 1.2.11 | Stable 1.x, MIT | Embedded; saver optional | Checkpoints are not audit/auth/exactly-once; state can accumulate | `OrchestratorPort` | Select |
| LangGraph checkpoint | 4.2.0 transitively | Stable, MIT | Saver backend | Memory saver is process-local; default permissive deserialization must be overridden | JSON state + strict serializer + saver adapter | Select |
| PostgreSQL saver | 3.1.2 | Stable, MIT | PostgreSQL + Psycopg 3.3.4 | Saver schema is not authority; RLS overlay remains ours | `OrchestratorPort` + SQL export | Tenant-bound durable mode |
| Temporal Python | 1.31.0 | Mature, MIT | Temporal Server and datastore | Workflow determinism; activities remain at-least-once and need idempotency | Durable-workflow port in later layer | Defer |
| FastAPI | 0.141.1 | Mature, MIT | ASGI server | Does not supply identity, RBAC, or tenancy | Delivery adapter only | Select |
| Pydantic | 2.13.4 | Stable, MIT | None | Validation is not authorization | Domain models are framework-neutral | Select |
| PyJWT | 2.13.0 | Production/stable, MIT | cryptography 50.0.0 | JWKS bounds, issuer registry, grants, and policy remain ours | `AuthenticatorPort` | Select |
| Authlib / joserfc | 1.7.2 / 1.7.4 candidates | Production/stable, BSD | cryptography | Authlib JOSE is moving to joserfc; broader OAuth surface than required | Standard OIDC/JWK documents | Defer |
| Casbin / OPA | 1.43.0 / 1.19.0 candidates | Apache-2.0 | OPA adds a service | Neither authenticates or owns grants; Casbin lacks declared Python 3.13/3.14 support | `PolicyPort` | Defer |
| Langfuse Python | 4.14.4 | Stable SDK; MIT core, commercial `ee/` areas | Hosted service or self-hosted stack | Backend operations and feature license boundaries | `ObservabilityPort` + OTel | Primary optional backend |
| LangSmith client | 0.11.0 transitively | MIT client; commercial platform | SaaS, or enterprise-licensed self-host stack | Strong LangGraph coupling and backend lock-in | Do not call it in Layer 2 | Redundant; not selected |
| OpenTelemetry | 1.44.0 | Stable API/SDK, Apache-2.0 | Exporter/backend optional | Redaction/cardinality are not automatic | Standard API and OTLP | Select |
| OTel instrumentation | 0.65b0 transitively | Beta, Apache-2.0 | Instrumented integrations | Beta semconv can rename | Manual stable application spans | Limit use |
| PostgreSQL/pgvector | PG 17.11 line + pgvector 0.8.6 image | Mature/permissive PostgreSQL licenses | Database operations | HA, backup/restore, retention and regional policy remain unproven | Repository ports + SQL export | Select with forced RLS; vectors defer |
| Keycloak | 26.7.1 local candidate | Mature, Apache-2.0 | JVM service + database | Realm operations, HA, rotation, and production evidence remain external | OIDC standards + `AuthenticatorPort` | Optional local profile |
| Redis | redis-py 8.1.0 candidate; Redis 8 server | Client MIT; server triple license | New stateful service | No cache/queue need; licensing/ownership cost | Add only with measured requirement; consider Valkey | Reject Layer 2 |
| OpenAI adapter | langchain-openai 1.5.1 candidate | Stable, MIT adapter | Provider credentials/network | Provider schema, cost, data policy | `StructuredModelPort` | Defer |
| Anthropic adapter | langchain-anthropic 1.5.6 candidate | Stable, MIT adapter | Provider credentials/network | Same, with provider-specific semantics | `StructuredModelPort` | Defer |
| React/TypeScript | Current stable when UI begins | Mature | Node/browser toolchain | No Layer 2 UI requirement | API contract | Defer |
| MCP/A2A SDKs | Re-evaluate official stable releases | Evolving | Protocol servers/identity | Adds tool delegation attack surface | Tool/effect ports | Defer |

Ruff 0.16.3 and uv 0.12.5 are production-proven but pre-1.0, so both are exact
pinned. Mypy 2.3.0, pytest 9.1.1, coverage 7.15.4, and pre-commit 4.6.2 are pinned
after compatibility validation. Strict mypy is the single Python type gate; pyright
is not added because a second checker would duplicate the Layer 2 surface without a
measured correctness benefit. Revisit that choice when editor/BFF integration adds a
distinct need. The complete transitive graph is in `uv.lock`.

## Why PyJWT but no policy engine

PyJWT removes custom JOSE parsing, signature verification, JWK conversion, and
registered issuer/audience validation. Layer 2 still owns a bounded cache because
maximum key count, refresh cooldown, configured endpoint policy, and fail-closed
staleness are application security decisions. The token's unverified issuer is used
only to choose an exact configured verifier. Tenant and grants are resolved from
application storage.

The current policy is intentionally small: immutable role definitions plus current
tenant policy, purpose, risk ceiling, grant expiry, revocation, and version checks.
Casbin would not supply identity or grant management, and OPA would add another
policy service and lifecycle. Both remain valid future adapters behind `PolicyPort`
when policy volume or independent authoring justifies them. See
[ADR 005](adr/005-pyjwt-and-explicit-authorization.md).

## Why LangGraph

LangGraph directly removes custom graph scheduling, parallel super-step joins,
checkpoint plumbing, and state-history APIs. Its explicit state and fixed graph fit a
bounded investigation better than an open-ended agent loop. The coordinator fans out
to telemetry and change nodes, reducers make merge order deterministic, and a critic
joins before completion.

It does not remove application code for identity, policy, budget, evidence tenancy,
idempotency, citation integrity, approval, effects, fencing, audit, redaction, or
reconciliation. [ADR 001](adr/001-langgraph-orchestration.md) records the choice.

## LangGraph versus Temporal

They solve different durability scopes:

- **LangGraph** checkpoints state around nodes in one investigation graph. It is
  ideal for pausing/resuming model and specialist reasoning.
- **Temporal** replays deterministic workflow code from event history across worker
  loss and long waits. Non-deterministic or side-effecting work belongs in Activities,
  whose duplicate/retry behavior still needs idempotency.

Putting both in charge of the same node retry tree creates overlapping ownership.
Layer 2 has no production effect or multi-day approval workflow, so Temporal's
separate server cluster is unjustified. Add it when approval/effect/reconciliation
must survive deployment and process boundaries; keep LangGraph inside a single
investigation Activity. See [ADR 002](adr/002-defer-temporal.md).

## Langfuse versus LangSmith

Both would duplicate tracing/evaluation ownership if enabled together.

LangSmith offers the tightest LangGraph run-tree and hosted evaluation experience,
but the platform is commercial; self-hosting is an Enterprise add-on and requires a
larger storage stack. Its MIT client being in the lockfile does not make the platform
open source.

Langfuse v4 is OpenTelemetry-native, has an MIT core, can be self-hosted, and accepts
manual observations. It is the primary external backend. The adapter sends only
fixed names, tenant buckets, counts, and status; automatic LangGraph capture is
blocked because graph state includes evidence. Evals publish aggregate counts only.
OpenTelemetry remains canonical, so removing Langfuse does not change application
code. See [ADR 003](adr/003-langfuse-and-opentelemetry.md).

## Primary sources

All links were accessed 2026-08-15:

- [Python downloads](https://www.python.org/downloads/)
- [LangGraph PyPI metadata](https://pypi.org/pypi/langgraph/json)
- [LangGraph persistence](https://docs.langchain.com/oss/python/langgraph/persistence)
- [LangGraph graph API and super-steps](https://docs.langchain.com/oss/python/langgraph/graph-api)
- [Temporal workflows](https://docs.temporal.io/workflows)
- [Temporal Server](https://docs.temporal.io/temporal-service/temporal-server)
- [FastAPI releases](https://pypi.org/project/fastapi/)
- [Pydantic releases](https://pypi.org/project/pydantic/)
- [PyJWT 2.13.0 metadata](https://pypi.org/pypi/PyJWT/2.13.0/json)
- [PyJWT API and algorithm warning](https://pyjwt.readthedocs.io/en/stable/api.html)
- [cryptography 50.0.0 metadata](https://pypi.org/pypi/cryptography/50.0.0/json)
- [Authlib 1.7.2 metadata](https://pypi.org/pypi/Authlib/1.7.2/json)
- [joserfc 1.7.4 metadata](https://pypi.org/pypi/joserfc/1.7.4/json)
- [Casbin 1.43.0 metadata](https://pypi.org/pypi/casbin/1.43.0/json)
- [OPA 1.19.0 release](https://github.com/open-policy-agent/opa/releases/tag/v1.19.0)
- [Keycloak 26.7.1 release](https://github.com/keycloak/keycloak/releases/tag/26.7.1)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [JWT BCP, RFC 8725](https://www.rfc-editor.org/rfc/rfc8725)
- [Langfuse Python](https://pypi.org/project/langfuse/)
- [Langfuse repository license](https://github.com/langfuse/langfuse/blob/main/LICENSE)
- [Langfuse masking](https://langfuse.com/docs/observability/features/masking)
- [LangSmith self-hosting](https://docs.langchain.com/langsmith/self-hosted)
- [OpenTelemetry GenAI spans](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-spans/)
- [PostgreSQL releases](https://www.postgresql.org/support/versioning/)
- [pgvector](https://github.com/pgvector/pgvector)
- [Redis licensing](https://redis.io/legal/licenses/)
- [Docker build best practices](https://docs.docker.com/build/building/best-practices/)
- [GitHub Actions secure use](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
- [CodeQL](https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning-with-codeql)
- [Dependabot version updates](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/about-dependabot-version-updates)

Package metadata is the source of exact release versions. License boundaries for
deployed services still require organizational legal review.
