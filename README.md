# Aegis Framework Platform

[![CI](https://github.com/mrinmoyece/aegis-framework-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/mrinmoyece/aegis-framework-platform/actions/workflows/ci.yml)
[![CodeQL](https://github.com/mrinmoyece/aegis-framework-platform/actions/workflows/codeql.yml/badge.svg)](https://github.com/mrinmoyece/aegis-framework-platform/actions/workflows/codeql.yml)

A framework-first educational implementation of enterprise checkout incident
response. It uses proven frameworks for orchestration, delivery, persistence,
cryptography and observability while keeping identity, tenancy, authorization,
quota, secrets and audit authority in explicit application ports.

**Layer 2 authenticates and governs investigations; it still cannot execute a
production effect.**

## Delivered Layer 2 controls

- OIDC/JWT access-token verification with exact issuer/audience, hard-coded
  asymmetric algorithms, required `kid`, signature, `exp`/`iat`/`nbf`, skew and
  maximum lifetime validation;
- bounded fail-closed JWKS caching and deterministic key rotation;
- authoritative `(issuer, subject)` human/workload principals, tenant mapping and
  grant-version freshness from application storage;
- immutable role/permission/purpose/risk bindings, deny-by-default policy, revoked
  and expired grant handling;
- authenticated `/v1/me`, tenant, policy, quota, audit and investigation routes with
  cross-tenant anti-enumeration;
- forced PostgreSQL RLS, non-superuser/non-`BYPASSRLS` runtime role, transaction-local
  tenant context and connection-pool reset checks;
- atomic retry-safe quota reservations, optimistic policy/quota updates and
  tenant-bound secret references;
- redacted per-tenant hash-chained audit with runtime mutation denial and a database
  trigger;
- forced RLS over LangGraph saver tables through application checkpoint ownership;
- production readiness that fails closed; deterministic static identity only in
  explicit demo/test mode.

LangGraph still owns only one bounded fan-out/fan-in investigation:

> alert -> allowlisted evidence -> telemetry/change specialists -> cited hypothesis
> -> critic -> approval-required rollback proposal

It cannot approve, execute or verify a change. A checkpoint, prompt, trace, tool
result or model output is never authorization, a tenant grant, quota receipt,
approval, audit event, fencing token or effect receipt.

## Quick start

Prerequisites: [uv 0.12.5](https://docs.astral.sh/uv/), Python 3.14.7 and Docker for
container/integration targets.

```bash
make bootstrap
make ci
make eval
```

Run the explicit deterministic API:

```bash
AEGIS_MODE=demo make serve

curl --fail-with-body \
  -H 'Authorization: Bearer demo-responder-token' \
  -H 'X-Request-ID: readme-me' \
  http://127.0.0.1:8000/v1/me

curl --fail-with-body \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer demo-responder-token' \
  -H 'X-Request-ID: readme-investigation' \
  --data @examples/investigation-request.json \
  http://127.0.0.1:8000/v1/investigations
```

Without `AEGIS_MODE=demo`, the app starts in production mode. `/healthz` remains a
liveness probe, while `/readyz` and authenticated routes fail closed until all of:

```text
AEGIS_POSTGRES_DSN
AEGIS_OIDC_ISSUER
AEGIS_OIDC_AUDIENCE
AEGIS_OIDC_JWKS_URI
```

are configured. Production identity/governance routes then use PostgreSQL and OIDC.
The production investigation route remains unavailable until later live evidence and
model adapters exist; it never falls back to deterministic fixtures.

## Selected stack

| Concern | Selection | Authority boundary |
|---|---|---|
| Identity cryptography | PyJWT 2.13.0 + cryptography 50.0.0 | Application issuer/JWKS/grant policy |
| API/contracts | FastAPI 0.141.1 + Pydantic 2.13.4 | Delivery only |
| Investigation graph | LangGraph 1.2.11 | Scheduling/checkpoints only |
| Durable state | PostgreSQL 17 line + Psycopg 3.3.4 | Application schema/RLS/audit |
| Graph saver | langgraph-checkpoint-postgres 3.1.2 | RLS overlay + owner registry |
| Telemetry | OpenTelemetry 1.44.0 | Manual redaction/allowlists |
| Optional trace/eval | Langfuse 4.14.4 | Counts/status only; no automatic graph capture |
| Local IdP compatibility | Keycloak 26.7.1 digest | Optional profile; no committed users/secrets |
| Policy engine | Explicit immutable RBAC | Casbin/OPA deferred behind `PolicyPort` |
| Durable effect workflow | Temporal deferred | No production effects in Layer 2 |

Exact versions, alternatives, licenses and exit strategies are in
[framework selection](docs/framework-selection.md),
[ADR 005](docs/adr/005-pyjwt-and-explicit-authorization.md), and
[ADR 006](docs/adr/006-postgresql-rls-and-application-audit.md).

## Local PostgreSQL qualification

No live credential is committed. Generate disposable values:

```bash
export AEGIS_POSTGRES_ADMIN_PASSWORD="$(openssl rand -hex 24)"
export AEGIS_POSTGRES_RUNTIME_PASSWORD="$(openssl rand -hex 24)"
docker compose --profile durable up -d postgres

export AEGIS_TEST_POSTGRES_ADMIN_DSN="postgresql://aegis_admin:${AEGIS_POSTGRES_ADMIN_PASSWORD}@127.0.0.1:55432/aegis"
export AEGIS_TEST_POSTGRES_RUNTIME_DSN="postgresql://aegis_app:${AEGIS_POSTGRES_RUNTIME_PASSWORD}@127.0.0.1:55432/aegis"
make integration
```

The three PostgreSQL tests verify forced RLS, pool reset, audit immutability, quota
races and framework checkpoint tenant isolation. One additional Keycloak-compatible
test is environment-gated and rejects non-loopback issuer/JWKS hosts. See the
[tutorial](docs/tutorial.md).

## Qualification status

- 100 deterministic unit/API tests pass with 92% meaningful branch coverage;
- eight deterministic evals cover investigation and identity/tenant authority
  attacks;
- three local PostgreSQL integration tests pass;
- one local Keycloak compatibility test remains environment-gated;
- tests/evals make no external network or real model calls.

Live IdP rotation and production deployment evidence remain explicitly unproven.
So do TLS/ingress, HA/backup/restore, retention/erasure execution, WORM witnessing,
KMS/Vault resolution, external model/evidence adapters, approvals, effects, fencing
and reconciliation.

## Framework comparison

The machine-readable [Layer 2 metrics](comparison/layer2-metrics.json) compare this
branch with custom Aegis Layer 2 at
`81409792c97698479a9ca827a4143c6391f28d2b`. They report production/test LOC,
dependencies, Git-change effort proxy, framework mechanics removed, remaining custom
controls, lock-in and escape hatches. The
[parity manifest](comparison/parity-manifest.json) uses the same 16-capability
progression.

## Repository commands

| Command | Purpose |
|---|---|
| `make lint` | Ruff formatting and lint |
| `make type` | Strict mypy |
| `make test` | Deterministic tests and branch coverage |
| `make integration` | Configured local PostgreSQL/Keycloak tests |
| `make eval` | Eight deterministic safety/authority evals |
| `make docs` | Documentation, manifest and pin validation |
| `make security` | Bandit and dependency vulnerability audit |
| `make container` | Digest-pinned non-root image |
| `make measure` | Refresh Layer 2 comparison metrics |
| `docker compose config --quiet` | Validate local topology |

Start with [architecture](docs/architecture.md), the
[authority matrix](docs/authority-boundaries.md), [threat model](docs/threat-model.md),
[limitations](docs/limitations.md), [curriculum](docs/curriculum.md), and
[interview questions](docs/interview-questions.md).

Licensed under the [MIT License](LICENSE). Security reporting and the explicit
non-production status are in [SECURITY.md](SECURITY.md).
