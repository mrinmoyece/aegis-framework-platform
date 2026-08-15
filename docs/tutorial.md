# Tutorial: authenticate and trace one tenant investigation

## 1. Run explicit demo mode

The default application mode is production and fails readiness closed without OIDC
and PostgreSQL configuration. Use explicit demo mode for the deterministic fixture:

```bash
AEGIS_MODE=demo make serve
```

In another shell:

```bash
curl --fail-with-body \
  -H 'Authorization: Bearer demo-responder-token' \
  -H 'X-Request-ID: tutorial-001' \
  http://127.0.0.1:8000/v1/me
```

The response contains tenant, issuer, subject, human/workload kind, roles,
permissions, purposes, grant version and expiry. It does not echo a bearer token.
`demo-responder-token` exists only in demo/test wiring; production never falls back to
it.

## 2. Understand the production token boundary

`JwtAuthenticator` first parses an unverified header/issuer only to select an exact
configured issuer. It then requires an allowed asymmetric algorithm and `kid`,
retrieves a key through the bounded cache, verifies the signature/issuer/audience,
and validates `exp`, `iat`, optional `nbf`, clock skew and maximum lifetime.

The verified token carries `aegis_tenant` and `aegis_grant_version`. The tenant value
only scopes an RLS query. Application storage must return the same tenant for the
exact `(issuer, subject)`, an active principal, and the same grant version. Current
roles and purposes come from application grants; token role claims are ignored.

Human and service/workload tokens follow this path. The principal record—not a token
guess—sets `principal_kind`.

## 3. Read governance without enumerating tenants

```bash
curl --fail-with-body \
  -H 'Authorization: Bearer demo-responder-token' \
  -H 'X-Request-ID: tutorial-tenant' \
  http://127.0.0.1:8000/v1/tenants/tenant-acme

curl --fail-with-body \
  -H 'Authorization: Bearer demo-responder-token' \
  -H 'X-Request-ID: tutorial-policy' \
  http://127.0.0.1:8000/v1/policies/current

curl --fail-with-body \
  -H 'Authorization: Bearer demo-responder-token' \
  -H 'X-Request-ID: tutorial-quota' \
  http://127.0.0.1:8000/v1/quotas/investigations
```

Requesting `tenant-beta` with the alpha token returns the same `404` used for an
unknown tenant. Policy runs before repository lookup. Audit additionally requires the
`tenant-auditor` or `tenant-admin` role.

## 4. Run the investigation

```bash
curl --fail-with-body \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer demo-responder-token' \
  -H 'X-Request-ID: tutorial-investigation' \
  --data @examples/investigation-request.json \
  http://127.0.0.1:8000/v1/investigations
```

`InvestigationService` evaluates `investigation:run` for purpose
`incident-response` at medium risk, claims the tenant/request idempotency key, and
reserves five quota units before evidence or graph work. A retry reuses the same
reservation. Exhaustion returns a deterministic abstention with zero graph
checkpoints.

The coordinator projects untrusted evidence through per-kind fact allowlists.
Telemetry and change specialists execute in one LangGraph super-step. The reducer
sorts findings, and the critic requires known evidence ID, locator and SHA-256 content
hash. Injection, malformed output, missing evidence, contradiction or invalid
citations cannot produce a proposal.

The graph may emit a rollback proposal. `InvestigationService` opens a separate
pending approval after graph execution. There is no decision/effect route, and
`DisabledEffectAdapter` rejects a forged approval.

## 5. Inspect durable isolation locally

No database or Keycloak password is committed. Generate local values and start the
PostgreSQL profile:

```bash
export AEGIS_POSTGRES_ADMIN_PASSWORD="$(openssl rand -hex 24)"
export AEGIS_POSTGRES_RUNTIME_PASSWORD="$(openssl rand -hex 24)"
docker compose --profile durable up -d postgres
```

The init script applies `migrations/0001_layer2.sql`, creates an `aegis_app` login,
and grants the non-login `aegis_runtime` role. Application connections execute
`SET ROLE aegis_runtime`; setup/migrations use the admin connection separately.

Run the gated tests:

```bash
export AEGIS_TEST_POSTGRES_ADMIN_DSN="postgresql://aegis_admin:${AEGIS_POSTGRES_ADMIN_PASSWORD}@127.0.0.1:55432/aegis"
export AEGIS_TEST_POSTGRES_RUNTIME_DSN="postgresql://aegis_app:${AEGIS_POSTGRES_RUNTIME_PASSWORD}@127.0.0.1:55432/aegis"
make integration
```

They prove forced RLS, pool reset safety, audit mutation rejection, concurrent quota
reservation, and LangGraph checkpoint isolation. They do not prove production HA,
backup/restore, or deployment.

## 6. Optional local Keycloak compatibility

Start an empty, loopback-only Keycloak 26.7.1 profile with generated bootstrap
credentials:

```bash
export AEGIS_KEYCLOAK_ADMIN_PASSWORD="$(openssl rand -hex 24)"
docker compose --profile identity up -d keycloak
```

Create a local realm/client manually, configure audience `aegis-api`, and add numeric
`aegis_grant_version` plus string `aegis_tenant` access-token claims. Do not put
client secrets or user passwords in the repository. The gated test requires:

```text
AEGIS_TEST_KEYCLOAK_TOKEN
AEGIS_TEST_KEYCLOAK_ISSUER
AEGIS_TEST_KEYCLOAK_JWKS_URI
AEGIS_TEST_KEYCLOAK_AUDIENCE
AEGIS_TEST_KEYCLOAK_SUBJECT
AEGIS_TEST_KEYCLOAK_TENANT
AEGIS_TEST_KEYCLOAK_GRANT_VERSION
```

The test refuses non-loopback issuer/JWKS hosts. It proves compatibility with one
local token, not production rotation.

## 7. Observe without leaking

OpenTelemetry and optional Langfuse use fixed observation names, a 64-bucket tenant
value, and allowlisted counts/status only. Automatic LangGraph/LangChain capture
remains blocked because graph state contains evidence. Audit is separate: it stores
tenant scope internally, a derived actor/request reference, allowlisted attributes,
and a per-tenant hash chain.

## 8. Run the qualification gates

```bash
make ci
make eval
make security
make container
docker compose config --quiet
```

The deterministic suite covers JWT attacks/rotation, stale and revoked grants,
purpose/risk policy, confused deputy and anti-enumeration behavior, malformed and
oversized input, graph authority resistance, checkpoint isolation, audit redaction,
and exporter redaction. PostgreSQL and Keycloak remain separately environment-gated.
