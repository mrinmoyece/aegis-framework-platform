# Layer 12 operator workspace runbook

## Local deterministic checkout

```bash
npm --prefix ui ci --ignore-scripts
npm --prefix ui run build
AEGIS_MODE=demo make serve
```

Open `http://127.0.0.1:8000`. The demo covers health/SLOs, an incident and cited
timeline, evidence, specialist/critic artifacts, model usage, exact-scope approval,
ambiguous effects, sandbox quarantine, memory provenance/retention, eval regression,
audit, and replay. It uses no credentials, network model, connector, or production
effect.

## Operator rules

1. Treat freshness warnings, offline state, schema rejection, conflicts, and ambiguity
   as unknown—not success.
2. Verify exact plan and approval digests, target, risk, quorum, separation of duties,
   server time, expiry, and rollback before a mutation.
3. Never interpret browser cache, a disabled button, a graph artifact, or a trace as
   authorization. The server rechecks current authority.
4. On tenant switch, wait for the empty-cache refetch. Never compare data retained in
   another tab as current.
5. Use replay/support only for diagnosis. Replay cannot execute an operation.

## Failure response

- `401`: session expired; return to sign-in. Do not retry a mutation with cached state.
- `403`: server authority denied the operation. The UI cannot override it.
- `404`: resource unavailable, including tenant-safe anti-enumeration.
- `409`: refresh; compare version/digests; re-review before a new idempotency key.
- `422`: correct the bounded request; do not weaken client validation.
- `5xx`, offline, stale, exhausted polling: stop mutations and use server runbooks.

UI outage or browser closure does not pause or complete Temporal work, mutate the
ledger, satisfy approval, or reconcile an effect.

## Release commands

```bash
make frontend-install frontend-ci
npm --prefix ui exec playwright install chromium
make frontend-e2e
make ci
make security
make container
docker compose config --quiet
```

Production must remain not-ready until live OIDC exchange, durable sessions, TLS proxy,
browser qualification, audit routing, and operations evidence are configured.
