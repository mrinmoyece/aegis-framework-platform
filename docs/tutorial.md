# Tutorial: trace one durable investigation without trusting framework state

## 1. Run the deterministic delivery adapter

```bash
AEGIS_MODE=demo make serve
```

Production remains the default and fails readiness closed without configured OIDC and
PostgreSQL. Demo identities/fixtures are never selected implicitly.

Submit durable intent:

```bash
curl --fail-with-body \
  -H 'Content-Type: application/json' \
  -H 'Authorization: ******' \
  -H 'X-Request-ID: tutorial-durable-001' \
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

The response is a redacted application projection. `202` means the requested event and
Temporal outbox intent committed atomically. It does not mean workflow completion.

## 2. Inspect application truth

```bash
curl --fail-with-body \
  -H 'Authorization: ******' \
  -H 'X-Request-ID: tutorial-read-001' \
  http://127.0.0.1:8000/v1/durable-investigations/RUN_ID

curl --fail-with-body \
  -H 'Authorization: ******' \
  -H 'X-Request-ID: tutorial-timeline-001' \
  'http://127.0.0.1:8000/v1/durable-investigations/RUN_ID/timeline?limit=50'
```

The timeline excludes tenant ID and event payload. A next cursor is HMAC-protected and
bound to the caller tenant and run. A cross-tenant caller receives `404`.

Temporal operational queries can show schedule state, but the API never uses them as
product truth.

## 3. Understand the ledger transaction

For a new command, `InMemoryDurability` (test/demo) or `PostgresDurability` (durable
adapter) performs:

```text
lock aggregate head + tenant cursor
check expected version
append event with aggregate and tenant previous hashes
claim request fingerprint
insert Temporal start outbox
update run/timeline projection
advance heads
commit
```

A conflict or outbox failure rolls back the entire operation, including the tenant
cursor. Event/idempotency/inbox rows are immutable.

## 4. Start PostgreSQL and Temporal locally

```bash
export AEGIS_POSTGRES_ADMIN_PASSWORD="$(openssl rand -hex 24)"
export AEGIS_POSTGRES_RUNTIME_PASSWORD="$(openssl rand -hex 24)"
docker compose --profile temporal up -d postgres temporal
docker compose exec -T temporal \
  tctl --address temporal:7233 cluster health
```

Temporal is exposed only at `127.0.0.1:57233`. It stores framework history in separate
databases. Application events remain in `aegis.*`.

## 5. Follow workflow ownership

The sandboxed workflow schedules:

```text
authorize/reserve -> collect evidence -> LangGraph -> optional wait -> complete
```

It has no database/network/random/wall-clock calls. Every Activity resolves opaque
tenant/actor references to current application authority and reevaluates policy. The
initial Activity reserves budget by run ID. Retries reuse that reservation.

Evidence and graph output are persisted as application artifacts. Temporal returns
only stable references. LangGraph continues to own fan-out/join and checkpoints inside
one Activity; Temporal does not retry individual nodes.

## 6. Resume or cancel safely

```bash
curl --fail-with-body -X POST \
  -H 'Content-Type: application/json' \
  -H 'Authorization: ******' \
  -H 'X-Request-ID: tutorial-signal-001' \
  --data '{"command_id":"resume-tutorial-001"}' \
  http://127.0.0.1:8000/v1/durable-investigations/RUN_ID/signals/resume
```

Delivery stores an inbox command and outbox signal before Temporal sees it. Duplicate
command IDs are idempotent. The workflow does not trust the signal body; a later
Activity reloads the command and current signaller. If policy was revoked while
waiting, resume fails closed.

Cancellation follows the same path. A stale graph result after `cancel_requested` is
rejected by the application aggregate state machine.

## 7. Exercise recovery and replay

```bash
AEGIS_TEST_TEMPORAL_ADDRESS=127.0.0.1:57233 make temporal-integration
```

The test starts one workflow before any worker, then starts a worker and observes
recovery. It also verifies one transient Activity retry, duplicate signal suppression,
cancellation signal, timer timeout, normal completion, and `Replayer` determinism.

For SDK time skipping without a network download, preinstall the Temporal test-server
binary and set `AEGIS_TEST_TEMPORAL_TEST_SERVER`.

## 8. Prove PostgreSQL controls

```bash
export AEGIS_TEST_POSTGRES_ADMIN_DSN="postgresql://aegis_admin:${AEGIS_POSTGRES_ADMIN_PASSWORD}@127.0.0.1:55432/aegis"
export AEGIS_TEST_POSTGRES_RUNTIME_DSN="postgresql://aegis_app:${AEGIS_POSTGRES_RUNTIME_PASSWORD}@127.0.0.1:55432/aegis"
make integration
```

The tests cover forced RLS, pool reset, audit/event immutability, quota races,
checkpoint isolation, event/outbox atomicity, projection rebuild, outbox claim, and
cross-tenant ledger hiding.

## 9. Observe without payloads

OpenTelemetry application spans expose fixed operation names and allowlisted
counts/status. The optional Temporal tracing interceptor is configured through the SDK
and does not export application payload contents. Temporal input contains only opaque
references. Langfuse remains model/graph telemetry; automatic graph capture is blocked.

## 10. Run all release gates

```bash
make ci
make eval
make security
make container
docker compose config --quiet
```

Read [the runbook](runbook.md) for DLQ, worker, cancellation, reconciliation, and
projection recovery. None of these procedures authorizes a production effect.
