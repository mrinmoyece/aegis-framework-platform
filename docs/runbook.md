# Layer 3 local operations runbook

## Start application PostgreSQL

```bash
export AEGIS_POSTGRES_ADMIN_PASSWORD="$(openssl rand -hex 24)"
export AEGIS_POSTGRES_RUNTIME_PASSWORD="$(openssl rand -hex 24)"
docker compose --profile durable up -d postgres
```

`tools/postgres-init.sh` applies Layer 2 and Layer 3 migrations, then creates the
non-superuser application login. Never run application workers with the admin DSN.
Production API configuration also requires an injected `AEGIS_CURSOR_SIGNING_KEY` of at
least 32 bytes and a separate `AEGIS_REFERENCE_ENCRYPTION_KEY` of at least 32 bytes.
Rotate them with explicit pagination/workflow-drain plans.

## Start the optional Temporal server

```bash
docker compose --profile temporal up -d postgres temporal
docker compose exec -T temporal \
  tctl --address temporal:7233 cluster health
```

The server is loopback-exposed at `127.0.0.1:57233`. The local profile shares the
PostgreSQL process but uses separate `temporal` and `temporal_visibility` databases.
This is a compatibility environment, not a production topology.

## Run qualification

```bash
make ci
make security
make container
docker compose config --quiet

export AEGIS_TEST_POSTGRES_ADMIN_DSN="postgresql://aegis_admin:${AEGIS_POSTGRES_ADMIN_PASSWORD}@127.0.0.1:55432/aegis"
export AEGIS_TEST_POSTGRES_RUNTIME_DSN="postgresql://aegis_app:${AEGIS_POSTGRES_RUNTIME_PASSWORD}@127.0.0.1:55432/aegis"
make integration

AEGIS_TEST_TEMPORAL_ADDRESS=127.0.0.1:57233 make temporal-integration
```

For the SDK time-skipping server, preinstall the Temporal test-server binary and set
`AEGIS_TEST_TEMPORAL_TEST_SERVER`; tests never download a binary implicitly.

## Diagnose a stuck run

1. Read the authorized application run/timeline API. Do not infer product status from
   a Temporal query.
2. Inspect the tenant outbox row: `pending`, expired `claimed`, `delivered`, or
   `dead_letter`.
3. Compare the application workflow ID with Temporal operational visibility.
4. If no workflow exists and intent is pending, reclaim/reissue the same outbox message
   and workflow ID.
5. If Temporal completed but no application result event exists, treat it as a platform
   incident and reconcile the stable Activity operation; never fabricate completion.
6. Verify ledger hash chains before rebuilding projections.

## Recover a worker

Stop the failed worker and start a compatible worker on the same task queue. Temporal
replays workflow history and reschedules the pending Activity. Activity code reloads
current application authority and artifacts. A retry reuses the run budget reservation.
Do not copy workflow history into application tables.

## Projection rebuild

Pause projection writers for the tenant or use a shadow projection. Replay
`application_events` in tenant cursor order, validate both hash chains and contiguous
aggregate sequences, write a projection checkpoint, compare counts/statuses, then swap.
Never edit source events to repair a projection.

## Dead-letter handling

Confirm the message payload hash/type and application event integrity. Correct the
adapter/configuration, create an explicit operator audit event, and requeue under a new
operator command that references the dead-letter message. Do not reset attempts or
mutate immutable intent.

## Cancellation

Persist `cancel_requested` before signalling Temporal. If an Activity later returns,
the aggregate state machine rejects its stale result. External Temporal termination is
an emergency operational action and does not itself create an application cancellation
fact.

## Shutdown

```bash
docker compose --profile temporal down --volumes
```

Deleting volumes destroys local application and framework history. Never use this
procedure for production recovery.
