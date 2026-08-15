# Layer 5 local operations runbook

Evidence connector enablement, source-specific operations, cursor recovery and
reconciliation are in the [connector runbook](connector-runbook.md). Connector code is
disabled by default; this general runbook does not authorize enabling it.

## Start application PostgreSQL

```bash
export AEGIS_POSTGRES_ADMIN_PASSWORD="$(openssl rand -hex 24)"
export AEGIS_POSTGRES_RUNTIME_PASSWORD="$(openssl rand -hex 24)"
docker compose --profile durable up -d postgres
```

`tools/postgres-init.sh` applies Layer 2 through Layer 5 migrations, then creates the
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

For evidence status, first verify the application ledger hash chain, then rebuild
`evidence_queries` from `evidence-query` aggregate events and record
`evidence.projection_rebuilt`. Never reconstruct a page result from Temporal history,
connector logs, or a framework cursor.

## Evidence connector incident

1. Disable the affected tenant/source revision without deleting its current facts.
2. Read only the authorized redacted query and cursor-status APIs. Cursor values, URLs,
   payloads, locators, credentials, and tenant identifiers must not enter tickets/traces.
3. Preserve unresolved page intent as `reconciliation_required`. Do not let an Activity
   retry repeat an ambiguous external read.
4. Treat cross-tenant visibility, cursor decryption, provenance/content digest,
   quarantine bypass, impossible transition, DNS/private-address, or RLS failures as
   security incidents.
5. Rotate a credential by creating a new secret/source version. In-flight old-version
   results are stale and cannot be accepted.

## Model call and billing reconciliation

1. Authorize the tenant model usage view. Never inspect another tenant through an admin
   connection for routine operations.
2. Find immutable `model_call_events` for the stable attempt ID. `requested` without
   `settled` is a crash window and must be treated as possibly billed.
3. Compare the provider's billing export using the separately controlled credential/account
   mapping. Do not put prompts, completions, credentials, tenant IDs, or provider request
   IDs into tickets or traces.
4. Append an explicit settlement through application tooling. Never mutate the requested
   fact or silently retry the provider call.
5. If a usage/health projection is corrupt, run the tenant-scoped projection rebuild from
   immutable call events and reservations, compare totals, then restore writers.

Unknown price, capability, region, classification, model, credential reference, or policy
revision is denial, not a reason to choose a default. Circuit and health views are derived
availability signals, never authorization or billing truth.

## Provider credential and catalog operations

Only secret references belong in policy/catalog. Values are resolved inside the provider
adapter and must never enter graph state, Temporal history, application events, API
responses, or telemetry. Rotate by publishing a new reference version, qualifying the
exact model/region/capability/price declaration, draining old calls, and retaining old
pricing versions for ledger replay. Live provider activation requires organizational
data-processing, retention, regional, security, legal, capacity, and billing sign-off.

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
