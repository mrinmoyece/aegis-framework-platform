# Layer 10 local operations runbook

Evidence connector enablement, source-specific operations, cursor recovery and
reconciliation are in the [connector runbook](connector-runbook.md). Connector code is
disabled by default; this general runbook does not authorize enabling it. Sandbox
activation and orphan cleanup are in the [sandbox runbook](sandbox-runbook.md). Memory
ingestion, retrieval, compaction, legal hold, and erasure incidents are in the
[memory runbook](memory-runbook.md). Evaluation baseline, dataset, waiver, replay and
tamper procedures are in the [evaluation runbook](evaluation-runbook.md).
Telemetry outage, SLO response, dashboard use and ledger replay are in the
[observability runbook](observability-runbook.md) and [SLO catalog](slo-catalog.md).

## Start application PostgreSQL

```bash
export AEGIS_POSTGRES_ADMIN_PASSWORD="$(openssl rand -hex 24)"
export AEGIS_POSTGRES_RUNTIME_PASSWORD="$(openssl rand -hex 24)"
docker compose --profile durable up -d postgres
```

`tools/postgres-init.sh` applies Layer 2 through Layer 9 migrations, then creates the
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
make eval-safety
make eval-adversarial
make eval-recovery
make eval-baseline
make eval-meta
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

For specialist artifacts, verify application event/fact integrity, replay immutable
`orchestration_facts` and `orchestration_artifacts` in deterministic ordinal/ID order,
validate each canonical digest/provenance transition, rebuild the run/task/artifact
projection, record `projection.rebuilt`, and compare the final decision. Never rebuild
artifact truth from a LangGraph checkpoint or trace.

For remediation, verify `remediation_facts` sequence/previous-digest integrity, fold
with `reduce_remediation`, compare exact plan/approval/effect/verification digests,
record an immutable rebuild row, then swap the projection. Never rebuild approval or
effect truth from Temporal history, a LangGraph checkpoint, Kubernetes events or traces.

For sandboxes, verify `sandbox_facts` sequence/previous-digest integrity and canonical
request/spec/policy/approval bindings, fold with `reduce_sandbox`, compare artifact
manifest/attestation/cleanup facts, record the immutable rebuild, then swap the projection.
Never rebuild sandbox truth from Temporal history, Kubernetes Job status, Pod logs, CSI
metadata, or traces.

For memory, verify `memory_facts` sequence/previous-digest integrity, fold with
`reduce_memory` in ordinal order, compare the resulting status/indexed/tombstoned/
hold_count/derived_purged/blob_erased/chunk_count fields, drop and rebuild the derived
`InMemoryHybridIndex`/cache and PostgreSQL `memory_chunks` entries from the rebuilt
projection, then swap. Never rebuild memory truth, retention, or citation authority from
the derived index, cache, or a LangGraph checkpoint.

## Specialist graph recovery

1. Confirm current application run state and cancellation before reading a checkpoint.
2. Verify tenant/run/thread ownership, graph version `6.0.0`, and input digest.
3. A completed task result may be reused; dispatch intent without result is
   reconciliation-required and must not silently repeat a possibly billed model call.
4. If the checkpoint is lost, rerun only under the same run/budget/model/task identities
   and accept output through the application fence.
5. If checkpoint compatibility fails, retain application facts, deploy a compatible
   graph or start an explicit new run. Do not edit checkpoint or artifact rows.
6. A critic rejection, abstention, or escalation is a valid fail-closed terminal—not an
   operator reason to bypass citations or create an effect.
7. Keep the LangGraph saver and orchestration-ledger connection pools separate. Sharing
   one bounded pool can deadlock when an outer checkpoint transaction holds a connection
   while parallel specialist branches persist application facts.

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

## Memory incident

See the [memory runbook](memory-runbook.md) for activation gate, normal lifecycle,
legal-hold/erasure, embedding-provider incident, ambiguous-ingestion, retrieval/context,
and rebuild procedures. In summary: never authorize a memory candidate outside
`accepted`/`redacted` evidence dispositions, never bypass an open legal hold to erase,
never treat the derived index/cache as authoritative. Retrieval and context-build
append digest-only `MemoryOperationFact`s; those facts do not contain raw query or
content and do not make the derived index authoritative.

## Evaluation release incident

Follow the [evaluation runbook](evaluation-runbook.md). Stop promotion on suite,
dataset/source, baseline, case-set or scorer mismatch; nondeterministic replay; shard
gaps/overlap; report overflow/redaction failure; expired waiver; hard-safety waiver;
or evaluator error. Preserve bounded digests/reason codes. Never regenerate a
baseline to make a failure disappear and never treat an evaluator or Langfuse trace
as production truth.

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

Cancellation after an external effect cannot undo it. Reconcile and verify the exact
target, then use only the approved compensation contract or escalate.

## Approval and effect incidents

Use the [approval/effect runbook](approval-effect-runbook.md) for SoD/quorum decisions,
expiry/revocation, stale fences, ambiguous effects, reconciliation, independent
verification and rollback. Destructive defaults remain disabled; operators may not turn
a graph proposal, Temporal state or API acceptance into authorization.

## Shutdown

```bash
docker compose --profile temporal down --volumes
```

Deleting volumes destroys local application and framework history. Never use this
procedure for production recovery.
