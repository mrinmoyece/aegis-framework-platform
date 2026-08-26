# Database and framework lifecycle

## Migration rules

`MigrationRunner` reads exact ordered files, hashes content, checks
`aegis.schema_migrations`, and applies each migration under its SQL advisory lock.
Layer 14 is additive: deployment generation/fence evidence, restore drill evidence,
and retention execution evidence. Runtime roles receive no access to those
administrative tables. A separate non-login, non-bypass `aegis_operations` role owns
only select/insert access to immutable generation/restore/retention evidence and
select/insert/update access to the current region-state projection. Deployment/DR
tooling receives membership separately; the application runtime never does.

Release order is expand -> compatible code -> bounded backfill -> verification ->
contract in a later release. A migration must not rename/drop a column, rewrite a
large table, remove an RLS policy, or change event meaning in the same release that
introduces its replacement. RLS is enabled/forced before runtime access. Backfills
must use cursor/key ranges, statement/lock timeouts, observable checkpoints, and
pause on replication lag or SLO burn.

Migration failure leaves the old application digest and additive schema. Never restore
availability by editing `schema_migrations`, immutable events/facts, or checksums.

## Compatibility

- Event schemas are additive and explicitly upcast. The application ledger must remain
  replayable by the current and rollback application versions.
- Temporal workflows retain patch markers and representative histories. New Worker
  Deployment/build IDs use pinned behavior; old workers remain until all histories
  replay or close. Activity/provider retries remain singly owned.
- LangGraph `graph_version`, input digest, tenant/thread/run binding, and strict
  serializer are checked before checkpoint reuse. `PostgresSaver.setup()` runs after
  application migrations in the migration Job; its migration table is separately
  retained. Node/state incompatibility requires a compatible worker or ledger-grounded
  rerun, never checkpoint mutation.
- Checkpoint and application-ledger pools remain separate to avoid branch/checkpoint
  deadlock. Pool totals must fit the guarded RDS connection budget.

## Retention and archive

| Data | Policy boundary |
|---|---|
| Application ledger, approvals, receipts, audit | Policy-bound archive; never deleted because a framework retention expired |
| Projections and vector indexes | Derived; rebuild then bounded deletion |
| LangGraph checkpoints | 1-30 days after terminal compatibility/rebuild gate |
| Temporal visibility | 7-90 days; not application audit |
| Temporal history | Managed namespace policy; open workflows and replay fixtures retained as required |
| Evidence/blob objects | Classification, purpose, tenant, legal hold, KMS key, archive manifest, erasure workflow |
| Telemetry | 1-90 days, allowlisted and non-authoritative |
| Backups | 35-365 days with vault/object lock and legal policy |
| Redis/derived cache | Disposable; no recovery dependency |

`retention_executions` records policy revision, class, cutoff, legal-hold check, counts,
and manifest digest. It is evidence of the application decision, not proof that a cloud
object was physically erased. Production archival executors, partition maintenance,
KMS crypto-erasure, legal review, and WORM witnessing remain unproven.
