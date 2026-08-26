# Backup, restore, and disaster recovery

RPO and RTO are **objectives**, not measured claims:

- application ledger/object metadata objective RPO: 5 minutes;
- regional service objective RTO: 60 minutes;
- no Temporal-history RPO is used as application-data truth.

## Backup scope

RDS automated backups/PITR plus AWS Backup cover the PostgreSQL application ledger,
RLS policy/configuration, projections, trust registries, migration/checkpoint metadata,
and pgvector tables. Versioned encrypted S3 covers evidence/blob/archive manifests.
The separate backup KMS key and vault lock permit cross-account/cross-region policy,
but the reference does not execute that copy. Temporal Cloud recovery follows the
contracted namespace service; retained replay histories and application outbox remain
our recovery inputs. Redis and derived caches are deliberately excluded.

## Isolated restore drill

1. Freeze the backup identifier and record its manifest/checksum without logging data.
2. Restore into a new isolated account/VPC/database with no application writer.
3. Apply no new migration. Verify exact migration filenames/checksums in the backup.
4. Verify event count, contiguous tenant cursor, aggregate sequence, aggregate previous
   hash, tenant previous hash, and record hash. Any mismatch is data loss/security
   incident.
5. Verify blob/archive manifest hashes, object versions, KMS accessibility, trust
   registry revisions, RLS enabled/forced, runtime non-bypass role, and sequences.
6. Drop/rebuild projections, vector indexes, and LangGraph checkpoints from application
   ledger plus retained objects. Do not rebuild approval/effect truth from checkpoints.
7. Connect to the target Temporal namespace only after fencing. Reissue pending outbox
   intent under stable workflow IDs, reconcile present/missing workflows, schedules,
   signals, and Activity ambiguity. Never translate missing history to completion.
8. Reconcile model/connector/protocol billing/task ambiguity, effect receipts,
   verification/compensation, and sandbox Jobs/cleanup by observation.
9. Confirm Redis/cache loss has no correctness effect. Run authorized smoke/replay and
   safety gates before routing.
10. Record elapsed recovery, last recoverable application cursor/time, gaps, approvals,
    hashes, and reconciliations. Only measured drills may update RPO/RTO evidence.

`make restore-drill` exercises deterministic chain/generation/rebuild contracts.
`make restore-drill-db` creates an isolated digest-pinned PostgreSQL container, applies
all migrations and saver hardening, writes valid dual-chain events, takes/restores a
logical backup into a second database, recomputes hashes/sequences, verifies migration
checksums/RLS, rebuilds run/timeline and vector index, discards checkpoints, and
preserves pending outbox reconciliation. Neither is an RDS PITR, Temporal managed
failover, cross-account restore, or production DR drill.
