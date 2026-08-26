# Database migration runbook

1. Confirm migration files/checksums and representative event/Temporal replay.
2. Take a verified backup and measure headroom, locks, table size, replication lag, and
   expected rewrite. Large rewrites require a separate bounded backfill release.
3. Stop promotion if RLS, immutable triggers, schema compatibility, saver migration,
   statement/lock timeout, or rollback compatibility is unknown.
4. Run the one PreSync migration Job. Advisory lock/checksum failure is terminal.
5. Deploy old/new compatible workers and APIs. Backfill by deterministic key/cursor
   batches with checkpoints and pause thresholds.
6. Verify RLS, sequences, ledger replay, projections, pgvector indexes, saver schema,
   queue health, and old-version reads.
7. Contract only in a later release after retained rollback/history windows close.

