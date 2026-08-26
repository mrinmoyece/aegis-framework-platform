# Restore and regional failover runbook

Follow [backup/restore/DR](../backup-restore-dr.md) and
[capacity/multi-region](../capacity-and-multi-region.md). Fence source writer and
effects before target promotion. Restore in isolation; verify migration checksums,
dual hash chains, sequences, RLS, objects, and trust revisions; rebuild only derived
state; advance generation once; reconcile Temporal/outbox/effects; then route.

Missing history, unknown effect state, hash mismatch, stale generation, residency/key
failure, or source-fence uncertainty blocks routing. Failback is a new approved
generation. Do not use DNS alone as fencing.

