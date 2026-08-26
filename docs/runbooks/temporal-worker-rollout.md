# Temporal worker rollout runbook

1. Assign one deployment name/build ID per image and explicit queue. Never reuse a build
   ID for different code.
2. Replay retained histories with the new SDK/code before registration. Keep patch
   markers and default pinned behavior.
3. Start new workers, verify mTLS/API-key/codec/namespace, identity, pollers,
   schedule-to-start, Activity rate/concurrency, DB pool, and payload redaction.
4. Route new workflows gradually. Keep old workers for pinned histories.
5. Drain by removing readiness and stopping polls; allow 90 seconds before termination.
6. Roll back routing to the compatible build on nondeterminism, task failures, queue
   growth, saturation, or stale result rejection. Reconcile application facts.

