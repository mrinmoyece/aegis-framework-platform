# Sandbox operations runbook

## Activation gate

Keep the adapter disabled until operators have independently qualified the configured
RuntimeClass, admission policies, NetworkPolicy CNI, workload identity, content-addressed CSI drivers, node patching, registry policy, quotas, and
cleanup controller. Exact DNS egress remains disabled in Layer 8: an authenticated proxy
and policy-registration adapter are both required first. A green Kubernetes API health
check is insufficient.

Never enable an ordinary `runc` fallback. Never mount a host path, Docker/containerd
socket, service-account token, arbitrary Secret, device, or operator kubeconfig. Never
convert argv into a shell string.

## Normal lifecycle

1. Confirm the Layer 7 approval is current and binds the exact plan/action/policy digests.
2. Persist sandbox request, current sandbox policy, approval binding, quota reservation,
   and claim before provider I/O.
3. Observe the deterministic Job name. Create only when absent; accept an existing Job
   only when request digest, execution ID, fence, attempt, and managed-by labels match.
4. Heartbeat while waiting. Record start and terminal provider observations as application
   facts; never report Job or Temporal completion directly.
5. Capture only expected output paths and media types within file/count/byte bounds.
   Hash, scan, redact or quarantine, write the canonical manifest, then attest.
6. Persist cleanup intent, delete with the exact Job UID precondition, observe absence,
   and record cleanup completion.

## Ambiguous create or delete

Do not blind-retry. Record reconciliation start and inspect the deterministic Job identity.
A matching request/fence/UID may be adopted. A mismatched object is a security conflict.
Unknown provider state remains ambiguous until an operator signal or timeout escalates.
Cleanup redrive uses a tenant-scoped claim and exact UID; it must not delete by name alone.

## Timeout, OOM, violation, and cancellation

Record the explicit terminal result and retain only policy-permitted diagnostics. Never
translate timeout, OOM, nonzero exit, cancellation, scanner failure, or policy violation
into a success-shaped result. Cancellation cannot undo code already started; stale result
acceptance is rejected by the application fence.

## Artifact quarantine

Quarantined artifacts expose no object reference. Preserve only bounded metadata, digest,
scanner codes, and retention state. Treat archive traversal, symlink/device entries,
compression bombs, path conflicts, secret findings, unexpected paths/MIME, and byte/count
overflow as quarantine events. Review and release tooling is not delivered in Layer 8.

## Incident triggers

Escalate RuntimeClass fallback, admission drift, CNI bypass, workload identity failure,
host mount/socket/device discovery, request-label mismatch, UID change, cross-tenant RLS
access, hash-chain failure, stale-fence acceptance, cleanup orphan beyond SLO, or raw
tenant/secret/evidence leakage as platform security incidents.

## Recovery source of truth

Rebuild from PostgreSQL sandbox requests, immutable facts, manifests, artifacts,
attestations, and cleanup claims. Temporal history and Kubernetes objects are observations,
not authorization or audit truth. Never edit immutable facts to recover availability.
