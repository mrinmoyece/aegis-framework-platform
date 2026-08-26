# ADR 013: Use hardened Kubernetes Jobs behind a neutral sandbox port

- Status: accepted
- Date: 2026-08-17

## Context

Layer 8 needs ephemeral execution for bounded analysis, tests, and patch preparation.
Tenant code and artifacts are untrusted. The runtime must support immutable workloads,
strict resource and network policy, durable create/wait/cancel/delete mechanics,
reconciliation after ambiguous calls, and hermetic adapter tests without adding a local
host-execution escape hatch.

Kubernetes explicitly states that containers share a host kernel and recommends sandboxed
runtimes or virtual machines for untrusted multi-tenancy. Jobs provide durable one-shot
lifecycle mechanics but remain at-least-once. RuntimeClass selects an operator-installed
runtime without coupling the application contract to gVisor or Kata.

## Decision

Keep `SandboxBackend` provider-neutral and ship one disabled-by-default official
Kubernetes Python client adapter. It creates one fixed `batch/v1` Job and a default-deny
NetworkPolicy from an immutable request. Activation requires:

1. an allowlisted RuntimeClass, with Kata recommended for mutually distrustful tenants;
2. admission policies for digest images and hardened Pod shape;
3. an enforcing NetworkPolicy CNI and workload identity;
4. content-addressed CSI input/output drivers;
5. an external enforcing proxy before exact DNS egress is permitted.

The application persists request/policy/approval/claim intent before provider I/O and
result/artifact/attestation/cleanup facts afterward. Observe-before-create, stable labels,
request digest, fence, provider UID, UID-precondition delete, reconciliation, and orphan
redrive handle at-least-once and ambiguous provider outcomes. Temporal provides Activity
scheduling/retry/heartbeat/cancellation/replay only. PostgreSQL facts are audit truth.

The Job always uses an OCI sha256 digest, argv tokens, non-root UID/GID, read-only root,
drop-all capabilities, no privilege escalation, RuntimeDefault seccomp, required AppArmor,
no service token, no host namespaces, no host path/socket/device, fixed limits, deadline,
bounded memory-backed `/tmp`, and digest-bound CSI volumes.

## Alternatives

- **gVisor/Kata directly:** retained as RuntimeClass deployment profiles. Kata has the
  stronger VM boundary; gVisor may offer lower overhead but needs separate compatibility
  and escape qualification.
- **E2B:** credible Firecracker-based managed option with lifecycle and network controls.
  Deferred pending region, DPA, retention, private network, idempotency, attestation, SLA,
  incident-response, and vendor qualification.
- **Modal:** credible gVisor managed option with mature SDK/lifecycle. Deferred because
  outbound defaults, beta domain filtering, provider image identity, UID semantics, and
  vendor qualification differ from the portable contract.
- **Daytona:** VM/container options exist, but its public core moved to a private codebase
  in June 2026; require renewed vendor and independent-control review.
- **Docker SDK/socket:** rejected. Daemon access is host-privileged and a shared kernel is
  not the selected hostile-tenant boundary.
- **Raw Firecracker wrappers:** deferred. They require building scheduling, jailer,
  kernel/rootfs, TAP/firewall, snapshot, node, and lifecycle controls already supplied by
  a sandbox platform.
- **RestrictedPython:** rejected because its own documentation says it is not a sandbox.
- **Local subprocess:** rejected. It supplies process management, not filesystem/kernel/
  network isolation, durable reconciliation, or tenant separation.

## Consequences and escape

Kubernetes removes custom scheduling, Job state, deadlines, resource placement, and
official API wire mechanics. Temporal removes custom durable waits/retries/heartbeats/
cancellation/replay. Aegis retains security-sensitive contracts, policy, exact approval,
ledger, claims, fencing, egress declarations, artifact trust, reconciliation, cleanup, and
readiness gates.

No cluster-isolation claim follows from unit tests. Live Kata/gVisor, admission, CNI, CSI,
proxy, workload identity, node hardening, escape, load, chaos, and upgrade qualification
remain release gates.

Escape is through `SandboxBackend`, opaque Temporal messages, immutable application facts,
and pure `reduce_sandbox` replay. A managed backend may replace Kubernetes only after
passing equivalent contract, policy, idempotency, network, artifact, attestation, cleanup,
privacy, and failure tests.
