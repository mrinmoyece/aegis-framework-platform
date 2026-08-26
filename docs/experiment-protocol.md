# Equivalent comparison protocol

The custom Aegis and framework-first Aegis must be compared using equivalent product
behavior, not framework-specific demos.

## Frozen scenario

Both implementations receive the same logical checkout alert and tenant identity.
Evidence semantics are fixed:

- failure rate 0.42, threshold 0.05, baseline 0.01;
- checkout-api deployment seven minutes before the alert;
- rollback-candidate runbook condition;
- stable evidence IDs/locators/hashes per implementation fixture.

Success must return one ranked, cited post-deployment hypothesis and a proposal that
requires approval. Neither implementation may execute a production effect in the
compared layer.

## Required safety cases

1. success/corroboration;
2. specialist contradiction and abstention;
3. prompt injection in untrusted evidence;
4. budget exhaustion before orchestration;
5. tenant-isolated concurrent identities;
6. duplicate request;
7. retry after framework/provider failure;
8. malformed structured output;
9. invalid citation;
10. checkpoint/replay process behavior.
11. JWT issuer/audience/algorithm/key/time attacks;
12. deterministic signing-key rotation and JWKS bounds;
13. stale/revoked grant and purpose/risk denial;
14. cross-tenant API anti-enumeration;
15. forced RLS and connection-pool reset;
16. quota race and retry behavior;
17. durable audit mutation prevention/redaction;
18. tenant-isolated framework checkpoints.
19. expected-version event race and commit-safe tenant cursor;
20. application event/outbox/idempotency atomicity;
21. immutable fact mutation and dual hash verification;
22. deterministic projection rebuild and cursor tamper;
23. no-worker recovery and transient Activity retry;
24. duplicate start/signal/Activity delivery;
25. cancellation/stale-result race and timer timeout;
26. policy revocation during a durable wait;
27. malformed/oversized Temporal payload containment;
28. workflow history replay/version compatibility;
29. framework history/checkpoint loss reconciliation boundary.
30. deterministic model route and exact capability/price denial;
31. structured repair bound and malformed/hostile provider response;
32. provider budget exhaustion before network intent;
33. fallback/circuit/rate/concurrency behavior;
34. timeout/cancellation and explicit billing ambiguity;
35. duplicate call suppression and policy revocation during I/O;
36. model usage/catalog/health RLS and projection rebuild.
37. connector page/cursor/retry/crash and reconciliation behavior;
38. SSRF/DNS/private-IP/redirect and malformed/oversized/MIME response rejection;
39. secret/PII/injection scanning, redaction, quarantine and duplicate handling;
40. source policy/credential revocation, cancellation and stale-result exclusion;
41. deterministic correlation order, conflict, freshness, missing source and citation;
42. evidence forced-RLS isolation and application-event projection rebuild.
43. fixed-role fan-out/fan-in and deterministic artifact order;
44. role/capability and artifact-transition denial;
45. duplicate task intent/result fencing and cancellation race;
46. graph-version/input/checkpoint compatibility and projection rebuild;
47. malformed/hostile specialist output, fabricated citations and critic rejection.
48. memory candidate binding to accepted/redacted evidence and rejection of quarantined
    content;
49. chunker/embedder version-mismatch integrity failure before embed/index;
50. legal hold blocking tombstone/crypto-erasure and release-then-erase behavior;
51. cross-tenant derived-index/cache isolation and rebuild-from-ledger determinism;
52. retrieved-memory instruction-boundary framing and citation-coverage compaction
    fallback.

Inputs, expected status, citation rules, and authority boundaries must match. A
framework feature cannot be credited if the custom implementation is tested against
a stricter scenario.

## Measurements

Capture on a clean checkout:

- production and test source LOC using the committed definition;
- direct runtime/optional/dev dependency count and locked total;
- cold bootstrap and container build time;
- deterministic warm invocation median and p95 for at least 50 runs;
- test/eval count, branch coverage, and wall time;
- container compressed/uncompressed size;
- required stateful services;
- number of application-owned versus framework-owned controls;
- defect count from independent review and CI;
- implementation elapsed time from first commit to green PR.
- framework mechanics removed, remaining application-owned controls, and an explicit
  port/escape hatch for every selected framework.
- model gateway equivalent scenario against custom Aegis Layer 5, including provider
  dependency/operational cost and whether framework use increased code.
- evidence correlation equivalent scenario against custom Aegis Layer 6
  `7a685bc52772e1c92467baba58a1c668646e9bf7`, including connector/parser dependencies,
  retained security controls, operational cost and whether framework use removed code.
- governed specialist equivalent scenario against custom Aegis Layer 7
- approval-bound deterministic fake sandbox lifecycle against custom Aegis Layer 9
  `dce0054a40c34ab4cc9d515aa753bc71d73fab57`, including fixed roles/artifacts,
  scheduler/checkpoint LOC removed, remaining controls, operational cost and escape plan.
- approval-bound deterministic fake sandbox lifecycle against custom Aegis Layer 9

Record OS, architecture, Python, framework versions, CPU/memory limits, network
policy, and run count. Do not compare local Apple Silicon numbers with cloud x86
numbers without labeling them.

## Code classification

Every source file is classified as:

- product/domain behavior;
- enterprise control;
- framework adapter/glue;
- delivery/operations;
- test/eval;
- documentation/measurement.

Generated lockfiles are excluded from LOC but included in dependency count. Blank and
comment-only Python lines are excluded. Do not delete assertions, types, or safety
checks to optimize LOC.

## Correctness gate

A data point is publishable only if both implementations pass the same required
safety cases, no live network/model is used, branch coverage is at least 90%, and an
independent reviewer has no unresolved high-confidence correctness finding.

Environment-gated PostgreSQL and local Keycloak compatibility are reported separately
from the network-free deterministic count. A skipped gate is not a pass and cannot be
reported as production evidence.

The local Temporal integration is also reported separately. Its server/SDK versions,
image digest, test topology, and absence of production credentials must be recorded.
Time-skipping tests may use only a preinstalled binary; test execution must not download
one implicitly.

## Lock-in evaluation

Score each framework on:

1. proprietary data/control plane dependency;
2. state format and migration access;
3. application imports outside its adapter;
4. replacement interface coverage;
5. operational services required;
6. retry/ownership semantics coupled to application behavior;
7. observability portability;
8. license constraints.

The [decision matrix](../comparison/decision-matrix.csv) and
[parity manifest](../comparison/parity-manifest.json) are the machine-readable
starting assets.
## Layer 10 deterministic evaluation protocol

Required release evidence uses only the repository's reviewed synthetic dataset,
fixed suite clock/seed/fingerprints, deterministic adapters, one bounded case at a
time, hard timeout, stable sorted selection/hash shards, and canonical reports.
Run `make eval`, `eval-safety`, `eval-adversarial`, `eval-recovery`,
`eval-baseline`, and `eval-meta`.

PostgreSQL/pgvector and Temporal evidence is collected by their separate
environment-gated integration jobs. Time skipping may use only a preinstalled
Temporal test-server binary; no test may download it. Model judges, live providers,
production records, sleeps, and random process termination are excluded from
required CI. See ADR 015 and `docs/evaluation-runbook.md`.
