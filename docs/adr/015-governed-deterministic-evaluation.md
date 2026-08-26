# ADR 015: Governed deterministic evaluation and release gates

- Status: Accepted
- Date: 2026-08-17

## Context

Layers 1-9 have deterministic tests and 44 cross-layer cases, but the former
evaluation entry point has no immutable suite/dataset/scorer contracts, reviewed
baseline, waiver policy, reproducible sharding, bounded reports, or explicit
dataset lifecycle. A pass count alone cannot distinguish release evidence from
runtime truth and cannot detect a changed corpus or scorer.

Required CI cannot use production records, credentials, network access, provider
calls, model judges, hosted control planes, sleeps, or effects. Evaluation must not
weaken identity, authorization, budget, citation, approval, fencing, idempotency,
reconciliation, sandbox, memory, or audit controls.

## Decision

1. `evaluation.py` defines frozen strict neutral suite, scenario, case, dataset,
   scorer, result, baseline, comparison, waiver, report, trace, provenance,
   fingerprint, bounds, fault-plan, and recovery contracts. Canonical JSON/SHA-256
   binds all declared fields.
2. Required evaluation runs the real deterministic Layers 1-9 application cases
   through `EvaluationExecutorPort`. Fixed clocks, seeds, digest-derived IDs,
   sorting, stable hash sharding, a hard per-case timeout, bounded reports, and
   denied network/process entry points make the harness reproducible.
3. The checked-in synthetic corpus records source hash, MIT license, synthetic
   consent, internal classification, retention, migration, quarantine, deletion,
   and a secret/PII scan. Digest mismatch or unsafe provenance fails before a case.
4. Safety metrics have exact non-waivable baseline thresholds. Missing/new cases,
   changed suite/dataset digests, missing/new scorers, expired/mismatched waivers,
   and attempts to waive hard safety fail closed. `update-baseline` requires named
   review, reason, and a complete passing run.
   Evaluation time remains fixed for replay, while waiver expiry and baseline review
   timestamps use a separate injectable UTC governance clock.
   Every baseline direction/threshold/tolerance/safety flag must exactly match its
   suite scorer contract; editing a baseline cannot weaken a scorer. Executors may
   report soft measurements only—hard safety is evaluator-owned and an attempted
   override fails the case.
5. Named deterministic fault plans cover intent, effect, result, projection,
   outbox, Activity, signal, timer, heartbeat, checkpoint, provider, connector,
   action, sandbox, embed, index, and cache cuts. They assert convergence, at most
   one authorized effect, no unauthorized/stale/duplicate effect, reconciliation,
   cleanup, audit, and tenant isolation. Temporal integration continues to use
   replay and a preinstalled time-skipping binary or the digest-pinned local server;
   sleeps are not acceptance evidence.
6. JSON, Markdown, and JUnit reports contain bounded digests, IDs, outcomes,
   metrics, and reason codes only. They exclude prompts, completions, raw evidence,
   secrets, identity, tenant and request values, and evidence locators.
7. Langfuse remains optional and non-authoritative. Its adapter publishes only
   sanitized dataset/report digests and aggregate counts. Required CI is offline.
   Automatic LangGraph/LangChain tracing remains disabled.
8. An optional model-judge contract is versioned and disabled in required CI. It
   cannot be a hard invariant or sole safety gate. No judge implementation or live
   provider qualification is shipped.

## Tool selection

pytest is retained for deterministic execution, assertions, JUnit, branch coverage,
and Temporal's supported Python testing model. Hypothesis is valuable for future
bounded property exploration, but is not added merely to restate the finite,
reviewed release corpus; minimized failures would still require promotion into the
governed dataset.

Langfuse is selected only as the existing optional sanitized publisher. LangSmith
is rejected because self-hosting is commercially gated and its control plane and
automatic LangGraph tracing increase lock-in/privacy risk. DeepEval and the core
Ragas metrics depend primarily on model judges; their deterministic subsets do not
replace application safety assertions. promptfoo adds Node/process/YAML machinery
and is optimized for live provider matrices. OpenAI Evals is provider/network
dependent and its hosted platform is scheduled for shutdown on 2026-11-30.

## Consequences

- Evaluation artifacts are reviewable release evidence, never authorization,
  approval, audit, fencing, effect receipt, production verification, or SLO proof.
- Framework Layer 10 is smaller than custom Aegis Layer 11 but less broad: 44 real
  application cases plus 17 separately meta-tested fault points versus the pinned
  custom catalog's 91 cases and 22 cut points. See
  `comparison/layer10-metrics.json`.
- Environment-gated PostgreSQL/pgvector and Temporal jobs qualify the relevant
  adapters separately; the offline report does not pretend those services ran.

## Explicit deferrals

Production model/connector qualification, independent penetration testing, human
label calibration, the observability/SLO layer, operator UI, MCP/A2A, deployment,
HA/DR, and final load/chaos certification remain separate work.
