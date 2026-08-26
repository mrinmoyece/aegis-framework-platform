# Layer 10 evaluation runbook

## Required offline gates

```bash
make eval
make eval-safety
make eval-adversarial
make eval-recovery
make eval-baseline
make eval-meta
```

These commands require no service, network, credential, model judge, or process
execution. `make eval` writes bounded deterministic JSON, Markdown, and JUnit under
`build/evals/`. A report is release evidence only.

## CLI

```bash
uv run aegis-framework eval list
uv run aegis-framework eval list --filter remediation
uv run aegis-framework eval run --filter safe-failure
uv run aegis-framework eval run --shard-index 0 --shard-count 4
uv run aegis-framework eval replay
uv run aegis-framework eval compare
uv run aegis-framework eval update-baseline \
  --reviewed-by REVIEWER \
  --reason "Reviewed change reference and expected metric movement."
```

Selection and sharding are case-ID sorted and stable. A filtered or sharded run
checks selected results and scorer thresholds but does not report absent baseline
cases as missing. The unfiltered baseline gate always checks the complete corpus.

## Baseline review

Never regenerate a baseline merely because CI failed. Review the suite, dataset
source hash, case additions/deletions, scorer direction/threshold/tolerance,
fingerprints, and expected behavior. Hard safety metrics are non-waivable.
Baseline scorer fields must exactly match the suite scorer contract; mismatch is a
tamper violation rather than an alternate tolerance.
`update-baseline` writes only after the complete suite passes and requires reviewer
and reason fields. Review the resulting diff like policy code.

A soft waiver must name the exact baseline, scorer, cases, owner, reason, and expiry.
Expiry, unknown scope, wrong baseline, missing scorer, or hard-safety scope fails
closed. Remove expired waivers; never extend one without new review evidence.
Expiry is evaluated against the current UTC governance clock, not the frozen suite
clock used for deterministic scenario execution.

## Dataset lifecycle

Only repository-local synthetic data is accepted. Keep provenance, license,
synthetic consent, classification, retention, source hash, schema version, and
migration text current. Secret/PII scan or hash failure blocks loading.

For suspected poisoning, leakage, license/provenance loss, or malformed schema:

1. stop promotion and preserve only bounded hashes/reason codes;
2. move the case ID to `quarantined_case_ids` in a new dataset version;
3. investigate without copying raw content into tickets or traces;
4. replace or delete through review, recording a tombstoned ID in
   `deleted_case_ids`; and
5. update the baseline only after the new complete suite passes.

Do not copy private production data into the corpus.

## Integration qualification

PostgreSQL/pgvector and Temporal remain separate environment-gated jobs:

```bash
make integration
make temporal-integration
```

Set the documented disposable DSNs and either
`AEGIS_TEST_TEMPORAL_ADDRESS` or a preinstalled
`AEGIS_TEST_TEMPORAL_TEST_SERVER`. The SDK must never download a test server during
tests. Temporal timers use time skipping where the preinstalled server is selected;
functional CI uses the digest-pinned Compose server and history replay.

## Tamper or evaluator incident

Treat changed suite/dataset digests, unexpected cases/scorers, report overflow,
redaction failure, nondeterministic replay, shard overlap/gaps, expired waivers, and
evaluator exceptions as release/security incidents. Preserve digests, stop
promotion, fix the evaluator or corpus in a reviewed change, and rerun every gate.
Never weaken runtime safety controls or infer production state from an evaluation.

Optional Langfuse publishing requires separately approved configuration. It exports
dataset/report digests and counts only; an outage or rejected publication cannot
change local pass/fail.
