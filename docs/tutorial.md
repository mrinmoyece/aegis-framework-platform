# Tutorial: trace one checkout investigation

## 1. Start at the delivery boundary

`api.py` accepts the alert body but constructs `IdentityContext` from headers. The
body cannot choose its tenant, actor, roles, request ID, or trace ID. The CLI builds
the same models from deterministic demo values.

```bash
make demo
```

The request fixture in `fixtures.py` describes a 42% checkout failure rate against a
5% threshold. Fake adapters provide:

- an OpenTelemetry-shaped metric window;
- a GitHub-shaped deployment seven minutes before the alert;
- a rollback decision runbook.

They are structured records, not live network responses.

## 2. Enforce controls before the graph

`InvestigationService.investigate` performs the authority-bearing work:

1. `PolicyPort.authorize` requires the explicit `incident-responder` grant;
2. `IdempotencyPort.acquire` scopes the request key by tenant and fingerprints input;
3. `BudgetPort.reserve` reserves five units once for the opaque thread reference;
4. `EvidencePort.collect` scopes by tenant, and the service rejects any mismatched
   evidence item, duplicate evidence ID, or recomputed content-hash mismatch.

A denial or exhausted budget never starts LangGraph. A duplicate completed request
reauthorizes the caller, returns the stored result, and creates no checkpoint.

## 3. Minimize evidence

The coordinator in `graph.py` calls `prepare_model_evidence`. It:

- sorts evidence IDs;
- scans summaries/untrusted text for instruction patterns;
- drops raw untrusted text;
- includes only per-kind allowlisted facts;
- preserves an ID, locator, and content hash for citation verification.

The prompt-injection eval proves that `"ignore previous instructions"` is treated as
data, forces abstention, and cannot create a proposal.

## 4. Fan out and join

LangGraph schedules telemetry and change specialists in the same super-step. The
structured fake model implements `StructuredModelPort`, so later provider adapters
cannot bypass output validation.

Each node validates `SpecialistFinding`. Malformed output and declared provider
errors become named specialist abstentions; unexpected adapter defects cross the
framework boundary as `OrchestrationFailure`.

The reducer deduplicates and sorts findings. The critic runs once after both branches.

## 5. Validate citations and contradictions

The critic requires every citation to match the collected evidence ID, locator, and
SHA-256 content hash. It abstains when:

- prompt injection was detected;
- a specialist abstained or failed;
- fewer than two findings corroborate;
- specialists identify different cause codes.

Only the success case produces a ranked hypothesis. Its citations are sorted.

## 6. Cross the approval boundary

The graph can emit a `RemediationProposal`, but it cannot approve it.
`InvestigationService` passes that proposal to `ApprovalPort` after graph execution.
The response contains a separate pending approval requiring an incident commander.

Try to execute it in Python and `DisabledEffectAdapter` raises `EffectsDisabled`.
There is intentionally no API route to decide an approval.

## 7. Observe without leaking

`OpenTelemetryObservability` emits one fixed span with a 64-bucket tenant value and
allowlisted counts/status. `LangfuseObservability` is opt-in and manually creates a
chain/evaluator observation. It blocks automatic OpenAI, Anthropic, and LangChain
instrumentation scopes and applies a masking function as defense in depth.

```bash
# Requires standard Langfuse credentials and intentionally performs network I/O.
uv run aegis-framework eval --publish-langfuse
```

Normal tests/evals never run that path.

## 8. Inspect the guarantees

Run:

```bash
make test
make eval
make measure
```

The test suite enables strict LangGraph msgpack behavior in CI, verifies five
checkpoints for the bounded graph, verifies a duplicate adds none, and tests that
actual checkpoint state round-trips through JSON. Runtime memory and PostgreSQL
savers also receive an explicit strict serializer that blocks reconstruction of
unregistered types. The checkpoint is useful resumption state, not the source of
authority described in
[authority boundaries](authority-boundaries.md).
