# Tutorial: trace one approval-gated remediation without trusting frameworks

## 1. Run the deterministic delivery adapter

```bash
AEGIS_MODE=demo make serve
```

Production remains the default and fails readiness closed without configured OIDC and
PostgreSQL. Demo identities/fixtures are never selected implicitly.

Submit durable intent:

```bash
curl --fail-with-body \
  -H 'Content-Type: application/json' \
  -H 'Authorization: ******' \
  -H 'X-Request-ID: tutorial-durable-001' \
  --data '{
    "incident_id":"checkout-20260815-001",
    "alert":{
      "signal":"checkout_failure_rate",
      "service":"checkout-api",
      "region":"eu-west-1",
      "observed_at":"2026-08-15T00:00:00Z",
      "failure_rate":0.42,
      "threshold":0.05
    },
    "wait_for_signal":true
  }' \
  http://127.0.0.1:8000/v1/durable-investigations
```

The response is a redacted application projection. `202` means the requested event and
Temporal outbox intent committed atomically. It does not mean workflow completion.

## 2. Inspect application truth

```bash
curl --fail-with-body \
  -H 'Authorization: ******' \
  -H 'X-Request-ID: tutorial-read-001' \
  http://127.0.0.1:8000/v1/durable-investigations/RUN_ID

curl --fail-with-body \
  -H 'Authorization: ******' \
  -H 'X-Request-ID: tutorial-timeline-001' \
  'http://127.0.0.1:8000/v1/durable-investigations/RUN_ID/timeline?limit=50'
```

The timeline excludes tenant ID and event payload. A next cursor is HMAC-protected and
bound to the caller tenant and run. A cross-tenant caller receives `404`.

Temporal operational queries can show schedule state, but the API never uses them as
product truth.

## 3. Understand the ledger transaction

For a new command, `InMemoryDurability` (test/demo) or `PostgresDurability` (durable
adapter) performs:

```text
lock aggregate head + tenant cursor
check expected version
append event with aggregate and tenant previous hashes
claim request fingerprint
insert Temporal start outbox
update run/timeline projection
advance heads
commit
```

A conflict or outbox failure rolls back the entire operation, including the tenant
cursor. Event/idempotency/inbox rows are immutable.

## 4. Start PostgreSQL and Temporal locally

```bash
export AEGIS_POSTGRES_ADMIN_PASSWORD="$(openssl rand -hex 24)"
export AEGIS_POSTGRES_RUNTIME_PASSWORD="$(openssl rand -hex 24)"
docker compose --profile temporal up -d postgres temporal
docker compose exec -T temporal \
  tctl --address temporal:7233 cluster health
```

Temporal is exposed only at `127.0.0.1:57233`. It stores framework history in separate
databases. Application events remain in `aegis.*`.

## 5. Follow workflow ownership

The sandboxed workflow schedules:

```text
authorize/reserve -> collect evidence -> LangGraph -> optional wait -> complete
```

It has no database/network/random/wall-clock calls. Every Activity resolves opaque
tenant/actor references to current application authority and reevaluates policy. The
initial Activity reserves budget by run ID. Retries reuse that reservation.

Evidence and graph output are persisted as application artifacts. Temporal returns
only stable references. LangGraph continues to own fan-out/join and checkpoints inside
one Activity; Temporal does not retry individual nodes.

## 6. Resume or cancel safely

```bash
curl --fail-with-body -X POST \
  -H 'Content-Type: application/json' \
  -H 'Authorization: ******' \
  -H 'X-Request-ID: tutorial-signal-001' \
  --data '{"command_id":"resume-tutorial-001"}' \
  http://127.0.0.1:8000/v1/durable-investigations/RUN_ID/signals/resume
```

Delivery stores an inbox command and outbox signal before Temporal sees it. Duplicate
command IDs are idempotent. The workflow does not trust the signal body; a later
Activity reloads the command and current signaller. If policy was revoked while
waiting, resume fails closed.

Cancellation follows the same path. A stale graph result after `cancel_requested` is
rejected by the application aggregate state machine.

## 7. Exercise recovery and replay

```bash
AEGIS_TEST_TEMPORAL_ADDRESS=127.0.0.1:57233 make temporal-integration
```

The test starts one workflow before any worker, then starts a worker and observes
recovery. It also verifies one transient Activity retry, duplicate signal suppression,
cancellation signal, timer timeout, normal completion, and `Replayer` determinism.

For SDK time skipping without a network download, preinstall the Temporal test-server
binary and set `AEGIS_TEST_TEMPORAL_TEST_SERVER`.

## 8. Prove PostgreSQL controls

```bash
export AEGIS_TEST_POSTGRES_ADMIN_DSN="postgresql://aegis_admin:${AEGIS_POSTGRES_ADMIN_PASSWORD}@127.0.0.1:55432/aegis"
export AEGIS_TEST_POSTGRES_RUNTIME_DSN="postgresql://aegis_app:${AEGIS_POSTGRES_RUNTIME_PASSWORD}@127.0.0.1:55432/aegis"
make integration
```

The tests cover forced RLS, pool reset, audit/event immutability, quota races,
checkpoint isolation, event/outbox atomicity, projection rebuild, outbox claim, and
cross-tenant ledger hiding.

## 9. Observe without payloads

OpenTelemetry application spans expose fixed operation names and allowlisted
counts/status. The optional Temporal tracing interceptor is configured through the SDK
and does not export application payload contents. Temporal input contains only opaque
references. Langfuse remains model/graph telemetry; automatic graph capture is blocked.

## 10. Inspect model operations without exposing credentials

```bash
curl --fail-with-body \
  -H 'Authorization: ******' \
  -H 'X-Request-ID: tutorial-model-catalog-001' \
  http://127.0.0.1:8000/v1/models/catalog

curl --fail-with-body \
  -H 'Authorization: ******' \
  -H 'X-Request-ID: tutorial-model-usage-001' \
  http://127.0.0.1:8000/v1/models/usage/RUN_ID

curl --fail-with-body \
  -H 'Authorization: ******' \
  -H 'X-Request-ID: tutorial-model-health-001' \
  http://127.0.0.1:8000/v1/models/health
```

Catalog output omits credential and tenant references. Usage comes from application call
facts, and health is derived. The demo catalog uses only the deterministic fake; official
SDK adapters are never activated implicitly.

A model-backed node follows this order:

```text
current model policy/catalog
  -> worst-case token/cost reservation
  -> immutable requested attempt
  -> one SDK call (SDK retries disabled)
  -> current policy/cancellation recheck
  -> strict Pydantic output/citation validation
  -> immutable billed/not-billed/ambiguous settlement
```

Malformed output receives only the policy repair bound. Timeout/crash ambiguity blocks
silent duplicate calls. No model output can create identity, policy, approval, or effect.

## 11. Trace the evidence plane

1. Start at `evidence.py`. Source, query, cursor, provenance, normalized record,
   citation, and bundle are frozen strict contracts with canonical digests.
2. Follow `connector_adapters.py`. Origins/resources come from current configured
   sources, not evidence/model content. Redirects/proxies are disabled; DNS/IP, bytes,
   MIME and shapes are checked before mapping.
3. Follow `evidence_runtime.py`. Query/page intent is durable before I/O. Cursors are
   tenant/query-bound AES-GCM values. A crash window becomes
   `reconciliation_required`, not an invisible retry.
4. Follow `ingestion.py`. JSON/safe YAML/text/bounded ZIP is canonicalized, scanned,
   redacted or quarantined, classified, hashed and tenant/incident deduplicated.
5. Follow `correlation.py` into `graph.py`. Timeline and links are deterministic,
   conflicts/missing/stale sources are explicit, and links remain non-causal. LangGraph
   receives allowlisted facts plus provenance-bound citations.
6. Inspect `migrations/0004_layer5.sql` and evidence query/cursor routes. PostgreSQL
   forces tenant RLS; API output contains status/count/page/expiry only.

The five evidence evals exercise two-page continuation, injection quarantine,
source-policy revocation, deterministic non-causal correlation, and private-address
rejection without credentials or network.

## Layer 13: inspect protocol trust without granting peer authority

Open `/protocol-peers` in the operator workspace. Review owner, environment, trust tier,
revision, capabilities, transports, classifications, risks, expiry, and exact card/
schema/certificate/key digests. Quarantine requires typing
`QUARANTINE partner-investigator`; revocation and emergency disable use equally exact
confirmation. Browser state is not authority: the BFF validates current tenant,
revision and every digest before appending a transition.

Run the deterministic protocol gates:

```bash
python3 -m uv run pytest tests/test_interoperability_layer13.py --no-cov
python3 -m uv run aegis-framework eval run \
  --filter secure-protocol-interoperability
```

Trace an outbound operation as:

```text
identity + purpose -> trust/policy/quota -> digest-only intent -> network
  -> bounded untrusted result -> accept, quarantine, or ambiguity
  -> observe/reconcile before any retry
```

MCP uses modern `server/discover`/per-request negotiation with registered legacy
`initialize` compatibility. A2A requires protocol `1.0` and a signed/pinned Agent Card.
Raw protocol content never enters Temporal history or the application fact ledger.

## 12. Add a source safely

Implement `EvidenceConnector` and return `ConnectorPage`. Keep vendor imports in an
adapter. Add exact source/resource allowlists, tenant secret reference/version,
cancellation, page/record/byte/time bounds, deterministic fakes, durable intent/result,
scanner/provenance tests and current-policy checks. Do not add a loader, RAG framework,
retry library, arbitrary URL, raw query language, webhook, watch, or write API unless a
separate ADR proves its security and ownership.

Read the [connector runbook](connector-runbook.md). It describes production-shaped
enablement and reconciliation without claiming live qualification.

## 13. Run all release gates

```bash
make ci
make eval
make eval-safety
make eval-adversarial
make eval-recovery
make eval-baseline
make eval-meta
make security
make container
docker compose config --quiet
```

Read [the runbook](runbook.md) for DLQ, worker, cancellation, reconciliation, and
projection recovery. None of these procedures authorizes a production effect.

## 13.1 Inspect and replay the governed Layer 10 suite

```bash
uv run aegis-framework eval list --filter remediation
uv run aegis-framework eval run --filter safe-failure
uv run aegis-framework eval replay
uv run aegis-framework eval compare
```

Inspect `evals/suite.json`, `dataset.json`, `baseline.json`, and `waivers.json`.
Change a copy of the dataset source hash, remove a baseline case, expire a soft
waiver, and attempt to waive `privacy-isolation`; each must fail closed. Reverse the
case file and shard it four ways; canonical results stay ordered and the shard union
is exact.

Baseline updates are explicit reviewed changes:

```bash
uv run aegis-framework eval update-baseline \
  --reviewed-by REVIEWER \
  --reason "Reviewed change reference and expected metric movement."
```

The command requires a complete passing run. Do not use it to accept an unexplained
regression. See the [evaluation runbook](evaluation-runbook.md).

## 14. Trace the Layer 6 artifact chain

After the deterministic investigation response returns `run_id`, read the authorized
redacted artifact projection:

```bash
curl --fail-with-body \
  -H 'Authorization: ******' \
  -H 'X-Request-ID: tutorial-artifacts-001' \
  'http://127.0.0.1:8000/v1/orchestrations/RUN_ID/artifacts?limit=50'
```

The response exposes artifact ID, schema version, ordinal, fixed producer role, kind,
and task reference only. It omits tenant, payload, evidence, citations, locators,
prompts, completions, and digests. The opaque next cursor is tenant/run bound.

Follow `orchestration.py` for artifact/capability/transition contracts,
`graph.py` for static fan-out/fan-in and critic routing, migration 0005 plus
`orchestration_postgres.py` for application truth, and `activity_runtime.py` for the
single Temporal Activity boundary. Deleting LangGraph checkpoints must not delete these
application facts.

## 15. Exercise the Layer 7 approval/effect lifecycle

Run every redacted, deterministic scenario:

```bash
uv run aegis-framework remediation-demo --scenario success
uv run aegis-framework remediation-demo --scenario denial
uv run aegis-framework remediation-demo --scenario expiry
uv run aegis-framework remediation-demo --scenario ambiguity
uv run aegis-framework remediation-demo --scenario verification_failure
uv run aegis-framework remediation-demo --scenario rollback
```

The output contains opaque plan/action references, status/counts and explicit authority
owners. It omits tenant, actor, rationale, target, evidence and provider receipt values.
No scenario uses a cluster, network or credential.

Follow the success path:

```text
immutable plan + current policy
  -> exact approval request
  -> two distinct current human grants
  -> mandatory dry-run
  -> persist effect intent
  -> observe exact target
  -> one fenced ActionPort call
  -> persist receipt
  -> read-after-write
  -> fresh cited evidence + postconditions
  -> verified
```

The ambiguity scenario records an uncertain result, blocks blind retry, observes the
stable tenant/idempotency key and appends reconciliation before verification. The
verification-failure scenario does not claim recovery. The rollback scenario adds an
independent compensation intent and receipt.

Start the demo API and read the preloaded exact-scope approval:

```bash
AEGIS_MODE=demo make serve

curl --fail-with-body \
  -H 'Authorization: ******' \
  -H 'X-Request-ID: approval-read-001' \
  http://127.0.0.1:8000/v1/approvals/APPROVAL_ID
```

The view supplies canonical plan/approval digests needed for a decision but redacts
human rationale and identity. Submit decisions with two distinct demo approver tokens,
the current optimistic version, both digests, a unique command ID and bounded rationale.
Cross-tenant and unauthorized reads return the same `404`.

Inspect `remediation.py` for immutable contracts, policy/approval/effect services and
pure replay; `remediation_temporal.py` for durable waits/signals/timers/Activities;
`action_adapters.py` for the fixed Kubernetes operation; migration 0006 and
`remediation_postgres.py` for RLS/claims/rebuild; and
[ADR 012](adr/012-temporal-approval-and-effects.md). LangGraph remains proposal-only.

## Layer 8: approval-bound ephemeral sandboxes

Start with `SandboxSpec`, not a command string. Bind the exact tenant, run, task, Layer 7
plan/action/approval digests, current sandbox policy digest, immutable OCI image digest,
argv tokens, content hashes, secret references, network mode, limits, security context,
expected outputs, retry owner, cleanup policy, idempotency key, attempt, and fence. Any
change creates a new digest and requires fresh approval.

The durable path is:

```text
persist request/policy/approval
  -> reserve quota and claim
  -> observe deterministic Job identity
  -> persist provision intent
  -> create fixed Job + default-deny network policy
  -> wait/heartbeat/cancel
  -> persist terminal result
  -> capture expected outputs
  -> hash/scan/redact-or-quarantine
  -> persist manifest and attestation
  -> persist cleanup intent
  -> UID-bound delete and observe absence
```

If create/delete is ambiguous, do not blind-retry. Temporal waits for an opaque reconcile
or orphan-redrive command; the Activity loads current application truth and observes the
exact request digest, fence, and provider UID. Kubernetes and Temporal state never become
audit truth.

Read `sandbox.py` for contracts/policy/ledger/claims, `sandbox_adapters.py` for the fake,
Kubernetes Job and safe artifact boundary, `sandbox_temporal.py` for durable mechanics,
`sandbox_postgres.py` and migration 0007 for forced RLS/rebuild, the
[sandbox runbook](sandbox-runbook.md), and [ADR 013](adr/013-kubernetes-job-sandbox.md).
Tests are hermetic and execute no process, container, cluster, network, or credential.

## Layer 9: event-grounded three-tier memory and pgvector RAG

Start with accepted or redacted evidence, never raw text. `MemoryLifecycleService.ingest`
binds a `MemoryRecord` candidate to a specific evidence ID/digest, current chunker/embedder
versions, tenant/ACL/classification, an optional `ErasableBlobReference`, and an explicit
`MemoryAcceptance` (human or policy `reviewer_kind`, `disposition` accept/reject, reason
code) — a missing or mismatched acceptance raises `IntegrityFailure` before any fact is
appended — then appends strictly ordered facts (`candidate_registered` through `scanned`,
`chunked`, `embedded`, `indexed`) that carry only opaque digests/counts — never raw text,
query, prompt, completion, tenant ID, or a locator.

Run the deterministic demo directly:

```bash
uv run aegis-framework memory-demo
```

This prints a `MemoryContext`: bounded `ContextSnippet`s with a fixed
`instruction_boundary` literal marking them as untrusted retrieved data, never
instructions. The same demo is the basis for the `memory-retrieval`,
`memory-tenant-cache`, `memory-context`, and `memory-retention` eval cases.

Read status or retrieve through the authorized API:

```bash
AEGIS_MODE=demo make serve

curl --fail-with-body \
  -H 'Authorization: ******' \
  -H 'X-Request-ID: memory-status-001' \
  http://127.0.0.1:8000/v1/memories/MEMORY_ID

curl --fail-with-body -X POST \
  -H 'Authorization: ******' \
  -H 'X-Request-ID: memory-retrieve-001' \
  -H 'Content-Type: application/json' \
  -d '{"query_id": "q-1", "run_id": "run-1", "incident_id": "inc-1", "text": "incident summary"}' \
  http://127.0.0.1:8000/v1/memories/retrieve
```

`Action.MEMORY_READ`/`MEMORY_RETRIEVE` authorize both endpoints under the same
tenant/policy boundary as every other Layer 2+ action; cross-tenant reads return the
same `404` used elsewhere.

Supersession, legal hold, and `tombstone_and_erase` follow the same append-only,
version-fenced pattern as remediation/sandbox: `set_legal_hold` blocks erasure while a
hold is open, and erasure purges the derived index/cache before invoking an injected
`erase_blob` callback — never a real KMS/blob integration.

Read `memory.py` for contracts, the lifecycle service, `reduce_memory`, and the
in-memory hybrid index/compactor/context-builder; `memory_postgres.py` and migration
0008 for the durable pgvector-column chunk/fact schema, forced RLS, and the live
`hybrid_candidates` hybrid SQL query; `memory_temporal.py` for the `aegis.memory.v1`
durable ingest/compact/purge/rebuild Activities with periodic heartbeating;
`memory_demo.py` for the deterministic scenario; the
[memory runbook](memory-runbook.md); and
[ADR 014](adr/014-pgvector-sql-event-grounded-memory.md). This repository implements and
integration-tests a live forced-RLS pgvector `hybrid_candidates` SQL query and digest-only
retrieval/context-build ledger facts (`MemoryOperationFact`), but the production
`/v1/memories/retrieve` API and demo still serve from `InMemoryHybridIndex` — wiring the
SQL query into that serving path is a documented gap, not an implicit capability. Tests
are hermetic and use no live embedding provider, network call, or credential.

## Layer 10: governed deterministic evaluation

Run `uv run aegis-framework eval run`, `replay`, and `compare`. The suite uses only
reviewed synthetic cases, fixed clocks/seeds/fingerprints, canonical digests, hard
safety scorers and an explicit reviewed baseline. Langfuse publication is optional and
never changes the local result.

## Layer 11: portable observability and ledger replay

Validate and start the local profile:

```bash
make observability-config
docker compose --profile observability up -d app otel-collector prometheus grafana
```

Read the authenticated SLO catalog and operational readiness through
`/v1/operations/slos` and `/v1/operations/readiness`. Export one tenant's application
events through an authorized ledger path, then run:

```bash
uv run aegis-framework replay \
  --events application-events.json \
  --run-id run:opaque \
  --view support
```

The replay CLI validates hash chains, sequence and schema before projection. It cannot
call a model, connector, tool, sandbox or effect. Trace links are optional navigation;
the ledger remains truth. Continue with [ADR 016](adr/016-provider-neutral-observability-replay.md),
the [SLO catalog](slo-catalog.md), and the
[observability runbook](observability-runbook.md).
## Layer 12: operate the synthetic checkout without moving authority

```bash
npm --prefix ui ci --ignore-scripts
npm --prefix ui run build
AEGIS_MODE=demo make serve
```

Open `http://127.0.0.1:8000`, sign in to the deterministic demo, and follow Overview,
Investigation, Approvals, Effects, Sandboxes, Memory, Evaluations, Audit, and Replay.
Inspect the exact approval digests and server expiry; the responder lacks
`approval:decide`, so the server denial remains visible and cannot be overridden. The
prior ambiguous effect is never presented as success. Switch to `tenant-beta`: requests
are cancelled, the old cache is removed, session/CSRF rotates, and the empty authorized
tenant projection loads.

The browser stores no bearer credential. Closing it does not stop or complete runtime
work. Production operator readiness remains `503` until live IdP exchange and durable
sessions are configured.
