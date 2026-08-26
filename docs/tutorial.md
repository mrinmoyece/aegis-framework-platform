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
make security
make container
docker compose config --quiet
```

Read [the runbook](runbook.md) for DLQ, worker, cancellation, reconciliation, and
projection recovery. None of these procedures authorizes a production effect.

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
