# Layer 10 failure modes

| Failure | Fail-closed behavior | Durable owner | Qualification |
|---|---|---|---|
| Stale aggregate writer | Expected-version conflict; no event/cursor/outbox commit | Application ledger | unit + PostgreSQL |
| Duplicate request/signal/activity | Fingerprint/inbox/event ID returns same fact or rejects conflict | Application database | unit + eval |
| Event/outbox insert race | Whole transaction rolls back | PostgreSQL | unit + integration |
| Event mutation/reorder/delete | Runtime privilege/trigger rejects mutation; hash verification fails | PostgreSQL ledger | integration |
| Tenant cursor race | Locked tenant cursor produces contiguous commit order | PostgreSQL | integration |
| Projection corruption/loss | Rebuild from verified events; projection is never source truth | Application reducer | unit + eval |
| Tampered/wrong cursor | HMAC/tenant/run binding rejects cursor | Application API | unit/API |
| Cross-tenant ledger/API read | Current policy and forced RLS hide object | Policy/PostgreSQL | unit/integration |
| Outbox worker crash | Claim expires and another worker reclaims | Application outbox | unit |
| Repeated delivery failure | Fifth failure becomes explicit dead letter | Application outbox | unit |
| Temporal unavailable | Intent/outbox remain pending; API stays queued, never claims completion | Application database | documented/dispatcher test |
| Duplicate Temporal start | Stable workflow ID and conflict policy reuse current execution | Application + Temporal | adapter/integration |
| Worker absent/crashes | Temporal retains work; compatible worker replays and resumes | Temporal | integration |
| Activity transient failure | Temporal retries up to three attempts with same operation/budget IDs | Temporal + application idempotency | integration/eval |
| Activity poison/framework defect | Non-retryable typed failure; worker process survives | Activity adapter | unit |
| Activity heartbeat timeout | Temporal retries bounded attempt | Temporal | configuration/integration boundary |
| Workflow timer expiry | `timed_out` application event; no silent success | Temporal timer + application event | integration |
| Duplicate resume signal | Workflow set and inbox suppress duplicate command | Temporal + application inbox | integration/unit |
| Forged signal payload | Signal reference is reloaded from inbox and current signaller reauthorized | Application authority | unit/eval |
| Policy revoked during wait | Resume Activity denies; workflow fails safely | Current policy | eval |
| Cancellation/result race | Persisted cancel transition rejects stale graph result | Application aggregate state machine | unit/eval |
| Temporal history loss | Reconcile pending application intent using same workflow/message IDs; never infer completion | Application ledger | documented boundary |
| LangGraph checkpoint loss | Bounded graph Activity may rerun under stable operation/budget; checkpoint is not truth | LangGraph + application idempotency | eval/documented |
| Workflow code incompatibility | Replay test fails release; patch/version strategy required | Temporal deployment | integration |
| Oversized/malformed payload | Pydantic/codec rejects before handler; no unbounded allocation | Application converter | unit |
| Evidence tenant/hash mismatch | Activity fails before LangGraph | Application evidence validation | inherited unit tests |
| Budget exhausted | Authorization Activity records fail-closed outcome before evidence/graph | Application budget | eval |
| Audit/ledger unavailable | Operation cannot be represented as durable success | PostgreSQL | fail-closed adapter |
| OTel/Langfuse unavailable | Product truth unaffected; export remains optional | Observability adapter | non-authoritative |
| Missing/unknown model policy/catalog/price | Deny before network intent | Application model control store | unit/eval/integration |
| Model reservation race | Row lock allows only budget-fitting reservations | PostgreSQL | integration |
| Crash after call intent | Pending call appears as ambiguous reserved cost; duplicate network call suppressed | Immutable model ledger | unit/integration |
| Provider timeout/connection loss | Settle explicit billing ambiguity; no fallback unless policy opts in | Application gateway/ledger | eval |
| Provider rate/unavailable | Bounded deterministic fallback and circuit; no SDK retries | Application gateway | unit/eval |
| Malformed/hostile structured output | Strict schema, bounded repair, then fail/abstain | Pydantic/application graph | unit/eval |
| Unsupported tool/citation | Exact tool allowlist and citation triple validation reject output | Application safety | unit/eval |
| Policy revoked/cancel during call | Usage is settled but stale result is rejected | Current policy + ledger | unit/eval |
| Usage/health projection loss | Rebuild from immutable reservations/call events | PostgreSQL application ledger | integration |
| Connector disabled/unconfigured | Deny before secret resolution/network | Current source policy | unit/eval |
| Connector URL/resource injection | Ignore caller/model URL; exact configured origin/resource allowlist | Application source registry | unit/security |
| DNS/private-IP/redirect attempt | Reject before transport or credential forwarding | Application transport + egress | unit/eval |
| Connector timeout/SDK exception | Explicit failure; SDK retry disabled | Temporal Activity/application intent | unit |
| Rate limit | Explicit rate-limited failure/count; no hidden client retry | Application/Temporal | unit |
| Malformed/MIME/oversized response | Reject/quarantine within byte/schema bounds | Connector/ingestion | unit |
| Cursor loop/expiry/substitution | Bound pages; bind/encrypt cursor; expired Kubernetes cursor requires relist | Application cursor projection | unit |
| Crash after page intent | Mark reconciliation required; do not repeat ambiguous read | Application ledger | unit/PostgreSQL |
| Cancellation during page | Check before call and result commit; reject stale result | Current application cancellation | unit/Temporal boundary |
| Source policy/credential rotated | Recheck source digest/version; reject stale page | Current source registry | unit/eval |
| Secret/PII/injection detected | Redact or quarantine; never project quarantined text | Ingestion policy | unit/eval |
| Archive/document bomb | Reject active/traversal/type/member/ratio/byte/depth overflow | Ingestion policy | unit |
| Duplicate content | Tenant/incident digest marks duplicate without duplicate model context | Evidence metadata | unit |
| Conflicting evidence | Preserve deterministic conflict and abstain where required | Correlation reducer | unit/eval |
| Missing/stale telemetry/change | Critic abstains; missing runbook prevents proposal | Correlation + critic | unit |
| Evidence projection loss | Verify ledger, deterministic rebuild, record rebuild fact | Application ledger/PostgreSQL | unit/integration |
| Cursor/status cross-tenant read | Current authorization plus forced RLS/404 | Policy/PostgreSQL | API/integration |
| Unknown role/capability | Closed enum and deny-by-default write policy reject before dispatch | Application orchestration policy | unit/eval |
| Illegal artifact provenance/transition | Strict envelope/digest/transition validation rejects artifact | Application artifact boundary | unit/eval |
| Duplicate task while intent unresolved | Rotate attempt fence; no second model call; explicit reconciliation-required abstention rejects the abandoned result | Application orchestration ledger | unit/eval/PostgreSQL |
| Concurrent first run intent | Conflict-safe insert and locked reread return one binding; changed input fails as orchestration failure | Application orchestration ledger | PostgreSQL |
| Stale fenced task/artifact after cancel | Reject result and preserve cancelled application state | Application orchestration ledger | unit/eval/PostgreSQL |
| Incompatible graph checkpoint | Reject graph-version/run/input mismatch; rebuild from application facts | Application compatibility gate | unit/eval |
| Specialist/provider exception | Convert at node boundary to named abstention; worker remains alive | Graph adapter | unit |
| Critic rejection/low confidence | Deterministic abstain/escalate; no proposal/effect path | Application critic gate | unit/eval |
| Artifact projection loss | Rebuild from immutable orchestration facts/artifacts under tenant RLS | Application ledger | unit/PostgreSQL |
| Missing/disabled action policy | Deny before approval/effect | Application policy | unit/eval |
| Maintenance window closes | Current policy recheck invalidates approval | Application policy | unit |
| Plan/action/target digest changed | Reject decision/effect and require new approval | Application contracts | unit/eval |
| Self/workload/wrong-role approval | Deny without recording grant | Approval service | unit/API |
| Duplicate approver | Unique approver decision rejects quorum reuse | Application/PostgreSQL | unit/integration |
| Concurrent decision/version race | Expected version permits one append | Application ledger | unit/PostgreSQL |
| Approval decision replay changed | Command ID/digest conflict | Application ledger | unit/API |
| Approval expiry/revocation | Add terminal fact; effect recheck rejects | Application ledger/policy | unit/Temporal |
| Forged approval signal | Reload opaque command and immutable decision | Application authority | unit/Temporal |
| Dry-run rejection | Record fail-closed outcome; no live request | Action adapter/application | unit |
| Kubernetes target UID/resourceVersion changed | Reject before patch | Fixed adapter | unit |
| Worker crash before effect | Requested intent remains claimable under current fence | PostgreSQL/Temporal | integration |
| Worker crash after effect | Mark/retain ambiguity; observe before retry | Application reconciler | unit/Temporal |
| Duplicate effect Activity | Observe + stable tenant key returns duplicate receipt | Action adapter/application | unit |
| Stale attempt/fence completion | Compare-and-set rejects receipt | PostgreSQL claim | integration |
| Reconciliation inconclusive | Escalate; no success or blind retry | Application ledger | unit/Temporal |
| Verification evidence not fresh | `verification_failed`; no recovered claim | Verification service | unit |
| Postcondition fails | Roll back only if exact compensation exists, else escalate | Application service | unit |
| Rollback fails/ambiguous | Escalate and preserve both receipts | Application ledger | unit |
| Temporal remediation history loss | Reissue from application intent/reference or escalate | Application ledger | documented |
| Sandbox policy disabled/missing | Deny before claim or provider I/O | Application policy | unit |
| Spec/policy/approval digest changes | Invalidate request and require fresh approval | Application contracts | unit |
| Mutable image/shell/privilege/host mount | Strict contract/admission shape rejects | Application + admission | unit/security |
| Sandbox claim race/stale attempt | One active claim; expiry requires advancing attempt; stale completion rejected | PostgreSQL claim | unit/integration |
| Kubernetes create timeout/conflict | Observe exact labels/request digest/fence/UID before create/retry | Application reconciler | unit/Temporal |
| Kubernetes delete timeout | Observe exact UID; retry UID-precondition delete or quarantine | Cleanup reconciler | unit/Temporal |
| Runtime/admission/CNI/workload identity absent | Readiness fails closed; no Job submitted | Kubernetes adapter | unit/live deferred |
| Exact egress without proxy | Reject before NetworkPolicy/Job creation | Application policy/adapter | unit |
| Sandbox timeout/OOM/nonzero/violation | Explicit terminal fact/result; never success-shaped | Backend + ledger | unit |
| Cancellation race | Persist intent, provider cancel/delete, reject stale result under fence | Application + Temporal | unit/Temporal |
| Output path/MIME/count/size overflow | Quarantine; no artifact object reference | Artifact boundary | unit |
| Archive traversal/link/device/bomb | Atomic staging removed; request quarantined | Artifact boundary | unit |
| Secret/scanner finding | Redact or quarantine before artifact publication | Artifact boundary | unit |
| Artifact/projection loss | Verify immutable facts/manifests and rebuild pure projection | PostgreSQL/application | unit/integration |
| Orphan Job after workflow loss | Application cleanup claim owns observe/delete redrive | PostgreSQL + Temporal | documented/integration |
| Quarantined/duplicate evidence proposed as memory | `ingest` rejects before any candidate fact; only accepted/redacted dispositions qualify | Application lifecycle service | unit/eval |
| Chunker/embedder version mismatch | `IntegrityFailure` before embed/index; ledger stays at last valid fact | Application lifecycle service | unit |
| Embedding provider timeout/exhaustion | `ControlledEmbeddingGateway` bounds concurrency/attempts/timeout; embed fact left incomplete, never silently retried past budget | Embedding gateway | unit/eval |
| Crash mid-ingest fact chain | Resume at next expected fact type via `reduce_memory` replay; never re-append a completed fact | Application ledger | unit |
| Erasure attempted under legal hold | `PolicyDenied` before tombstone/purge/erase-blob callback | Application lifecycle service | unit |
| Insufficient citation coverage at retrieval/compaction | `insufficient_context=true` / deterministic extractive fallback; no uncited claim | Derived index + compactor | unit/eval |
| Cross-tenant index/cache access attempt | Tenant-scoped bounded cache and index reject/omit foreign-tenant entries | Derived index | unit |
| Superseded-memory set incomplete/stale | `PolicyDenied` before any superseded fact is appended | Application lifecycle service | unit |
| Retrieved memory treated as instruction downstream | `MemoryContext.instruction_boundary` fixed literal; no graph edge to an effect | Application/graph contract | unit/documented |
| Derived index/chunk table loss | Rebuild from immutable `memory_facts` via `reduce_memory`; ledger is never derived from the index | Application ledger | unit/documented |
| Live pgvector query not yet wired to serving path | `hybrid_candidates` is implemented and integration-tested at the store layer; production retrieval still serves from `InMemoryHybridIndex` until wired into `MemoryRetrievalService` | Documented boundary | integration-tested (store) / documented (serving path) |
| Retrieval/context-build unaudited | `MemoryRetrievalService` appends digest-only `RETRIEVE_REQUESTED`/`RETRIEVE_COMPLETED`/`CONTEXT_BUILT` `MemoryOperationFact`s with strict sequencing and idempotent replay | Application ledger | unit |
| Memory ingested without explicit acceptance | `MemoryAcceptance` (human/policy disposition, digest, reason code) bound to tenant/memory ID is required before any candidate/scan/chunk/embed/index fact | Application lifecycle service | unit |
| Temporal Activity heartbeat stalls silently | Initial heartbeat plus a periodic 10-second heartbeat under a 30-second `heartbeat_timeout` detects a stalled worker | Temporal Activity | unit |
| Evaluation suite/dataset source tampered | Canonical suite/dataset/source hashes differ from reviewed baseline; promotion stops | Evaluation comparison | meta + baseline gate |
| Case added or removed silently | Complete run compares exact baseline and dataset case sets | Evaluation comparison | meta + baseline gate |
| Scorer direction/threshold changed | Suite digest and exact baseline scorer set fail comparison until explicit review | Evaluation comparison | meta + baseline gate |
| Safety waiver attempted | Hard-safety scorer rejects waiver regardless of owner/expiry | Evaluation comparison | meta |
| Waiver expired or mis-scoped | Comparison fails closed and reports stable reason code | Evaluation comparison | meta |
| Dataset contains secret/PII/private production content | Provenance validation, source digest and bounded scan reject before execution | Dataset governance | meta |
| Case hangs | Hard per-case signal timeout becomes evaluator failure; no silent skip | Evaluation runner | meta |
| Eval attempts network/process escape | Hermetic guard raises before connection/process creation | Evaluation runner | meta |
| Eval report overflows or leaks payload | Byte cap and digest/reason-only schema reject; redaction tests gate exporter | Reporting adapter | meta |
| Order/shard/replay differs | Stable sorted selection/hash shard and canonical result comparison fail | Evaluation runner | meta |
| Langfuse unavailable | Local report/comparison remains authoritative; publication fails separately | Optional adapter | unit |
| Hostile trace/baggage context | Strict W3C parser rejects before application delivery; no foreign parent accepted | Delivery boundary | unit/API |
| Telemetry cardinality/secret injection | Attribute/label allowlist and bounded enum reject before export | Semantic policy | unit/eval |
| Collector/exporter unavailable | Bounded queue/retry/drop; application correctness continues and operations readiness degrades | Optional telemetry | unit/config |
| Retry/replay metric duplication | Logical-operation digest suppresses total; retry remains a separate counter | Metrics registry | unit/eval |
| SLO fast/slow burn | Multi-window alert links the owning runbook; release policy applies | Prometheus/application SLO | rule validation |
| Safety violation | Immediate non-budgetable page; fence/reconcile affected work | Application control + alert | eval/rule validation |
| Replay hash/sequence/schema divergence | Stop before projection/support conclusion; preserve source events | Application ledger | unit/eval |
| Privileged support audit unavailable | SLO/support/rebuild request fails closed | Application audit | API |

## Retry rules

The application dispatcher retries command delivery. Temporal retries whole Activities.
LangGraph owns graph checkpoints but not a second retry loop. Connector/provider retries
must be disabled. Bounded repair/fallback is application gateway work within the Activity
attempt and uses distinct durable attempt IDs. No framework retry converts an
at-least-once external operation into exactly-once behavior.

For effects, Temporal alone retries the Activity. The provider SDK/client has no retry
loop. Before a retry, application code observes the exact target. Ambiguous intent blocks
automatic replay until reconciliation. Stable tenant idempotency keys suppress duplicate
provider work where supported; fencing rejects stale application results but cannot undo
an already delivered external request.

For sandboxes, Temporal alone retries provision/wait/capture/cleanup Activities.
Provision always observes the deterministic Job identity before create. Ambiguous create
or delete never becomes success; reconciliation or orphan redrive observes the exact
request digest, fence, and provider UID. The official Kubernetes client has no adapter
retry loop.

For memory, Temporal `aegis.memory.v1` retries ingest/compact/purge/rebuild Activities.
Each retry resumes at the next expected ledger fact rather than replaying the whole
ingest; an ambiguous embed/index step is resolved by replaying `reduce_memory`, never by
blind re-embedding under a stale version.

## Operator rules

- Never edit an immutable event, idempotency row, or inbox fact.
- Never report Temporal `COMPLETED` as product completion without the application event.
- Never bypass current policy/budget to recover availability.
- Never switch silently to memory persistence.
- Treat hash failure, cross-tenant access, stale results, and framework defects as
  platform/security incidents.

## Layer 14 deployment and recovery failures

| Failure | Fail-closed behavior | Evidence |
|---|---|---|
| Missing enterprise worker bootstrap | Pod never becomes ready; no fake Activity implementation | worker runtime tests |
| Temporal TLS/API key/mTLS/codec/namespace absent | bootstrap exits configuration failure before polling | unit/config |
| Worker build incompatible | replay/promotion stops; old pinned worker remains | replay + rollout runbook |
| Queue schedule-to-start rises | stop low-priority admission, preserve cleanup/remediation capacity, scale within DB/provider limits | objective/runbook; production metric adapter and load deferred |
| DB pool exceeds headroom | strict `CapacityPlan` rejects configuration | unit |
| Migration checksum/lock failure | PreSync Job fails; application digest is not promoted | migration runner/integration |
| Admission/signature policy unavailable | production readiness/promotion blocked | policy/render; live enforcement deferred |
| CNI/proxy/private endpoint unavailable | dependent workload remains unready; no direct egress fallback | NetworkPolicy/runbook |
| Node drain/rollout | readiness removed, polls drain for 90 seconds, Temporal reschedules | probe/control tests |
| Backup hash/sequence mismatch | target remains isolated; security/data-loss incident | deterministic restore verifier |
| Projection/vector/checkpoint loss | rebuild from verified ledger/objects; cache discarded | restore contract |
| Temporal history missing after restore | reconcile same workflow/outbox IDs; never infer completion | DR runbook |
| Ambiguous provider/effect/sandbox state | observe and reconcile under current fence before routing | application ledger |
| Stale regional generation | writer transition denied | failover contract test |
| Source writer not fenced | target writer/routing denied | failover contract/runbook |
| DNS routes early | readiness does not override generation/ledger fence | runbook |
| Telemetry unavailable | correctness continues; operations readiness degrades | existing containment |

## Layer 13 protocol failures

| Failure | Fail-closed behavior | Durable owner |
|---|---|---|
| Unknown/expired/review-due peer | Deny before quota or network | Tenant trust registry |
| Card/schema/cert/key drift | New pending revision or quarantine; stale work rejected | Registry + application facts |
| Workload token replay/audience/scope mismatch | Authentication denial; no protocol dispatch | Identity boundary |
| MCP version/capability mismatch | Deny negotiation; no legacy fallback unless registered | MCP adapter + registry |
| A2A missing `1.0`/invalid signature | Reject card before client creation | A2A adapter + registry |
| Tool/capability/schema poisoning | Reject advertisement/result against exact allowlist/digests | Application policy |
| Timeout after request | Append ambiguity; block resend; reconcile same operation | Application ledger + Temporal |
| Stream disconnect/cancel race | Persist cancellation; peer cancel; reject stale result by fence | Application ledger |
| Forged/URL/raw artifact | Quarantine metadata only; no artifact publication | Artifact projection |
| Cursor loop/substitution | Reject loop, expiry, tenant/peer/query mismatch | Cursor registry |
| Quota/circuit exhaustion | Deny before network; no success-shaped fallback | PostgreSQL quota/circuit |
| PostgreSQL/audit unavailable | Operation cannot become durable success | Application database |

MCP/A2A SDK retries do not own application retry. Temporal retries whole Activities with
the same operation, idempotency and fence. An ambiguous peer outcome is observed before
any new network attempt.
# Layer 15 qualification failure modes

- A failed journey, eval, chaos invariant, performance budget or manifest validation
  fails `make qualification`; do not regenerate baselines or loosen budgets to pass.
- Missing PostgreSQL, Temporal, browser or restore services leave the named item
  environment-gated; a skip is not evidence.
- Timing regression is a CI signal, not production SLO failure. Reproduce on comparable
  hardware before changing a budget.
- Report loss is not application data loss. Re-run from source events/manifests.
- A readiness blocker cannot be cleared by an aggregate score or documentation-only
  status change.
- Production chaos that risks unauthorized effects, tenant isolation or unreconciled
  ambiguity must stop and fence new work.
