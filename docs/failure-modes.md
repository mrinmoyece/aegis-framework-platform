# Layer 7 failure modes

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

## Operator rules

- Never edit an immutable event, idempotency row, or inbox fact.
- Never report Temporal `COMPLETED` as product completion without the application event.
- Never bypass current policy/budget to recover availability.
- Never switch silently to memory persistence.
- Treat hash failure, cross-tenant access, stale results, and framework defects as
  platform/security incidents.
