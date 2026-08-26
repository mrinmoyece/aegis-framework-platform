# Layer 7 threat model

## Assets and trust boundaries

Assets are current identity/grants/policy, quota reservations, application events and
hash heads, tenant cursors, idempotency/inbox/outbox, projections, evidence artifacts,
LangGraph checkpoints, Temporal histories/task queues, audit, and telemetry.

Boundaries exist at FastAPI, OIDC/JWKS, PostgreSQL RLS, dispatcher claims, Temporal
client/server/worker payload conversion, signal handlers, Activities, evidence/model
adapters, LangGraph saver state, and telemetry exporters. Temporal and LangGraph are
trusted to provide their documented mechanics, not enterprise authority.

## Threats and controls

| Threat | Control | Residual risk |
|---|---|---|
| Tenant spoof in body/signal/history | Tenant established at delivery; opaque reference resolves through current application authority | Resolver/config defect |
| Cross-tenant event read/write | Tenant-first keys, transaction-local context, forced RLS, non-bypass runtime role | DBA/superuser boundary |
| Stale/competing aggregate write | Locked head plus expected version | Multi-region ordering not designed |
| Cursor gaps/reordering | Tenant cursor advances in same transaction as events/outbox | Database loss/corruption |
| Event tampering | Runtime mutation denial, trigger, aggregate/tenant hash chains | No signature/external witness/WORM |
| Duplicate request with changed input | Tenant/request fingerprint conflict | Caller must retain stable IDs |
| Duplicate inbox/outbox/activity | Unique IDs, stable operation IDs, claim compare-and-set | External connectors still require idempotency |
| Claim theft/stale worker | Claim token, attempt, expiry, tenant scope | Clock/DB availability |
| Poison delivery | Strict type/size bounds, permanent non-retryable errors, DLQ | Novel parser/SDK defects |
| Workflow payload exfiltration | Authenticated-encrypted tenant refs; hashed actor/request refs; no raw evidence/prompts/secrets; no tenant search attribute | Key compromise or traffic analysis |
| Search attribute leak | No custom search attributes; built-in visibility only | Workflow ID remains visible but is hash-derived |
| Forged/duplicate signal | Command ref dedupe; authoritative inbox lookup and current signaller policy | Denial-of-service within signal bound |
| Policy revocation ignored | Reauthorize before every Activity and signal action | Revocation store latency |
| Workflow replay nondeterminism | Sandbox, Temporal APIs only, patch marker, history replay CI | SDK/server upgrade defect |
| Overlapping retries | Explicit retry matrix; one LangGraph Activity; connector retries bounded/disabled | Future adapter misconfiguration |
| Worker fleet crash loop | Unexpected framework defects converted to non-retryable Activity failure | Severe interpreter/native crash |
| Cancellation race | Persist cancel intent first; aggregate state rejects stale result | External work already performed would need future fencing |
| Framework history treated as audit | API and audit read only application ledger/projections | Operator misuse outside app |
| Framework history/checkpoint loss | Reconcile from application intent; never infer outcome | Manual recovery error |
| Trace payload leak | Fixed names, allowlists, tenant buckets, no automatic LangGraph capture | Exporter/runtime changes need redaction tests |
| Dependency/image substitution | Exact Python pins, lockfile, Action SHAs, image digests, CodeQL/audit | Registry/toolchain compromise |
| Provider/vendor shape crosses boundary | Strict neutral contracts; vendor parsing only in adapters | Adapter mapping defect |
| Model chooses tenant/role/policy/approval | Binding comes from application context; output schema has no authority fields | Application wiring defect |
| Unknown model capability/price | Deny by default before reservation/network | Stale catalog availability |
| Context/tool abuse | Byte/token bounds, strict schema, exact tool allowlist, evidence framing | Provider tokenizer variance |
| Retry/billing multiplication | SDK retries disabled; stable intent suppresses duplicate; ambiguous billing blocks fallback by default | Provider may bill an unknown outcome |
| Budget race | Locked PostgreSQL budget and immutable tenant reservation | DBA boundary |
| Policy revoked during call | Current revision/cancellation recheck; settle billing then reject output | Revocation-store latency |
| Circuit/health treated as truth | Circuit is bounded availability control; health is derived projection | Small-sample false signal |
| Prompt/completion telemetry leak | No automatic tracing; manual redacted OTel counts/status only | SDK/operator instrumentation changes |
| Model/evidence supplies connector URL | Connector origins/resources come only from current administrator configuration | Configuration compromise |
| SSRF, DNS rebinding, redirect to credential sink | Exact HTTPS host/origin, A/AAAA global/exact-CIDR validation, redirects/proxies disabled; production egress required | DNS resolution/connect TOCTOU without egress enforcement |
| Stale connector credential/policy | Tenant-bound secret reference/version and source digest rechecked before and after page I/O | Revocation-store latency |
| Oversized/malformed/wrong-MIME response | Content-length plus streamed byte bounds, MIME and strict JSON/SDK shape checks | Decompression/native SDK defect |
| Pagination loop/cursor substitution | Page/record/byte bounds; source/query/page-bound AES-GCM cursor; no cursor API value | Provider pagination defect |
| Worker crash after connector call | Persisted page intent blocks duplicate call and requires reconciliation | Provider without reconciliation identifier |
| Prompt injection/poisoned runbook | Canonicalization, injection scanner, quarantine, fact allowlist; text framed as untrusted | Novel semantic injection |
| Secret/PII in evidence | Scanner hooks, redaction or quarantine before graph/model projection | Detector false negative |
| Archive/parser bomb or active content | UTF-8/JSON/safe-YAML only; bounded ZIP traversal/type/ratio/member/byte checks | Parser CPU not sandboxed |
| Loader metadata grants authority | No broad loader installed; application provenance rebuilt from current source/query/page bindings | Adapter mapping defect |
| Duplicate/conflicting source facts | Tenant/incident digest dedupe; explicit deterministic conflicts; no model winner | Semantically equivalent different values |
| Temporal proximity treated as cause | Correlation links set `causal=false`; critic/model cannot elevate unsupported links | Human misinterpretation |
| Quarantined evidence reaches model | Disposition gate plus extended citation validation | Application wiring defect |
| Cursor/status cross-tenant read | Current policy, anti-enumeration and forced RLS | DBA/superuser boundary |
| Dynamic/self-granted role or capability | Closed `AgentRole`, fixed role policy and artifact write set | Application policy defect |
| Peer-agent prompt injection/chat | No peer chat channel; specialists receive bounded application tasks and allowlisted evidence | Model semantic defect |
| Illegal artifact transition | Typed payload discriminator, provenance digest and transition matrix | Application wiring defect |
| Duplicate/ambiguous specialist task | Durable dispatch intent before model call; completed result cache; unresolved intent requires reconciliation | Provider reconciliation gap |
| Stale task/artifact result after retry/cancel | Attempt-scoped rotating task fence, run cancellation flag and terminal-state rejection | Database/operator compromise |
| Checkpoint from old graph/input | Tenant/run/thread, graph version and canonical input digest compatibility check | Upgrade qualification defect |
| Framework checkpoint treated as artifact truth | Artifact/status APIs read application ledger projection only | Operator misuse outside app |
| Automatic graph trace leaks full state | Automatic capture disabled; fixed graph/node/model spans export allowlisted counts/status only | Exporter configuration drift |
| Model/graph approves or executes | No approval/effect schema or edge; application service alone opens approval and calls `ActionPort` | Application wiring defect |
| Approval scope substitution | Canonical plan/action/approval/policy/target digests reloaded immediately before effect | Digest implementation defect |
| Self or workload approval | Current human principal, SoD and configurable no-self policy | Identity repository compromise |
| Quorum reuse/sybil approvers | Distinct actor references and one immutable decision per approver | Compromised distinct human accounts |
| Stale role/policy approval | Current policy/role/quota snapshot equality invalidates prior decision | Revocation-store latency |
| Forged/replayed decision signal | Persist decision first; signal carries opaque command ref; command/digest dedupe | Authorized command flooding |
| Approval enumeration | Current authorization, tenant RLS and uniform `404` | Timing side channel |
| Expired/revoked approval executes | Application state and current expiry/revocation rechecked before every effect Activity | Clock/configuration defect |
| Target changes after approval | Exact fingerprint, UID and resourceVersion precondition | Provider identity defect |
| Arbitrary command/patch injection | Closed action enum and fixed Kubernetes Deployment patch; no shell/URL/body input | Official-client/adapter defect |
| Duplicate effect | Tenant idempotency key, observe-before-retry, atomic claim and receipt conflict checks | Provider ignores request marker |
| Stale worker performs effect | Attempt claim token plus current fence/digests; stale completion rejected | Worker acts after external call but before rejection |
| Crash/timeout after effect | Persist intent first, record ambiguity, block blind retry, observe/reconcile | Provider cannot expose sufficient state |
| API acceptance treated as recovery | Fresh post-effect evidence and deterministic postconditions required | Evidence source lag/false result |
| Malicious/failed rollback | Separate compensation contract, current policy, intent/fence/receipt and verification | Some actions have no safe inverse |
| Temporal history treated as approval/audit | APIs and effect Activities load only application facts | Operator misuse outside application |
| Approval rationale leaks | Redacted API/OTel; rationale stays immutable under RLS | DBA/operator boundary |

Layer 2 JWT/JWKS, grant freshness, purpose/risk policy, pool reset, audit, and checkpoint
threats remain applicable.

## Abuse cases

1. An attacker sends a Temporal resume signal containing another tenant reference.
   Workflow input has no authority; the Activity loads the persisted command in the
   workflow tenant and current policy denies any mismatch.
2. Two API instances append sequence 4. The aggregate row lock and expected version let
   one commit; the loser writes no event, cursor, projection, or outbox row.
3. A dispatcher dies after claiming a start message. The claim expires; a new worker
   uses the same workflow ID. Duplicate start cannot create a second application run.
4. A worker returns graph output after cancellation. The immutable aggregate transition
   rejects running/completed after `cancel_requested`.
5. Malformed payload repeatedly kills one Activity. The codec/type boundary rejects it
   and the failure is non-retryable/DLQ-bounded rather than crashing every worker.
6. Temporal reports completion after the database was unavailable. The application API
   continues to show its last durable fact and reconciliation raises an incident.
7. A runbook contains “ignore previous instructions” and a token. Ingestion redacts the
   token, records scanner counts, quarantines the document, and excludes it from graph
   state.
8. A Dynatrace hostname resolves to loopback or redirects to another origin. The request
   is rejected before credentials are sent; egress policy supplies connection-time
   enforcement.
9. A worker dies after a GitHub page response but before result commit. The existing page
   intent becomes `reconciliation_required`; Temporal retry cannot issue a second call.

## Explicitly unproven

Temporal mTLS/authentication, production namespace/task-queue isolation, HA/failover,
server schema upgrades, worker version routing, backup/restore, multi-cluster
replication, load limits, and disaster recovery are not proven. PostgreSQL HA/PITR,
external event witnessing, retention/erasure execution, live connector/model/Kubernetes
qualification, DNS-rebinding egress enforcement, parser/general execution sandboxing,
external reconciliation evidence, UI, MCP/A2A, and deployment are also unproven.
Official adapters are present, but live credentials, regional data
handling, model/version qualification, tokenizer accuracy, pricing feed freshness,
provider retention/abuse policy, and load/failover are unproven.
