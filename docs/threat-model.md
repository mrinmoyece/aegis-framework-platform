# Layer 10 threat model

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
| Shell/argument injection | Immutable argv tuple; shells, command-string flags, interpolation, controls and bidi rejected | Approved executable vulnerability |
| Mutable or substituted image | Registry plus exact OCI sha256 allowlist; admission prerequisite | Registry/toolchain compromise |
| Host escape surface | No host namespaces/path/socket/devices, no service token, non-root, read-only root, drop-all, no escalation, RuntimeDefault seccomp, required AppArmor/RuntimeClass | Runtime/kernel/admission defect |
| Namespace mistaken for sandbox | Readiness requires qualified RuntimeClass; docs make no namespace-isolation claim | Cluster operator misconfiguration |
| Sandbox tenant/approval substitution | Exact tenant/run/task/remediation/action/approval/policy/spec digests reloaded before claim | Authority repository compromise |
| Sandbox duplicate/stale attempt | Tenant idempotency, observe-before-create, claim expiry, advancing attempts and stable fence | Provider work can outlive a stale worker |
| Ambiguous Job create/delete | Intent first, observe exact labels/UID, reconcile or escalate; UID-precondition cleanup | API outage can remain ambiguous |
| Path/symlink/device/archive abuse | Relative NFC paths, traversal/device/control denial, atomic bounded extraction, no links/devices, ratio/member/byte limits | Parser/filesystem defect |
| Secret literal or output leak | Secret references only; literal scanner; output scanning, redaction/quarantine and no quarantined object ref | Detector false negative |
| Output/artifact spoofing | Expected path/MIME/count/size allowlists, tenant/run/task/execution binding and canonical manifest | Scanner/provenance defect |
| Sandbox output grants authority | Output is untrusted and never an approval, effect receipt, audit record, or tenant grant | Downstream wiring defect |
| Egress to metadata/private service | Network-none default; exact public DNS declarations; external proxy required for exact destinations | Proxy/CNI/DNS compromise |
| Kubernetes status treated as audit | APIs and replay use application ledger only | Operator misuse outside application |
| Cluster prerequisite drift | Readiness fails closed for RuntimeClass, admission, CNI and workload identity | Drift after admission |
| Sensitive field enters immutable memory fact | `MemoryFact` payload schema bans raw text/query/prompt/completion/tenant/locator fields | Application code defect |
| Poisoned/injected content becomes memory authority | Only accepted/redacted evidence may become a candidate; retrieved memory is framed with a fixed untrusted-data boundary, never processed as instructions | Novel semantic injection at retrieval-consumer boundary |
| Cross-tenant memory retrieval/cache hit | Tenant-scoped bounded cache and index; forced RLS on durable chunks/facts | Application wiring defect |
| Stale chunker/embedder version silently reused | Ingest compares record binding against current `EmbeddingSpec`/chunker version and raises before embed/index | Version-registry defect |
| Erasure proceeds under legal hold | `tombstone_and_erase` checks `legal_hold_count`/`retention.held` before purge/erase | Application wiring defect |
| Crypto-erasure treated as qualified KMS deletion | `erase_blob` is an explicit injected callback; no KMS/blob integration is shipped or claimed | Callback implementation gap outside this repository |
| pgvector retrieval treated as production-qualified serving path | `PostgresMemoryStore.hybrid_candidates` implements and integration-tests a live forced-RLS ANN/lexical/recency/quality query, but `/v1/memories/retrieve` and the demo still serve from `InMemoryHybridIndex`; the SQL path is not yet wired into production retrieval | Documentation/operator misreading |
| Memory acceptance bypassed | `MemoryLifecycleService.ingest` requires a `MemoryAcceptance` bound by tenant/memory ID with an explicit human/policy disposition before any candidate/scan/chunk/embed/index fact | Application wiring defect |
| Retrieved memory content escalated to instruction/effect | `MemoryContext.instruction_boundary` fixed literal; no graph edge from memory context to an effect | Downstream consumer defect |
| Evaluation dataset contains production data/secret/PII | Repository-local synthetic provenance, source hash, classification/consent/retention checks and pre-run scan | Detector false negative or dishonest metadata |
| Baseline edited to bless regression | Suite/dataset/case/scorer digests, explicit reviewer/reason and complete passing update command | Colluding reviewer or source compromise |
| Quality score hides safety failure | Exact per-scorer hard thresholds; every real case failure lowers every required hard dimension; hard controls are non-waivable | Incorrect scorer-to-case applicability |
| Expired/broad/mismatched waiver | Exact baseline/scorer/case scope and fail-closed expiry; hard-safety waiver is rejected | Clock/configuration defect |
| Malicious evaluator opens network/process | Hermetic guard denies DNS/socket helper and subprocess/system entry points; no arbitrary fixture callable | Native extension or unwrapped low-level syscall |
| Nondeterministic ordering/sharding/replay | Sorted IDs, digest hash shards, fixed seed/clock and byte-stable replay meta-test | Hidden framework/global entropy |
| Report leaks prompt/evidence/identity | Bounded digest/count/status/reason-only JSON/Markdown/JUnit plus redaction/meta-tests | New report field/exporter without review |
| Hosted evaluator becomes release authority | Required CI is local/offline; Langfuse is optional sanitized publication only | Operator bypass outside CI |
| Model judge becomes sole safety gate | Judge contract cannot be hard safety and is disabled/unimplemented in required CI | Future adapter misconfiguration |

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
10. An attacker submits quarantined evidence as a memory candidate. `ingest` rejects it
    before any candidate fact because only `accepted`/`redacted` evidence dispositions may
    become memory; no scan/chunk/embed/index fact is ever appended for it.
11. An operator attempts `tombstone_and_erase` on a memory under an open legal hold. The
    service raises `PolicyDenied` before appending a `tombstoned` fact, purging the
    derived index, or invoking the erase-blob callback.

## Explicitly unproven

Temporal mTLS/authentication, production namespace/task-queue isolation, HA/failover,
server schema upgrades, worker version routing, backup/restore, multi-cluster
replication, load limits, and disaster recovery are not proven. PostgreSQL HA/PITR,
external event witnessing, retention/erasure execution, live connector/model/Kubernetes
qualification, DNS-rebinding egress enforcement, live Kata/gVisor/admission/CNI,
external reconciliation evidence, UI, MCP/A2A, and deployment are also unproven.
Production model/connector qualification, independent penetration/human labeling,
the observability/SLO layer, and final load/chaos certification remain unproven.
Official adapters are present, but live credentials, regional data
handling, model/version qualification, tokenizer accuracy, pricing feed freshness,
provider retention/abuse policy, and load/failover are unproven. `PostgresMemoryStore
.hybrid_candidates` implements and integration-tests a live forced-RLS pgvector
ANN/lexical/recency/quality query, and `MemoryRetrievalService` now records digest-only
`RETRIEVE_REQUESTED`/`RETRIEVE_COMPLETED`/`CONTEXT_BUILT` facts around every retrieval and
context build — but wiring that SQL query into the production retrieval control path
(`/v1/memories/retrieve`, the demo), a real embedding/summarization provider, and
KMS/blob-qualified crypto-erasure remain unproven; only ingest, supersession, legal hold,
tombstone, digest-only retrieval/context facts, and the derived in-memory index/cache path
are exercised by tests today.
# Layer 11 observability threats

1. **Telemetry tenant/identity exfiltration.** Semantic and metric policies reject
   tenant, actor, user, request, run, incident, artifact and locator dimensions.
2. **Prompt/secret/PII export.** Value scanning, key allowlists, bounded structured
   logs and Collector deletion reject sensitive material before exporters.
3. **Cardinality denial of service.** Metrics permit at most four registered labels
   with stable enumerated values; log rate suppression and exporter queues are bounded.
4. **Trace-context poisoning.** Strict lowercase W3C parsing rejects zero/oversized/
   malformed parents and baggage outside the boolean allowlist.
5. **Trace-as-authority confusion.** APIs, docs and replay preserve the application
   ledger as truth; traces cannot authorize, approve, fence or prove effects.
6. **Replay tool execution.** Replay accepts only bounded strict event arrays and has
   no model, connector, tool, sandbox or effect port.

Managed backend tenancy, exporter mTLS, production alert routing and external
penetration testing remain unproven.

# Layer 12 operator UI and BFF threats

| Threat | Control | Residual/deferred |
|---|---|---|
| Browser bearer theft | Server-side HttpOnly `__Host-` session; no web storage token | Live exchange/store not delivered |
| Login CSRF/code substitution | One-use state, nonce, PKCE S256 and short handshake expiry | Live IdP qualification deferred |
| Session fixation/reuse | Rotate on callback and tenant switch; delete on logout/expiry | Distributed revocation deferred |
| CSRF/cross-site mutation | SameSite=Strict, session CSRF and exact trusted Origin | TLS proxy qualification deferred |
| Cross-tenant cache/data | Tenant key, cancel/remove/refetch, backend anti-enumeration | Multi-tab UX is not production-qualified |
| Stale/revoked grants | UX deny-default; server reauthorizes; session expiry and `401` teardown | Push revocation not delivered |
| XSS from evidence | Zod bounds, React text rendering, CSP, no HTML sink | Independent penetration deferred |
| URL/download/CSV/clipboard abuse | Same-origin URL, MIME/size/name allowlist, formula neutralization, clipboard bound | External DLP deferred |
| Double/stale approval | Review, typed risk confirmation, idempotency, expected status/digests, disabled pending submit | Demo principal is always denied |
| Ambiguous effect shown healthy | Closed status enum and explicit alert styling/test | Operator training still required |
| Poll replay/reorder | Runtime schema, generation watermark, dedupe, retry cap, tenant/auth teardown | Durable SSE cursor deferred |
| Analytics/telemetry leak | No third-party analytics; fixed no-payload error handling | Browser RUM deliberately absent |

# Layer 13 MCP and A2A threats

| Threat | Control | Residual/deferred |
|---|---|---|
| Tool/card description poisoning | Treat every description/instruction/capability as untrusted data; registry policy wins | Novel semantic deception |
| Peer grants role/tenant/approval | Workload identity and tenant purpose established before protocol; authority fields rejected | Application wiring defect |
| Confused deputy/token passthrough | Exact audience/resource/scope/purpose, no downstream client-token forwarding, current RBAC | Token broker not deployed |
| Replay | Token-ID replay cache, tenant idempotency digest, message/task dedupe | Distributed replay store deferred |
| Schema/JSON/Unicode bomb | Strict models, byte/member/depth/count/NFC/control/bidi bounds | Native SDK/parser defect |
| SSRF/DNS rebinding/redirect | Exact registry origin/path, global-IP validation, no redirects/proxy inheritance, production egress prerequisite | DNS/connect TOCTOU without egress proxy |
| Forged Agent Card/artifact | Detached JWS verification, card/key/cert pin, task/peer/capability/content/citation provenance | Partner PKI not qualified |
| MIME/URL exfiltration | Text/JSON allowlist; raw bytes and external artifact URLs quarantined | Future format admission risk |
| Denial of wallet | Reserve quota before network; request/cost/byte/concurrency/time/page/event bounds and circuit | Distributed rate service deferred |
| Crash/timeout after delivery | Intent first, stable idempotency/fence, explicit ambiguity, observe-before-retry | Peer may expose insufficient observation |
| Revoked/drifted peer result | Reauthorize trust revision after wait; stale fence rejection and quarantine | External work cannot be undone |
| MCP SDK telemetry leak | Remove default request middleware; manual fixed spans only | SDK internals/client spans require upgrade review |

Public federation, production PKI/token brokerage, partner qualification, deployment,
and independent conformance/security certification remain unproven.

## Layer 14 deployment threats

| Threat | Control | Residual/unproven boundary |
|---|---|---|
| Mutable/substituted release | OCI digest, SPDX, vulnerability/license/secret gates, keyless signature/provenance, admission identity | Registry/GitHub/Sigstore compromise; protected branch configuration |
| Privileged workload/host escape | restricted PSS/CEL, non-root/read-only/drop-all/seccomp, no host resources | Node/runtime/CNI/admission operation not live-qualified |
| Broad Kubernetes authority | explicit tokenless accounts; one narrow sandbox Role; projected audience-bound controller token | Cloud/IAM/RBAC drift and break-glass |
| Egress bypass/DNS rebinding | namespace default deny and named boundary proxies/private endpoints | Enforcing CNI/proxy/firewall evidence required |
| Temporal payload/history leak | opaque bounded values, codec required, TLS server name, API key/mTLS refs, no custom search attributes | Key/namespace/vendor operations and traffic analysis |
| Incompatible workflow rollout | patch markers, replay fixtures, pinned Worker Deployment/build ID, old worker drain | Long-lived production history corpus unproven |
| Retry/scale storm | queue isolation, Activity/task-queue rate and concurrency, slow scale-down, DB headroom | Workload capacity/load and external quota behavior unmeasured |
| Migration lock/rewrite outage | checksum/advisory lock, additive expand-contract, separate backfill | Large production tables/replication lag unmeasured |
| Backup silently unusable | vault/object lock reference, isolated chain/sequence verification and rebuild runbook | Live RDS PITR/cross-account/cross-region restore unproven |
| Split brain | one writer, source fence, monotonic generation, restore verification before route | Second region and partition/clock/DNS chaos unproven |
| Framework recovery treated as truth | rebuild/reconcile from application ledger; checkpoints/history never audit | Operator bypass outside application |
| Telemetry/UI/protocol leaks | fixed allowlists, automatic tracing disabled, TLS ingress, boundary proxies | Live IdP/session/PKI/partner/SLO operations unproven |

The checked-in production digest is an offline render fixture and must not be promoted.
No source commit signature, real cloud apply, managed failover, production PKI,
load/chaos, on-call, penetration, accessibility, or compliance effectiveness claim is
made.
