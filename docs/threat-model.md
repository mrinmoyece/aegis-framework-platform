# Layer 4 threat model

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

## Explicitly unproven

Temporal mTLS/authentication, production namespace/task-queue isolation, HA/failover,
server schema upgrades, worker version routing, backup/restore, multi-cluster
replication, load limits, and disaster recovery are not proven. PostgreSQL HA/PITR,
external event witnessing, retention/erasure, live connectors/models, approvals,
effects, fencing, reconciliation, sandbox tools, UI, MCP/A2A, and deployment are also
unproven. Official provider adapters are present, but live credentials, regional data
handling, model/version qualification, tokenizer accuracy, pricing feed freshness,
provider retention/abuse policy, and load/failover are unproven.
