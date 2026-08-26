# Interview questions

## Architecture and frameworks

1. **Why use LangGraph instead of a custom event ledger?**
   LangGraph removes graph scheduling, synchronized parallel branches, reducers, and
   checkpoint APIs. It does not replace enterprise authority or an evidentiary
   ledger, so the comparison measures saved orchestration code against added
   framework state/upgrade coupling.

2. **Why not use Temporal for every node?**
   Temporal is best for durable workflows across workers and long waits. LangGraph is
   best for investigation state around model/specialist nodes. Letting both own the
   same retries obscures idempotency and failure semantics.

3. **When should Temporal enter?**
   When approval, execution, verification, or reconciliation must survive process
   and deployment boundaries. The investigation becomes one bounded Activity.

4. **What does a LangGraph checkpoint guarantee?**
   Recoverable graph state at saver-defined super-step boundaries. It does not grant
   access, prove approval, create exactly-once effects, or replace audit/retention.

5. **How is fan-in deterministic if branches run in parallel?**
   The reducer deduplicates by stable finding ID and sorts by specialist/ID before
   the critic.

6. **Why a fixed graph rather than model-directed routing?**
   The use case is known and safety-critical. Fixed topology makes budget, maximum
   work, testing, and authority review tractable.

## Enterprise controls

7. **Why can identity not live in graph state?**
   State is mutable, replayable framework data. Authorization must be evaluated
   against a trusted current identity/policy at the application boundary.

8. **Why reauthorize duplicate reads?**
   A prior caller's permission does not prove the current caller still has access.

9. **Why is a pending approval separate from the proposal?**
   Separation prevents model/graph output from self-authorizing. Approval has its own
   actor, policy, status, persistence, and future signature/fencing requirements.

10. **What prevents direct rollback?**
    No graph edge or API route reaches an effect. `DisabledEffectAdapter` rejects even
    a forged approved grant.

11. **Why are idempotency and checkpoints different?**
    Checkpoints track graph progress. Idempotency decides whether a tenant/request
    operation may execute again and detects input conflicts.

12. **Why does retry reuse budget?**
    Charging the same reserved work twice harms availability; granting fresh budget
    lets failures bypass quota. The tenant/thread reservation is idempotent.

13. **What must be added before production effects?**
    Durable signed approval, separation of duties, idempotency, fencing, credential
    brokering, sandbox/egress policy, independent verification, reconciliation, and
    durable audit.

## Safety and correctness

14. **How are prompt injections contained?**
    Raw/untrusted text never reaches the model view; facts are allowlisted. Detection
    forces critic abstention, and no effect path exists.

15. **Why validate locator and hash, not just citation ID?**
    A reused or fabricated ID could point at different content. The triple binds the
    hypothesis to the collected snapshot.

16. **Why require two specialists?**
    The thin slice demonstrates corroboration and contradiction. A single
    non-abstaining finding cannot produce the remediation proposal.

17. **What happens on malformed model output?**
    Pydantic rejects it at the node boundary, the node records a named abstention,
    and the critic cannot propose.

18. **Why propagate unexpected framework exceptions?**
    Turning infrastructure defects into an empty “successful” result hides outages.
    The adapter raises a typed application failure and audit records failure.

## Observability and lock-in

19. **Why Langfuse instead of LangSmith?**
    Langfuse's MIT core, self-host option, and OTel-native SDK fit portability.
    LangSmith is tighter with LangGraph but its platform/self-host path is commercial.

20. **Why not enable automatic LangGraph tracing?**
    It can capture complete state, including evidence. Manual fixed-name spans export
    only buckets, counts, and status.

21. **Does OpenTelemetry perform redaction?**
    No. The application allowlist/mask and tests enforce privacy before export.

22. **How would LangGraph be replaced?**
    Implement `OrchestratorPort`, preserve domain results and control call order, then
    pass the same scenario/eval/checkpoint contract.

23. **What is the main framework lock-in surface?**
    Graph topology/reducer semantics, checkpoint schema/serialization, error model,
    and upgrade behavior. Those imports are isolated in adapter files.

24. **Why no Redis?**
    There is no measured cache, rate-limit, or pub/sub requirement. PostgreSQL already
    serves durable checkpoint needs; another state owner would add operations and
    licensing decisions without value.

## Layer 12 operator UI and BFF

**L12-1. Why reject a browser OIDC client?**
The BFF keeps access/refresh tokens out of JavaScript and web storage. The browser has
only a rotated HttpOnly same-origin session and session-bound CSRF value.

**L12-2. Why is hiding a button not authorization?**
Roles can be stale or revoked and DOM requests can be forged. UX is deny-default, but
the server reloads current identity/policy and anti-enumerates unauthorized resources.

**L12-3. What must tenant switch destroy?**
In-flight requests, query data, polling watermark/retry state, review/confirmation
state, and session/CSRF material before the new tenant fetch.

**L12-4. Why use polling rather than SSE?**
No durable server stream cursor exists. Bounded polling can validate schemas, dedupe by
generation, reject out-of-order state, cap reconnect, and tear down safely. SSE should
enter only with equivalent resume and tenant/auth semantics.

**L12-5. Why can approval still be denied after complete review?**
Review is presentation, not a grant. Current server policy, role, SoD, quorum, expiry,
version and immutable digests remain authoritative.

**L12-6. What is the candid framework trade-off?**
TanStack removes generic query/router/table mechanics and reduces authored LOC, but adds
three runtime dependencies and a larger bundle than custom Layer 13. All enterprise
security and authority controls remain custom and framework-neutral.

## Layer 13 MCP and A2A interoperability

**L13-1. Why are official protocol messages not application authority?**
The SDK proves wire shape and transport mechanics. Tenant, role, purpose, policy,
approval, fencing, quota and audit come from current application stores. Peer content
is untrusted even after authenticated transport.

**L13-2. What changed in MCP `2026-07-28`?**
Modern MCP is stateless, uses `server/discover` and per-request version/capability
metadata, and removes session/GET-SSE/server-request assumptions. The SDK retains
registered legacy `initialize` compatibility. Experimental Tasks are not an application
durability mechanism.

**L13-3. What does a signed A2A Agent Card prove?**
It can prove integrity under a reviewed key. It does not grant tenant access, sign task
artifacts, qualify a partner, or authorize the advertised capabilities. Aegis pins the
card and independently validates every artifact/task.

**L13-4. Why persist intent before protocol I/O?**
At-least-once Activities and timeouts can leave an unknown outcome. Stable request,
trust, policy, idempotency and fence digests let recovery observe/reconcile without a
blind duplicate.

**L13-5. Can an external agent request remediation?**
It can submit a cited proposal candidate. Layer 7 application policy may record it for
independent review. The protocol cannot open approval, satisfy quorum, fence, execute,
verify, or claim a production effect.

**L13-6. What did the frameworks remove?**
Official SDKs remove current wire models, protobuf/ProtoJSON, discovery, version
negotiation, route factories, stdio/HTTP/gRPC and stream mechanics. Trust registry,
identity, SSRF, quotas, ledger, provenance, reconciliation and operator controls remain
custom. This layer uses real SDK surfaces; the pinned custom Layer 14 only imports SDK
packages as presence markers and hand-writes the wire mapping.

**L10-1. Why is an evaluation report not production truth?**
    It is versioned release evidence over synthetic fixtures and deterministic
    adapters. Runtime state, authorization, approval, effects and audit still come
    from their application authorities.

**L10-2. Why can a quality average not compensate for one safety failure?**
    Hard safety scorers use exact thresholds and are non-waivable. Every failed
    canonical control produces a hard regression regardless of aggregate quality.

**L10-3. How is a baseline update governed?**
    The command requires a complete passing run, reviewer and reason. The baseline
    binds exact suite, dataset, case set, scorer direction, threshold and tolerance.

**L10-4. Why keep model judges out of required CI?**
    They are probabilistic, provider/network dependent and vulnerable to the same
    untrusted content. A future isolated judge can supplement reviewed labels but
    cannot be the sole safety gate.

**L10-5. Why retain custom evaluation code instead of adopting LangSmith/DeepEval?**
    Domain invariants concern tenant authority, citations, budgets, approvals,
    effects and recovery. Hosted or judge-oriented tools do not remove those
    controls; neutral contracts keep CI offline and replaceable.

## Layer 2 identity, tenancy and durability

25. **Why are verified token roles ignored?**
    A valid signature proves the issuer made a claim, not that the application's
    current tenant grant remains active. Roles, purposes, risk ceilings and
    permissions come from the current application principal/grant records.

26. **What is authoritative about `(issuer, subject)`?**
    The exact configured issuer and verified subject form the external identity key.
    Application storage maps that key to one tenant and principal kind. Subject alone
    is not globally authoritative.

27. **Why include a grant version in the token?**
    Revocation/role change advances the application principal version. An older signed
    token then fails before policy instead of retaining stale authorization until
    expiry.

28. **Why can an unverified tenant claim scope an RLS lookup?**
    It cannot grant access by itself. It only chooses a denied-by-default partition;
    the exact verified issuer/subject must resolve inside it and return the same
    authoritative tenant and grant version.

29. **Which JWKS behaviors are custom and why?**
    Maximum response/key/ID size, TTL, unknown-key cooldown, HTTPS/loopback policy and
    no stale-on-error behavior are product risk choices. PyJWT supplies JOSE
    cryptography and registered-claim validation.

30. **Why not Casbin or OPA in Layer 2?**
    The policy surface is a small immutable role map plus current purpose/risk/grant
    checks. Casbin does not authenticate/manage grants; OPA adds another service.
    `PolicyPort` preserves a later escape when scale justifies one.

31. **Why both forced RLS and application predicates?**
    Predicates communicate intent and support indexes. Forced RLS remains a database
    guard when a predicate is omitted and prevents table owners from silently
    bypassing policy (except PostgreSQL superusers, which remain an operator boundary).

32. **How does pool reset prevent tenant leakage?**
    Tenant context is set with transaction-local `set_config`. Commit/rollback clears
    it; the transaction helper verifies that, and the pool reset hook rejects any
    surviving value before reuse.

33. **How are quota races serialized?**
    A transaction advisory-locks the tenant/reservation key for retry identity, then
    locks the tenant quota row. The durable reservation stores both allow and deny
    decisions.

34. **Why is audit per-tenant hash-chained?**
    It detects deletion/reordering within each tenant without creating cross-tenant
    ordering dependencies. RLS, privilege denial and a trigger enforce immutability;
    external witnessing remains a gap.

35. **How are LangGraph PostgreSQL tables tenant-protected?**
    An application owner table binds opaque thread IDs to tenants. Forced RLS policies
    on saver tables join each `thread_id` to that owner under transaction tenant
    context.

36. **What does the local Keycloak test prove?**
    One loopback token follows the same strict verifier. It does not prove production
    IdP rotation, HA, outage behavior, revocation latency or deployment.

## Layer 3 durability and Temporal

37. **Why introduce Temporal now but not for each LangGraph node?**
    Cross-process recovery, timers, signals, Activity heartbeat/retry, and replay are
    now requirements. The cognitive graph remains one bounded Activity so Temporal and
    LangGraph do not own the same retry tree.

38. **Why is Temporal history not the run-status API?**
    History is framework scheduling state with different retention/access semantics.
    Product status is an authorized application fact derived from immutable events and
    remains available across framework replacement.

39. **What makes the tenant cursor commit-safe?**
    The tenant cursor row is locked and advanced in the same transaction that inserts
    events, outbox, idempotency and projections. A rollback leaves no committed gap.

40. **Why keep aggregate and tenant hash chains?**
    Aggregate order detects per-run mutation/reordering; tenant order provides a
    deterministic export/rebuild cursor across aggregates. Neither replaces signatures
    or external witnessing.

41. **Where is exactly-once achieved?**
    Nowhere universally. Commands and Activity results are application-idempotent.
    Temporal Activities and external delivery remain at-least-once; future effects need
    fencing, idempotency and reconciliation.

42. **How is a duplicate signal handled?**
    The application inbox deduplicates command ID and the workflow maintains a bounded
    processed-command set. The Activity still reloads the command and current signaller.

43. **What happens if policy is revoked during a wait?**
    The resume Activity reevaluates current authority and fails closed. The historical
    start decision cannot authorize later work.

44. **How does a worker crash recover?**
    Temporal retains workflow/Activity schedule. Another compatible worker replays
    deterministic history and retries the Activity using the same operation and budget
    reservation IDs.

45. **Why no continue-as-new?**
    One bounded graph, at most 32 signals and a two-day execution cap keep history
    bounded. Adding continue-as-new without measured need complicates signal handoff.

46. **How is workflow code upgraded?**
    Preserve deterministic paths with `workflow.patched` or current Worker Versioning,
    replay representative histories in CI, then deprecate/remove patches only after old
    executions drain.

47. **What if Temporal history is lost but PostgreSQL survives?**
    Reconcile pending application intent with the stable workflow/outbox ID or record an
    explicit platform failure. Never infer completion from missing history.

48. **What if LangGraph checkpoints are lost?**
    The bounded graph Activity may rerun under the same operation and budget IDs. Its
    result is accepted only through the application aggregate state machine.

49. **What custom code remains after Temporal adoption?**
    Event envelopes, hash/sequence rules, RLS, identity/policy/budget, inbox/outbox,
    idempotency, stale-result handling, projections/API, redaction, audit, and future
    effect controls.

50. **What is the Temporal escape strategy?**
    Consume the same application outbox, emit the same event transitions, implement
    `ActivityOperations`, and pass retry/timer/signal/recovery/replay equivalence. No
    application fact must be extracted from Temporal first.

## Layer 4 model gateway

51. **Why use official SDKs rather than LiteLLM or Instructor?**
    The official SDKs remove provider wire-protocol code and allow retries to be disabled.
    LiteLLM and Instructor currently conflict with OpenAI 3.x and add routing/repair/retry
    axes while leaving Aegis policy, budget, ledger and safety controls intact.

52. **What is authoritative for model usage and cost?**
    Immutable application reservation and call-settlement facts under tenant RLS. SDK
    usage is untrusted provider input until validated and settled. Langfuse, provider
    dashboards, traces, and health projections are not application ledger truth.

53. **Why reserve the worst case before network intent?**
    Fallbacks and structured repairs can each incur cost. Reserving only the first route
    lets failures exceed policy. The reservation covers the bounded route/repair envelope
    and is reused by stable call identity.

54. **What happens after a timeout or crash?**
    The provider may have billed. Aegis records or derives billing ambiguity, blocks a
    silent duplicate provider call, and requires reconciliation. It does not claim
    exactly-once billing.

55. **Why recheck policy after the provider returns?**
    Authority may be revoked while I/O is in flight. Usage can still require settlement,
    but stale output cannot enter graph state.

56. **Why is provider health not truth?**
    It is a replaceable projection from a bounded sample of application outcomes. It may
    guide availability routing but cannot grant model access, prove an SLA, or establish
    cost.

57. **How are tools and structured output constrained?**
    Tools must exactly match an application allowlist. JSON Schema and Pydantic reject
    undeclared fields and bounds; citations are checked against known evidence triples.
    No output schema contains identity, role, policy, approval, credential, or effect
    authority.

58. **How can the provider stack be replaced?**
    Implement `ModelProviderAdapter` for the neutral request/result contracts. Routing,
    policy, budget, immutable facts, APIs, graph integration and evals remain unchanged.

## Layer 5 evidence connectors and correlation

59. **Why use HTTPX directly for Dynatrace and GitHub?**
    There is no suitable official general Python SDK for either. HTTPX removes connection
    and stream mechanics while exact paths, auth, redirects, pagination, rate limits,
    response bounds and exceptions remain visible behind `HttpTransport`.

60. **Why is the official Kubernetes client not a security boundary?**
    It decodes API objects. Aegis still fixes the server without exec kubeconfig plugins,
    binds tenant secrets, restricts RBAC/namespaces/resources, owns continue-token
    expiry/relist and bounds responses/cancellation.

61. **What happens after a worker dies between connector response and result commit?**
    The ledger contains page intent without result. Retry detects ambiguity, does not
    issue a second call, and records `reconciliation_required`.

62. **How is evidence prevented from becoming instructions?**
    Text is canonicalized/scanned, secrets and PII are redacted or quarantined, facts are
    allowlisted, quarantine cannot enter graph state, and the model contract labels
    evidence untrusted with provenance-bound citations.

63. **Can deterministic correlation claim a deployment caused an outage?**
    No. It emits temporal/shared-fact links with `causal=false`; conflicts, missing and
    stale sources remain explicit and unsupported causality requires abstention.

64. **Why reject LangChain, Unstructured, and LlamaIndex loaders?**
    They add broad parser/network/metadata/RAG surfaces without removing source authority,
    provenance, sandboxing, scanning, retention, RLS or citation controls.

65. **What may an evidence API reveal?**
    Authorized source kind, status, bounded counts, failure code, page number, cursor
    availability and expiry—not tenant IDs, cursor values, URLs, locators, evidence,
    scanner matches or credentials.

66. **What did frameworks remove in Layer 5?**
    HTTP pooling/streaming, Kubernetes wire/object decoding, JWT cryptography, YAML
    syntax parsing, Temporal mechanics and LangGraph mechanics. Most secure-connector
    controls remain custom; neutral ports preserve escape.

## Layer 11 observability and replay

133. **Why is OTel not application truth?**
     It transports operational signals that may be sampled, dropped, delayed, forged
     or unavailable. Authorization, approval, audit and effect receipts remain explicit
     application facts.
134. **Why keep Langfuse optional and reject LangSmith here?**
     Langfuse provides manual sanitized model/graph UX with an OTLP escape. LangSmith
     adds a proprietary self-hosted control plane and automatic capture pressure without
     removing semantic, privacy, SLO or replay controls.
135. **How are retry and replay prevented from double-counting availability?**
     Logical-operation counters accept a stable digest once; retry/redelivery counters
     are separate. Replayed projections do not emit new logical success.
136. **What happens when telemetry export fails?**
     Bounded queues/retries/drop counts protect memory and correctness continues.
     Operational readiness is degraded while identity/governance/ledger readiness keeps
     its own fail-closed semantics.
137. **What validates a replay?**
     Tenant cursor, aggregate sequence, schema version, aggregate and tenant previous
     hashes, record hash, duplicate IDs and deterministic reducer output.
138. **Can replay execute a model or effect?**
     No. It is read-only over strict application events and has no external-operation
     ports.
139. **Why are safety violations excluded from error budget?**
     Availability budget cannot authorize tenant leakage, unsafe execution, missing
     approval/fence, integrity failure or unreconciled cleanup.
140. **What is the Layer 11 escape strategy?**
     Replace exporters/backends behind W3C/OTLP/OpenMetrics and provisioned JSON, while
     preserving application semantic policy and canonical ledger replay.

## Layer 6 governed specialist orchestration

67. **Why add four specialists without adding CrewAI or AutoGen?**
    LangGraph already supplies the required static graph mechanics. Another agent
    framework would overlap scheduling, messages, retries, memory and tracing without
    replacing application role, artifact, citation, ledger or tenant controls.

68. **Why are roles an enum rather than model-created agents?**
    Fixed roles make maximum work, evidence access, outputs, budgets and reviewable
    authority explicit. Unknown roles and capabilities deny before dispatch.

69. **What did LangGraph genuinely remove?**
    Custom DAG scheduling, parallel super-step execution, synchronized fan-in, reducer
    invocation, conditional routing, checkpoint serialization and history traversal.
    It did not remove governance or application persistence.

70. **Why not use `Send`, `Command`, subgraphs, or interrupts here?**
    They are stable APIs, but the topology has exactly four known branches and two
    deterministic routes. Static edges are simpler to audit. Interrupts cannot represent
    approval; approval remains an external future service.

71. **What makes a reasoning artifact durable and neutral?**
    A strict schema-versioned envelope binds tenant, incident, run, task, producer role,
    typed payload, provenance digests, deterministic ordinal and canonical SHA-256
    digest. No LangGraph or provider type crosses the boundary.

72. **How is duplicate specialist work prevented?**
    The application ledger records dispatch intent before a model call and a fenced
    result afterward. A completed result is cached; unresolved intent requires
    reconciliation instead of a silent second call.

73. **What happens when one model adapter raises unexpectedly?**
    The node boundary emits a named abstention and fixed low-cardinality failure status;
    the critic cannot accept a failed core specialist. The worker process remains alive.

74. **How is graph replay versioned?**
    Every run binds graph version `6.0.0`, tenant/run/thread, request and canonical input
    digest. Incompatible checkpoints fail closed. Application artifacts can rebuild
    projections even if the checkpoint is discarded.

75. **Why does Temporal still wrap one graph Activity?**
    Temporal owns cross-process scheduling, retry, heartbeat, signals and cancellation.
    Per-node Temporal Activities or its experimental LangGraph plugin would overlap the
    existing graph/application retry and intent boundaries.

76. **Can the verification agent claim a rollback worked?**
    No. It emits a future verification plan with
    `production_verification_performed=false`. There is no approval or effect edge,
    fencing token, executor, reconciler or receipt.

## Layer 7 approvals and controlled effects

77. **Why is LangGraph not used for human approval?**
    A checkpoint or interrupt is cognitive framework state, not a current authenticated
    human decision, SoD/quorum record, expiry timer, tenant audit fact or authorization.
    LangGraph may propose only; the application approval service owns decisions.

78. **What exact scope does approval bind?**
    Tenant/run/incident, plan and every action digest, target fingerprint, risk/blast
    radius, pre/postconditions, dry-run/retry/idempotency/compensation, citations, critic
    status and current policy/role/quota snapshot.

79. **Why do policy or role changes invalidate approval?**
    A prior human accepted a specific policy context. Reusing it after authority or risk
    changed silently expands the decision beyond its immutable rationale.

80. **What does Temporal remove from the approval lifecycle?**
    Custom durable wait/poller, timer, signal history/deduplication, Activity scheduling,
    retry/backoff, heartbeat, cancellation delivery, crash recovery and replay mechanics.

81. **What approval/effect controls remain custom after Temporal?**
    Identity/policy, SoD/quorum, exact digests, RLS/audit, quota, idempotency, fencing,
    target allowlists, dry-run, reconciliation, verification, rollback and redaction.

82. **Why does a signal contain only a command reference?**
    Signal history is replayable framework input. The Activity reloads the persisted
    decision and current signaller/policy instead of trusting signal fields.

83. **Where is exactly-once effect execution guaranteed?**
    Nowhere. Activities and external APIs are at-least-once. Stable tenant keys,
    observe-before-retry, atomic claims, fencing, read-after-write and reconciliation
    reduce duplicates and make ambiguity explicit.

84. **What can fencing prevent and not prevent?**
    It rejects stale application claims/results. It cannot retract an external request
    already delivered by a stale worker, so reconciliation is still required.

85. **Why persist requested intent before the external call?**
    A crash afterward leaves an inspectable ambiguity window. Persisting only the result
    would make “never called” indistinguishable from “called but result lost.”

86. **Why is provider/API acceptance not verification?**
    Acceptance proves request handling, not restored checkout behavior. Verification must
    use fresh evidence observed after the receipt and satisfy immutable postconditions.

87. **Why is rollout restart the only Kubernetes action?**
    It directly addresses the checkout incident while permitting an exact fixed-shape
    Deployment patch. A generic patch, shell or `kubectl` surface would allow model/caller
    escalation beyond the approved action.

88. **Does rollout restart have a rollback?**
    No intrinsic inverse. The official adapter rejects generic compensation. Rolling back
    an image revision requires another fixed action contract and approval.

89. **How is approval enumeration prevented?**
    Current authorization and forced tenant RLS precede reads; missing, unauthorized and
    cross-tenant resources all return the same `404`, and views redact actors/rationale.

90. **How is Temporal replaced?**
    Consume the same application outbox and opaque command references, implement
    `RemediationActivityOperations`, preserve application facts/`ActionPort`, and pass
    wait/timer/signal/retry/heartbeat/cancel/crash/replay equivalence. Temporal history
    need not be migrated into approval truth.

91. **Why is a Kubernetes namespace not called a sandbox?**
    Containers normally share the host kernel and namespace isolation depends on cluster
    policy. Aegis requires a separately qualified RuntimeClass and admission/network/node
    controls; Kata is recommended for mutually distrustful tenants.

92. **Why use Kubernetes Jobs rather than Docker SDK or subprocess?**
    Jobs provide durable one-shot lifecycle, identity, deadlines, scheduling and official
    API mechanics without exposing a host daemon. Docker socket and subprocess do not
    supply the selected hostile-tenant kernel/filesystem/network boundary.

93. **What does Temporal remove for sandbox execution?**
    Custom Activity scheduling, retry/backoff, heartbeat timeout, durable cancellation,
    ambiguity waits, signal history, crash recovery and workflow replay. It does not remove
    approval, policy, ledger, claims, fencing, artifact trust or reconciliation controls.

94. **Why are exact destinations not enforced by NetworkPolicy alone?**
    Standard NetworkPolicy is CNI-dependent L3/L4 and has no portable FQDN semantics.
    Network none is enforceable; exact DNS destinations require a qualified external proxy
    or equivalent CNI feature and fail closed otherwise.

95. **How is duplicate Job creation handled?**
    Persist intent first, observe the deterministic name, and adopt only an object with the
    exact managed-by, execution, request-digest and fence labels. Anything else is conflict;
    unknown state remains ambiguous.

96. **Why does cleanup bind a provider UID?**
    A name can be deleted and reused. UID preconditions prevent a stale cleanup worker from
    deleting a different Job created under the same deterministic name.

97. **How are sandbox artifacts trusted?**
    They are not. Paths/MIME/count/bytes are allowlisted, content is hashed and scanned,
    secrets are redacted or quarantined, manifests bind tenant/run/task/execution, and
    quarantined records expose no object reference.

98. **Can a successful sandbox output authorize remediation?**
    No. Output is untrusted analysis data, never an approval, policy decision, audit record,
    fencing token, effect receipt, tenant grant or verification of production state.

99. **What is the managed-sandbox tradeoff?**
    E2B/Modal can remove cluster operations and provide strong managed isolation, but add
    vendor image/lifecycle/network/attestation semantics, region/retention/DPA/SLA review,
    remote availability and lock-in. They must pass the same neutral contract suite.

100. **What remains unproven in Layer 8?**
     Live Kata/gVisor isolation, admission/CNI/CSI/proxy/workload identity, node escape,
     cluster upgrades, load/chaos, scanner efficacy, retention deletion, managed vendors,
     and production credentials. Unit manifest tests cannot qualify those controls.

## Layer 9: event-grounded memory and pgvector RAG

101. **Why must a memory candidate bind to accepted or redacted evidence rather than raw
     text?**
     Untrusted or quarantined content must never become a durable memory authority. Binding
     to an evidence ID/digest keeps memory provenance traceable and rejects anything not
     already through the evidence disposition gate.

102. **What fields are banned from every `MemoryFact` payload, and why?**
     Raw text, query text, prompt, completion, tenant ID and locator. Facts are the audit
     trail; leaking any of these would put untrusted or sensitive content directly into an
     immutable, potentially long-lived ledger.

103. **Why is the derived vector/lexical index never authoritative?**
     `InMemoryHybridIndex` and the PostgreSQL `memory_chunks`/cache tables are rebuildable
     projections of `memory_facts`. Losing or corrupting them changes nothing about tenancy,
     retention, or what actually happened; only replaying `reduce_memory` does.

104. **What does `MemoryContext.instruction_boundary` do, and why is it fixed?**
     It is a constant literal prefixed to every retrieved snippet, marking the content as
     untrusted LangGraph state. A model or downstream node must never treat retrieved
     memory as an instruction, approval, or effect trigger.

105. **Why does `tombstone_and_erase` check legal hold before purging anything?**
     Retention/legal obligations must outrank a deletion request. The service raises
     `PolicyDenied` before appending a tombstone fact, purging the derived index, or
     invoking the erase-blob callback whenever `legal_hold_count` is nonzero.

106. **Is `erase_blob` a KMS integration?**
     No. It is an injected callback contract point. This repository does not ship or claim a
     qualified KMS/blob-storage crypto-erasure integration; key rotation and cross-region
     erasure durability are unproven.

107. **Does this framework run a live pgvector similarity query?**
     Yes, at the store layer. `PostgresMemoryStore.hybrid_candidates` implements a single
     forced-RLS SQL query combining cosine ANN distance (`embedding <=> %s::vector`),
     lexical `ts_rank_cd`, recency/quality scoring, and ACL/classification/time/retention
     prefilters into one deterministic weighted score, exercised by a PostgreSQL
     integration test including a cross-tenant/classification isolation assertion. It is
     not yet wired into `MemoryRetrievalService`/`InMemoryMemoryControl` or
     `/v1/memories/retrieve`; production retrieval still serves from
     `InMemoryHybridIndex` until that wiring lands. Final MMR diversification and
     `ContextBudget` selection remain application-owned regardless of candidate source.

108. **Are retrieval and context-build part of the immutable audit trail?**
     Yes. `MemoryRetrievalService` wraps every retrieval and context build, appending
     digest-only `MemoryOperationFact`s (`RETRIEVE_REQUESTED`, `RETRIEVE_COMPLETED`,
     `CONTEXT_BUILT`) with strict per-operation sequencing and idempotent replay to
     `InMemoryMemoryOperationLedger` or the durable, immutable `aegis
     .memory_operation_facts` table. These facts carry only policy/query/result digests —
     never raw query text or content — and are a separate, purpose-built ledger from the
     primary `MemoryFact` ingest/lifecycle ledger; they share the `MemoryFactType` enum
     values but not a table or class. Ingest, supersession, legal hold, tombstone/erasure,
     and now retrieval/context-build are all ledger-audited.

109. **How does `MemoryCompactor` avoid uncited summarization claims?**
     It requires citation coverage over the candidate snippet set; when coverage is
     insufficient it marks `insufficient_context=true` or falls back to a deterministic
     extractive summary rather than fabricate an uncited claim.

110. **What does Temporal's `aegis.memory.v1` workflow add, and what does it not add?**
     Durable retry/backoff/timeout for ingest/compact/purge/rebuild Activities carrying only
     opaque references. It adds no authority: version fencing, legal-hold checks, and fact
     ordering remain enforced entirely by the application lifecycle service.

111. **What is `MemoryAcceptance`, and why does `ingest` require one?**
     An explicit, digested decision record (`disposition` accept/reject, `reviewer_kind`
     human/policy, policy ID/revision/digest, reason code) bound by tenant/memory ID.
     `MemoryLifecycleService.ingest` validates the binding and raises `IntegrityFailure`
     if it is missing or mismatched, so a memory candidate can never become durable from
     evidence disposition alone — a human or policy decision is always on record.

112. **How does `TemporalMemoryActivities` detect a stalled long-running operation?**
     It calls `activity.heartbeat()` immediately, then spawns a background task that
     heartbeats every 10 seconds for the duration of the Activity, against a 30-second
     `heartbeat_timeout`. A worker that stops heartbeating — crash, stuck adapter call —
     is detected and the Activity retried well before the timeout, not only discovered at
     Activity completion.
