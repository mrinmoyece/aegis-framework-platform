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
