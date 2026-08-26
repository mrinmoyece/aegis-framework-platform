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
