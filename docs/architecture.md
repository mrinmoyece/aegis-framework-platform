# Layer 1 architecture

## Product journey

The canonical target journey is:

1. checkout telemetry raises a tenant-scoped alert;
2. evidence is collected and integrity-addressed;
3. telemetry and change specialists investigate in parallel;
4. hypotheses cite evidence;
5. a critic rejects contradictions, malformed output, and invalid citations;
6. a remediation proposal crosses an approval boundary;
7. an approved, fenced effect executes;
8. independent verification reconciles intended and observed state;
9. durable audit records the complete chain.

Layer 1 executes steps 1–6 only, where step 6 means **opening a pending approval
request**. It appends educational in-memory audit events for the executed steps. It
has no approval decision endpoint, effect, production verification, or durable audit
store, and makes no claim that steps 7–9 run.

## Components

```mermaid
flowchart TB
  subgraph Delivery
    CLI[CLI]
    API[FastAPI]
  end
  subgraph Enterprise["Enterprise-owned application controls"]
    SVC[InvestigationService]
    ID[IdentityContext]
    POL[PolicyPort]
    BUD[BudgetPort]
    EVI[EvidencePort]
    IDEM[IdempotencyPort]
    APP[ApprovalPort]
    AUD[AuditPort]
    EFF[EffectPort: disabled]
    OBS[ObservabilityPort]
  end
  subgraph Framework["Framework-owned mechanics"]
    LG[LangGraph adapter]
    CO[Coordinator]
    TS[Telemetry specialist]
    CS[Change specialist]
    CR[Critic]
    CP[(Checkpoint saver)]
  end

  CLI --> SVC
  API --> SVC
  ID --> SVC
  SVC --> POL
  SVC --> IDEM
  SVC --> BUD
  SVC --> EVI
  SVC --> LG
  SVC --> APP
  SVC --> AUD
  SVC --> OBS
  LG --> CO
  CO --> TS
  CO --> CS
  TS --> CR
  CS --> CR
  LG --> CP
  APP -. no call path .-> EFF
```

`ports.py` is the stable application seam. `graph.py`, `postgres.py`, and
`langfuse_adapter.py` contain framework-specific behavior. `adapters.py` contains
deterministic local enterprise-control doubles; they demonstrate boundaries but are
not production storage.

## Sequence

```mermaid
sequenceDiagram
  actor R as Responder
  participant A as CLI / FastAPI
  participant S as InvestigationService
  participant P as Policy + budget
  participant E as Evidence port
  participant G as LangGraph
  participant T as Telemetry specialist
  participant C as Change specialist
  participant K as Critic
  participant V as Checkpointer
  participant Q as Approval boundary
  participant U as Audit port

  R->>A: alert + identity headers
  A->>S: typed request and IdentityContext
  S->>P: authorize and reserve
  P-->>S: explicit allow + reservation
  S->>E: collect(tenant, incident)
  E-->>S: sorted tenant evidence
  S->>G: invoke typed state + opaque thread_ref
  G->>V: checkpoint input/super-steps
  G->>T: sanitized structured facts
  G->>C: sanitized structured facts
  par same LangGraph super-step
    T-->>K: typed cited finding
    C-->>K: typed cited finding
  end
  K-->>G: verdict + hypothesis + proposal
  G-->>S: application result
  S->>Q: open pending approval
  S->>U: append outcome
  S-->>A: cited result
  Note over Q,U: No approval decision or effect execution in Layer 1
```

## Graph semantics

The graph has one bounded pass:

```mermaid
flowchart LR
  START --> coordinator
  coordinator --> telemetry_specialist
  coordinator --> change_specialist
  telemetry_specialist --> critic
  change_specialist --> critic
  critic --> END
```

The two specialists share a LangGraph super-step and join before the critic.
Reducers sort/deduplicate findings, so scheduler completion order cannot change the
result. There is no model-directed routing and no loop; `recursion_limit=8` is a
secondary guard. The structured fake model consumes only allowlisted facts.

## Checkpoint contract

`InMemorySaver` is the default only so the demo and tests have no external service.
The state is made of JSON-compatible records, and tests enable
`LANGGRAPH_STRICT_MSGPACK=true` as defense in depth. Both memory and PostgreSQL
adapters explicitly install a strict `JsonPlusSerializer`, so runtime safety does not
depend on that environment variable. The optional PostgreSQL adapter calls
`PostgresSaver.setup()` and is the production-shaped checkpoint path.

A checkpoint guarantees recoverable graph state at framework super-step boundaries
when the selected saver persists successfully. It does not guarantee:

- authorization or tenant access to that state;
- idempotency of external calls or effects;
- approval integrity;
- append-only audit;
- exactly-once execution;
- retention, erasure, backup, or regional policy;
- safe streaming—LangGraph value streaming can expose private channels unless
  outputs are explicitly filtered.

The service reauthorizes checkpoint reads and derives the opaque, tenant-bound thread
reference rather than accepting an arbitrary one.

## Replaceability

- Replace LangGraph by implementing `OrchestratorPort`; domain models and controls
  do not import LangGraph.
- Replace Langfuse by implementing `ObservabilityPort`; OpenTelemetry remains the
  portable signal format.
- Replace PostgreSQL saver construction inside `postgres.py`; it is not an
  authorization or audit database.
- Add OpenAI or Anthropic through `StructuredModelPort`; provider output still passes
  Pydantic and citation validation.
- Introduce Temporal outside the graph when durable effects arrive. Temporal owns the
  effect workflow; LangGraph owns investigation. Neither nests the other's retries.
