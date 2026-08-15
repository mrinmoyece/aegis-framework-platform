# Layer 1 limitations

- Evidence, policy, budget, approval, idempotency, and audit adapters are in-memory
  educational doubles. They are neither distributed nor durable.
- The default LangGraph saver is `InMemorySaver`; process restart loses checkpoints.
  PostgreSQL construction and Compose are supplied, but the demo API does not switch
  itself to PostgreSQL. The local profile publishes PostgreSQL on port `55432`.
- PostgreSQL has no tenant RLS, backup, HA, retention, migration, or erasure policy in
  this layer. pgvector is installed in the image but no embedding/vector code exists.
- No live OpenAI or Anthropic adapter is installed. The fake model proves structured
  contracts and safety routing, not model quality.
- Injection detection is deliberately simple. It demonstrates containment by
  minimization and abstention, not universal prompt-injection detection.
- Content hashes detect citation mismatch but do not prove source authenticity.
- Hash-chain audit is process-local and not an enterprise ledger.
- Langfuse is opt-in. Its service is not included in Compose, and automatic
  LangGraph/LangChain capture is prohibited because it may export graph state.
- No authentication middleware exists; the API trusts identity headers supplied by a
  secure upstream in any real deployment.
- The educational API budget is in-memory, configurable at app construction, and
  defaults to 10,000 units per fixture tenant. It resets with the process and is not
  a distributed quota.
- There is no approval decision endpoint, effect execution, fencing, independent
  verification, reconciliation, or rollback.
- Temporal, MCP, A2A, browser/UI, retrieval, memory, and human workflow are deferred.
- Runtime measurements are single-process local measurements, not load, reliability,
  or cost benchmarks.
- Dependency vulnerability audit needs network access to current advisory data;
  `make ci` remains network-free and `make security` is a separate gate.

These are deliberate scope limits, not implied framework capabilities.
