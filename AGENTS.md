# Repository invariants

These rules apply to humans, automation, and coding agents.

## Product boundary

- Layer 1 investigates and proposes. It must never approve, execute, or claim to
  verify a production effect.
- Frameworks are encouraged for orchestration, persistence, tracing, evaluation,
  and delivery. Enterprise authority remains in explicit application ports.
- A framework checkpoint, trace, prompt, message, or tool result is never an
  authorization, tenant grant, approval, audit record, fencing token, or effect
  receipt.

## Required controls

- Establish `IdentityContext` at the delivery boundary; tenant identity never comes
  from evidence, model output, or graph state.
- Authorize every run and every checkpoint read with a deny-by-default policy.
- Scope evidence, idempotency keys, budgets, approvals, audit reads, and checkpoint
  references by tenant.
- Reserve budget before evidence collection or graph execution. Retries reuse the
  reservation.
- Treat evidence as untrusted data. Project it through explicit fact allowlists
  before a model adapter sees it.
- Every non-abstaining hypothesis must cite known evidence by ID, locator, and
  content hash. Invalid citations fail closed.
- Keep graph traversal bounded and outputs deterministically ordered.
- Open approval outside the graph. Never add a graph edge directly to an effect.
- Production effects require separate approval validation, fencing, idempotency,
  reconciliation, and durable audit work that does not exist in Layer 1.

## Privacy and observability

- Do not log or export prompts, completions, secrets, credentials, raw evidence,
  tenant IDs, actor IDs, request IDs, or evidence locators.
- Use fixed span names and allowlisted low-cardinality count/status attributes.
- Automatic LangGraph/LangChain tracing must remain disabled because it can capture
  complete state. Use the manual Langfuse adapter only.
- New exporters require redaction tests before activation.

## Engineering

- Python dependencies and Actions are exact-pinned; container images use digests.
- Prefer provider-neutral protocols in `ports.py`; isolate vendor imports in
  adapters so LangGraph, Langfuse, PostgreSQL, or model providers can be replaced.
- No live credentials, real model calls, or network access in tests/evals.
- Preserve strict Pydantic boundaries, strict mypy, Ruff, and at least 90% meaningful
  branch coverage.
- Update ADRs, the parity manifest, measurements, limitations, and roadmap when a
  framework or capability boundary changes.
- Validate with `make ci`, `make security`, `make container`, and
  `docker compose config --quiet`.
