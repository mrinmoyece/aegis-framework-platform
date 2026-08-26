# ADR 020: Ledger-grounded enterprise qualification

Status: accepted

## Context

Layers 1-14 provide application controls, framework adapters, operator surfaces and
deployment foundations. A final qualification must exercise them together without
turning framework history, local timing, deterministic fakes or CI artifacts into a
production claim.

## Decision

Layer 15 adds one network-free canonical runner, `make qualification`. It composes the
real application service, LangGraph investigator, governed eval cases, exact
two-person approval/effect service, memory lifecycle, application ledger and replay
debugger. Deterministic fault cuts use the existing evaluation contracts. Bounded
wall-clock profiles are CI regression guards; PostgreSQL/pgvector, Temporal, browser
and restore profiles remain separate environment gates.

Machine-readable source manifests live in `qualification/`. Generated evidence lives
under `build/qualification/` and is never authoritative application state. Readiness
uses only `Implemented`, `Locally Verified`, `Environment-Gated`,
`Live Evidence Required` and `Deferred`. There is no aggregate score.

## Consequences

- Local replay, fault convergence, security cases and latency budgets fail CI.
- Live identity, managed recovery, sandbox isolation, provider/partner operation,
  production capacity/SLO/on-call and independent reviews remain hard blockers.
- Framework state remains replaceable; replay uses application events.
- Qualification output excludes raw evidence, prompts, credentials and identity
  fields and makes no certification or production-effect claim.

## Alternatives rejected

- A green percentage: it can hide a single go-live blocker.
- Production-shaped mocks presented as live evidence: false assurance.
- Reimplementing subsystems in a test-only simulator: it would not qualify product
  paths.
- Letting Temporal, LangGraph, traces or the qualification archive become audit
  authority: violates the application-ledger boundary.
