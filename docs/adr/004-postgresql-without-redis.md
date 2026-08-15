# ADR 004: Prepare PostgreSQL checkpoints and omit Redis

- Status: accepted
- Date: 2026-08-15

## Context

Durable LangGraph state needs a production database. Future tenant metadata, durable
audit projections, and vector evidence also favor relational controls. Redis would
add another state owner and server license/operations decision without a Layer 1
cache, rate-limit, or pub/sub requirement.

## Decision

Use the PostgreSQL 17 line with pgvector 0.8.6 in the pinned local image. Provide
`langgraph-checkpoint-postgres` 3.1.2 and Psycopg 3.3.4 as an optional adapter.
Keep the network-free demo on memory checkpoints. Do not add Redis or its client.
Do not implement vector retrieval until evidence tenancy, provenance, and relevance
evals exist.

## Consequences

Layer 2 now supplies application migrations, a non-bypass runtime role, forced tenant
RLS, quota/audit repositories, and an RLS overlay for checkpoint tables as described
by [ADR 006](006-postgresql-rls-and-application-audit.md). Operators must still design
encryption, HA, backup/restore, retention, pruning, erasure, and regional policy. The
checkpoint tables remain framework state, not audit or authority tables. pgvector
being available is not a claim that Layer 2 uses embeddings.

## Escape

`OrchestratorPort` isolates saver choice. SQL data must remain exportable, and
enterprise authority stores should have application-owned schemas independent of the
LangGraph saver.
