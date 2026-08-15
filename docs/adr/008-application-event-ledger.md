# ADR 008: Use an application-owned immutable event ledger and transactional delivery

- Status: accepted
- Date: 2026-08-15

## Context

Temporal history and LangGraph checkpoints optimize framework recovery. Neither is a
tenant-authorized, append-only application fact store, and either framework can be
replaced or lose history. Layer 3 requires expected-version concurrency, commit-order
tenant cursors, independently verifiable events, duplicate command handling,
transactional framework delivery, and rebuildable API projections.

## Decision

Add application event envelopes with tenant/aggregate sequence, tenant cursor,
schema version, opaque actor/correlation/causation references, bounded JSON, aggregate
previous hash, tenant previous hash, and record hash.

PostgreSQL appends lock the aggregate head and tenant cursor, reject a stale expected
version, and atomically write events, idempotency, outbox, timeline/run projection, and
heads. Application events, idempotency facts, and inbox facts are immutable to the
runtime and guarded by triggers. All tables force tenant RLS. The runtime role remains
non-superuser and non-`BYPASSRLS`.

Inbox suppresses duplicate boundary commands. Outbox rows have bounded lease claims,
attempt counters, stable tokens, explicit retries, and dead-letter status. Read models
are derived; replay is deterministic and records cursor/hash/version checkpoints.
Legacy version-zero rows require an explicit upcaster.

## Consequences

The application owns more schema and reducer code than a framework-history-only design.
That code preserves enterprise truth across Temporal/LangGraph replacement and supports
authorized API reads without querying framework state. Hash chains detect mutation or
reordering but are not signatures, external witnesses, WORM retention, or legal proof.

## Escape

Canonical envelopes are JSON/SQL exportable. Repository ports and deterministic
reducers permit another transactional database if it preserves expected-version,
tenant-order, integrity, immutability, and RLS semantics.
