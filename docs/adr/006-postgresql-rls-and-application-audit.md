# ADR 006: Use forced PostgreSQL RLS and application-owned audit

- Status: accepted
- Date: 2026-08-15

## Context

LangGraph's PostgreSQL saver persists framework state but its tables do not represent
principals, grants, policy, quota, secrets, audit, or authorization. Layer 2 needs
tenant isolation that remains active when application predicates are missing, and
connection-pool reuse must not retain tenant context.

## Decision

Create application-owned PostgreSQL tables for tenants, principals, grants, policies,
quotas, quota reservations, secret references, checkpoint thread ownership, audit
heads, and audit events. Every tenant table enables and forces RLS using a
transaction-local `aegis.tenant_id`. The runtime switches to the `aegis_runtime`
group role, which is `NOSUPERUSER` and `NOBYPASSRLS`. Pool configure/reset hooks
verify those properties and reject leaked context.

Migrations use an advisory lock, exact checksum history, exact constraints, and
idempotent DDL. Policy and quota updates use optimistic versions. Quota reservations
take a reservation advisory lock and quota-row lock. Audit appends lock a per-tenant
head, redact attributes, hash-chain records, and deny update/delete through both
privileges and a mutation trigger.

After `PostgresSaver.setup()` runs administratively, its three tenant-bearing tables
receive forced RLS policies joined to application-owned checkpoint thread ownership.
Runtime graph calls use one tenant transaction. Saver setup never runs as the runtime
role.

## Consequences

PostgreSQL 17 and Psycopg 3.3.4 remain operational dependencies. The default unit
suite excludes the environment-gated PostgreSQL adapter from its coverage
denominator; a dedicated Compose/CI job proves forced RLS, reset safety, immutable
audit, quota races, and checkpoint isolation against PostgreSQL.

Backups, restore drills, retention/erasure execution, HA, regional deployment, and
database credential rotation remain operator responsibilities and are unproven.

## Escape

Application repository ports and SQL-exportable tables isolate PostgreSQL. Replacing
the LangGraph saver does not migrate or weaken application authority or audit.
