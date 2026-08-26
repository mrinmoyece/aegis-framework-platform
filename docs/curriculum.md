# Layer 2 curriculum

## Learning outcomes

After this layer, an engineer should be able to:

1. separate authentication identity from current application authorization;
2. explain why verified token roles still are not authoritative tenant grants;
3. implement JWT BCP defenses for issuer, audience, algorithm, key ID and time;
4. design bounded JWKS refresh and fail-closed rotation;
5. model human and workload principals with immutable purpose-bound grants;
6. evaluate deny-by-default tenant, action, purpose and risk policy;
7. use PostgreSQL forced RLS with a non-bypass runtime role;
8. prevent transaction/pool tenant context leakage;
9. distinguish application audit and quota from framework checkpoints;
10. test cross-tenant, concurrency, mutation and exporter attacks deterministically.

## Suggested sequence

| Module | Read | Lab | Qualification question |
|---|---|---|---|
| Identity boundary | ADR 005, `identity.py` | Forge algorithm/audience/time claims | Which token claims may establish authority? |
| Grant governance | `access.py`, `authorization.py` | Revoke a grant/version and retry | Why reload grants on every authentication? |
| Delivery | `api.py` | Attempt tenant enumeration and oversized bodies | Why is readiness separate from liveness? |
| PostgreSQL tenancy | ADR 006, migration | Run RLS and pool leakage probes | Why is `FORCE ROW LEVEL SECURITY` required? |
| Quota | `PostgresRepository.reserve` | Race ten reservations for five units | Which lock owns retries? |
| Audit | audit migration/repository | Attempt update/delete and verify chain | Why is a checkpoint not audit evidence? |
| Graph boundary | `service.py`, `graph.py` | Attempt cross-tenant thread rebinding | Can graph output change current policy? |
| Privacy | `safety.py`, exporter tests | Inject identifiers/secrets into attributes | Where must redaction occur? |

## Practical exercises

1. Add a second trusted issuer without using token data to construct a JWKS URL.
2. Add a low-risk read-only purpose and prove an incident grant cannot use it for
   writes.
3. Advance a principal grant version and show that an old signed token fails.
4. Remove `FORCE ROW LEVEL SECURITY` in a disposable branch and explain which role
   could observe rows.
5. Add a saver table in a simulated framework upgrade and update the RLS
   qualification test.
6. Design—but do not implement—a Vault resolver that cannot expose values to graph
   state or observability.

## Assessment rubric

- **Pass:** all deterministic unit/eval gates and local PostgreSQL integration pass;
  the engineer correctly identifies every authority owner.
- **Strong pass:** adds an attack case with a fail-closed implementation and explains
  retry, tenant and redaction semantics.
- **Not qualified:** treats IdP roles, LangGraph checkpoints, traces, or API payloads
  as current authorization/audit truth, or claims production evidence from the local
  Keycloak/PostgreSQL profiles.
