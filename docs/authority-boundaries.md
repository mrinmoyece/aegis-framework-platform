# Framework state and enterprise authority

## Ownership matrix

| Data or decision | Owner | May appear in checkpoint? | Authoritative there? |
|---|---|---:|---:|
| Node progress and intermediate findings | LangGraph | Yes | For graph resumption only |
| Issuer/subject authentication | PyJWT adapter + application principal store | Never authoritative | No |
| Tenant, grant version, roles, purposes, risk | Application identity/policy store | Minimal routing context | No |
| Run authorization | `PolicyPort` | No grant stored | No |
| Quota reservation | `BudgetPort` + PostgreSQL | No | No |
| Evidence access decision | `EvidencePort` | Evidence copy may | No |
| Duplicate suppression | `IdempotencyPort` | No | No |
| Hypothesis/citations | Domain + critic | Yes | Candidate output only |
| Approval request/decision | `ApprovalPort` | Proposal may | No |
| Fencing token | Future durable effect layer | Never in Layer 2 | No |
| Effect receipt and verification | Future effect/reconciliation layer | Never in Layer 2 | No |
| Audit | Application PostgreSQL audit | No | No |
| Secret reference | Application tenant store | No secret values | No |
| Trace/eval | OTel/Langfuse adapters | Counts/status only | No |

## Required call order

1. Delivery validates a bearer token against an exact configured issuer, audience,
   algorithm, key ID, signature, and time policy.
2. Application storage resolves `(issuer, subject)` to one active principal/tenant
   and current grant version; token roles are ignored.
3. Policy authorizes the exact tenant/action/purpose/risk using current grants.
4. Idempotency claims the tenant/request key.
5. Quota reserves once for the opaque thread reference.
6. Evidence collection scopes by tenant and the service checks every returned item.
7. LangGraph receives data but no authority object.
8. The application opens approval from a proposal after the graph returns.
9. Durable audit records the redacted application outcome.

Changing this order is a security-sensitive architecture change.

## Why framework persistence is insufficient

Checkpoint availability is useful, but a mutable row containing `"approved": true`
cannot prove who approved, under which policy, at what revision, or whether a fencing
token remains current. A trace backend is optimized for debugging, not evidentiary
retention or access governance. A workflow retry does not make an external API
idempotent. Production layers therefore require:

- tenant RLS and independent authorization;
- signed/append-only durable audit with retention controls;
- separation of proposer and approver;
- idempotency keys and leases;
- fencing before effects;
- reconciliation against observed state;
- supply-chain provenance and deploy policy.

Layer 2 supplies PostgreSQL authority and audit repositories without creating a
shortcut through framework state.

## Secrets boundary

Application records contain only tenant-bound `SecretReference` values such as a
Vault URI. The API, graph, checkpoint, trace, and audit never receive resolved secret
material. A future resolver must authenticate the workload, verify the same tenant,
return credentials only to a narrow provider adapter, and prevent values from entering
models or telemetry. Layer 2 deliberately does not implement secret resolution.
