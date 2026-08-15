# Framework state and enterprise authority

## Ownership matrix

| Data or decision | Owner | May appear in checkpoint? | Authoritative there? |
|---|---|---:|---:|
| Node progress and intermediate findings | LangGraph | Yes | For graph resumption only |
| Identity and tenant access | Application identity/policy | Minimal routing context | No |
| Run authorization | `PolicyPort` | No grant stored | No |
| Budget reservation | `BudgetPort` | No | No |
| Evidence access decision | `EvidencePort` | Evidence copy may | No |
| Duplicate suppression | `IdempotencyPort` | No | No |
| Hypothesis/citations | Domain + critic | Yes | Candidate output only |
| Approval request/decision | `ApprovalPort` | Proposal may | No |
| Fencing token | Future durable effect layer | Never in Layer 1 | No |
| Effect receipt and verification | Future effect/reconciliation layer | Never in Layer 1 | No |
| Audit | `AuditPort` | No | No |
| Trace/eval | OTel/Langfuse adapters | Counts/status only | No |

## Required call order

1. Delivery code constructs identity from trusted headers/session middleware, not the
   body.
2. Policy authorizes the action for the identity's tenant.
3. Idempotency claims the tenant/request key.
4. Budget reserves once for the opaque thread reference.
5. Evidence collection scopes by tenant and the service checks every returned item.
6. LangGraph receives data but no authority object.
7. The application opens approval from a proposal after the graph returns.
8. Audit records the application outcome.

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

Layer 1 names these ports and deliberately supplies no shortcut around them.
