# Layer 2 threat model

## Assets and boundaries

Assets are signing-key trust, authoritative principals/tenants/grants, policy and
quota state, secret references, evidence, checkpoint state, pending approvals,
application audit, and telemetry. Boundaries exist at FastAPI, OIDC/JWKS, PostgreSQL
connections/RLS, evidence/model adapters, LangGraph saver state, observability
exporters, approval, and the absent effect service.

The bearer network is untrusted. JWT claims other than verified issuer/subject and
required protocol claims do not grant application authority. Tenant claims only scope
an RLS lookup whose result must match the authoritative principal.

## Threats and controls

| Threat | Layer 2 control | Residual gap |
|---|---|---|
| `alg=none` or algorithm confusion | Hard-coded asymmetric algorithms; header algorithm and JWK algorithm must agree | Library vulnerabilities remain possible |
| Forged issuer/audience | Exact configured issuer and audience verification | IdP configuration mistakes remain operator risk |
| Expired/future/long token | Explicit `exp`, `iat`, optional `nbf`, skew, and maximum lifetime | Clock synchronization is external |
| Missing/attacker `kid` | Required bounded `kid`; configured issuer cache only | Key compromise still requires IdP response |
| JWKS flood/rotation race | Response/key/ID bounds, TTL, cooldown, forced unknown-key refresh, no stale-on-error | Live production rotation is unproven |
| Token role escalation | Token role/group claims ignored; roles derive from current application grants | Grant administration UI is not implemented |
| Stale/revoked grant | Token grant version must match principal; current active non-expired grants reloaded | Revocation propagation depends on IdP token issuance and DB availability |
| Human/workload confusion | Principal kind is authoritative principal data | Workload credential issuance/attestation is external |
| Cross-tenant confused deputy | Identity tenant, resource tenant, purpose and policy must agree | Evidence connector implementations remain future work |
| Tenant/body/header spoofing | Tenant never comes from body or legacy identity headers | Reverse-proxy/TLS deployment is unproven |
| IDOR/enumeration | Tenant resources authorize before lookup; missing/forbidden both return `404` | Timing equalization is not load-tested |
| Pool tenant leakage | Transaction-local tenant setting, post-transaction check, reset hook | Driver/server upgrades require regression tests |
| Owner/RLS bypass | Runtime `SET ROLE` verifies `NOSUPERUSER` and `NOBYPASSRLS`; every tenant table forces RLS | DBA/superuser remains an operational trust boundary |
| Quota race/retry bypass | Reservation advisory lock, quota row lock, durable allow/deny result | Multi-region quota design is absent |
| Audit update/delete | Runtime privilege denial, forced RLS, mutation trigger, per-tenant hash chain | No WORM media or external witness |
| Audit secret/identifier leak | Derived actor/request references and attribute allowlist | Audit retention/access operations remain external |
| Secret exfiltration | Only tenant-bound references exist; no resolver or values reach graph/API | KMS/Vault integration and rotation are absent |
| Cross-tenant checkpoint | Application owner table plus forced RLS on saver tables | Saver schema upgrades require policy revalidation |
| Framework state grants authority | Policy is evaluated before graph; graph receives no grant object | Application call-order changes remain security-sensitive |
| Prompt injection/model fabrication | Fact allowlists, abstention, exact evidence ID/locator/hash citations | Detection is not universal; source signatures absent |
| Trace leakage | Fixed names, allowlisted counts/status, tenant buckets, blocked automatic capture | Exporter/operator configuration still matters |
| Oversized/malformed API input | Body/token/JWKS/model bounds and strict Pydantic models | Edge proxy limits are separate |
| Dependency/action substitution | Exact pins, lockfile, action SHAs, image digests, audit/CodeQL | Provenance signing/admission is later work |

## Abuse cases

1. An attacker signs `HS256` using a public RSA key. The configured algorithm rejects
   the header before key use.
2. A valid old token carries grant version 3 after revocation advances the principal
   to version 4. Authentication fails before policy.
3. A token claims tenant beta for an issuer/subject registered in tenant alpha. The
   tenant-scoped lookup cannot produce a matching principal.
4. A responder requests a beta tenant route. Policy denies before lookup and the API
   returns the same `404` as a missing object.
5. A pooled connection returns after tenant alpha. `SET LOCAL` clears at commit and
   both transaction and reset checks require no tenant value before reuse.
6. Two workers reserve the final quota unit. The quota row lock permits one update;
   retries with the same reservation return its durable decision.
7. A graph attempts to reuse another tenant's thread. Owner uniqueness rejects the
   insert while RLS hides the existing row and saver state.
8. A privileged writer attempts to update an audit event. The mutation trigger fails
   the statement.

## Explicitly unproven

Production IdP rotation, IdP HA, token revocation latency under load, TLS/ingress,
database HA/backups/restore, cross-region quotas, WORM audit witnessing, KMS/Vault
resolution, secret rotation, retention/erasure execution, deployment admission,
external model/evidence credentials, approval decisions, effects, fencing,
verification, and reconciliation are not proven by Layer 2.
