# Layer 15 adversarial and security assessment

`qualification/adversarial-assessment.json` maps executable cases to eleven attack
families: OIDC/JWKS and confused deputy, prompt/evidence/memory poisoning, model/tool/
schema attacks, SSRF/DNS/redirect, path/archive/shell, approval forgery/duplicate
effects, sandbox isolation/resources, protocol drift/escalation/revocation, UI
XSS/CSRF/cache, telemetry/backup secrets and supply chain.

The review fixed durable workflow tenant leakage/backend divergence, restored durable
trace propagation, aligned event page defaults, rejected hash-valid unknown event
schemas, bounded PostgreSQL projection rebuild, removed a demo role over-grant and
made approval/support/rebuild routes enforce the explicit outer authorization
boundary. Independent review then corrected Kubernetes container command composition,
restored deterministic workflow IDs and prevented stale PostgreSQL artifact reads.

No high-confidence exploitable in-repository issue remains from this review. This is
not a penetration test. Live IdP, TLS ingress, cloud IAM, Kubernetes isolation,
provider/partner endpoints, browser matrix, backup media, registry/admission and
organizational access remain independently reviewable surfaces.

Residual risks, exact owners, expiry and fail-closed handling are in
`qualification/residual-risks.json`. Container CVE waivers remain governed separately
by `security/vulnerability-waivers.json`; fixed, expired, broad, unused or unmatched
waivers fail the supply-chain gate.
