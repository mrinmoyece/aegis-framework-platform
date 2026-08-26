# Layer 12 browser and BFF security

## Trust boundary

The browser receives bounded redacted view models. It never receives a backend bearer
token, tenant grant, raw evidence, credential, effect receipt payload, or reusable
authorization. UI permissions explain affordances only; every read and mutation is
server-authorized against current identity, tenant, purpose, risk, policy, and ledger.

## Session boundary

- authorization code shape with one-use PKCE S256, state, nonce, and five-minute bound;
- Secure, HttpOnly, SameSite=Strict, path `/`, `__Host-aegis-session` cookie;
- session-bound CSRF plus exact trusted Origin for state changes;
- rotation on login and tenant switch; logout deletion; thirty-minute expiry;
- anti-enumerating resource/tenant `404`;
- no localStorage/sessionStorage bearer credential;
- deterministic fake only outside production; production readiness fails closed.

The fake does not perform a live token exchange and its in-memory repository is neither
distributed nor durable. A deployment adapter must use encrypted server-side tokens,
current grant resolution, bounded refresh rotation/reuse detection, back-channel/end
session handling where supported, shared expiry/revocation, and audited failure.

## Browser controls

CSP denies default, object, base, frame, cross-origin connect, inline/eval script, and
unreviewed form targets. HSTS, no-referrer, nosniff, frame denial, permissions policy,
no-store HTML/API, and immutable fingerprinted asset caching are applied centrally.
No third-party analytics or automatic LangGraph/LangChain tracing is present.

React text escaping is the only evidence rendering path. Central helpers restrict
same-origin URLs, reviewed bounded downloads, safe filenames, CSV formula prefixes,
bounded clipboard writes, redacted error messages, and no-payload telemetry. Source and
built CSP gates reject inline handlers/scripts and authored HTML sinks.

## Mutation invariants

Review/typed confirmation is not approval. The request includes exact digests,
expected status, current server-time expiry, and an idempotency key; the server remains
authoritative. Double submit is disabled, conflicts require refresh/re-review, agents and
request creators cannot self-approve, and ambiguity is never mapped to success.

## Deferred qualification

Live IdP/browser/logout/rotation, production TLS/proxy, distributed sessions, deployment,
independent penetration and accessibility audits, managed telemetry, load/chaos,
MCP/A2A, and compliance certification remain unproven.

Layer 14 supplies internal TLS ingress shape, body/rate/connection/time limits,
non-root/read-only Pods, PDB/HPA/spread, default-deny networking, and digest admission.
It does not implement the live OIDC exchange or durable shared session repository, so
the production `/operator/readyz` remains intentionally unavailable. Proxy trust,
certificate rotation, browser/IdP logout, session KMS/replication, WAF/rate identity,
penetration, and assistive-technology qualification remain activation gates.
