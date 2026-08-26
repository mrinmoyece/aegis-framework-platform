# ADR 017: Use a same-origin BFF and derived React operator workspace

- Status: accepted
- Date: 2026-08-17

## Context

Layer 11 exposes authenticated, tenant-authorized projections but a browser must not
hold backend bearer tokens or become a second policy, approval, audit, or effect
authority. Operators need accessible, bounded views across every implemented control
plane and explicit safe-failure behavior.

## Decision

Use FastAPI as the same-origin BFF and static delivery boundary. Use React 19.2.8,
TanStack Query 5.101.4, Router 1.170.29 and Table 8.21.3, and Zod 4.4.3. Vite 8.2.1
builds the workspace. No design system, client state framework, second router, browser
OIDC client, or analytics SDK is added.

The BFF owns one-use authorization-code demonstration state with PKCE S256, state and
nonce; rotates a Secure, HttpOnly, SameSite=Strict `__Host-` cookie; binds CSRF to the
session; and checks exact Origin on every mutation. The deterministic adapter is
demo/test only. Production operator readiness returns `503` until a live code exchange
and durable shared session repository are supplied. No browser bearer token exists.

All UI data is a runtime-validated, bounded, derived view. Tenant changes cancel work,
remove tenant query data, rotate session/CSRF material, and fetch the new tenant from an
empty cache. A bounded poller validates each snapshot, uses a generation watermark to
deduplicate and reject out-of-order state, caps reconnect delay/failures, reacts to
online/visibility changes, stops on authentication expiry, and is destroyed on tenant
change.

## Consequences

TanStack removes query lifecycle, route matching, and table rendering code, but adds
bundle weight and library-specific configuration. Enterprise session, tenancy, response
bounds, approval semantics, XSS/download/CSV/clipboard controls, CSP, and accessibility
remain application code. The neutral JSON/Pydantic/Zod contracts and backend ports are
the escape hatch.

Polling is selected instead of SSE because the current API has no durable stream cursor
contract. A future SSE adapter must retain schema validation, resume watermark,
deduplication, ordering, retry bounds, authentication expiry, and tenant teardown.

OIDC live exchange, distributed sessions, TLS proxy behavior, live browsers/IdP,
independent penetration/accessibility audit, deployment, MCP/A2A, and production
qualification remain deferred.
