# ADR 005: Use PyJWT and keep authorization application-owned

- Status: accepted
- Date: 2026-08-15

## Context

Layer 2 must validate OIDC JWT access tokens without making an identity provider,
LangGraph, or a policy framework authoritative for tenant grants. The verifier needs
hard-coded algorithms, exact issuer/audience checks, NumericDate validation, required
`kid`, bounded JWKS refresh, rotation, and current grant resolution. Python 3.13 and
3.14 support and inspectable failure semantics are required.

PyJWT 2.13.0, Authlib 1.7.2, joserfc 1.7.4, Casbin 1.43.0, and OPA 1.19.0 were
reviewed from official sources on 2026-08-15. Authlib now delegates JOSE to joserfc;
both are broader than this verifier. Casbin does not authenticate or manage grants
and does not declare Python 3.13/3.14 support. OPA would add a second service and
policy lifecycle before the policy surface needs one.

## Decision

Use exact-pinned `PyJWT[crypto]==2.13.0` and `cryptography==50.0.0` for JOSE
cryptography and registered-claim checks. Keep a small application-owned bounded JWKS
cache because refresh cooldown, maximum key count, no stale-on-error behavior, and
configured-endpoint transport policy are product security decisions.

Tokens select only a configured issuer and identify `(issuer, subject)`. The
application database resolves the principal, tenant, principal kind, grant version,
roles, permissions, purposes, risk ceilings, revocation, and expiry. Token role claims
are ignored. Every operation evaluates the current tenant policy and a current
purpose-bound grant. No policy result is stored as authority in graph state.

## Consequences

The application owns more control code than an IdP SDK-only integration, but stale
tokens and mutable group claims cannot silently become current authorization. Live IdP
rotation behavior remains environment-gated and is not production evidence.

## Escape

`AuthenticatorPort`, `IdentityRepositoryPort`, and `PolicyPort` isolate PyJWT, the
IdP, and policy implementation. A future joserfc, Authlib, Cedar, Casbin, or OPA
adapter must pass the same attack suite and cannot move tenant/grant authority into
the framework.
