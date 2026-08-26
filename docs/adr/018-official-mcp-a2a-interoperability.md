# ADR 018: Official MCP and A2A SDKs behind application trust controls

## Status

Accepted for Layer 13 on 2026-08-17.

## Context

Aegis must interoperate with external tools and agents without making a protocol
message, Agent Card, tool description, framework task, or peer assertion an enterprise
authority. Internal investigation orchestration remains LangGraph inside Temporal
Activities. PostgreSQL application facts remain trust, idempotency, quota, audit,
artifact, and outcome truth.

The implementation refresh found these current official releases:

- MCP specification `2026-07-28`, official Python SDK `mcp==2.0.0`;
- A2A protocol `1.0`, specification errata tag `v1.0.1`, official Python SDK
  `a2a-sdk==1.1.2`.

MCP `2026-07-28` is stateless and negotiates version/capabilities per request after
`server/discover`; legacy `initialize` remains an SDK compatibility mode. Standard
transports are stdio and Streamable HTTP. Legacy HTTP+SSE is deprecated. MCP Tasks are
experimental and absent from the Python SDK, so application tasks remain Aegis-owned.

A2A 1.0 is protobuf-first and supports JSON-RPC/SSE, HTTP+JSON/SSE, and gRPC. Agent
Cards may be detached-JWS signed, but the specification does not sign task messages or
artifacts. Aegis therefore adds pinned card/schema/certificate/key digests and its own
artifact provenance contract.

## Decision

1. Use official SDK wire models, negotiation, serialization, route factories, stdio,
   Streamable HTTP, JSON-RPC, HTTP+JSON, and gRPC mechanics only in
   `protocol_adapters.py`.
2. Keep neutral principal, capability, resource, tool, task, message, artifact,
   citation, status, error, idempotency, policy, audit, and trust contracts in
   application modules.
3. Expose exactly seven curated MCP tools. Destructive requests become a cited Layer 7
   proposal only. They never open approval or invoke `ActionPort`.
4. Expose exactly four A2A skills: bounded investigation, status, artifact read, and
   proposal submission. External peers never become internal LangGraph roles.
5. Require an explicit tenant trust registry with owner, environment, tier, expiry,
   review, card/schema/certificate/key pins, classifications, risks, egress, quotas,
   revision invalidation, quarantine, revocation, and emergency disable.
6. Establish workload identity outside protocol content. Validate issuer, audience,
   scope, tenant reference, purpose, proof, expiry, replay, and application RBAC.
   Production readiness fails closed without distributed replay and mTLS prerequisites.
7. Persist intent before network I/O. Temporal schedules bounded Activities and
   reconciliation; application facts own at-least-once idempotency, ambiguity, fencing,
   cancellation, cursor/resume, quarantine, and terminal outcome.
8. Keep raw protocol content out of Temporal history and the application fact ledger.
   Only opaque references, counts, reason codes, and stable digests enter those stores.
9. Remove the MCP SDK's default request-level OTel middleware because it exports request
   IDs and dynamic tool names outside the Aegis semantic allowlist. Emit only manual
   fixed `aegis.mcp.call` and `aegis.a2a.task` observations.
10. Reject raw bytes and external artifact URLs by default. Accept bounded NFC text or
    JSON data only after schema, size, Unicode, provenance, citation, MIME, and digest
    checks.

## Consequences

The official SDKs remove current wire-protocol, protobuf, route, streaming, discovery,
and transport maintenance. They do not remove application trust, authentication,
authorization, tenant isolation, SSRF, budget, ledger, audit, provenance, approval, or
effect controls.

The dependency closure grows materially. MCP and A2A SDK changes remain adapter
compatibility work, and modern MCP versus legacy initialization requires explicit tests.
Provider-neutral ports, neutral persisted contracts, and isolated adapter imports
preserve replacement paths.

Public federation, production PKI/token brokerage, partner qualification, deployment,
and independent conformance/security certification remain deferred.

## Sources

Accessed 2026-08-17:

- [MCP 2026-07-28 specification](https://modelcontextprotocol.io/specification/2026-07-28)
- [MCP Python SDK v2.0.0](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.0.0)
- [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [MCP Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
- [A2A 1.0 specification](https://a2a-protocol.org/latest/specification/)
- [A2A specification v1.0.1](https://github.com/a2aproject/A2A/releases/tag/v1.0.1)
- [A2A Python SDK v1.1.2](https://github.com/a2aproject/a2a-python/releases/tag/v1.1.2)
