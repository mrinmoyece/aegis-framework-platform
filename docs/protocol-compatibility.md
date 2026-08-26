# MCP and A2A compatibility

| Protocol | Primary target | Official Python SDK | Supported adapter surface | Deliberately excluded |
|---|---|---|---|---|
| MCP | `2026-07-28` | `mcp==2.0.0` | `server/discover`, per-request version/capability negotiation, official server/tool types, stdio, stateless Streamable HTTP, tools/resources pagination, progress/cancel, bounded shutdown | Deprecated HTTP+SSE, removed ping/logging, roots/sampling/logging, experimental Tasks |
| MCP legacy | `2025-11-25` | SDK auto/legacy mode | `initialize` compatibility for registered peers only | Model-supplied executable/transport config, unregistered dynamic discovery |
| A2A | protocol `1.0`, spec tag `v1.0.1` | `a2a-sdk==1.1.2` | signed Agent Card discovery, JSON-RPC/SSE, HTTP+JSON/SSE, gRPC route/client mechanics, task send/get/list/subscribe/cancel, artifact projection | protocol `0.3` fallback, public registry discovery, push webhooks until qualified |

## Negotiation policy

- MCP clients register exact supported revisions and required capabilities. An
  unsupported result fails closed. Server-reported instructions, descriptions, tools,
  and capabilities remain untrusted data and never change registry policy.
- MCP local stdio uses an administrator-pinned absolute executable, argv, working
  directory, executable digest, and named environment references. No shell or
  model-supplied command is accepted.
- MCP network transport is exact HTTPS origin/path, no redirects or environment proxy,
  authenticated by secret reference, and bound to certificate/server-name pins. A
  secure injected HTTP factory must enforce DNS/IP/rebinding and mTLS.
- A2A always sends/requires `A2A-Version: 1.0`; missing-header fallback to `0.3` is not
  accepted. Registered transport preference and card digest override peer preference.
- Agent Cards must be signed and pinned. Card signatures authenticate card metadata,
  not task content or application authority. Artifact provenance is independently
  pinned to peer, card, capability, task, content digest, and citations.

## Lifecycle mapping

MCP's experimental Tasks extension is not used. Long-running MCP work returns an
application-owned opaque handle and uses curated status/cancel tools. A2A task states
map to the neutral Aegis task state; `AUTH_REQUIRED` is input-required data, never an
authorization grant. Poll or snapshot-first subscribe reconciles an ambiguous A2A
delivery. Broken streams never imply success.

Production enablement requires independent SDK/spec compatibility tests, partner
qualification, PKI/key rotation, distributed replay/idempotency/quota enforcement,
qualified DNS/egress, and conformance/security certification.
