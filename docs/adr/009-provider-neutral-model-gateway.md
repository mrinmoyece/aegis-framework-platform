# ADR 009: Use official provider SDKs behind an application model gateway

- Status: accepted
- Date: 2026-08-15

## Context

Layer 4 needs structured OpenAI and Anthropic paths, deterministic routing, fallback,
budget reservation, usage reconciliation, safety containment, and hermetic evaluation.
No provider framework may become tenant policy, pricing, budget, audit, usage, or health
truth. Provider retries must not multiply the Temporal Activity retry tree.

Current stable candidates were checked against Python 3.13-3.14, Pydantic 2.13.4,
LangChain Core 1.5.5, LangGraph 1.2.11, and Temporal SDK 1.31.0.

## Decision

Use exact optional SDKs `openai==3.1.0` and `anthropic==0.122.0`, each constructed with
`max_retries=0` and bounded timeout. Keep vendor requests, responses, exceptions, and
secret resolution in `provider_adapters.py`. The application-owned `ModelGateway`
validates neutral contracts, current tenant model policy, catalog capability/pricing,
token/context bounds, tool allowlists, route order, worst-case reservation, durable call
intent, settlement, fallback, rate/concurrency limits, circuit state, and stale results.

Pydantic validates strict output. One policy-bounded repair is permitted. LangGraph nodes
use `GatewayStructuredModel`; they receive only allowlisted evidence projections and
cannot create identity, roles, policy, approval, credentials, or effects.

PostgreSQL owns forced-RLS policy/catalog projections, immutable reservations/call facts,
usage/cost projections, and derived health. A requested call without settlement remains
an explicit ambiguous-billing window. No exactly-once billing claim is made.

## Rejected alternatives

- LiteLLM 1.98.0 conflicts with OpenAI 3.x, adds boto3/tiktoken/aiohttp and overlapping
  routing/retry/telemetry ownership.
- Instructor 1.16.0 conflicts with OpenAI 3.x, pins an older Anthropic extra, and adds a
  Tenacity repair/retry axis already owned by Aegis.
- LangChain provider packages add message/runtime coupling and automatic tracing risk
  without removing the application controls.
- Portkey and OpenRouter add an external call-path authority, retry/configuration plane,
  and prompt/completion observability risk.

## Consequences and escape

Two provider SDK dependencies and adapter qualification remain. Live credentials,
provider/model qualification, regional data-processing review, tokenizer conformance,
price-feed operations, and load tests are deferred. Replacing either SDK requires only a
`ModelProviderAdapter`; replacing routing/storage requires `ModelControlStore`.
Application contracts and immutable facts remain usable without either provider.
