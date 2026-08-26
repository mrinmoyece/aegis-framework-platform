# ADR 003: Use OpenTelemetry with opt-in Langfuse

- Status: accepted
- Date: 2026-08-15

## Context

Layer 1 needs portable system telemetry plus framework-aware trace/eval viewing.
LangSmith is tightly integrated with LangGraph but its backend is commercial and
self-hosting is an Enterprise feature. Langfuse has an MIT core, self-host path, and
an OpenTelemetry-native v4 SDK. Running both would duplicate trace/eval ownership.

## Decision

OpenTelemetry 1.44.0 is the application instrumentation boundary. Langfuse 4.14.4 is
the primary optional external trace/eval backend. Do not use decorators or automatic
LangGraph/LangChain instrumentation. Manually send fixed operation names, tenant
buckets, counts, status, and aggregate eval results. Block OpenAI, Anthropic, and
LangChain instrumentation scopes and apply masking as defense in depth.

Do not configure LangSmith. Its client may appear transitively through LangGraph, but
no Layer 1 code calls it.

Layer 4 provider calls follow the same boundary: automatic OpenAI, Anthropic and
LangChain instrumentation stays disabled. Langfuse may receive only manual redacted OTel
counts/status and aggregate eval outcomes; the application model ledger owns usage/cost.

## Consequences

The default demo and all tests/evals are offline. Operators must deliberately supply
Langfuse credentials and accept its backend operations/license model. OpenTelemetry
does not enforce redaction or cardinality; application tests do.

## Escape

Replace `ObservabilityPort` or route OTLP to another backend. Domain/service code and
eval expectations remain unchanged.
