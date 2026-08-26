# Layer 6 qualification status

## Delivered

- immutable additive application events with aggregate sequence, tenant cursor, dual
  hash chains, expected-version concurrency, legacy upcast, and deterministic rebuild;
- tenant-scoped idempotency, inbox/outbox, lease claims, retries, dead-letter state,
  projection checkpoints, and redacted cursor API;
- Temporal SDK 1.31.0 workflow around one bounded LangGraph Activity lifecycle;
- durable wait/resume/cancel/timeout, duplicate signal handling, Activity heartbeat and
  retry bounds, workflow patch marker, payload limits, and replay test;
- current policy checks at commands and immediately before every Activity;
- forced RLS/non-bypass runtime role for all Layer 3 PostgreSQL tables;
- optional digest-pinned Temporal 1.29.1 Compose server and CI integration job;
- provider-neutral worker runtime that drains explicitly configured trusted tenant
  partitions; it is an embeddable runtime rather than a production CLI because live
  connector/model qualification and credential brokering are deliberately deferred;
- manual OTel/optional Langfuse privacy boundary with no payload export;
- immutable provider-neutral message/content/tool/schema/safety/usage/pricing/error
  contracts with canonical digests and tenant/run/purpose bindings;
- deny-by-default tenant model policy/catalog, deterministic routing, exact capability and
  price declarations, worst-case reservation, stable call intent, billing reconciliation,
  fallback/circuit/rate/concurrency controls, and stale-result rejection;
- deterministic fake plus official OpenAI 3.1.0 and Anthropic 0.122.0 adapters with SDK
  retries disabled and secret references only;
- strict Pydantic structured generation in LangGraph nodes, evidence framing, bounded
  repair, exact tool allowlists, citation rejection, and safe abstention;
- forced-RLS model policy/catalog/reservation/call/usage/health tables and authorized
  redacted model operations APIs.
- immutable versioned source/query/page/cursor/provenance/evidence/citation/bundle
  contracts with tenant/incident/run/time/trust/policy/credential/retention bindings;
- disabled-by-default Dynatrace and GitHub App HTTPX adapters, official Kubernetes
  client adapter, and neutral trusted-runbook adapter;
- exact origins/resources, tenant secret references, DNS/IP/redirect/proxy, timeout,
  response byte/MIME/schema, page/record, cancellation and rate-limit controls;
- opaque Temporal evidence-query workflow/Activities with page intent/result,
  heartbeat, cancellation, retry ownership, cursor checkpoints, stale-result rejection
  and reconciliation-required outcomes;
- safe JSON/YAML/text/ZIP ingestion with canonical hashes, tenant/incident deduplication,
  secret/PII/injection scanner hooks, redaction, classification, quarantine and retention
  references;
- deterministic non-LLM timeline/shared-fact/conflict/freshness/missing-source
  correlation integrated into LangGraph specialist context and extended citations;
- forced-RLS evidence source/query/cursor/metadata/quarantine/bundle/rebuild tables,
  authorized redacted query/cursor endpoints, and application-ledger projection rebuild;
- fixed-name OTel/Langfuse evidence observations containing only source kind,
  status/counts and reconciliation flags.
- immutable typed reasoning artifacts and fixed-role capability/transition policy;
- four-specialist LangGraph fan-out/fan-in, critic/planner/verification routing,
  graph-version replay binding, deterministic duplicate suppression and safe terminals;
- application-ledger run/task/artifact/decision facts, fencing, forced-RLS projections,
  deterministic rebuild and authorized redacted cursor reads;
- one Temporal-owned bounded graph Activity with no graph/provider retry overlap;
- fixed-name redacted graph-node and model observations.

## Qualification snapshot

- 226 deterministic tests pass with 90.01% meaningful branch coverage;
- 31 deterministic evals pass, including pagination, poisoning, source revocation,
  deterministic non-causal correlation and private-destination rejection;
- eight local PostgreSQL integration tests cover forced RLS/tenant isolation,
  immutable audit/events/model/evidence/orchestration facts, quota/model races,
  checkpoint isolation, dedicated-pool concurrency, crash ambiguity/reconciliation
  and deterministic rebuild;
- three local Temporal integration tests cover no-worker recovery, Activity retry,
  duplicate signal, cancellation, timeout, replay, opaque evidence pagination, and the
  real application outbox/Activity/projection path;
- one Keycloak compatibility test remains environment-gated.

Counts are refreshed by the final release run and recorded in
`comparison/layer5-metrics.json`.

## Not proven

Production Temporal HA/upgrade/failover, PostgreSQL HA/PITR/restore, multi-region order,
load/capacity, WORM witnessing, retention/erasure execution, live IdP rotation, live
connector/model credentials and provider qualification, production DNS/egress,
complex-document parser isolation,
approvals/effects/fencing/reconciliation, sandbox tools, memory/RAG, UI/BFF, MCP/A2A,
and deployment admission remain unproven.
