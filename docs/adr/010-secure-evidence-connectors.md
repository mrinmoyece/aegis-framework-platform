# ADR 010: Use narrow official clients behind an application evidence plane

- Status: accepted
- Date: 2026-08-15

## Context

Layer 5 needs durable read-only evidence from Dynatrace, GitHub, Kubernetes, and
trusted runbooks. Connector frameworks can remove transport or parsing code, but none
establish tenant authority, provenance, safe destinations, durable intent, retention,
or trustworthy citations. Temporal history, SDK pagination, loader metadata, and graph
state cannot become application truth.

Official package and documentation research was refreshed on 2026-08-15. There is no
maintained general-purpose official Dynatrace Python REST SDK and no official GitHub
Python Octokit. Kubernetes publishes an official Python client. Broad document-loader
frameworks add overlapping RAG abstractions, transitive parsers, automatic metadata, or
external document processing without removing the required security controls.

## Decision

Select:

- `httpx==0.28.1` for bounded Dynatrace and GitHub REST transport;
- existing `PyJWT[crypto]==2.13.0` for short-lived GitHub App JWTs;
- optional official `kubernetes==36.0.3`, configured directly without executable
  kubeconfig plugins;
- `PyYAML==6.0.3` with `safe_load`, node/depth/byte bounds, and strict projection;
- Python standard-library UTF-8, JSON, and ZIP handling under explicit limits.

Keep `EvidenceConnector`, source/query/page/cursor/provenance/bundle contracts and the
evidence ledger provider-neutral. Every connector is disabled by default. Configuration
binds tenant, source, exact resources, trust, classification, region, policy revision,
secret reference/version, and bounds.

HTTP destinations come only from administrator configuration. HTTPS origin and host
allowlists, DNS resolution, IPv4/IPv6 public-address checks, optional exact CIDRs,
redirect denial, environment-proxy denial, timeouts, streamed byte caps, MIME checks,
schema validation, cancellation, rate-limit classification, and one retry owner are
application controls. Network egress policy must close the remaining DNS
resolution-to-connect race.

Temporal owns page Activity scheduling, heartbeat, cancellation delivery, and bounded
retry. Its payloads carry only opaque tenant/actor/request/run/query/cursor references.
The application event ledger records query and page intent before I/O and result after
I/O. An unresolved intent becomes `reconciliation_required`; it is not blindly retried.
Current source policy and credential version are checked before a page and before its
result is accepted. Cursor values are AES-GCM encrypted and never returned by APIs.

Ingestion canonicalizes UTF-8/JSON/safe YAML, rejects active or unsupported content,
bounds archives, hashes raw and canonical content, deduplicates by tenant/incident,
runs secret/PII/injection and injected scanning hooks, redacts, classifies, quarantines,
and binds a retention reference. Extracted text is always untrusted data. Loader
metadata is never authority.

Correlation is deterministic and non-LLM. It orders by UTC timestamp/kind/evidence ID,
emits temporal/shared-fact links with `causal=false`, preserves conflicts, and reports
missing or stale required sources. LangGraph specialist context receives the correlation
artifact plus extended citation fields. A non-abstaining claim must still match the
evidence ID, locator, content hash, provenance digest, source, query, and page.

## Rejected alternatives

- `PyGithub==2.9.1`: community-maintained, `requests`/`urllib3` plus additional
  dependencies, and less visibility into token, redirect, pagination, and response
  controls.
- `githubkit==0.16.1`: capable generated HTTPX client, but non-official and adds cache,
  schema, and retry surfaces without removing enterprise controls.
- Dynatrace `oneagent-sdk`: instrumentation SDK, not an API client.
- `langchain-community==0.4.2`: sunset package with broad loader/network dependencies.
- `langchain-unstructured==1.0.1` and Unstructured: local extra is incompatible with the
  supported Python range or requires a broad parser/ML/system surface; API mode can send
  documents to another service.
- LlamaIndex readers: overlapping connector/RAG framework with no authority or
  provenance advantage.
- DOCX/PDF/XML ingestion: deferred until separately sandboxed parser workers, format
  threat models, and redaction tests exist.

## Consequences and escape

The selected libraries eliminate HTTP pooling/streaming mechanics, Kubernetes wire
object decoding, JWT cryptography, and YAML syntax parsing only. Aegis still owns most
connector code because secure allowlists, SSRF defense, credential brokering,
pagination truth, ingestion, provenance, ledger integration, RLS, reconciliation, and
correlation are product controls.

HTTPX is replaceable through `HttpTransport`; Kubernetes through `KubernetesApi`; YAML
through the canonical JSON/text boundary; Temporal through opaque messages and
`EvidenceActivityOperations`; PostgreSQL through application events and deterministic
rebuild. No loader or SDK type crosses a neutral port.

## Primary sources

Accessed 2026-08-15:

- [Dynatrace API](https://docs.dynatrace.com/docs/dynatrace-api)
- [Dynatrace API authentication](https://docs.dynatrace.com/docs/dynatrace-api/basics/dynatrace-api-authentication)
- [GitHub App installation tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)
- [GitHub REST pagination](https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api)
- [GitHub REST best practices](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api)
- [Kubernetes Python client](https://github.com/kubernetes-client/python)
- [Kubernetes list pagination](https://kubernetes.io/docs/reference/using-api/api-concepts/#retrieving-large-results-sets-in-chunks)
- [Kubernetes watch semantics](https://kubernetes.io/docs/reference/using-api/api-concepts/#efficient-detection-of-changes)
- [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
