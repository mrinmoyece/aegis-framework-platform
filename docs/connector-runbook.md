# Layer 5 evidence connector runbook

All live connectors are disabled by default. Enabling code does not qualify an
environment: operators must separately approve tenant policy, source configuration,
credentials, egress, residency, retention, and capacity.

## Enablement checklist

1. Register an `EvidenceSource` under the tenant with an exact source/resource allowlist,
   classification, trust, region, policy revision, and tenant-owned secret reference plus
   version. Never store a credential value in source configuration.
2. Permit only the required HTTPS origin at the network layer. Confirm A/AAAA answers,
   redirects, proxies, and private/link-local/loopback addresses are denied unless a
   reviewed exact enterprise CIDR is configured and enforced by egress policy.
3. Set page, record, response, aggregate-byte, timeout, and query-window limits below the
   tenant quota. Connector SDK retries stay disabled; Temporal owns Activity retry.
4. Validate least-privilege external grants. GitHub App tokens are repository and
   permission scoped. Kubernetes identities cannot read Secrets, exec, mutate, or list
   unrelated namespaces. Dynatrace tokens contain only required read scopes.
5. Run the hermetic adapter, poisoning, pagination, stale-policy, cancellation, and
   projection-rebuild suites. Live qualification is a separate environment-specific
   exercise and is not part of required CI.
6. Enable one tenant/source at a time. Watch only fixed source-kind/status/count metrics;
   never add tenant, URL, repository, namespace, locator, cursor, query, or credential
   attributes.

## Source-specific operation

**Dynatrace:** use the administrator-configured tenant origin and API v2 resource.
Initial requests contain the bounded window and page size. A continuation request uses
only `nextPageKey`. Empty, malformed, oversized, wrong-MIME, redirected, or rate-limited
responses fail explicitly.

**GitHub App:** store the RSA private key behind the source secret reference. The adapter
creates a nine-minute App JWT, requests a one-hour installation token restricted to the
configured repository/permissions, and follows only validated `rel="next"` page numbers.
Rotate the private-key version by replacing the source revision; in-flight results under
the old revision become stale.

**Kubernetes:** build `Configuration` directly from the fixed server origin and
short-lived service-account token. Do not load arbitrary kubeconfig, exec plugins, auth
providers, or model-provided selectors. Continue tokens normally expire; `410 Gone`
requires explicit relist/reconciliation, not an ordinary page retry.

**Runbooks:** permit only administrator-owned repository/object adapters and text,
Markdown, JSON, or YAML. The default adapter never executes procedures or active content.
ZIP is accepted only by the shared bounded ingestion layer; traversal, active extensions,
compression bombs, malformed UTF-8, and unsupported types are quarantined.

## Failure and reconciliation

- A query/page intent without a result means the external outcome is ambiguous. Set
  `reconciliation_required`; do not advance its cursor or silently repeat the call.
- Rate limit and transient transport failures remain visible status. Retry requires the
  same durable operation and a reconciliation-safe classification.
- Cancellation is checked before I/O and before result acceptance. It cannot undo a
  completed external read.
- Policy, source digest, credential version, or enablement changes make an in-flight
  result stale. Persist status and discard the page.
- Scanner, classification, active-content, malformed, and size failures create
  quarantine metadata only. Never expose quarantined content to LangGraph or a model.
- Cursor API output is availability/page/expiry metadata only. Decrypt cursor values only
  inside the tenant-bound page Activity.

## Recovery

1. Verify the application event ledger hash chain. Temporal history and connector logs
   are not evidence-query truth.
2. Rebuild `evidence_queries` from `evidence-query` aggregate events, then record
   `evidence.projection_rebuilt`. Never synthesize a page result from an SDK log.
3. Reconcile unresolved page intent with the external provider where a stable request or
   audit identifier exists. Otherwise retain the ambiguity and start a newly authorized
   query.
4. Treat cross-tenant visibility, cursor decryption failure, digest mismatch, impossible
   transition, or RLS bypass as a security incident.

## Explicitly absent

Layer 5 has no webhook ingestion, live credential broker, sandboxed PDF/DOCX conversion,
watch stream, multi-agent expansion, approval/effect execution, memory/RAG, UI, MCP/A2A,
or production deployment qualification.
