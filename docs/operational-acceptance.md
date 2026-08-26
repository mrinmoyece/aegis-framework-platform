# Operational acceptance

Local operational acceptance is **not** production acceptance. The machine contract
`qualification/operational-acceptance.json` sets `accepted_for_production: false`.

## Day 0, 1 and 2

| Phase | Owner | Required evidence | Stop/rollback |
|---|---|---|---|
| Day 0 release | release-commander | CI, security, container, qualification, signed immutable candidate | stop promotion; retain prior digest |
| Day 1 service | primary-on-call | fresh PostgreSQL/Temporal, restore, telemetry and error-budget observations | fence new work; drain; reconcile intent |
| Day 2 acceptance | service-owner | browser, protocol, eval, tenant and support walkthrough | disable affected tenant/source/peer |

## Operational matrix

| Operation | Owner/runbook | Acceptance and fail-closed response |
|---|---|---|
| On-call and incident command | SRE / [general runbook](runbook.md) | named primary/secondary, alert delivery and escalation; otherwise no go-live |
| Backup/restore/failover | data-platform / [restore](runbooks/restore-failover.md) | dual chains, sequences, projections, vector index, outbox and ambiguous effects reconcile |
| Credential/JWKS/PKI rotation | identity-platform / [deployment](production-deployment.md) | old/new overlap, revocation and rollback; no default key |
| CVE/supply chain | platform-security / [promotion](runbooks/deployment-promotion.md) | exact owner/expiry/no-fix waiver; fixed/expired mismatch blocks |
| Capacity/noisy tenant | SRE / [capacity](capacity-and-multi-region.md) | preserve DB headroom, queue isolation and cleanup capacity |
| Tenant onboarding/offboarding | tenant-operations / [database lifecycle](database-lifecycle.md) | RLS, quotas, residency, retention/deletion and access recertification |
| Protocol peer | integrations / [protocol](protocol-runbook.md) | exact pins, capability/schema tests, quota and revocation drill |
| Sandbox quarantine/orphans | sandbox-platform / [sandbox](sandbox-runbook.md) | stop admission, quarantine output, reconcile/delete by UID |
| Provider/connector outage | integrations / [connector](connector-runbook.md) | disable revision, preserve intent, reconcile billing/read ambiguity |
| Audit/replay/support | security-operations / [observability](observability-runbook.md) | authorized redacted reads; ledger not traces/framework state is truth |

Go-live also requires branch/environment protection, signed promotion, rollback
authority, maintenance ownership and the hard gates in the
[readiness scorecard](production-readiness-scorecard.md).
