# Troubleshooting

| Symptom | Likely cause | Command | Next runbook |
|---|---|---|---|
| `release-check` reports stale metrics | docs/source/config changed | `python tools/release_check.py --update-comparison` | [release checklist](release-checklist.md) |
| waiver expired or unused | date, base image or scanner result changed | `python tools/vulnerability_check.py --help` | [governance](governance.md) |
| run accepted but no progress | outbox/Temporal worker or authorization | `make temporal-integration` | [durable freshness](runbooks/durable-freshness.md) |
| projection differs after replay | integrity/schema/reducer drift | `make restore-drill` | [restore/failover](runbooks/restore-failover.md) |
| evidence is missing/quarantined | source policy, scanner, citation or pagination | `make eval-adversarial` | [evidence health](runbooks/evidence-health.md) |
| approval does not execute | SoD/quorum/expiry/digest/policy/fence | `make eval-recovery` | [approval/effect](runbooks/approval-effect.md) |
| sandbox stays unavailable | live isolation prerequisite absent | `make deployment-check` | [sandbox cleanup](runbooks/sandbox-cleanup.md) |
| memory returns no candidates | tenant/ACL/classification/retention or derived index | `make integration` | [memory retrieval](runbooks/memory-retrieval.md) |
| protocol peer is denied | identity/trust/capability/schema/card/cert/key pin | `make protocol` | [protocol](protocol-runbook.md) |
| UI is `503 not_ready` | production OIDC/session boundary is intentionally absent | `make frontend-ci` | [operator](operator-runbook.md) |
| telemetry is absent | exporter/collector is degraded | `make observability-config` | [observability](observability-runbook.md) |

Never repair an authority failure by editing framework history, checkpoints,
traces, UI state, Redis/pgvector rows, or generated qualification output. Preserve
the application ledger, stop new work/effects, verify tenant and hashes, then
rebuild or reconcile through the named application service.
