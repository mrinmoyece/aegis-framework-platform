# Custom Aegis versus framework Aegis

The machine-readable source is
[`comparison/layer16-final.json`](../comparison/layer16-final.json). Framework
Aegis is based exactly on
`mrinmoyece/aegis-framework-platform@4f4b8924247367f959c910f8261baea3337967d6`.
Custom Aegis evidence is the public
`mrinmoyece/aegis-agent-platform@1cccd9363fec83f7f4b2748b0e913be3a123d5ce`
(PR 18, observed open on 2026-08-18).

## Reproduce

```bash
# Framework metrics and manifest validation
python tools/release_check.py --update-comparison
make release-check

# Public custom source snapshot
gh api repos/mrinmoyece/aegis-agent-platform/tarball/\
1cccd9363fec83f7f4b2748b0e913be3a123d5ce > custom.tar.gz
```

LOC is physical lines including comments/blanks under the exact scopes documented
in the JSON. Dependency counts distinguish direct from locked closure. Changed
files/additions/deletions are an implementation-size proxy, not person-hours.

## Equivalent-axis synthesis

| Axis | Framework Aegis | Custom Aegis | Comparability |
|---|---|---|---|
| Production/test/config/docs LOC | Recomputed in CI | 70,701 / 32,299 / 23,730 / 10,382 | Equivalent scope; LOC is not quality |
| Direct dependencies | Python 14; UI 6 | Python 14; UI 3 | Equivalent |
| Locked dependencies | Python 151; npm 615 packages | Python 71; pnpm 652 entries | Python equivalent; UI lock structures differ |
| Compose services | 7, including Temporal | 9, including Redis | Partially equivalent topology |
| Layer increment proxy | Current PR diff from exact base | 71 files, +5,549/-139, one commit | No person-hour data |
| Eval/chaos/capacity | 58 cases / 17 faults / 12 profiles | 127 cases / 17 branches / 12 profiles | Coverage units differ |
| Stateful services | PostgreSQL/pgvector + Temporal | PostgreSQL/pgvector + Redis | Equivalent role, different semantics |
| Deployment | 15 Kubernetes YAML files, 10 migrations | 18 Kubernetes YAML files, 11 migrations | Partially equivalent |

The same host executed both pinned revisions. Framework profiles used Python
3.14.7 and 20 samples (50 for ledger replay); custom used Python 3.13.15 and three
samples after warmup. Framework checkout p50/p95/p99 was
51.456/57.709/114.753 ms; custom archive/replay was
139.269/254.417/254.417 ms. The fixtures, interpreters, sample counts and profile
boundaries are **not equivalent**, so these numbers support reproducibility and
regression checks only. They do not support a latency winner or production
extrapolation.

## What the architectures trade

Framework Aegis removes generic graph scheduling and custom durable worker/timer/
signal/replay mechanics. It adds a larger dependency closure, Temporal operations,
LangGraph checkpoint compatibility, and more framework upgrade surfaces. Custom
Aegis owns Redis delivery, leases, heartbeats, retries and workflow recovery in
application code, giving direct control at the cost of implementation and on-call
burden.

Both still require application-owned identity, tenant/RLS policy, immutable events,
budgets, evidence/provenance/citations, approval, fencing, idempotency, receipts,
reconciliation, sandbox policy, memory lifecycle, protocol trust, telemetry
redaction and release evidence. Neither has live production capacity, managed
recovery, provider/partner, independent assessment, or certification evidence.

## Conclusion

Choose framework Aegis when durable waits/recovery and bounded graph mechanics
remove enough bespoke code to justify Temporal/LangGraph operations and upgrade
risk. Choose custom Aegis when the team is prepared to own and prove every queue,
lease, timer and replay mechanic and wants fewer orchestration-framework formats.
Reject either design if application truth cannot export and rebuild without its
queue/history/checkpoint/trace/index services.

There is deliberately no aggregate score. Missing data and non-equivalent
benchmarks cannot be averaged into a defensible winner.
