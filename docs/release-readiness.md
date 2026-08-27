# Final release readiness

The source of truth is the machine-validated
[`release-readiness.json`](../qualification/release-readiness.json). It maps all
16 capabilities to code, tests, eval cases, CI jobs, runbooks, owners, status,
commands, release gates, and explicit release sign-off fields (`owner`,
`approver`, `sign_off_date`, `slo_gates_passed`, `security_review_complete`, and
`open_risks`). Run:

```bash
make release-check
make qualification
```

## Status

- **Locally qualified:** deterministic source/test/eval/protocol/UI/config
  boundaries, repository governance validation, bounded chaos/capacity, and
  application-ledger replay.
- **Environment-gated:** PostgreSQL/pgvector, Temporal, live provider/connector
  adapters, operator browser/IdP sessions, and MCP/A2A partner environments.
- **Live evidence required:** managed identity/key rotation, backup/restore and
  failover, Temporal Cloud recovery/upgrades, sandbox isolation, representative
  load/chaos/SLO/on-call, signed promotion/admission, and independent reviews.
- **Deferred:** active-active multi-region writes and any capability explicitly
  marked deferred in the readiness scorecard.

`production_ready` and `certification_claimed` are both `false`. See the
[risk register](../qualification/residual-risks.json) and
[release checklist](release-checklist.md). A passing local command cannot clear a
hard live gate.

The 2026-08-18 bounded backend run recorded 450 passed, 18 environment-skipped,
and 90.03% branch coverage. The governed catalog contains 58 eval cases, the
qualification matrix contains 17 fault points and 12 capacity profiles. These
counts are release evidence, not production-effect or certification evidence.
