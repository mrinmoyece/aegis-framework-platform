# Layer 15 demos and learning walkthrough

## 15 minutes

1. Run `make qualification`.
2. Inspect the journey, 58-case result and boundary flags in
   `build/qualification/evidence.json`.
3. Show two-person approval, ambiguity reconciliation, memory context and application
   replay.
4. State the live blockers; do not call the result production ready.

## 30 minutes

Add `chaos.json`, `performance.json`, one tenant/poisoning case, one protocol
revocation case, projection rebuild and the readiness scorecard. Explain why p99 is a
CI guard and why Temporal/LangGraph are never approval or audit truth.

## 60 minutes

Trace each journey surface to source, tests, ADR and runbook. Run PostgreSQL/Temporal/
browser gates where available, inject five fault families, verify convergence, inspect
the residual-risk register and rehearse one hard-gate rollback decision.

## Learning path

Read [architecture](architecture.md), ADRs 007/011/020,
[authority boundaries](authority-boundaries.md), this qualification guide,
[security assessment](security-assessment.md), [performance and chaos](performance-chaos-qualification.md),
[readiness](production-readiness-scorecard.md) and
[operational acceptance](operational-acceptance.md), in that order.
