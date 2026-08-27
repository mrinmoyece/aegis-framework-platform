# Final security, threat, and residual-risk review

Layer 16 found no evidence that framework state directly grants identity, tenant
access, approval, fencing, effect, audit, or verification authority. Executable
coverage includes current authorization, forced RLS, budget-before-work,
evidence/citation fail-closed behavior, bounded graph traversal, exact approval,
ambiguity/reconciliation, telemetry minimization, protocol confused-deputy and
proposal-only rules, operator CSRF/tenant teardown, and signed supply-chain policy.

An independent read-only static security review of the pinned Layer 15 base and
Layer 16 working tree reported no BLOCKER, HIGH, or reportable MEDIUM finding.
That review is repository evidence only; it is not a penetration test, live
control assessment, or certification.

Locally fixed release risks include scheduled vulnerability scanning, immutable
pre-commit pins, broader dependency update coverage, CODEOWNERS routing,
bounded/manual restore and promotion workflows, input-to-environment workflow
handling, stricter risk/waiver dates and controls, release manifest validation,
and executable framework-loss/bypass checks.

The machine-validated source of residual risk is
[`qualification/residual-risks.json`](../qualification/residual-risks.json).
CRITICAL live risks remain sandbox isolation and managed restore/failover. HIGH
risks remain identity/session operation, integrations, SLO/capacity/on-call,
protected signed promotion, memory serving/erasure, network rate limiting, and two
short-lived no-fix runtime waivers. Independent penetration, accessibility,
privacy, legal and compliance assessments are absent.

One medium correctness/DR gap remains explicit: protocol invocation and artifact
projections have immutable facts and a rebuild table but no pure reducer/rebuilder.
Peers therefore remain environment-gated and no protocol projection-recovery
claim is made.

Passing repository tests does not clear those risks. The system is locally
qualified only, not production approved or certified. See the detailed
[threat model](threat-model.md), [security assessment](security-assessment.md),
[governance policy](governance.md), and [release checklist](release-checklist.md).
