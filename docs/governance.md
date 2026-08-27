# Repository and release governance

## Ownership

`CODEOWNERS` routes review; it does not prove review occurred. Capability owners
and current status live in
[`qualification/release-readiness.json`](../qualification/release-readiness.json).
Risk owners, mitigations, triggers, review dates, and fail-closed behavior live in
[`qualification/residual-risks.json`](../qualification/residual-risks.json).

Only a reviewed pull request may change a capability status, risk, waiver, ADR,
dependency, workflow, migration, or deployment policy. A local test cannot clear a
live gate. Framework state and CI evidence never authorize a production effect.

## Required GitHub ruleset

The repository operator must configure, and independently export evidence for:

- no direct push, force-push, deletion, or bypass on `master`;
- at least one approval and CODEOWNERS review for owned paths;
- dismissal of stale approvals and approval after the latest push;
- resolved review conversations and linear history;
- required checks: `lint`, `type`, both `tests` matrix jobs,
  `postgres-integration`, `temporal-integration`, `evals`, every `eval-gates`
  matrix job, `enterprise-qualification`, `docs`, `security`,
  `dependency-review`, `operator-ui`, `container`, infrastructure, restore, and
  signed supply-chain `verify`;
- staging and production GitHub Environments with non-author reviewers;
- immutable tag/release creation only after the release checklist.

These are required settings, not configured or claimed by this repository.

## Dependencies and waivers

Dependabot proposes uv, npm, Actions, Docker, and Compose updates. Maintainers
regenerate locks, review licenses and transitive changes, and run every affected
gate. Automatic merge is not authorized.

HIGH/CRITICAL image findings fail closed. A no-fix waiver must match CVE, severity,
package, and version exactly; name an owner, approval date, affected scope,
compensating controls, review reference, and expiry of at most 30 days; state that
no fixed version exists; and require a new review for renewal. Published fixes,
unused waivers, tuple drift, or expiry block publication.

## Decision records and releases

The [ADR index](adr/README.md), [version policy](versioning.md),
[release checklist](release-checklist.md), [security policy](../SECURITY.md), and
[changelog](../CHANGELOG.md) are mandatory release inputs. No repository artifact
is a production certification or organizational approval.
