# Contributing

Use Python 3.13 or 3.14, `uv==0.12.5`, Node 24, and npm 11.12.1. Dependencies,
GitHub Actions, and images must remain exactly pinned.

## Authority and privacy

Read [AGENTS.md](AGENTS.md) first. Framework state may never become identity,
authorization, tenancy, approval, audit, fencing, effect, or verification truth.
Do not put prompts, completions, secrets, credentials, raw evidence, tenant IDs,
actor IDs, request IDs, or evidence locators in code, tests, logs, issues, or
telemetry.

## Change workflow

1. Add or change provider-neutral contracts before vendor adapters.
2. Add deterministic positive, denial, tenant-isolation, retry, and failure tests.
3. Update the relevant ADR, parity/readiness/comparison artifact, limitations, and
   runbook when a boundary changes.
4. Run the smallest focused checks, then the release commands in
   [the checklist](docs/release-checklist.md).
5. Complete the pull-request safety checklist. Security reports belong in a
   private advisory, never a public issue.

Generated build evidence is not committed. Do not weaken a hard gate or extend a
waiver to make CI green; submit a reviewed replacement with an owner, exact scope,
compensating controls, and expiry.
