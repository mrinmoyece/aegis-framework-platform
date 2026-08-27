# ADR 021: Machine-validated final release and governance evidence

- Status: accepted
- Date: 2026-08-18

## Context

Layer 15 qualified the bounded local journey but split readiness, risk, comparison,
learning, and governance evidence across files with inconsistent validation. The
final layer must be reproducible without converting local or framework evidence
into production authority.

## Decision

Layer 16 adds one 16-capability readiness manifest, one detailed risk register, one
pinned equivalent-axis comparison, a framework verdict document, a consolidated
learning path, and release/governance policies. `tools/release_check.py` validates
paths, eval IDs, Make targets, owners, statuses, dates, comparison axes, metrics,
framework verdicts, versions, and required governance assets in CI.

No aggregate score exists: one hard live gate cannot be averaged away. The exact
Layer 15 base is `4f4b8924247367f959c910f8261baea3337967d6`; custom comparison evidence is
pinned to `1cccd9363fec83f7f4b2748b0e913be3a123d5ce`.

## Consequences

Release evidence is more explicit and drift fails closed. Maintainers own more
manifest upkeep, but commands and links are executable. Local qualification still
does not prove cloud apply, managed recovery, live identity, provider behavior,
sandbox isolation, human operations, legal acceptance, or certification.
