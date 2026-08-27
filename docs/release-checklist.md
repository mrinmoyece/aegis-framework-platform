# Layer 16 release checklist

## Repository and bounded-local gates

Run from a clean checkout at the exact candidate commit:

```bash
make bootstrap
make ci
make security
make python-licenses
make integration
make temporal-integration
make frontend-e2e
make terraform-check
make restore-drill-db
make container
docker compose config --quiet
```

Retain command versions, candidate SHA, durations, coverage, test/eval counts,
qualification JSON, restore evidence, rendered manifests, SBOMs, vulnerability
policy, image digests, signatures, attestations, and reviewer identities outside
the application ledger. Failure blocks release; do not raise thresholds or extend
waivers merely to pass.

## Review

- Verify the [readiness manifest](../qualification/release-readiness.json), [risk
  register](../qualification/residual-risks.json), [comparison](../comparison/layer16-final.json),
  parity manifest, ADR index, changelog, limitations, and roadmap.
- Confirm framework histories/checkpoints/traces are disposable and no UI/protocol
  path bypasses identity, policy, approval, tenancy, fencing, or audit.
- Confirm automatic LangGraph/LangChain tracing remains disabled and telemetry
  contains only allowlisted low-cardinality counts/status.
- Confirm dependencies, Actions and pre-commit hooks are immutable; images use
  digests; active waivers are exact, no-fix, owned, reviewed, and unexpired.

## Hard go-live gates

The candidate remains **not production approved** until live OIDC/session/key
rotation, managed PostgreSQL restore/failover, Temporal Cloud recovery/upgrade,
provider/connector/partner qualification, sandbox isolation, representative
load/chaos/SLO/on-call, signed promotion/admission, independent penetration and
accessibility reviews, privacy/legal acceptance, and organizational compliance
evidence all pass. Record rollback criteria before traffic. Do not claim
certification.
