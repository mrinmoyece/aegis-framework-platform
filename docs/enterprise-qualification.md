# Layer 15 enterprise qualification

Layer 15 is integrated repository and bounded-local qualification, not production
approval. Run:

```bash
make qualification
```

The command emits `build/qualification/evidence.json`, `chaos.json` and
`performance.json`. It uses fixed synthetic checkout inputs, deterministic adapters,
no network and no live credentials.

## Canonical checkout journey

The runner composes the authenticated tenant service boundary, evidence projection,
bounded LangGraph specialist/critic path, budget-before-evidence rule, exact
two-person approval, controlled effect ambiguity/reconciliation, fresh verification,
memory ingestion/retrieval/context, protocol and sandbox adversarial cases, application
ledger replay and projection comparison. The complete governed suite supplies the
connector/correlation, Temporal simulated activity/recovery, sandbox quarantine,
MCP/A2A, telemetry, replay and support assertions.

PostgreSQL/pgvector and Temporal are intentionally not replaced with toy
implementations. Their real adapters run in `make integration` and
`make temporal-integration`. UI behavior runs through `make frontend-ci
frontend-e2e`; logical restore runs through `make restore-drill-db`.

## Evidence boundary

Local evidence proves deterministic repository behavior only. It does not prove live
OIDC/JWKS rotation, managed PostgreSQL or Temporal HA, production provider/connector
behavior, hostile-runtime isolation, real browser/TLS ingress, SLO attainment,
on-call response, cloud failover, penetration testing, legal/privacy acceptance or
certification. See the [readiness scorecard](production-readiness-scorecard.md).

## Release commands

```bash
make ci
make security
make container
docker compose config --quiet
make integration
make temporal-integration
make frontend-e2e
make terraform-check
make restore-drill-db
```

Environment-backed commands are evidence only when their required services are fresh,
healthy and recorded. A skipped test is not a pass.
