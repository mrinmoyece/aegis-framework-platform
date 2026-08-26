# Layer 11 observability and replay runbook

## Local qualification

```bash
make observability-config
docker compose config --quiet
docker compose --profile observability up -d app otel-collector prometheus grafana
docker compose exec -T prometheus promtool check rules /etc/prometheus/rules/aegis-slos.yaml
```

The profile is loopback-only and uses a 24-hour/256 MB Prometheus bound. Set
`AEGIS_OTLP_TRACE_ENDPOINT` and `AEGIS_OTLP_TRACE_AUTHORIZATION` only for an approved
sanitized OTLP backend. The default endpoint is deliberately non-routable. Never add a
debug/logging exporter.

## Telemetry outage

1. Confirm `/healthz` and correctness-critical `/readyz` independently.
2. Read authenticated `/v1/operations/readiness`; `telemetry-export` may be degraded.
3. Inspect `aegis_export_dropped_total` and Collector queue/retry health.
4. Repair capacity or credentials without expanding queues beyond reviewed bounds.
5. Do not bypass policy, ledger, approval, or reconciliation to improve an SLO.

## SLO response

Use the [SLO catalog](slo-catalog.md). Fast burn pages on 5 minute and 1 hour windows;
slow burn creates work on 30 minute and 6 hour windows. A safety alert pages
immediately and is never budgetable. Dashboard values are operational signals, not
proof that an effect occurred.

## Replay and support

```bash
uv run aegis-framework replay \
  --events application-events.json \
  --run-id run:opaque \
  --view support
```

Export events through an authorized tenant-scoped ledger path. Verify integrity before
state, causal-chain, comparison, support-report, or projection output. The CLI is
read-only. The authenticated projection rebuild endpoint verifies ledger integrity and
rebuilds only the derived run projection.

## Escalation

Hash, sequence, tenant isolation, safety, approval/effect ambiguity, or cleanup
violations are platform/security incidents. Preserve immutable facts and fencing.
Never reconstruct truth from OTel, Langfuse, Prometheus, Grafana, Temporal visibility,
logs, or LangGraph checkpoints.
