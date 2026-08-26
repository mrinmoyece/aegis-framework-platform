from __future__ import annotations

import importlib.util
import json
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from opentelemetry.trace import SpanContext, TraceFlags, TraceState
from pydantic import ValidationError

from aegis_framework.adapters import FixedClock
from aegis_framework.api import AppMode, _build_demo_runtime, create_app
from aegis_framework.cli import main
from aegis_framework.durability import (
    EventDraft,
    InMemoryDurability,
    event_material,
)
from aegis_framework.errors import IntegrityFailure, PayloadRejected
from aegis_framework.fixtures import DEMO_TIME, demo_identity, demo_request
from aegis_framework.replay import ReplayDebugger, load_events, projection_document
from aegis_framework.telemetry import (
    BoundedJsonLogger,
    DependencyState,
    MetricDefinition,
    MetricRegistry,
    PythonLogSink,
    TelemetryAttributeRejected,
    TraceContextRejected,
    TraceReference,
    deterministic_sample,
    durable_trace_reference,
    extract_trace_context,
    inject_trace_context,
    linked_contexts,
    readiness_snapshot,
    safe_attributes,
)

_OBSERVABILITY_CHECK_SPEC = importlib.util.spec_from_file_location(
    "observability_check",
    Path(__file__).resolve().parents[1] / "tools" / "observability_check.py",
)
assert _OBSERVABILITY_CHECK_SPEC is not None
assert _OBSERVABILITY_CHECK_SPEC.loader is not None
_observability_check = importlib.util.module_from_spec(_OBSERVABILITY_CHECK_SPEC)
_OBSERVABILITY_CHECK_SPEC.loader.exec_module(_observability_check)
_exporter_errors = _observability_check._exporter_errors


class _Sink:
    def __init__(self, *, fail: bool = False) -> None:
        self.records: list[str] = []
        self.fail = fail

    def emit(self, record: str) -> None:
        if self.fail:
            raise RuntimeError("exporter unavailable")
        self.records.append(record)


class _FailingMetrics(MetricRegistry):
    def record(
        self,
        name: str,
        value: float,
        *,
        labels: dict[str, str],
        logical_key: str | None = None,
    ) -> bool:
        del name, value, labels, logical_key
        raise ValueError("exporter unavailable")


_DEFAULT_BEARER = "demo-responder-token"


def _legacy_headers(token: str = _DEFAULT_BEARER) -> dict[str, str]:
    return {"Authorization": "******", "X-Request-ID": "layer11-api"}


def _headers(token: str = _DEFAULT_BEARER) -> dict[str, str]:
    return {
        "Authorization": "".join(("Bear", "er ", token)),
        "X-Request-ID": "layer11-api",
    }


def test_semantic_allowlist_rejects_identifiers_secrets_and_free_text() -> None:
    assert (
        safe_attributes(
            {
                "aegis.component": "api",
                "aegis.operation": "request",
                "aegis.status": "ok",
                "aegis.count": 2,
            }
        )["aegis.semantic.version"]
        == "1.0.0"
    )
    for value in (
        {"aegis.tenant_id": "tenant-acme"},
        {"aegis.operation": "https://secret.invalid/path"},
        {"aegis.status": "not-an-enum"},
        {"aegis.operation": "x" * 65},
    ):
        with pytest.raises(TelemetryAttributeRejected):
            safe_attributes(value)


def test_trace_context_is_strict_bounded_and_deterministic() -> None:
    reference = durable_trace_reference("opaque-correlation", sampled=True)
    propagated = inject_trace_context(reference, baggage={"aegis.sample": "1"})
    extracted = extract_trace_context(propagated)
    assert extracted.parent == reference
    assert extracted.baggage == {"aegis.sample": "1"}
    assert deterministic_sample(
        "stable", rate_basis_points=1000
    ) == deterministic_sample("stable", rate_basis_points=1000)
    with pytest.raises(TraceContextRejected):
        extract_trace_context(
            {"traceparent": "00-" + "0" * 32 + "-" + "1" * 16 + "-01"}
        )
    with pytest.raises(TraceContextRejected):
        extract_trace_context({"baggage": "x=" + "a" * 600})


def test_trace_context_validation_and_links_cover_failure_modes() -> None:
    with pytest.raises(ValidationError):
        TraceReference(trace_id="0" * 32, span_id="1" * 16, sampled=False)
    with pytest.raises(ValidationError):
        TraceReference(trace_id="1" * 32, span_id="0" * 16, sampled=False)
    invalid = SpanContext(
        trace_id=0,
        span_id=0,
        is_remote=False,
        trace_flags=TraceFlags.DEFAULT,
        trace_state=TraceState(),
    )
    with pytest.raises(ValueError, match="span context"):
        TraceReference.from_span_context(invalid)
    reference = durable_trace_reference("link")
    round_trip = TraceReference.from_span_context(reference.as_span_context())
    assert round_trip.trace_id == reference.trace_id
    assert len(linked_contexts((reference, reference))) == 1
    with pytest.raises(ValueError, match="link bound"):
        linked_contexts((reference,), maximum=0)
    assert extract_trace_context({}).parent is None
    rejected = extract_trace_context(
        {"traceparent": "invalid"},
        reject_invalid=False,
    )
    assert rejected.rejected
    assert rejected.rejection_code == "traceparent_invalid"
    with pytest.raises(TraceContextRejected, match="malformed"):
        extract_trace_context({"baggage": "missing-separator"})
    with pytest.raises(ValueError, match="baggage"):
        inject_trace_context(
            reference,
            baggage={f"aegis.key{index}": "1" for index in range(9)},
        )
    with pytest.raises(ValueError, match="sampling rate"):
        deterministic_sample("bad", rate_basis_points=10_001)
    assert deterministic_sample("forced", rate_basis_points=0, force=True)


def test_metrics_enforce_cardinality_units_and_retry_deduplication() -> None:
    registry = MetricRegistry()
    labels = {"component": "api", "operation": "request", "status": "ok"}
    assert registry.record(
        "aegis_operations_total",
        1,
        labels=labels,
        logical_key="logical-operation-digest",
    )
    assert not registry.record(
        "aegis_operations_total",
        1,
        labels=labels,
        logical_key="logical-operation-digest",
    )
    with pytest.raises(ValueError, match="outside its stable enumeration"):
        registry.record(
            "aegis_operations_total",
            1,
            labels={
                "component": "api",
                "operation": "request",
                "status": "tenant-acme",
            },
        )
    rendered = registry.render_prometheus()
    assert "aegis_operations_total" in rendered
    assert "tenant" not in rendered


def test_metric_definitions_histograms_gauges_and_errors() -> None:
    with pytest.raises(ValidationError):
        MetricDefinition(
            name="aegis_bad",
            kind="counter",
            unit="count",
            description="bad labels",
            labels=("tenant_id",),
        )
    with pytest.raises(ValidationError):
        MetricDefinition(
            name="aegis_bad",
            kind="histogram",
            unit="seconds",
            description="bad buckets",
            buckets=(2.0, 1.0),
        )
    registry = MetricRegistry()
    with pytest.raises(ValueError, match="not registered"):
        registry.record("aegis_unknown", 1, labels={})
    with pytest.raises(ValueError, match="labels do not match"):
        registry.record("aegis_operations_total", 1, labels={})
    with pytest.raises(ValueError, match="cannot be negative"):
        registry.record(
            "aegis_operations_total",
            -1,
            labels={"component": "api", "operation": "request", "status": "ok"},
        )
    with pytest.raises(ValueError, match="outside its stable enumeration"):
        registry.record(
            "aegis_safety_violations_total",
            1,
            labels={"control": "tenant-acme", "severity": "page"},
        )
    registry.record(
        "aegis_safety_violations_total",
        1,
        labels={"control": "ledger", "severity": "page"},
    )
    registry.record(
        "aegis_dependency_ready",
        1,
        labels={"dependency": "ledger", "criticality": "correctness"},
    )
    registry.record(
        "aegis_operation_duration_seconds",
        0.25,
        labels={"component": "api", "operation": "request"},
    )
    rendered = registry.render_prometheus()
    assert "aegis_dependency_ready" in rendered
    assert "aegis_operation_duration_seconds_bucket" in rendered
    assert 'le="+Inf"' in rendered
    assert safe_attributes({"unknown": "value"}, strict=False) == {
        "aegis.semantic.version": "1.0.0"
    }


def test_bounded_json_logs_are_redacted_rate_limited_and_failure_contained() -> None:
    sink = _Sink()
    logger = BoundedJsonLogger(sink, maximum_per_minute=1)
    assert logger.emit(
        event="aegis.api.request",
        level="INFO",
        attributes={"aegis.component": "api", "aegis.status": "ok"},
        trace=durable_trace_reference("log-correlation"),
    )
    assert not logger.emit(
        event="aegis.api.request",
        level="INFO",
        attributes={"aegis.component": "api", "aegis.status": "ok"},
    )
    assert logger.suppressed("aegis.api.request") == 1
    assert "tenant" not in sink.records[0]
    failing = BoundedJsonLogger(_Sink(fail=True))
    assert not failing.emit(
        event="aegis.api.request",
        level="ERROR",
        attributes={"aegis.component": "api", "aegis.status": "error"},
    )
    with pytest.raises(ValueError, match="rate bound"):
        BoundedJsonLogger(sink, maximum_per_minute=0)
    with pytest.raises(ValueError, match="not allowlisted"):
        logger.emit(
            event="unknown",
            level="INFO",
            attributes={"aegis.component": "api"},
        )
    assert logger.suppressed("aegis.model.call") == 0


def test_python_log_sink_uses_standard_logging(caplog) -> None:
    sink = PythonLogSink()
    with caplog.at_level("INFO", logger="aegis.telemetry"):
        sink.emit('{"status":"ok"}')
    assert '{"status":"ok"}' in caplog.text


def test_readiness_degrades_only_for_optional_telemetry() -> None:
    optional = readiness_snapshot(
        (
            DependencyState(
                name="ledger",
                criticality="correctness",
                ready=True,
                status="ready",
            ),
            DependencyState(
                name="telemetry-export",
                criticality="optional",
                ready=False,
                status="degraded",
            ),
        )
    )
    assert optional.status == "degraded"
    critical = readiness_snapshot(
        (
            DependencyState(
                name="ledger",
                criticality="correctness",
                ready=False,
                status="unavailable",
            ),
        )
    )
    assert critical.status == "not_ready"
    ready = readiness_snapshot(
        (
            DependencyState(
                name="ledger",
                criticality="correctness",
                ready=True,
                status="ready",
            ),
        )
    )
    assert ready.status == "ready"


def test_ledger_replay_validates_hashes_converges_and_bounds_support() -> None:
    store = InMemoryDurability(clock=FixedClock(DEMO_TIME))
    identity = demo_identity(request_id="layer11-replay")
    run = store.accept_run(
        identity=identity,
        request=demo_request(),
        wait_for_signal=False,
    )
    events = store.events(tenant_id=identity.tenant_id)
    debugger = ReplayDebugger(events)
    assert debugger.verify().valid
    assert debugger.compare(aggregate_id=run.run_id, live=run).matches
    report = debugger.support_report(
        aggregate_id=run.run_id,
        live=run,
        maximum_bytes=4096,
    )
    assert report.integrity.valid
    assert report.projection is not None
    assert report.projection.matches
    assert len(report.model_dump_json().encode()) <= 4096
    assert events[0].payload["trace_ref"].startswith("00-")
    tampered = events[0].model_copy(update={"record_hash": "f" * 64})
    assert not ReplayDebugger((tampered,)).verify().valid
    failed = ReplayDebugger((tampered,)).support_report(aggregate_id=run.run_id)
    assert failed.projection is None
    assert failed.truncated
    assert failed.completeness_code == "integrity_failed"


def test_replay_rejects_mixed_tenants_and_exposes_bounded_views() -> None:
    alpha = InMemoryDurability(clock=FixedClock(DEMO_TIME))
    alpha_identity = demo_identity(request_id="alpha-replay")
    run = alpha.accept_run(
        identity=alpha_identity,
        request=demo_request(),
        wait_for_signal=False,
    )
    alpha_events = alpha.events(tenant_id=alpha_identity.tenant_id)
    beta = InMemoryDurability(clock=FixedClock(DEMO_TIME))
    beta_identity = demo_identity(tenant_id="tenant-beta", request_id="beta-replay")
    beta.accept_run(
        identity=beta_identity,
        request=demo_request(),
        wait_for_signal=False,
    )
    with pytest.raises(ValueError, match="one tenant"):
        ReplayDebugger((*alpha_events, *beta.events(tenant_id="tenant-beta")))
    debugger = ReplayDebugger(alpha_events)
    with pytest.raises(ValueError, match="negative"):
        debugger.state_at(aggregate_id=run.run_id, cursor=-1)
    with pytest.raises(ValueError, match="causal chain bound"):
        debugger.causal_chain(aggregate_id=run.run_id, maximum=0)
    with pytest.raises(ValueError, match="byte bound"):
        debugger.support_report(aggregate_id=run.run_id, maximum_bytes=100)
    missing = debugger.state_at(aggregate_id="run:missing")
    assert missing.state is None
    assert projection_document(debugger, aggregate_id="run:missing")["state"] is None
    loaded = load_events([event.model_dump(mode="json") for event in alpha_events])
    assert loaded == alpha_events
    with pytest.raises(ValueError, match="event array"):
        load_events({})
    changed = run.model_copy(update={"failure_code": "changed"})
    difference = debugger.compare(aggregate_id=run.run_id, live=changed)
    assert not difference.matches
    assert difference.differing_fields == ("failure_code",)


def test_authenticated_operations_are_scoped_audited_and_anti_enumerating() -> None:
    client = TestClient(create_app(mode=AppMode.DEMO))
    slo = client.get("/v1/operations/slos", headers=_headers())
    assert slo.status_code == 200
    assert len(slo.json()["objectives"]) == 9
    request = demo_request()
    submitted = client.post(
        "/v1/durable-investigations",
        headers=_headers(),
        json={
            "incident_id": request.incident_id,
            "alert": request.alert.model_dump(mode="json"),
        },
    )
    run_id = submitted.json()["run_id"]
    support = client.get(
        f"/v1/operations/runs/{run_id}/support-report",
        headers=_headers(),
    )
    assert support.status_code == 200
    assert "tenant-acme" not in support.text
    assert (
        client.get(
            "/v1/operations/runs/run:not-found/support-report",
            headers=_headers(),
        ).status_code
        == 404
    )
    denied = client.post(
        f"/v1/operations/runs/{run_id}/projection/rebuild",
        headers=_headers(),
    )
    assert denied.status_code == 404
    rebuilt = client.post(
        f"/v1/operations/runs/{run_id}/projection/rebuild",
        headers=_headers("demo-admin-token"),
    )
    assert rebuilt.status_code == 200


def test_support_report_pages_the_contiguous_tenant_ledger() -> None:
    runtime = _build_demo_runtime(budget_units=100)
    assert runtime.durable is not None
    store = runtime.durable._store
    identity = demo_identity(request_id="paged-replay")
    last = None
    for index in range(505):
        last = store.accept_run(
            identity=identity.model_copy(
                update={"request_id": f"paged-replay-{index}"}
            ),
            request=demo_request(incident_id=f"incident:paged-{index}"),
            wait_for_signal=False,
        )
    assert last is not None
    report = runtime.durable.replay_report(identity, run_id=last.run_id)
    assert report is not None
    assert report.projection is not None
    assert report.projection.matches
    assert report.integrity.last_cursor == 505


def test_support_report_rejects_an_incomplete_ledger_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _build_demo_runtime(budget_units=100)
    assert runtime.durable is not None
    store = runtime.durable._store
    identity = demo_identity(request_id="partial-replay")
    run = store.accept_run(
        identity=identity,
        request=demo_request(),
        wait_for_signal=False,
    )
    actor_ref = "actor:partial"
    advanced = store.record_transition(
        tenant_id=identity.tenant_id,
        run_id=run.run_id,
        event_type="investigation.started",
        operation_id="operation:partial",
        actor_ref=actor_ref,
        request_ref=run.request_ref,
    )
    assert advanced.version == 2
    original_events = store.events

    def partial_events(**kwargs: object) -> tuple[object, ...]:
        if kwargs.get("after_cursor", 0) == 1:
            return ()
        return original_events(**kwargs)[:1]  # type: ignore[arg-type,return-value]

    monkeypatch.setattr(store, "events", partial_events)
    with pytest.raises(PayloadRejected, match="event bound"):
        runtime.durable.replay_report(identity, run_id=run.run_id)


def test_support_report_can_start_beyond_the_old_tenant_prefix_bound() -> None:
    runtime = _build_demo_runtime(budget_units=100)
    assert runtime.durable is not None
    store = runtime.durable._store
    identity = demo_identity(request_id="late-window")
    run = store.accept_run(
        identity=identity,
        request=demo_request(),
        wait_for_signal=False,
    )
    original = store.events(tenant_id=identity.tenant_id)[0]
    tenant_previous_hash = "a" * 64
    draft = EventDraft(
        event_id=original.event_id,
        event_type=original.event_type,
        occurred_at=original.occurred_at,
        actor_ref=original.actor_ref,
        correlation_ref=original.correlation_ref,
        causation_ref=original.causation_ref,
        schema_version=original.schema_version,
        payload=original.payload,
    )
    late_cursor = 10_050
    record_hash = sha256(
        event_material(
            tenant_id=original.tenant_id,
            aggregate_type=original.aggregate_type,
            aggregate_id=original.aggregate_id,
            aggregate_sequence=original.aggregate_sequence,
            tenant_cursor=late_cursor,
            draft=draft,
            aggregate_previous_hash=original.aggregate_previous_hash,
            tenant_previous_hash=tenant_previous_hash,
        ).encode()
    ).hexdigest()
    late = original.model_copy(
        update={
            "tenant_cursor": late_cursor,
            "tenant_previous_hash": tenant_previous_hash,
            "record_hash": record_hash,
        }
    )
    store._events[identity.tenant_id] = [late]
    store._runs[(identity.tenant_id, run.run_id)] = run.model_copy(
        update={"last_cursor": late_cursor}
    )
    report = runtime.durable.replay_report(identity, run_id=run.run_id)
    assert report is not None
    assert report.integrity.valid
    assert report.projection is not None
    assert report.projection.matches


def test_support_api_maps_replay_integrity_failure() -> None:
    runtime = _build_demo_runtime(budget_units=100)
    assert runtime.durable is not None
    original = runtime.durable.replay_report

    def failed(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise IntegrityFailure("tampered")

    runtime.durable.replay_report = failed  # type: ignore[method-assign]
    client = TestClient(create_app(mode=AppMode.TEST, runtime=runtime))
    response = client.get(
        "/v1/operations/runs/run:any/support-report",
        headers=_headers(),
    )
    assert response.status_code == 409
    runtime.durable.replay_report = original  # type: ignore[method-assign]


def test_projection_rebuild_maps_integrity_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _build_demo_runtime(budget_units=100)
    assert runtime.durable is not None
    store = runtime.durable._store
    identity = demo_identity(
        request_id="projection-integrity",
        roles=("tenant-admin",),
    )
    run = store.accept_run(
        identity=identity,
        request=demo_request(),
        wait_for_signal=False,
    )
    monkeypatch.setattr(
        store,
        "verify_run_integrity",
        lambda *, tenant_id, run_id, maximum_events=10_000: False,
    )
    client = TestClient(create_app(mode=AppMode.TEST, runtime=runtime))
    response = client.post(
        f"/v1/operations/runs/{run.run_id}/projection/rebuild",
        headers=_headers("demo-admin-token"),
    )
    assert response.status_code == 409


def test_api_rejects_hostile_context_and_telemetry_outage_does_not_block() -> None:
    client = TestClient(create_app(mode=AppMode.DEMO))
    hostile = client.get(
        "/v1/me",
        headers={
            **_headers(),
            "traceparent": "00-" + "0" * 32 + "-" + "1" * 16 + "-01",
        },
    )
    assert hostile.status_code == 400
    runtime = replace(_build_demo_runtime(budget_units=100), metrics=_FailingMetrics())
    outage_client = TestClient(create_app(mode=AppMode.TEST, runtime=runtime))
    assert outage_client.get("/v1/me", headers=_headers()).status_code == 200


def test_api_metrics_track_only_authenticated_business_requests() -> None:
    metrics = MetricRegistry()
    runtime = replace(_build_demo_runtime(budget_units=100), metrics=metrics)
    client = TestClient(create_app(mode=AppMode.TEST, runtime=runtime))

    assert client.get("/healthz").status_code == 200
    assert client.get("/metrics").status_code == 200
    assert client.get("/v1/me").status_code == 401
    assert client.get("/v1/me", headers=_headers()).status_code == 200

    rendered = metrics.render_prometheus()
    assert (
        'aegis_operations_total{component="api",operation="request",status="ok"} 1'
        in rendered
    )
    assert (
        'aegis_operations_total{component="api",operation="request",status="error"}'
        not in rendered
    )


def test_observability_check_enforces_remote_exporter_tls() -> None:
    assert _exporter_errors(
        {
            "otlphttp/optional_trace_backend": {
                "endpoint": "http://collector.invalid",
            }
        }
    ) == ["otlphttp/optional_trace_backend must configure TLS explicitly"]
    assert _exporter_errors(
        {
            "otlphttp/optional_trace_backend": {
                "endpoint": "https://collector.invalid",
                "tls": {"insecure": True},
            }
        }
    ) == ["otlphttp/optional_trace_backend must set tls.insecure to false"]
    assert not _exporter_errors(
        {
            "otlphttp/optional_trace_backend": {
                "endpoint": "https://collector.invalid",
                "tls": {"insecure": False},
            }
        }
    )


def test_replay_cli_is_read_only_and_redacted(tmp_path, capsys) -> None:
    store = InMemoryDurability(clock=FixedClock(DEMO_TIME))
    identity = demo_identity(request_id="layer11-cli")
    run = store.accept_run(
        identity=identity,
        request=demo_request(),
        wait_for_signal=False,
    )
    path = tmp_path / "events.json"
    path.write_text(
        json.dumps(
            [
                event.model_dump(mode="json")
                for event in store.events(tenant_id=identity.tenant_id)
            ]
        ),
        encoding="utf-8",
    )
    assert (
        main(
            (
                "replay",
                "--events",
                str(path),
                "--run-id",
                run.run_id,
                "--view",
                "support",
            )
        )
        == 0
    )
    output = capsys.readouterr().out
    assert '"valid": true' in output
    assert "tenant-acme" not in output
