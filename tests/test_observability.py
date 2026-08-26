from __future__ import annotations

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from aegis_framework.fixtures import build_demo_bundle, demo_identity, demo_request
from aegis_framework.observability import NoopObservability, OpenTelemetryObservability


def test_otel_exports_only_redacted_low_cardinality_attributes() -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    observability = OpenTelemetryObservability(
        provider.get_tracer("aegis-framework-tests")
    )
    with observability.investigation(
        tenant_id="tenant-sensitive-name",
        attributes={
            "scenario": "success",
            "request_id": "high-cardinality",
            "prompt": "never-export",
        },
    ) as observation:
        observation.finish(
            status="complete",
            attributes={
                "evidence_count": 3,
                "citation_count": 4,
                "raw_evidence": "never-export",
            },
        )

    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    attributes = dict(spans[0].attributes)
    assert attributes["aegis.operation"] == "checkout_investigation"
    assert attributes["aegis.scenario"] == "success"
    assert attributes["aegis.status"] == "complete"
    assert attributes["aegis.evidence_count"] == 3
    assert len(str(attributes["aegis.tenant.bucket"])) == 2
    rendered = repr(attributes)
    assert "tenant-sensitive-name" not in rendered
    assert "high-cardinality" not in rendered
    assert "never-export" not in rendered


def test_noop_observability_has_no_side_effects() -> None:
    with NoopObservability().investigation(
        tenant_id="tenant-acme",
        attributes={"scenario": "success"},
    ) as observation:
        assert (
            observation.finish(
                status="complete",
                attributes={"evidence_count": 3},
            )
            is None
        )
    with NoopObservability().remediation(
        tenant_id="tenant-acme",
        attributes={"action_kind": "kubernetes_rollout_restart"},
    ) as observation:
        assert (
            observation.finish(
                status="verified",
                attributes={"rollback": False},
            )
            is None
        )


def test_service_can_emit_otel_without_exporter() -> None:
    bundle = build_demo_bundle(use_otel=True)
    result = bundle.service.investigate(
        demo_identity(request_id="otel-service"),
        demo_request(),
    )
    assert result.status.value == "complete"


def test_remediation_span_exports_only_fixed_bounded_attributes() -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    observability = OpenTelemetryObservability(
        provider.get_tracer("aegis-framework-remediation-tests")
    )
    with observability.remediation(
        tenant_id="tenant-sensitive",
        attributes={
            "action_kind": "kubernetes_rollout_restart",
            "approval_status": "approved",
            "plan_id": "never-export",
            "rationale": "never-export",
        },
    ) as observation:
        observation.finish(
            status="verified",
            attributes={
                "effect_outcome": "succeeded",
                "verification_status": "verified",
                "rollback": False,
                "target": "never-export",
            },
        )
    span = exporter.get_finished_spans()[0]
    assert span.name == "aegis.remediation.activity"
    attributes = dict(span.attributes)
    assert attributes["aegis.operation"] == "remediation_activity"
    assert attributes["aegis.action_kind"] == "kubernetes_rollout_restart"
    assert attributes["aegis.effect_outcome"] == "succeeded"
    assert "tenant-sensitive" not in repr(attributes)
    assert "never-export" not in repr(attributes)
