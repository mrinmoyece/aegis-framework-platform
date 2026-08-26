"""Redacted, low-cardinality OpenTelemetry application instrumentation."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass

from opentelemetry import trace
from opentelemetry.trace import Span, Tracer

from aegis_framework.ports import Observation
from aegis_framework.telemetry import SEMANTIC_CONVENTION_VERSION, safe_attributes


@dataclass
class _SpanObservation:
    span: Span

    def finish(
        self,
        *,
        status: str,
        attributes: Mapping[str, str | int | bool],
    ) -> None:
        prefixed = {
            f"aegis.{k}": v for k, v in {**attributes, "status": status}.items()
        }
        safe = safe_attributes(prefixed, strict=False)
        for key, value in safe.items():
            self.span.set_attribute(key, value)


class OpenTelemetryObservability:
    def __init__(self, tracer: Tracer | None = None) -> None:
        self._tracer = tracer or trace.get_tracer(
            "aegis-framework", SEMANTIC_CONVENTION_VERSION
        )

    def investigation(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        return self._span(tenant_id=tenant_id, attributes=attributes)

    def evidence_query(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        return self._span(
            tenant_id=tenant_id,
            attributes={**attributes, "operation": "evidence_query"},
            span_name="aegis.evidence.query",
        )

    def graph_node(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        return self._span(
            tenant_id=tenant_id,
            attributes={**attributes, "operation": "graph_node"},
            span_name="aegis.graph.node",
        )

    def model_call(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        return self._span(
            tenant_id=tenant_id,
            attributes={**attributes, "operation": "model_call"},
            span_name="aegis.graph.model",
        )

    def remediation(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        return self._span(
            tenant_id=tenant_id,
            attributes={**attributes, "operation": "remediation_activity"},
            span_name="aegis.remediation.activity",
        )

    def sandbox(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        return self._span(
            tenant_id=tenant_id,
            attributes={**attributes, "operation": "sandbox_activity"},
            span_name="aegis.sandbox.activity",
        )

    def memory(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        return self._span(
            tenant_id=tenant_id,
            attributes={**attributes, "operation": "memory_activity"},
            span_name="aegis.memory.activity",
        )

    def interoperability(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        protocol = attributes.get("protocol_kind")
        span_name = "aegis.a2a.task" if protocol == "a2a" else "aegis.mcp.call"
        return self._span(
            tenant_id=tenant_id,
            attributes={**attributes, "operation": "protocol_operation"},
            span_name=span_name,
        )

    @contextmanager
    def _span(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
        span_name: str = "aegis.investigation",
    ) -> Iterator[Observation]:
        # Prefix keys with "aegis." so safe_attributes can enforce the
        # semantic allowlist, value bounds, and low-cardinality enum rules
        # defined in the telemetry module.
        prefixed = {f"aegis.{k}": v for k, v in attributes.items()}
        safe = safe_attributes(prefixed, strict=False)
        safe.setdefault("aegis.operation", "checkout_investigation")
        with self._tracer.start_as_current_span(span_name) as span:
            del tenant_id
            span.set_attribute("aegis.semantic.version", SEMANTIC_CONVENTION_VERSION)
            for key, value in safe.items():
                span.set_attribute(key, value)
            yield _SpanObservation(span)


class NoopObservability:
    def investigation(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        del tenant_id, attributes
        return self._observation()

    def evidence_query(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        del tenant_id, attributes
        return self._observation()

    def graph_node(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        del tenant_id, attributes
        return self._observation()

    def model_call(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        del tenant_id, attributes
        return self._observation()

    def remediation(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        del tenant_id, attributes
        return self._observation()

    def sandbox(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        del tenant_id, attributes
        return self._observation()

    def memory(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        del tenant_id, attributes
        return self._observation()

    def interoperability(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        del tenant_id, attributes
        return self._observation()

    @staticmethod
    @contextmanager
    def _observation() -> Iterator[Observation]:
        yield _NoopObservation()


class _NoopObservation:
    def finish(
        self,
        *,
        status: str,
        attributes: Mapping[str, str | int | bool],
    ) -> None:
        del status, attributes
