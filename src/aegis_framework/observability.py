"""Redacted, low-cardinality OpenTelemetry application instrumentation."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass

from opentelemetry import trace
from opentelemetry.trace import Span, Tracer

from aegis_framework.ports import Observation
from aegis_framework.safety import safe_observability_attributes, tenant_bucket


@dataclass
class _SpanObservation:
    span: Span

    def finish(
        self,
        *,
        status: str,
        attributes: Mapping[str, str | int | bool],
    ) -> None:
        safe = safe_observability_attributes({**attributes, "status": status})
        for key, value in safe.items():
            self.span.set_attribute(f"aegis.{key}", value)


class OpenTelemetryObservability:
    def __init__(self, tracer: Tracer | None = None) -> None:
        self._tracer = tracer or trace.get_tracer("aegis-framework", "0.3.0")

    def investigation(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        return self._span(tenant_id=tenant_id, attributes=attributes)

    @contextmanager
    def _span(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> Iterator[Observation]:
        safe = safe_observability_attributes(attributes)
        safe["operation"] = "checkout_investigation"
        with self._tracer.start_as_current_span("aegis.investigation") as span:
            span.set_attribute("aegis.tenant.bucket", tenant_bucket(tenant_id))
            for key, value in safe.items():
                span.set_attribute(f"aegis.{key}", value)
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
