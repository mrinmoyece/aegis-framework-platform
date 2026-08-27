"""Versioned, provider-neutral telemetry controls for Layer 11."""

from __future__ import annotations

import json
import logging
import re
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from threading import Lock
from time import monotonic
from typing import Final, Protocol

from opentelemetry.trace import Link, SpanContext, TraceFlags, TraceState
from pydantic import Field, field_validator

from aegis_framework.domain import Identifier, StrictModel

SEMANTIC_CONVENTION_VERSION: Final = "1.0.0"
INSTRUMENTATION_SCOPE: Final = "aegis.framework"

SPAN_NAMES: Final = frozenset(
    {
        "aegis.api.request",
        "aegis.ledger.append",
        "aegis.outbox.deliver",
        "aegis.temporal.workflow",
        "aegis.temporal.activity",
        "aegis.graph.run",
        "aegis.graph.node",
        "aegis.model.call",
        "aegis.connector.query",
        "aegis.approval.wait",
        "aegis.effect.execute",
        "aegis.sandbox.execute",
        "aegis.memory.retrieve",
        "aegis.eval.case",
        "aegis.mcp.call",
        "aegis.a2a.task",
    }
)

_TRACEPARENT = re.compile(
    r"^00-([0-9a-f]{32})-([0-9a-f]{16})-(00|01)$",
    re.ASCII,
)
_SENSITIVE_VALUE = re.compile(
    r"(?i)(?:bearer\s+[a-z0-9._~+/=-]+|"
    r"(?:api[_-]?key|authorization|cookie|password|prompt|secret|token)\s*[:=]|"
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b|"
    r"https?://\S+)"
)
_FORBIDDEN_KEY_PART = re.compile(
    r"(?i)(?:actor|artifact|authorization|cookie|credential|evidence_locator|"
    r"incident_id|prompt|raw|request_id|run_id|secret|subject|tenant|token|user)"
)
_SAFE_ATTRIBUTE_KEYS: Final = frozenset(
    {
        "aegis.component",
        "aegis.operation",
        "aegis.status",
        "aegis.error.type",
        "aegis.retry",
        "aegis.redelivery",
        "aegis.ambiguous",
        "aegis.replayed",
        "aegis.outcome",
        "aegis.connector.kind",
        "aegis.model.provider",
        "aegis.model.family",
        "aegis.graph.node",
        "aegis.specialist.role",
        "aegis.approval.status",
        "aegis.effect.kind",
        "aegis.sandbox.runtime",
        "aegis.memory.tier",
        "aegis.eval.suite",
        "aegis.protocol.kind",
        "aegis.protocol.transport",
        "aegis.protocol.trust_status",
        "aegis.count",
        "aegis.size.bytes",
        "aegis.duration.ms",
        "aegis.cost.microunits",
        "aegis.tokens.input",
        "aegis.tokens.output",
        "aegis.queue.age.ms",
        "aegis.semantic.version",
    }
)
_ENUM_VALUES: Final[dict[str, frozenset[str]]] = {
    "aegis.component": frozenset(
        {
            "api",
            "ledger",
            "outbox",
            "temporal",
            "graph",
            "model",
            "connector",
            "approval",
            "effect",
            "sandbox",
            "memory",
            "eval",
            "mcp",
            "a2a",
            "interop",
        }
    ),
    "aegis.status": frozenset(
        {
            "ok",
            "error",
            "denied",
            "cancelled",
            "timeout",
            "ambiguous",
            "degraded",
            "unavailable",
        }
    ),
    "aegis.error.type": frozenset(
        {
            "none",
            "authentication",
            "authorization",
            "validation",
            "capacity",
            "dependency",
            "integrity",
            "timeout",
            "conflict",
            "cancelled",
            "unknown",
        }
    ),
}
_BAGGAGE_ALLOWLIST: Final = frozenset({"aegis.sample", "aegis.debug"})
_METRIC_LABEL_VALUES: Final[dict[str, frozenset[str]]] = {
    "component": _ENUM_VALUES["aegis.component"],
    "status": _ENUM_VALUES["aegis.status"],
    "operation": frozenset(
        {
            "request",
            "append",
            "deliver",
            "workflow",
            "activity",
            "run",
            "node",
            "call",
            "query",
            "wait",
            "execute",
            "cleanup",
            "retrieve",
            "case",
            "projection",
            "negotiate",
            "discover",
            "reconcile",
            "cancel",
        }
    ),
    "reason": _ENUM_VALUES["aegis.error.type"],
    "severity": frozenset({"page", "ticket", "warning"}),
    "signal": frozenset({"traces", "metrics", "logs"}),
    "criticality": frozenset({"correctness", "optional"}),
    "dependency": frozenset(
        {
            "identity",
            "governance",
            "ledger",
            "postgresql",
            "temporal",
            "telemetry-export",
        }
    ),
    "queue": frozenset(
        {"outbox", "temporal", "sandbox", "memory", "eval", "mcp", "a2a"}
    ),
}
_MAX_ATTRIBUTE_TEXT = 64
_MAX_LOG_BYTES = 4096


class TraceContextRejected(ValueError):
    """Raised when untrusted propagation data is malformed or unsupported."""


class TelemetryAttributeRejected(ValueError):
    """Raised when code attempts to export unsafe or unstable telemetry."""


class TraceReference(StrictModel):
    """Safe durable trace coordinates; never an authorization or audit fact."""

    version: int = Field(default=1, ge=1, le=1)
    trace_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    span_id: str = Field(pattern=r"^[0-9a-f]{16}$")
    sampled: bool

    @field_validator("trace_id")
    @classmethod
    def reject_zero_trace(cls, value: str) -> str:
        if value == "0" * 32:
            raise ValueError("zero trace id is invalid")
        return value

    @field_validator("span_id")
    @classmethod
    def reject_zero_span(cls, value: str) -> str:
        if value == "0" * 16:
            raise ValueError("zero span id is invalid")
        return value

    @property
    def traceparent(self) -> str:
        return f"00-{self.trace_id}-{self.span_id}-{'01' if self.sampled else '00'}"

    @classmethod
    def from_span_context(cls, context: SpanContext) -> TraceReference:
        if not context.is_valid:
            raise ValueError("span context is invalid")
        return cls(
            trace_id=f"{context.trace_id:032x}",
            span_id=f"{context.span_id:016x}",
            sampled=bool(context.trace_flags & TraceFlags.SAMPLED),
        )

    def as_span_context(self, *, remote: bool = True) -> SpanContext:
        return SpanContext(
            trace_id=int(self.trace_id, 16),
            span_id=int(self.span_id, 16),
            is_remote=remote,
            trace_flags=TraceFlags(
                TraceFlags.SAMPLED if self.sampled else TraceFlags.DEFAULT
            ),
            trace_state=TraceState(),
        )


class PropagationResult(StrictModel):
    parent: TraceReference | None
    baggage: dict[str, str]
    rejected: bool
    rejection_code: Identifier | None = None


def extract_trace_context(
    headers: Mapping[str, str],
    *,
    reject_invalid: bool = True,
) -> PropagationResult:
    """Extract strict W3C context without accepting arbitrary tracestate or baggage."""

    normalized = {key.lower(): value.strip() for key, value in headers.items()}
    supplied = normalized.get("traceparent")
    baggage = _parse_baggage(normalized.get("baggage", ""))
    if supplied is None:
        return PropagationResult(parent=None, baggage=baggage, rejected=False)
    if len(supplied) > 55:
        return _rejected_context("traceparent_size", reject_invalid)
    match = _TRACEPARENT.fullmatch(supplied)
    if match is None or match.group(1) == "0" * 32 or match.group(2) == "0" * 16:
        return _rejected_context("traceparent_invalid", reject_invalid)
    return PropagationResult(
        parent=TraceReference(
            trace_id=match.group(1),
            span_id=match.group(2),
            sampled=match.group(3) == "01",
        ),
        baggage=baggage,
        rejected=False,
    )


def inject_trace_context(
    reference: TraceReference,
    *,
    baggage: Mapping[str, str] | None = None,
) -> dict[str, str]:
    headers = {"traceparent": reference.traceparent}
    safe_baggage = _safe_baggage(baggage or {})
    if safe_baggage:
        headers["baggage"] = ",".join(
            f"{key}={value}" for key, value in sorted(safe_baggage.items())
        )
    return headers


def deterministic_sample(
    correlation_ref: str,
    *,
    rate_basis_points: int,
    force: bool = False,
) -> bool:
    if rate_basis_points < 0 or rate_basis_points > 10_000:
        raise ValueError("sampling rate must be between 0 and 10000 basis points")
    if force:
        return True
    slot = int.from_bytes(sha256(correlation_ref.encode()).digest()[:8], "big") % 10_000
    return slot < rate_basis_points


def durable_trace_reference(
    correlation_ref: str,
    *,
    sampled: bool | None = None,
) -> TraceReference:
    """Derive stable, opaque coordinates for durable retries and redeliveries."""

    trace_digest = sha256(f"trace:{correlation_ref}".encode()).hexdigest()
    span_digest = sha256(f"span:{correlation_ref}".encode()).hexdigest()
    return TraceReference(
        trace_id=trace_digest[:32],
        span_id=span_digest[:16],
        sampled=(
            deterministic_sample(correlation_ref, rate_basis_points=1000)
            if sampled is None
            else sampled
        ),
    )


def linked_contexts(
    references: Sequence[TraceReference], *, maximum: int = 32
) -> tuple[Link, ...]:
    """Build bounded links for retry, redelivery, and fan-out causality."""

    if maximum < 1 or maximum > 64:
        raise ValueError("trace link bound is invalid")
    unique: dict[tuple[str, str], TraceReference] = {}
    for reference in references:
        unique[(reference.trace_id, reference.span_id)] = reference
    return tuple(
        Link(reference.as_span_context())
        for reference in sorted(
            unique.values(), key=lambda item: (item.trace_id, item.span_id)
        )[:maximum]
    )


def safe_attributes(
    attributes: Mapping[str, str | int | float | bool],
    *,
    strict: bool = True,
) -> dict[str, str | int | float | bool]:
    """Enforce the semantic allowlist, units, and low-cardinality value bounds."""

    safe: dict[str, str | int | float | bool] = {}
    for key, value in attributes.items():
        if key not in _SAFE_ATTRIBUTE_KEYS or _FORBIDDEN_KEY_PART.search(key):
            if strict:
                raise TelemetryAttributeRejected(
                    f"telemetry attribute is not allowed: {key}"
                )
            continue
        if isinstance(value, str):
            if (
                len(value) > _MAX_ATTRIBUTE_TEXT
                or _SENSITIVE_VALUE.search(value)
                or any(character in value for character in ("\n", "\r", "\t"))
            ):
                if strict:
                    raise TelemetryAttributeRejected(
                        f"telemetry value is not bounded: {key}"
                    )
                continue
            allowed = _ENUM_VALUES.get(key)
            if allowed is not None and value not in allowed:
                if strict:
                    raise TelemetryAttributeRejected(
                        f"telemetry enum value is not allowed: {key}"
                    )
                continue
        safe[key] = value
    safe.setdefault("aegis.semantic.version", SEMANTIC_CONVENTION_VERSION)
    return dict(sorted(safe.items()))


class MetricDefinition(StrictModel):
    name: str = Field(pattern=r"^aegis_[a-z0-9_]+$")
    kind: str = Field(pattern=r"^(counter|gauge|histogram)$")
    unit: Identifier
    description: str = Field(min_length=1, max_length=200)
    labels: tuple[Identifier, ...] = ()
    buckets: tuple[float, ...] = ()

    @field_validator("labels")
    @classmethod
    def validate_labels(cls, labels: tuple[str, ...]) -> tuple[str, ...]:
        if len(labels) > 4 or len(labels) != len(set(labels)):
            raise ValueError("metric label budget exceeded")
        for label in labels:
            if _FORBIDDEN_KEY_PART.search(label):
                raise ValueError("metric label contains a forbidden identity dimension")
        return labels

    @field_validator("buckets")
    @classmethod
    def validate_buckets(cls, buckets: tuple[float, ...]) -> tuple[float, ...]:
        if len(buckets) > 16 or tuple(sorted(set(buckets))) != buckets:
            raise ValueError("histogram buckets must be unique, sorted, and bounded")
        return buckets


METRICS: Final[tuple[MetricDefinition, ...]] = (
    MetricDefinition(
        name="aegis_operations_total",
        kind="counter",
        unit="operations",
        description="Logical operations, excluding retries and replay duplicates.",
        labels=("component", "operation", "status"),
    ),
    MetricDefinition(
        name="aegis_operation_duration_seconds",
        kind="histogram",
        unit="seconds",
        description="End-to-end logical operation latency.",
        labels=("component", "operation"),
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
    ),
    MetricDefinition(
        name="aegis_queue_age_seconds",
        kind="histogram",
        unit="seconds",
        description="Age of durable work before claim.",
        labels=("component", "queue"),
        buckets=(0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 300, 900, 3600),
    ),
    MetricDefinition(
        name="aegis_retries_total",
        kind="counter",
        unit="attempts",
        description="Retry attempts, separate from logical operation totals.",
        labels=("component", "operation", "reason"),
    ),
    MetricDefinition(
        name="aegis_ambiguous_outcomes_total",
        kind="counter",
        unit="outcomes",
        description="Operations requiring reconciliation.",
        labels=("component", "operation"),
    ),
    MetricDefinition(
        name="aegis_safety_violations_total",
        kind="counter",
        unit="violations",
        description="Non-budgetable safety invariant violations.",
        labels=("control", "severity"),
    ),
    MetricDefinition(
        name="aegis_export_dropped_total",
        kind="counter",
        unit="records",
        description="Telemetry records dropped by bounded exporters.",
        labels=("signal", "reason"),
    ),
    MetricDefinition(
        name="aegis_dependency_ready",
        kind="gauge",
        unit="state",
        description="Dependency readiness where 1 is ready and 0 is unavailable.",
        labels=("dependency", "criticality"),
    ),
)


class MetricRegistry:
    """Small deterministic Prometheus registry with cardinality and dedupe guards."""

    def __init__(self, definitions: Sequence[MetricDefinition] = METRICS) -> None:
        self._definitions = {definition.name: definition for definition in definitions}
        self._values: dict[tuple[str, tuple[tuple[str, str], ...]], float] = (
            defaultdict(float)
        )
        self._histograms: dict[
            tuple[str, tuple[tuple[str, str], ...]], Counter[float]
        ] = defaultdict(Counter)
        self._logical_keys: set[tuple[str, str]] = set()
        self._lock = Lock()

    def record(
        self,
        name: str,
        value: float,
        *,
        labels: Mapping[str, str],
        logical_key: str | None = None,
    ) -> bool:
        definition = self._definitions.get(name)
        if definition is None:
            raise ValueError("metric is not registered")
        normalized = _metric_labels(definition, labels)
        with self._lock:
            if logical_key is not None:
                dedupe_key = (name, logical_key)
                if dedupe_key in self._logical_keys:
                    return False
                if len(self._logical_keys) >= 100_000:
                    raise ValueError("metric logical-key bound exceeded")
                self._logical_keys.add(dedupe_key)
            key = (name, normalized)
            if definition.kind == "gauge":
                self._values[key] = value
            elif definition.kind == "counter":
                if value < 0:
                    raise ValueError("counter increments cannot be negative")
                self._values[key] += value
            else:
                if value < 0:
                    raise ValueError("histogram observations cannot be negative")
                self._values[key] += value
                for bucket in definition.buckets:
                    if value <= bucket:
                        self._histograms[key][bucket] += 1
                self._histograms[key][float("inf")] += 1
            return True

    def render_prometheus(self) -> str:
        lines: list[str] = []
        with self._lock:
            for definition in sorted(
                self._definitions.values(), key=lambda item: item.name
            ):
                lines.extend(
                    (
                        f"# HELP {definition.name} {definition.description}",
                        f"# TYPE {definition.name} {definition.kind}",
                    )
                )
                for key, value in sorted(self._values.items()):
                    name, labels = key
                    if name != definition.name:
                        continue
                    rendered = _render_labels(labels)
                    if definition.kind != "histogram":
                        lines.append(f"{name}{rendered} {_number(value)}")
                        continue
                    counts = self._histograms[key]
                    for bucket in (*definition.buckets, float("inf")):
                        le = "+Inf" if bucket == float("inf") else _number(bucket)
                        bucket_labels = (*labels, ("le", le))
                        lines.append(
                            f"{name}_bucket{_render_labels(bucket_labels)} "
                            f"{counts[bucket]}"
                        )
                    lines.append(f"{name}_count{rendered} {counts[float('inf')]}")
                    lines.append(f"{name}_sum{rendered} {_number(value)}")
        return "\n".join(lines) + "\n"


class StructuredLogSink(Protocol):
    def emit(self, record: str) -> None: ...


class PythonLogSink:
    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger("aegis.telemetry")

    def emit(self, record: str) -> None:
        self._logger.info("%s", record)


@dataclass
class _RateWindow:
    started: float
    emitted: int = 0
    suppressed: int = 0


class BoundedJsonLogger:
    """Allowlisted JSON logger with trace correlation and per-event suppression."""

    def __init__(
        self,
        sink: StructuredLogSink,
        *,
        maximum_per_minute: int = 120,
    ) -> None:
        if maximum_per_minute < 1 or maximum_per_minute > 10_000:
            raise ValueError("log rate bound is invalid")
        self._sink = sink
        self._maximum = maximum_per_minute
        self._windows: dict[str, _RateWindow] = {}
        self._lock = Lock()

    def emit(
        self,
        *,
        event: str,
        level: str,
        attributes: Mapping[str, str | int | float | bool],
        trace: TraceReference | None = None,
    ) -> bool:
        if event not in SPAN_NAMES or level not in {"INFO", "WARNING", "ERROR"}:
            raise ValueError("log event or level is not allowlisted")
        now = monotonic()
        with self._lock:
            window = self._windows.setdefault(event, _RateWindow(started=now))
            if now - window.started >= 60:
                window.started = now
                window.emitted = 0
                window.suppressed = 0
            if window.emitted >= self._maximum:
                window.suppressed += 1
                return False
            window.emitted += 1
        payload: dict[str, object] = {
            "schema_version": SEMANTIC_CONVENTION_VERSION,
            "event": event,
            "level": level,
            "attributes": safe_attributes(attributes),
        }
        if trace is not None:
            payload["trace"] = {
                "trace_id": trace.trace_id,
                "span_id": trace.span_id,
                "sampled": trace.sampled,
            }
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        if len(encoded.encode()) > _MAX_LOG_BYTES:
            raise TelemetryAttributeRejected("structured log exceeds the byte bound")
        try:
            self._sink.emit(encoded)
        except Exception:  # exporter implementations are an untrusted optional boundary
            return False
        return True

    def suppressed(self, event: str) -> int:
        with self._lock:
            window = self._windows.get(event)
            return 0 if window is None else window.suppressed


class DependencyState(StrictModel):
    name: Identifier
    criticality: str = Field(pattern=r"^(correctness|optional)$")
    ready: bool
    status: str = Field(pattern=r"^(ready|degraded|unavailable)$")


class ReadinessSnapshot(StrictModel):
    status: str = Field(pattern=r"^(ready|degraded|not_ready)$")
    dependencies: tuple[DependencyState, ...]


def readiness_snapshot(dependencies: Sequence[DependencyState]) -> ReadinessSnapshot:
    ordered = tuple(sorted(dependencies, key=lambda item: item.name))
    if any(not item.ready and item.criticality == "correctness" for item in ordered):
        status = "not_ready"
    elif any(not item.ready for item in ordered):
        status = "degraded"
    else:
        status = "ready"
    return ReadinessSnapshot(status=status, dependencies=ordered)


def _parse_baggage(value: str) -> dict[str, str]:
    if not value:
        return {}
    if len(value) > 512 or len(value.split(",")) > 8:
        raise TraceContextRejected("baggage exceeds the permitted bound")
    parsed: dict[str, str] = {}
    for item in value.split(","):
        key, separator, child = item.strip().partition("=")
        if not separator:
            raise TraceContextRejected("baggage member is malformed")
        if key in _BAGGAGE_ALLOWLIST and child in {"0", "1"}:
            parsed[key] = child
    return dict(sorted(parsed.items()))


def _safe_baggage(value: Mapping[str, str]) -> dict[str, str]:
    if len(value) > 8:
        raise ValueError("baggage exceeds the permitted bound")
    return {
        key: child
        for key, child in sorted(value.items())
        if key in _BAGGAGE_ALLOWLIST and child in {"0", "1"}
    }


def _rejected_context(code: str, reject_invalid: bool) -> PropagationResult:
    if reject_invalid:
        raise TraceContextRejected(code)
    return PropagationResult(
        parent=None,
        baggage={},
        rejected=True,
        rejection_code=code,
    )


def _metric_labels(
    definition: MetricDefinition,
    labels: Mapping[str, str],
) -> tuple[tuple[str, str], ...]:
    if set(labels) != set(definition.labels):
        raise ValueError("metric labels do not match the registered schema")
    normalized: list[tuple[str, str]] = []
    for key, value in labels.items():
        if (
            len(value) < 1
            or len(value) > 48
            or _SENSITIVE_VALUE.search(value)
            or _FORBIDDEN_KEY_PART.search(key)
            or not re.fullmatch(r"[a-z0-9_.-]+", value)
        ):
            raise ValueError("metric label value is unsafe or unbounded")
        allowed = _METRIC_LABEL_VALUES.get(key)
        if allowed is not None and value not in allowed:
            raise ValueError("metric label value is outside its stable enumeration")
        normalized.append((key, value))
    return tuple(sorted(normalized))


def _render_labels(labels: Sequence[tuple[str, str]]) -> str:
    if not labels:
        return ""
    return "{" + ",".join(f'{key}="{value}"' for key, value in labels) + "}"


def _number(value: float) -> str:
    return str(int(value)) if value.is_integer() else format(value, ".12g")
