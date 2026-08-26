"""Ledger-grounded, deterministic, read-only replay debugging."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from hashlib import sha256

from pydantic import Field, JsonValue

from aegis_framework.domain import Identifier, StrictModel
from aegis_framework.durability import (
    ApplicationEvent,
    EventDraft,
    RunView,
    event_material,
    reduce_run,
)

_ZERO_HASH = "0" * 64
_MAX_EVENTS = 10_000
_MAX_REPORT_BYTES = 32_768


class ReplayIntegrity(StrictModel):
    valid: bool
    event_count: int = Field(ge=0, le=_MAX_EVENTS)
    last_cursor: int = Field(ge=0)
    last_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    failure_code: Identifier | None = None


class ReplayPoint(StrictModel):
    cursor: int = Field(ge=0)
    event_type: Identifier | None
    state: RunView | None
    state_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class ProjectionDifference(StrictModel):
    matches: bool
    live_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    replay_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    differing_fields: tuple[Identifier, ...]


class CausalItem(StrictModel):
    cursor: int = Field(ge=1)
    event_type: Identifier
    status: Identifier
    blocked: bool
    causation_known: bool
    trace_ref: str | None = Field(default=None, max_length=80)


class SupportReport(StrictModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    integrity: ReplayIntegrity
    projection: ProjectionDifference | None
    causal_chain: tuple[CausalItem, ...]
    report_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    truncated: bool
    completeness_code: Identifier | None = None


class ReplayDebugger:
    """Validates and projects application events without invoking external systems."""

    def __init__(
        self,
        events: Sequence[ApplicationEvent],
        *,
        tenant_anchor_cursor: int = 0,
        tenant_anchor_hash: str = _ZERO_HASH,
        aggregate_anchors: Mapping[tuple[str, str], tuple[int, str]] | None = None,
    ) -> None:
        if len(events) > _MAX_EVENTS:
            raise ValueError("replay event bound exceeded")
        if tenant_anchor_cursor < 0 or len(tenant_anchor_hash) != 64:
            raise ValueError("replay tenant anchor is invalid")
        self._events = tuple(sorted(events, key=lambda item: item.tenant_cursor))
        self._tenant_anchor_cursor = tenant_anchor_cursor
        self._tenant_anchor_hash = tenant_anchor_hash
        self._aggregate_anchors = dict(aggregate_anchors or {})
        tenant_ids = {event.tenant_id for event in self._events}
        if len(tenant_ids) > 1:
            raise ValueError("replay input must contain exactly one tenant")

    def verify(self) -> ReplayIntegrity:
        aggregate_heads = dict(self._aggregate_anchors)
        tenant_cursor = self._tenant_anchor_cursor
        tenant_hash = self._tenant_anchor_hash
        seen: set[str] = set()
        for event in self._events:
            key = (event.aggregate_type, event.aggregate_id)
            sequence, aggregate_hash = aggregate_heads.get(key, (0, _ZERO_HASH))
            draft = EventDraft(
                event_id=event.event_id,
                event_type=event.event_type,
                occurred_at=event.occurred_at,
                actor_ref=event.actor_ref,
                correlation_ref=event.correlation_ref,
                causation_ref=event.causation_ref,
                schema_version=event.schema_version,
                payload=event.payload,
            )
            expected = sha256(
                event_material(
                    tenant_id=event.tenant_id,
                    aggregate_type=event.aggregate_type,
                    aggregate_id=event.aggregate_id,
                    aggregate_sequence=event.aggregate_sequence,
                    tenant_cursor=event.tenant_cursor,
                    draft=draft,
                    aggregate_previous_hash=aggregate_hash,
                    tenant_previous_hash=tenant_hash,
                ).encode()
            ).hexdigest()
            failure = _integrity_failure(
                event=event,
                expected_sequence=sequence + 1,
                expected_cursor=tenant_cursor + 1,
                expected_aggregate_hash=aggregate_hash,
                expected_tenant_hash=tenant_hash,
                expected_record_hash=expected,
                seen=seen,
            )
            if failure is not None:
                return ReplayIntegrity(
                    valid=False,
                    event_count=len(seen),
                    last_cursor=tenant_cursor,
                    last_hash=tenant_hash,
                    failure_code=failure,
                )
            seen.add(event.event_id)
            aggregate_heads[key] = (event.aggregate_sequence, event.record_hash)
            tenant_cursor = event.tenant_cursor
            tenant_hash = event.record_hash
        return ReplayIntegrity(
            valid=True,
            event_count=len(self._events),
            last_cursor=tenant_cursor,
            last_hash=tenant_hash,
        )

    def state_at(
        self,
        *,
        aggregate_id: str,
        cursor: int | None = None,
    ) -> ReplayPoint:
        if cursor is not None and cursor < 0:
            raise ValueError("replay cursor cannot be negative")
        state: RunView | None = None
        last: ApplicationEvent | None = None
        for event in self._events:
            if cursor is not None and event.tenant_cursor > cursor:
                break
            if (
                event.aggregate_type != "investigation"
                or event.aggregate_id != aggregate_id
            ):
                continue
            state = reduce_run(state, event)
            last = event
        return ReplayPoint(
            cursor=0 if last is None else last.tenant_cursor,
            event_type=None if last is None else last.event_type,
            state=state,
            state_digest=_digest_model(state),
        )

    def compare(
        self,
        *,
        aggregate_id: str,
        live: RunView | None,
        cursor: int | None = None,
    ) -> ProjectionDifference:
        replay = self.state_at(aggregate_id=aggregate_id, cursor=cursor).state
        live_value = _model_value(live)
        replay_value = _model_value(replay)
        fields = tuple(
            sorted(
                str(key)
                for key in set(live_value) | set(replay_value)
                if live_value.get(key) != replay_value.get(key)
            )
        )
        return ProjectionDifference(
            matches=not fields,
            live_digest=_digest_mapping(live_value),
            replay_digest=_digest_mapping(replay_value),
            differing_fields=fields,
        )

    def causal_chain(
        self,
        *,
        aggregate_id: str,
        maximum: int = 200,
    ) -> tuple[CausalItem, ...]:
        if maximum < 1 or maximum > 500:
            raise ValueError("causal chain bound is invalid")
        known = {event.event_id for event in self._events}
        selected: list[CausalItem] = []
        state: RunView | None = None
        for event in self._events:
            if (
                event.aggregate_type != "investigation"
                or event.aggregate_id != aggregate_id
            ):
                continue
            state = reduce_run(state, event)
            trace_ref = event.payload.get("trace_ref")
            selected.append(
                CausalItem(
                    cursor=event.tenant_cursor,
                    event_type=event.event_type,
                    status=state.status.value,
                    blocked=state.status.value
                    in {"waiting", "cancel_requested", "failed", "timed_out"},
                    causation_known=(
                        event.causation_ref is None or event.causation_ref in known
                    ),
                    trace_ref=(
                        trace_ref
                        if isinstance(trace_ref, str)
                        and len(trace_ref) <= 80
                        and trace_ref.startswith("00-")
                        else None
                    ),
                )
            )
        return tuple(selected[:maximum])

    def support_report(
        self,
        *,
        aggregate_id: str,
        live: RunView | None = None,
        maximum_events: int = 200,
        maximum_bytes: int = _MAX_REPORT_BYTES,
    ) -> SupportReport:
        if maximum_bytes < 1024 or maximum_bytes > _MAX_REPORT_BYTES:
            raise ValueError("support report byte bound is invalid")
        integrity = self.verify()
        if not integrity.valid:
            failed_material: dict[str, object] = {
                "integrity": integrity.model_dump(mode="json"),
                "projection": None,
                "causal_chain": [],
                "truncated": True,
                "completeness_code": "integrity_failed",
            }
            return SupportReport(
                integrity=integrity,
                projection=None,
                causal_chain=(),
                report_digest=sha256(_canonical(failed_material).encode()).hexdigest(),
                truncated=True,
                completeness_code="integrity_failed",
            )
        chain = self.causal_chain(
            aggregate_id=aggregate_id,
            maximum=min(maximum_events, 500),
        )
        projection = self.compare(aggregate_id=aggregate_id, live=live)
        truncated = len(chain) < sum(
            event.aggregate_type == "investigation"
            and event.aggregate_id == aggregate_id
            for event in self._events
        )
        material = {
            "integrity": integrity.model_dump(mode="json"),
            "projection": projection.model_dump(mode="json"),
            "causal_chain": [item.model_dump(mode="json") for item in chain],
            "truncated": truncated,
            "completeness_code": None,
        }
        while len(_canonical(material).encode()) > maximum_bytes and chain:
            chain = chain[:-1]
            material["causal_chain"] = [item.model_dump(mode="json") for item in chain]
            material["truncated"] = True
        if len(_canonical(material).encode()) > maximum_bytes:
            raise ValueError("support report cannot fit within its byte bound")
        report = SupportReport(
            integrity=integrity,
            projection=projection,
            causal_chain=chain,
            report_digest=sha256(_canonical(material).encode()).hexdigest(),
            truncated=bool(material["truncated"]),
        )
        # Verify the fully-serialized report (which includes integrity and
        # projection) still satisfies the bound; trim the chain further if not.
        while len(report.model_dump_json().encode()) > maximum_bytes and chain:
            chain = chain[:-1]
            material["causal_chain"] = [item.model_dump(mode="json") for item in chain]
            material["truncated"] = True
            report = SupportReport(
                integrity=integrity,
                projection=projection,
                causal_chain=chain,
                report_digest=sha256(_canonical(material).encode()).hexdigest(),
                truncated=True,
            )
        if len(report.model_dump_json().encode()) > maximum_bytes:
            raise ValueError("support report cannot fit within its byte bound")
        return report


def load_events(value: object) -> tuple[ApplicationEvent, ...]:
    if not isinstance(value, list) or len(value) > _MAX_EVENTS:
        raise ValueError("replay input must be a bounded event array")
    return tuple(ApplicationEvent.model_validate(item) for item in value)


def projection_document(
    debugger: ReplayDebugger,
    *,
    aggregate_id: str,
    cursor: int | None = None,
) -> dict[str, JsonValue]:
    """Return a rebuild candidate document; this function never mutates storage."""

    point = debugger.state_at(aggregate_id=aggregate_id, cursor=cursor)
    return {
        "schema_version": 1,
        "aggregate_id": aggregate_id,
        "cursor": point.cursor,
        "event_type": point.event_type,
        "state": (
            None
            if point.state is None
            else point.state.model_dump(mode="json", exclude={"tenant_id"})
        ),
        "state_digest": point.state_digest,
    }


def _integrity_failure(
    *,
    event: ApplicationEvent,
    expected_sequence: int,
    expected_cursor: int,
    expected_aggregate_hash: str,
    expected_tenant_hash: str,
    expected_record_hash: str,
    seen: set[str],
) -> str | None:
    if event.event_id in seen:
        return "duplicate_event"
    if event.aggregate_sequence != expected_sequence:
        return "aggregate_sequence"
    if event.tenant_cursor != expected_cursor:
        return "tenant_cursor"
    if event.aggregate_previous_hash != expected_aggregate_hash:
        return "aggregate_hash"
    if event.tenant_previous_hash != expected_tenant_hash:
        return "tenant_hash"
    if event.record_hash != expected_record_hash:
        return "record_hash"
    if event.schema_version != 1:
        return "schema_version"
    return None


def _model_value(value: RunView | None) -> dict[str, JsonValue]:
    if value is None:
        return {}
    return value.model_dump(mode="json")


def _digest_model(value: RunView | None) -> str:
    return _digest_mapping(_model_value(value))


def _digest_mapping(value: Mapping[str, JsonValue]) -> str:
    return sha256(_canonical(value).encode()).hexdigest()


def _canonical(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)
