"""Application-owned durable events, delivery records, and rebuildable projections."""

from __future__ import annotations

import base64
import hmac
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from threading import Lock
from typing import TYPE_CHECKING, Protocol

from pydantic import (
    AwareDatetime,
    Field,
    JsonValue,
    ValidationError,
    field_validator,
)

from aegis_framework.domain import (
    Identifier,
    IdentityContext,
    InvestigationRequest,
    RiskLevel,
    StrictModel,
    stable_id,
)
from aegis_framework.errors import (
    ConcurrencyConflict,
    IdempotencyConflict,
    IntegrityFailure,
    MessageClaimConflict,
    PayloadRejected,
)
from aegis_framework.ports import Action, ClockPort, PolicyPort
from aegis_framework.telemetry import durable_trace_reference

if TYPE_CHECKING:
    from aegis_framework.replay import SupportReport

_ZERO_HASH = "0" * 64
_MAX_EVENT_BYTES = 32_768
_MAX_EVENTS_PER_APPEND = 32
_MAX_DELIVERY_ATTEMPTS = 5
_MAX_RESUME_COMMANDS = 32


class RunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCEL_REQUESTED = "cancel_requested"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class DeliveryStatus(StrEnum):
    PENDING = "pending"
    CLAIMED = "claimed"
    DELIVERED = "delivered"
    DEAD_LETTER = "dead_letter"


class EventDraft(StrictModel):
    event_id: Identifier
    event_type: Identifier
    occurred_at: AwareDatetime
    actor_ref: Identifier
    correlation_ref: Identifier
    causation_ref: Identifier | None = None
    schema_version: int = Field(default=1, ge=1, le=1_000)
    payload: dict[str, JsonValue] = Field(default_factory=dict, max_length=32)

    @field_validator("payload")
    @classmethod
    def bound_payload(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        encoded = _canonical_json(value).encode()
        if len(encoded) > _MAX_EVENT_BYTES:
            raise ValueError("event payload exceeds the application bound")
        return dict(sorted(value.items()))


class ApplicationEvent(StrictModel):
    tenant_id: Identifier
    aggregate_type: Identifier
    aggregate_id: Identifier
    aggregate_sequence: int = Field(ge=1)
    tenant_cursor: int = Field(ge=1)
    event_id: Identifier
    event_type: Identifier
    occurred_at: AwareDatetime
    actor_ref: Identifier
    correlation_ref: Identifier
    causation_ref: Identifier | None = None
    schema_version: int = Field(ge=1, le=1_000)
    payload: dict[str, JsonValue]
    aggregate_previous_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    tenant_previous_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    record_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class OutboxDraft(StrictModel):
    message_id: Identifier
    destination: Identifier
    message_type: Identifier
    available_at: AwareDatetime
    payload: dict[str, JsonValue] = Field(max_length=16)

    @field_validator("payload")
    @classmethod
    def bound_payload(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        if len(_canonical_json(value).encode()) > 8_192:
            raise ValueError("outbox payload exceeds the application bound")
        return dict(sorted(value.items()))


class InboxDraft(StrictModel):
    message_id: Identifier
    source: Identifier
    message_type: Identifier
    payload: dict[str, JsonValue] = Field(max_length=16)

    @field_validator("payload")
    @classmethod
    def bound_payload(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        if len(_canonical_json(value).encode()) > 8_192:
            raise ValueError("inbox payload exceeds the application bound")
        return dict(sorted(value.items()))


class DeliveryRecord(StrictModel):
    tenant_id: Identifier
    message_id: Identifier
    direction: str
    destination: Identifier
    message_type: Identifier
    status: DeliveryStatus
    attempts: int = Field(ge=0, le=_MAX_DELIVERY_ATTEMPTS)
    available_at: AwareDatetime
    claim_token: Identifier | None = None
    claim_until: AwareDatetime | None = None
    last_error_code: Identifier | None = None
    payload: dict[str, JsonValue]


class DeliveryClaim(StrictModel):
    tenant_id: Identifier
    message_id: Identifier
    claim_token: Identifier
    destination: Identifier
    message_type: Identifier
    attempt: int = Field(ge=1, le=_MAX_DELIVERY_ATTEMPTS)
    payload: dict[str, JsonValue]


class ProjectionCheckpoint(StrictModel):
    tenant_id: Identifier
    projection_name: Identifier
    last_cursor: int = Field(ge=0)
    last_event_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    version: int = Field(ge=1)


class RunView(StrictModel):
    tenant_id: Identifier
    run_id: Identifier
    incident_id: Identifier
    request_ref: Identifier
    workflow_id: Identifier
    status: RunStatus
    version: int = Field(ge=1)
    last_cursor: int = Field(ge=1)
    created_at: AwareDatetime
    updated_at: AwareDatetime
    failure_code: Identifier | None = None
    replayed: bool = False


class TimelineItem(StrictModel):
    cursor: int = Field(ge=1)
    event_type: Identifier
    occurred_at: AwareDatetime
    status: RunStatus
    failure_code: Identifier | None = None


class TimelinePage(StrictModel):
    items: tuple[TimelineItem, ...]
    next_cursor: str | None


class SignalCommand(StrictModel):
    command_id: Identifier
    run_id: Identifier
    command_type: str = Field(pattern=r"^(resume|cancel)$")


class LegacyEvent(StrictModel):
    """Version-zero import shape retained only for deterministic legacy replay."""

    event_type: Identifier
    occurred_at: AwareDatetime
    payload: dict[str, JsonValue]


class DurabilityPort(Protocol):
    def accept_run(
        self,
        *,
        identity: IdentityContext,
        request: InvestigationRequest,
        wait_for_signal: bool,
    ) -> RunView: ...

    def accept_signal(
        self,
        *,
        identity: IdentityContext,
        command: SignalCommand,
    ) -> RunView: ...

    def get_run(self, *, tenant_id: str, run_id: str) -> RunView | None: ...

    def events(
        self,
        *,
        tenant_id: str,
        aggregate_type: str | None = None,
        aggregate_id: str | None = None,
        after_cursor: int = 0,
        limit: int = 100,
    ) -> tuple[ApplicationEvent, ...]: ...

    def verify_integrity(self, *, tenant_id: str) -> bool: ...

    def verify_run_integrity(
        self,
        *,
        tenant_id: str,
        run_id: str,
        maximum_events: int = 10_000,
    ) -> bool: ...

    def rebuild_run(self, *, tenant_id: str, run_id: str) -> RunView: ...

    def timeline(
        self,
        *,
        tenant_id: str,
        run_id: str,
        after_cursor: int,
        limit: int,
        cursor_codec: CursorCodec,
    ) -> TimelinePage: ...

    def record_transition(
        self,
        *,
        tenant_id: str,
        run_id: str,
        event_type: str,
        operation_id: str,
        actor_ref: str,
        request_ref: str,
        failure_code: str | None = None,
        attributes: Mapping[str, JsonValue] | None = None,
    ) -> RunView: ...

    def run_request(self, *, tenant_id: str, run_id: str) -> InvestigationRequest: ...

    def activity_artifact(
        self,
        *,
        tenant_id: str,
        run_id: str,
        event_type: str,
    ) -> dict[str, JsonValue] | None: ...

    def delivery(
        self, *, tenant_id: str, direction: str, message_id: str
    ) -> DeliveryRecord | None: ...


class OutboxPort(Protocol):
    def claim_outbox(
        self,
        *,
        tenant_id: str,
        worker_ref: str,
        now: datetime,
        claim_until: datetime,
        limit: int,
    ) -> tuple[DeliveryClaim, ...]: ...

    def complete_outbox(self, claim: DeliveryClaim, *, now: datetime) -> None: ...

    def fail_outbox(
        self,
        claim: DeliveryClaim,
        *,
        now: datetime,
        error_code: str,
        retry_at: datetime,
        permanent: bool,
    ) -> None: ...


class CursorCodec:
    """Opaque, tenant-bound cursor tokens with tamper detection."""

    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("cursor signing key must contain at least 32 bytes")
        self._key = key

    def encode(self, *, tenant_id: str, run_id: str, cursor: int) -> str:
        body = _canonical_json(
            {"cursor": cursor, "run_id": run_id, "tenant_id": tenant_id}
        ).encode()
        signature = hmac.new(self._key, body, sha256).digest()
        return base64.urlsafe_b64encode(body + signature).decode().rstrip("=")

    def decode(self, token: str, *, tenant_id: str, run_id: str) -> int:
        if not token or len(token) > 1_024:
            raise ValueError("cursor token is invalid")
        try:
            padding = "=" * (-len(token) % 4)
            decoded = base64.urlsafe_b64decode(token + padding)
            body, supplied = decoded[:-32], decoded[-32:]
            expected = hmac.new(self._key, body, sha256).digest()
            value = json.loads(body)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("cursor token is invalid") from exc
        if (
            len(supplied) != 32
            or not hmac.compare_digest(supplied, expected)
            or not isinstance(value, dict)
            or value.get("tenant_id") != tenant_id
            or value.get("run_id") != run_id
            or not isinstance(value.get("cursor"), int)
            or isinstance(value.get("cursor"), bool)
            or value["cursor"] < 0
        ):
            raise ValueError("cursor token is invalid")
        return int(value["cursor"])


@dataclass
class _AggregateHead:
    sequence: int = 0
    record_hash: str = _ZERO_HASH


@dataclass
class _TenantHead:
    cursor: int = 0
    record_hash: str = _ZERO_HASH


@dataclass
class _IdempotencyRecord:
    fingerprint: str
    run_id: str


class InMemoryDurability:
    """Thread-safe reference implementation of ledger transaction semantics."""

    def __init__(self, *, clock: ClockPort) -> None:
        self._clock = clock
        self._events: dict[str, list[ApplicationEvent]] = {}
        self._aggregate_heads: dict[tuple[str, str, str], _AggregateHead] = {}
        self._tenant_heads: dict[str, _TenantHead] = {}
        self._event_ids: set[tuple[str, str]] = set()
        self._idempotency: dict[tuple[str, str], _IdempotencyRecord] = {}
        self._deliveries: dict[tuple[str, str, str], DeliveryRecord] = {}
        self._runs: dict[tuple[str, str], RunView] = {}
        self._projection_checkpoints: dict[tuple[str, str], ProjectionCheckpoint] = {}
        self._lock = Lock()

    def append(
        self,
        *,
        tenant_id: str,
        aggregate_type: str,
        aggregate_id: str,
        expected_version: int,
        drafts: Sequence[EventDraft],
        outbox: Sequence[OutboxDraft] = (),
        inbox: Sequence[InboxDraft] = (),
    ) -> tuple[ApplicationEvent, ...]:
        """Append events and outbox records atomically with expected-version control."""

        if not drafts or len(drafts) > _MAX_EVENTS_PER_APPEND:
            raise ValueError("event batch is outside the permitted bound")
        with self._lock:
            return self._append_locked(
                tenant_id=tenant_id,
                aggregate_type=aggregate_type,
                aggregate_id=aggregate_id,
                expected_version=expected_version,
                drafts=drafts,
                outbox=outbox,
                inbox=inbox,
            )

    def _append_locked(
        self,
        *,
        tenant_id: str,
        aggregate_type: str,
        aggregate_id: str,
        expected_version: int,
        drafts: Sequence[EventDraft],
        outbox: Sequence[OutboxDraft],
        inbox: Sequence[InboxDraft],
    ) -> tuple[ApplicationEvent, ...]:
        aggregate_key = (tenant_id, aggregate_type, aggregate_id)
        aggregate_head = self._aggregate_heads.get(aggregate_key, _AggregateHead())
        tenant_head = self._tenant_heads.get(tenant_id, _TenantHead())
        if aggregate_head.sequence != expected_version:
            raise ConcurrencyConflict("aggregate version changed")
        if len({draft.event_id for draft in drafts}) != len(drafts):
            raise IdempotencyConflict("event batch contains duplicate event ids")
        if any((tenant_id, draft.event_id) in self._event_ids for draft in drafts):
            raise IdempotencyConflict("event id already exists")
        if len({draft.message_id for draft in outbox}) != len(outbox):
            raise IdempotencyConflict("outbox batch contains duplicate message ids")
        if any(
            (tenant_id, "outbox", draft.message_id) in self._deliveries
            for draft in outbox
        ):
            raise IdempotencyConflict("outbox message already exists")
        if len({message.message_id for message in inbox}) != len(inbox):
            raise IdempotencyConflict("inbox batch contains duplicate message ids")
        if any(
            (tenant_id, "inbox", message.message_id) in self._deliveries
            for message in inbox
        ):
            raise IdempotencyConflict("inbox message already exists")

        appended: list[ApplicationEvent] = []
        aggregate_previous_hash = aggregate_head.record_hash
        tenant_previous_hash = tenant_head.record_hash
        for offset, draft in enumerate(drafts, start=1):
            aggregate_sequence = expected_version + offset
            tenant_cursor = tenant_head.cursor + offset
            material = event_material(
                tenant_id=tenant_id,
                aggregate_type=aggregate_type,
                aggregate_id=aggregate_id,
                aggregate_sequence=aggregate_sequence,
                tenant_cursor=tenant_cursor,
                draft=draft,
                aggregate_previous_hash=aggregate_previous_hash,
                tenant_previous_hash=tenant_previous_hash,
            )
            record_hash = sha256(material.encode()).hexdigest()
            event = ApplicationEvent(
                tenant_id=tenant_id,
                aggregate_type=aggregate_type,
                aggregate_id=aggregate_id,
                aggregate_sequence=aggregate_sequence,
                tenant_cursor=tenant_cursor,
                **draft.model_dump(),
                aggregate_previous_hash=aggregate_previous_hash,
                tenant_previous_hash=tenant_previous_hash,
                record_hash=record_hash,
            )
            appended.append(event)
            aggregate_previous_hash = record_hash
            tenant_previous_hash = record_hash

        projected: dict[tuple[str, str], RunView] = {}
        for event in appended:
            if event.aggregate_type != "investigation":
                continue
            key = (event.tenant_id, event.aggregate_id)
            current = projected.get(key, self._runs.get(key))
            projected[key] = reduce_run(current, event)

        for event in appended:
            self._event_ids.add((tenant_id, event.event_id))
        self._events.setdefault(tenant_id, []).extend(appended)
        self._aggregate_heads[aggregate_key] = _AggregateHead(
            sequence=appended[-1].aggregate_sequence,
            record_hash=appended[-1].record_hash,
        )
        self._tenant_heads[tenant_id] = _TenantHead(
            cursor=appended[-1].tenant_cursor,
            record_hash=appended[-1].record_hash,
        )
        for message in outbox:
            delivery_key = (tenant_id, "outbox", message.message_id)
            self._deliveries[delivery_key] = DeliveryRecord(
                tenant_id=tenant_id,
                message_id=message.message_id,
                direction="outbox",
                destination=message.destination,
                message_type=message.message_type,
                status=DeliveryStatus.PENDING,
                attempts=0,
                available_at=message.available_at,
                payload=message.payload,
            )
        for inbox_message in inbox:
            delivery_key = (tenant_id, "inbox", inbox_message.message_id)
            self._deliveries[delivery_key] = DeliveryRecord(
                tenant_id=tenant_id,
                message_id=inbox_message.message_id,
                direction="inbox",
                destination="application",
                message_type=inbox_message.message_type,
                status=DeliveryStatus.DELIVERED,
                attempts=1,
                available_at=appended[-1].occurred_at,
                payload=inbox_message.payload,
            )
        self._runs.update(projected)
        return tuple(appended)

    def accept_run(
        self,
        *,
        identity: IdentityContext,
        request: InvestigationRequest,
        wait_for_signal: bool,
    ) -> RunView:
        fingerprint = sha256(
            _canonical_json(
                {
                    "request": request.model_dump(mode="json"),
                    "wait_for_signal": wait_for_signal,
                }
            ).encode()
        ).hexdigest()
        key = (identity.tenant_id, identity.request_id)
        with self._lock:
            existing = self._idempotency.get(key)
            if existing is not None:
                if existing.fingerprint != fingerprint:
                    raise IdempotencyConflict(
                        "request id was reused with different durable input"
                    )
                return self._runs[(identity.tenant_id, existing.run_id)].model_copy(
                    update={"replayed": True}
                )

            run_id = stable_id(
                "run",
                identity.tenant_id,
                request.incident_id,
                identity.request_id,
                length=32,
            )
            request_ref = stable_id(
                "request", identity.tenant_id, identity.request_id, length=32
            )
            tenant_ref = stable_id("tenant", identity.tenant_id, length=32)
            actor_ref = stable_id(
                "actor", identity.issuer, identity.subject_id, length=32
            )
            workflow_id = stable_id(
                "workflow", tenant_ref, run_id, request_ref, length=40
            )
            trace_ref = durable_trace_reference(identity.trace_id).traceparent
            now = self._clock.now()
            event_id = stable_id("event", run_id, "requested", length=32)
            outbox_id = stable_id("outbox", run_id, "temporal-start", length=32)
            draft = EventDraft(
                event_id=event_id,
                event_type="investigation.requested",
                occurred_at=now,
                actor_ref=actor_ref,
                correlation_ref=request_ref,
                payload={
                    "incident_id": request.incident_id,
                    "request": request.model_dump(mode="json"),
                    "request_ref": request_ref,
                    "run_id": run_id,
                    "tenant_ref": tenant_ref,
                    "trace_ref": trace_ref,
                    "wait_for_signal": wait_for_signal,
                    "workflow_id": workflow_id,
                },
            )
            outbox = OutboxDraft(
                message_id=outbox_id,
                destination="temporal",
                message_type="investigation.start",
                available_at=now,
                payload={
                    "actor_ref": actor_ref,
                    "request_ref": request_ref,
                    "run_id": run_id,
                    "tenant_ref": tenant_ref,
                    "trace_ref": trace_ref,
                    "wait_for_signal": wait_for_signal,
                    "workflow_id": workflow_id,
                },
            )
            self._idempotency[key] = _IdempotencyRecord(
                fingerprint=fingerprint,
                run_id=run_id,
            )
            try:
                self._append_locked(
                    tenant_id=identity.tenant_id,
                    aggregate_type="investigation",
                    aggregate_id=run_id,
                    expected_version=0,
                    drafts=(draft,),
                    outbox=(outbox,),
                    inbox=(),
                )
            except Exception:
                self._idempotency.pop(key, None)
                raise
            return self._runs[(identity.tenant_id, run_id)]

    def record_transition(
        self,
        *,
        tenant_id: str,
        run_id: str,
        event_type: str,
        operation_id: str,
        actor_ref: str,
        request_ref: str,
        failure_code: str | None = None,
        attributes: Mapping[str, JsonValue] | None = None,
    ) -> RunView:
        with self._lock:
            current = self._runs.get((tenant_id, run_id))
            if current is None:
                raise IntegrityFailure("durable run does not exist")
            payload: dict[str, JsonValue] = {"run_id": run_id}
            if attributes is not None:
                payload.update(attributes)
            if failure_code is not None:
                payload["failure_code"] = failure_code
            event_id = stable_id("event", run_id, event_type, operation_id, length=32)
            if (tenant_id, event_id) in self._event_ids:
                return current.model_copy(update={"replayed": True})
            self._append_locked(
                tenant_id=tenant_id,
                aggregate_type="investigation",
                aggregate_id=run_id,
                expected_version=current.version,
                drafts=(
                    EventDraft(
                        event_id=event_id,
                        event_type=event_type,
                        occurred_at=self._clock.now(),
                        actor_ref=actor_ref,
                        correlation_ref=request_ref,
                        causation_ref=operation_id,
                        payload=payload,
                    ),
                ),
                outbox=(),
                inbox=(),
            )
            return self._runs[(tenant_id, run_id)]

    def run_request(self, *, tenant_id: str, run_id: str) -> InvestigationRequest:
        events = self.events(
            tenant_id=tenant_id,
            aggregate_type="investigation",
            aggregate_id=run_id,
            limit=1,
        )
        if not events:
            raise IntegrityFailure("durable run request is missing")
        try:
            return InvestigationRequest.model_validate(events[0].payload["request"])
        except (KeyError, ValidationError) as exc:
            raise IntegrityFailure("durable run request is malformed") from exc

    def activity_artifact(
        self,
        *,
        tenant_id: str,
        run_id: str,
        event_type: str,
    ) -> dict[str, JsonValue] | None:
        maximum_events = 10_000
        after_cursor = 0
        scanned = 0
        latest: dict[str, JsonValue] | None = None
        while scanned < maximum_events:
            page_limit = min(500, maximum_events - scanned)
            page = self.events(
                tenant_id=tenant_id,
                aggregate_type="investigation",
                aggregate_id=run_id,
                after_cursor=after_cursor,
                limit=page_limit,
            )
            for event in page:
                if event.event_type == event_type:
                    latest = dict(event.payload)
            scanned += len(page)
            if len(page) < page_limit:
                return latest
            after_cursor = page[-1].tenant_cursor
        if self.events(
            tenant_id=tenant_id,
            aggregate_type="investigation",
            aggregate_id=run_id,
            after_cursor=after_cursor,
            limit=1,
        ):
            raise IntegrityFailure("activity artifact scan exceeds the event bound")
        return latest

    def accept_signal(
        self,
        *,
        identity: IdentityContext,
        command: SignalCommand,
    ) -> RunView:
        with self._lock:
            current = self._runs.get((identity.tenant_id, command.run_id))
            if current is None:
                raise IntegrityFailure("durable run does not exist")
            message_key = (identity.tenant_id, "inbox", command.command_id)
            if message_key in self._deliveries:
                existing = self._deliveries[message_key]
                if (
                    existing.message_type != f"investigation.{command.command_type}"
                    or existing.payload.get("run_id") != command.run_id
                ):
                    raise IdempotencyConflict(
                        "signal command id conflicts with an existing command"
                    )
                return current.model_copy(update={"replayed": True})
            if command.command_type == "resume":
                resume_count = sum(
                    1
                    for record in self._deliveries.values()
                    if record.tenant_id == identity.tenant_id
                    and record.direction == "inbox"
                    and record.message_type == "investigation.resume"
                    and record.payload.get("run_id") == command.run_id
                )
                if resume_count >= _MAX_RESUME_COMMANDS:
                    raise PayloadRejected("run resume command bound exceeded")
            actor_ref = stable_id(
                "actor", identity.issuer, identity.subject_id, length=32
            )
            inbox = InboxDraft(
                message_id=command.command_id,
                source="api",
                message_type=f"investigation.{command.command_type}",
                payload={
                    "actor_ref": actor_ref,
                    "command_id": command.command_id,
                    "run_id": command.run_id,
                },
            )
            event_type = f"investigation.{command.command_type}_requested"
            outbox = OutboxDraft(
                message_id=stable_id(
                    "outbox", command.run_id, command.command_id, length=32
                ),
                destination="temporal",
                message_type=event_type,
                available_at=self._clock.now(),
                payload={
                    "command_ref": command.command_id,
                    "run_id": command.run_id,
                    "workflow_id": current.workflow_id,
                },
            )
            self._append_locked(
                tenant_id=identity.tenant_id,
                aggregate_type="investigation",
                aggregate_id=command.run_id,
                expected_version=current.version,
                drafts=(
                    EventDraft(
                        event_id=stable_id(
                            "event",
                            command.run_id,
                            event_type,
                            command.command_id,
                            length=32,
                        ),
                        event_type=event_type,
                        occurred_at=self._clock.now(),
                        actor_ref=actor_ref,
                        correlation_ref=current.request_ref,
                        causation_ref=command.command_id,
                        payload={
                            "command_ref": command.command_id,
                            "run_id": command.run_id,
                        },
                    ),
                ),
                outbox=(outbox,),
                inbox=(inbox,),
            )
            return self._runs[(identity.tenant_id, command.run_id)]

    def get_run(self, *, tenant_id: str, run_id: str) -> RunView | None:
        with self._lock:
            return self._runs.get((tenant_id, run_id))

    def events(
        self,
        *,
        tenant_id: str,
        aggregate_type: str | None = None,
        aggregate_id: str | None = None,
        after_cursor: int = 0,
        limit: int = 100,
    ) -> tuple[ApplicationEvent, ...]:
        if limit < 1 or limit > 500:
            raise ValueError("event page limit is outside the permitted range")
        with self._lock:
            return tuple(
                event
                for event in self._events.get(tenant_id, ())
                if event.tenant_cursor > after_cursor
                and (aggregate_type is None or event.aggregate_type == aggregate_type)
                and (aggregate_id is None or event.aggregate_id == aggregate_id)
            )[:limit]

    def timeline(
        self,
        *,
        tenant_id: str,
        run_id: str,
        after_cursor: int,
        limit: int,
        cursor_codec: CursorCodec,
    ) -> TimelinePage:
        events = self.events(
            tenant_id=tenant_id,
            aggregate_type="investigation",
            aggregate_id=run_id,
            limit=500,
        )
        projection: RunView | None = None
        projected: list[TimelineItem] = []
        for event in events:
            projection = reduce_run(projection, event)
            if event.tenant_cursor > after_cursor:
                projected.append(_timeline_item(event, projection.status))
        visible = projected[:limit]
        next_cursor = (
            cursor_codec.encode(
                tenant_id=tenant_id,
                run_id=run_id,
                cursor=visible[-1].cursor,
            )
            if len(projected) > limit and visible
            else None
        )
        return TimelinePage(items=tuple(visible), next_cursor=next_cursor)

    def claim_outbox(
        self,
        *,
        tenant_id: str,
        worker_ref: str,
        now: datetime,
        claim_until: datetime,
        limit: int,
    ) -> tuple[DeliveryClaim, ...]:
        if limit < 1 or limit > 100 or claim_until <= now:
            raise ValueError("outbox claim bounds are invalid")
        with self._lock:
            candidates = sorted(
                (
                    record
                    for key, record in self._deliveries.items()
                    if key[1] == "outbox"
                    and record.tenant_id == tenant_id
                    and record.available_at <= now
                    and (
                        record.status is DeliveryStatus.PENDING
                        or (
                            record.status is DeliveryStatus.CLAIMED
                            and record.claim_until is not None
                            and record.claim_until <= now
                        )
                    )
                ),
                key=lambda record: (
                    record.available_at,
                    record.tenant_id,
                    record.message_id,
                ),
            )[:limit]
            claims: list[DeliveryClaim] = []
            for record in candidates:
                attempt = record.attempts + 1
                if attempt > _MAX_DELIVERY_ATTEMPTS:
                    self._deliveries[
                        (record.tenant_id, "outbox", record.message_id)
                    ] = record.model_copy(update={"status": DeliveryStatus.DEAD_LETTER})
                    continue
                token = stable_id(
                    "claim",
                    worker_ref,
                    record.tenant_id,
                    record.message_id,
                    str(attempt),
                    length=32,
                )
                updated = record.model_copy(
                    update={
                        "attempts": attempt,
                        "claim_token": token,
                        "claim_until": claim_until,
                        "status": DeliveryStatus.CLAIMED,
                    }
                )
                self._deliveries[(record.tenant_id, "outbox", record.message_id)] = (
                    updated
                )
                claims.append(
                    DeliveryClaim(
                        tenant_id=record.tenant_id,
                        message_id=record.message_id,
                        claim_token=token,
                        destination=record.destination,
                        message_type=record.message_type,
                        attempt=attempt,
                        payload=record.payload,
                    )
                )
            return tuple(claims)

    def complete_outbox(self, claim: DeliveryClaim, *, now: datetime) -> None:
        del now
        self._update_claim(
            claim,
            status=DeliveryStatus.DELIVERED,
            error_code=None,
            retry_at=None,
        )

    def fail_outbox(
        self,
        claim: DeliveryClaim,
        *,
        now: datetime,
        error_code: str,
        retry_at: datetime,
        permanent: bool = False,
    ) -> None:
        del now
        self._update_claim(
            claim,
            status=(
                DeliveryStatus.DEAD_LETTER
                if permanent or claim.attempt >= _MAX_DELIVERY_ATTEMPTS
                else DeliveryStatus.PENDING
            ),
            error_code=error_code,
            retry_at=retry_at,
        )

    def _update_claim(
        self,
        claim: DeliveryClaim,
        *,
        status: DeliveryStatus,
        error_code: str | None,
        retry_at: datetime | None,
    ) -> None:
        key = (claim.tenant_id, "outbox", claim.message_id)
        with self._lock:
            record = self._deliveries.get(key)
            if (
                record is None
                or record.status is not DeliveryStatus.CLAIMED
                or record.claim_token != claim.claim_token
                or record.attempts != claim.attempt
            ):
                raise MessageClaimConflict("outbox claim is stale or not owned")
            self._deliveries[key] = record.model_copy(
                update={
                    "available_at": retry_at or record.available_at,
                    **dict.fromkeys(("claim_token", "claim_until")),
                    "last_error_code": error_code,
                    "status": status,
                }
            )

    def delivery(
        self, *, tenant_id: str, direction: str, message_id: str
    ) -> DeliveryRecord | None:
        with self._lock:
            return self._deliveries.get((tenant_id, direction, message_id))

    def verify_integrity(self, *, tenant_id: str) -> bool:
        with self._lock:
            events = tuple(self._events.get(tenant_id, ()))
        aggregate_heads: dict[tuple[str, str], _AggregateHead] = {}
        tenant_head = _TenantHead()
        seen: set[str] = set()
        for event in events:
            key = (event.aggregate_type, event.aggregate_id)
            aggregate = aggregate_heads.get(key, _AggregateHead())
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
                    aggregate_previous_hash=aggregate.record_hash,
                    tenant_previous_hash=tenant_head.record_hash,
                ).encode()
            ).hexdigest()
            if (
                event.schema_version != 1
                or event.event_id in seen
                or event.aggregate_sequence != aggregate.sequence + 1
                or event.tenant_cursor != tenant_head.cursor + 1
                or event.aggregate_previous_hash != aggregate.record_hash
                or event.tenant_previous_hash != tenant_head.record_hash
                or event.record_hash != expected
            ):
                return False
            seen.add(event.event_id)
            aggregate_heads[key] = _AggregateHead(
                event.aggregate_sequence, event.record_hash
            )
            tenant_head = _TenantHead(event.tenant_cursor, event.record_hash)
        return True

    def verify_run_integrity(
        self,
        *,
        tenant_id: str,
        run_id: str,
        maximum_events: int = 10_000,
    ) -> bool:
        if maximum_events < 1 or maximum_events > 10_000:
            raise ValueError("run integrity event bound is invalid")
        with self._lock:
            tenant_events = tuple(self._events.get(tenant_id, ()))
        selected = tuple(
            event
            for event in tenant_events
            if event.aggregate_type == "investigation" and event.aggregate_id == run_id
        )
        if not selected or len(selected) > maximum_events:
            return False
        aggregate_sequence = 0
        aggregate_hash = _ZERO_HASH
        aggregate_head = self._aggregate_heads.get((tenant_id, "investigation", run_id))
        for event in selected:
            if event.tenant_cursor < 1 or event.tenant_cursor > len(tenant_events):
                return False
            previous_tenant_hash = (
                _ZERO_HASH
                if event.tenant_cursor == 1
                else tenant_events[event.tenant_cursor - 2].record_hash
            )
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
                    tenant_previous_hash=previous_tenant_hash,
                ).encode()
            ).hexdigest()
            if (
                event.schema_version != 1
                or event.aggregate_sequence != aggregate_sequence + 1
                or event.aggregate_previous_hash != aggregate_hash
                or event.tenant_previous_hash != previous_tenant_hash
                or event.record_hash != expected
            ):
                return False
            if event.tenant_cursor < len(tenant_events):
                successor = tenant_events[event.tenant_cursor]
                if successor.tenant_previous_hash != event.record_hash:
                    return False
            elif self._tenant_heads.get(tenant_id, _TenantHead()).record_hash != (
                event.record_hash
            ):
                return False
            aggregate_sequence = event.aggregate_sequence
            aggregate_hash = event.record_hash
        return (
            aggregate_head is not None
            and aggregate_head.sequence == aggregate_sequence
            and aggregate_head.record_hash == aggregate_hash
        )

    def rebuild_run_projections(self, *, tenant_id: str) -> ProjectionCheckpoint:
        with self._lock:
            self._runs = {
                key: value for key, value in self._runs.items() if key[0] != tenant_id
            }
            events = tuple(self._events.get(tenant_id, ()))
            self._apply_projection_locked(events)
            head = self._tenant_heads.get(tenant_id, _TenantHead())
            key = (tenant_id, "investigation-runs")
            previous = self._projection_checkpoints.get(key)
            checkpoint = ProjectionCheckpoint(
                tenant_id=tenant_id,
                projection_name="investigation-runs",
                last_cursor=head.cursor,
                last_event_hash=head.record_hash,
                version=1 if previous is None else previous.version + 1,
            )
            self._projection_checkpoints[key] = checkpoint
            return checkpoint

    def rebuild_run(self, *, tenant_id: str, run_id: str) -> RunView:
        if not self.verify_integrity(tenant_id=tenant_id):
            raise IntegrityFailure("ledger integrity verification failed")
        with self._lock:
            events = tuple(
                event
                for event in self._events.get(tenant_id, ())
                if event.aggregate_type == "investigation"
                and event.aggregate_id == run_id
            )
            if not events:
                raise ValueError("run does not exist")
            projection: RunView | None = None
            for event in events:
                projection = reduce_run(projection, event)
            if projection is None:
                raise IntegrityFailure("run projection could not be rebuilt")
            self._runs[(tenant_id, run_id)] = projection
            return projection

    def replay_legacy(
        self,
        *,
        tenant_id: str,
        aggregate_id: str,
        actor_ref: str,
        correlation_ref: str,
        legacy: Sequence[LegacyEvent],
        upcast: Callable[[LegacyEvent], tuple[str, Mapping[str, JsonValue]]],
    ) -> tuple[ApplicationEvent, ...]:
        drafts: list[EventDraft] = []
        for index, item in enumerate(legacy, start=1):
            event_type, payload = upcast(item)
            drafts.append(
                EventDraft(
                    event_id=stable_id(
                        "legacy-event",
                        tenant_id,
                        aggregate_id,
                        str(index),
                        item.event_type,
                        length=32,
                    ),
                    event_type=event_type,
                    occurred_at=item.occurred_at,
                    actor_ref=actor_ref,
                    correlation_ref=correlation_ref,
                    schema_version=1,
                    payload=dict(payload),
                )
            )
        return self.append(
            tenant_id=tenant_id,
            aggregate_type="investigation",
            aggregate_id=aggregate_id,
            expected_version=0,
            drafts=tuple(drafts),
            inbox=(),
        )

    def _apply_projection_locked(self, events: Sequence[ApplicationEvent]) -> None:
        for event in events:
            if event.aggregate_type != "investigation":
                continue
            key = (event.tenant_id, event.aggregate_id)
            current = self._runs.get(key)
            self._runs[key] = reduce_run(current, event)


class DurableInvestigationService:
    """Authorize commands and expose only application-owned durable read models."""

    def __init__(
        self,
        *,
        policy: PolicyPort,
        store: DurabilityPort,
        cursor_codec: CursorCodec,
    ) -> None:
        self._policy = policy
        self._store = store
        self._cursor_codec = cursor_codec

    def submit(
        self,
        identity: IdentityContext,
        request: InvestigationRequest,
        *,
        wait_for_signal: bool,
    ) -> RunView:
        self._authorize(identity, Action.INVESTIGATION_RUN)
        return self._store.accept_run(
            identity=identity,
            request=request,
            wait_for_signal=wait_for_signal,
        )

    def get(self, identity: IdentityContext, *, run_id: str) -> RunView | None:
        self._authorize(identity, Action.INVESTIGATION_READ)
        return self._store.get_run(tenant_id=identity.tenant_id, run_id=run_id)

    def timeline(
        self,
        identity: IdentityContext,
        *,
        run_id: str,
        cursor: str | None,
        limit: int,
    ) -> TimelinePage:
        self._authorize(identity, Action.INVESTIGATION_READ)
        after = (
            self._cursor_codec.decode(
                cursor,
                tenant_id=identity.tenant_id,
                run_id=run_id,
            )
            if cursor is not None
            else 0
        )
        return self._store.timeline(
            tenant_id=identity.tenant_id,
            run_id=run_id,
            after_cursor=after,
            limit=limit,
            cursor_codec=self._cursor_codec,
        )

    def signal(
        self,
        identity: IdentityContext,
        *,
        command: SignalCommand,
    ) -> RunView:
        self._authorize(identity, Action.INVESTIGATION_RUN)
        return self._store.accept_signal(identity=identity, command=command)

    def replay_report(
        self,
        identity: IdentityContext,
        *,
        run_id: str,
        maximum_events: int = 200,
    ) -> SupportReport | None:
        self._authorize(identity, Action.REPLAY_READ)
        from aegis_framework.replay import ReplayDebugger

        live = self._store.get_run(tenant_id=identity.tenant_id, run_id=run_id)
        if live is None:
            return None
        seed = self._store.events(
            tenant_id=identity.tenant_id,
            aggregate_type="investigation",
            aggregate_id=run_id,
            limit=1,
        )
        if not seed:
            from aegis_framework.errors import IntegrityFailure

            raise IntegrityFailure("run events are unavailable")
        first_cursor = seed[0].tenant_cursor
        events: list[ApplicationEvent] = []
        after_cursor = first_cursor - 1
        ledger_limit = 10_000
        while len(events) < ledger_limit and after_cursor < live.last_cursor:
            page = self._store.events(
                tenant_id=identity.tenant_id,
                after_cursor=after_cursor,
                limit=min(500, ledger_limit - len(events)),
            )
            events.extend(
                event for event in page if event.tenant_cursor <= live.last_cursor
            )
            if not page or page[-1].tenant_cursor >= live.last_cursor:
                break
            after_cursor = page[-1].tenant_cursor
        if not events or events[-1].tenant_cursor < live.last_cursor:
            from aegis_framework.errors import PayloadRejected

            raise PayloadRejected("run replay window exceeds the event bound")
        return ReplayDebugger(
            events,
            tenant_anchor_cursor=first_cursor - 1,
            tenant_anchor_hash=events[0].tenant_previous_hash,
            aggregate_anchors={
                (event.aggregate_type, event.aggregate_id): (
                    event.aggregate_sequence - 1,
                    event.aggregate_previous_hash,
                )
                for event in reversed(events)
            },
        ).support_report(
            aggregate_id=run_id,
            live=live,
            maximum_events=maximum_events,
        )

    def rebuild_projection(self, identity: IdentityContext, *, run_id: str) -> RunView:
        self._authorize(identity, Action.PROJECTION_REBUILD)
        if self._store.get_run(tenant_id=identity.tenant_id, run_id=run_id) is None:
            raise ValueError("run does not exist")
        if not self._store.verify_run_integrity(
            tenant_id=identity.tenant_id,
            run_id=run_id,
        ):
            from aegis_framework.errors import IntegrityFailure

            raise IntegrityFailure("ledger integrity verification failed")
        return self._store.rebuild_run(
            tenant_id=identity.tenant_id,
            run_id=run_id,
        )

    def _authorize(self, identity: IdentityContext, action: Action) -> None:
        decision = self._policy.authorize(
            identity,
            action,
            resource_tenant_id=identity.tenant_id,
            purpose="incident-response",
            risk=RiskLevel.MEDIUM,
        )
        if not decision.allowed:
            from aegis_framework.errors import PolicyDenied

            raise PolicyDenied(decision.reason)


def reduce_run(current: RunView | None, event: ApplicationEvent) -> RunView:
    status_by_event = {
        "investigation.requested": RunStatus.QUEUED,
        "investigation.started": RunStatus.RUNNING,
        "investigation.evidence_collected": RunStatus.RUNNING,
        "investigation.graph_completed": RunStatus.RUNNING,
        "investigation.waiting": RunStatus.WAITING,
        "investigation.cancel_requested": RunStatus.CANCEL_REQUESTED,
        "investigation.completed": RunStatus.COMPLETED,
        "investigation.failed": RunStatus.FAILED,
        "investigation.cancelled": RunStatus.CANCELLED,
        "investigation.timed_out": RunStatus.TIMED_OUT,
    }
    status = (
        current.status
        if event.event_type == "investigation.resume_requested" and current is not None
        else status_by_event.get(event.event_type)
    )
    if status is None:
        raise IntegrityFailure("unknown investigation event type")
    failure_code = event.payload.get("failure_code")
    if failure_code is not None and not isinstance(failure_code, str):
        raise IntegrityFailure("failure code projection is invalid")
    if current is None:
        if event.event_type != "investigation.requested":
            raise IntegrityFailure(
                "investigation projection does not start at requested"
            )
        try:
            return RunView(
                tenant_id=event.tenant_id,
                run_id=str(event.payload["run_id"]),
                incident_id=str(event.payload["incident_id"]),
                request_ref=str(event.payload["request_ref"]),
                workflow_id=str(event.payload["workflow_id"]),
                status=status,
                version=event.aggregate_sequence,
                last_cursor=event.tenant_cursor,
                created_at=event.occurred_at,
                updated_at=event.occurred_at,
            )
        except (KeyError, ValidationError) as exc:
            raise IntegrityFailure(
                "requested event cannot build a run projection"
            ) from exc
    if event.aggregate_sequence != current.version + 1:
        raise IntegrityFailure(
            "projection observed a non-contiguous aggregate sequence"
        )
    _validate_run_transition(current.status, status)
    return current.model_copy(
        update={
            "failure_code": failure_code,
            "last_cursor": event.tenant_cursor,
            "replayed": False,
            "status": status,
            "updated_at": event.occurred_at,
            "version": event.aggregate_sequence,
        }
    )


def _timeline_item(
    event: ApplicationEvent,
    status: RunStatus,
) -> TimelineItem:
    failure_code = event.payload.get("failure_code")
    return TimelineItem(
        cursor=event.tenant_cursor,
        event_type=event.event_type,
        occurred_at=event.occurred_at,
        status=status,
        failure_code=failure_code if isinstance(failure_code, str) else None,
    )


def _validate_run_transition(previous: RunStatus, current: RunStatus) -> None:
    allowed: dict[RunStatus, frozenset[RunStatus]] = {
        RunStatus.QUEUED: frozenset(
            {
                RunStatus.RUNNING,
                RunStatus.QUEUED,
                RunStatus.CANCEL_REQUESTED,
                RunStatus.FAILED,
            }
        ),
        RunStatus.RUNNING: frozenset(
            {
                RunStatus.RUNNING,
                RunStatus.WAITING,
                RunStatus.COMPLETED,
                RunStatus.CANCEL_REQUESTED,
                RunStatus.FAILED,
                RunStatus.TIMED_OUT,
            }
        ),
        RunStatus.WAITING: frozenset(
            {
                RunStatus.WAITING,
                RunStatus.COMPLETED,
                RunStatus.CANCEL_REQUESTED,
                RunStatus.FAILED,
                RunStatus.TIMED_OUT,
            }
        ),
        RunStatus.CANCEL_REQUESTED: frozenset({RunStatus.CANCELLED}),
        RunStatus.COMPLETED: frozenset(),
        RunStatus.FAILED: frozenset(),
        RunStatus.CANCELLED: frozenset(),
        RunStatus.TIMED_OUT: frozenset(),
    }
    if current not in allowed[previous]:
        raise IntegrityFailure("investigation event violates the state machine")


def event_material(
    *,
    tenant_id: str,
    aggregate_type: str,
    aggregate_id: str,
    aggregate_sequence: int,
    tenant_cursor: int,
    draft: EventDraft,
    aggregate_previous_hash: str,
    tenant_previous_hash: str,
) -> str:
    return _canonical_json(
        {
            "actor_ref": draft.actor_ref,
            "aggregate_id": aggregate_id,
            "aggregate_previous_hash": aggregate_previous_hash,
            "aggregate_sequence": aggregate_sequence,
            "aggregate_type": aggregate_type,
            "causation_ref": draft.causation_ref,
            "correlation_ref": draft.correlation_ref,
            "event_id": draft.event_id,
            "event_type": draft.event_type,
            "occurred_at": draft.occurred_at.astimezone(UTC).isoformat(),
            "payload": draft.payload,
            "record_schema_version": 1,
            "schema_version": draft.schema_version,
            "tenant_cursor": tenant_cursor,
            "tenant_id": tenant_id,
            "tenant_previous_hash": tenant_previous_hash,
        }
    )


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
