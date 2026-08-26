"""PostgreSQL adapter for the application event ledger and transactional outbox."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from hashlib import sha256

from psycopg import Error, IntegrityError
from pydantic import Field, JsonValue, ValidationError

from aegis_framework.access import (
    GrantStatus,
    PrincipalStatus,
    TenantStatus,
)
from aegis_framework.authorization import RoleCatalog
from aegis_framework.domain import (
    GrantBinding,
    Identifier,
    IdentityContext,
    InvestigationRequest,
    PrincipalKind,
    StrictModel,
    stable_id,
)
from aegis_framework.durability import (
    ApplicationEvent,
    CursorCodec,
    DeliveryClaim,
    DeliveryRecord,
    DeliveryStatus,
    EventDraft,
    InboxDraft,
    LegacyEvent,
    OutboxDraft,
    RunView,
    SignalCommand,
    TimelineItem,
    TimelinePage,
    event_material,
    reduce_run,
)
from aegis_framework.errors import (
    ConcurrencyConflict,
    IdempotencyConflict,
    IntegrityFailure,
    MessageClaimConflict,
    PayloadRejected,
    RepositoryUnavailable,
)
from aegis_framework.ports import ClockPort
from aegis_framework.postgres import (
    DictConnection,
    PostgresRepository,
    RuntimePool,
    tenant_transaction,
)
from aegis_framework.references import TenantReferenceCodec

_ZERO_HASH = "0" * 64
_MAX_DELIVERY_ATTEMPTS = 5


class IdempotencyDraft(StrictModel):
    request_id: Identifier
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")


class ActorBindingDraft(StrictModel):
    actor_ref: Identifier
    issuer: str
    subject_id: str
    principal_kind: PrincipalKind


class PostgresDurability:
    """Append-only ledger transactions independent of Temporal/LangGraph state."""

    def __init__(
        self,
        *,
        pool: RuntimePool,
        clock: ClockPort,
        tenant_references: TenantReferenceCodec,
    ) -> None:
        self._pool = pool
        self._clock = clock
        self._tenant_references = tenant_references

    def accept_run(
        self,
        *,
        identity: IdentityContext,
        request: InvestigationRequest,
        wait_for_signal: bool,
    ) -> RunView:
        fingerprint = sha256(
            _json(
                {
                    "request": request.model_dump(mode="json"),
                    "wait_for_signal": wait_for_signal,
                }
            ).encode()
        ).hexdigest()
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
        tenant_ref = self._tenant_references.encode(identity.tenant_id)
        actor_ref = stable_id("actor", identity.issuer, identity.subject_id, length=32)
        workflow_id = stable_id(
            "workflow", identity.tenant_id, run_id, request_ref, length=40
        )
        now = self._clock.now()
        try:
            self.append(
                tenant_id=identity.tenant_id,
                aggregate_type="investigation",
                aggregate_id=run_id,
                expected_version=0,
                drafts=(
                    EventDraft(
                        event_id=stable_id("event", run_id, "requested", length=32),
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
                            "wait_for_signal": wait_for_signal,
                            "workflow_id": workflow_id,
                        },
                    ),
                ),
                outbox=(
                    OutboxDraft(
                        message_id=stable_id(
                            "outbox", run_id, "temporal-start", length=32
                        ),
                        destination="temporal",
                        message_type="investigation.start",
                        available_at=now,
                        payload={
                            "actor_ref": actor_ref,
                            "request_ref": request_ref,
                            "run_id": run_id,
                            "tenant_ref": tenant_ref,
                            "wait_for_signal": wait_for_signal,
                            "workflow_id": workflow_id,
                        },
                    ),
                ),
                idempotency=IdempotencyDraft(
                    request_id=identity.request_id,
                    fingerprint=fingerprint,
                ),
                actor_binding=ActorBindingDraft(
                    actor_ref=actor_ref,
                    issuer=identity.issuer,
                    subject_id=identity.subject_id,
                    principal_kind=identity.principal_kind,
                ),
            )
        except (ConcurrencyConflict, IdempotencyConflict):
            existing = self._idempotency(
                tenant_id=identity.tenant_id,
                request_id=identity.request_id,
            )
            if (
                existing is None
                or existing["fingerprint"] != fingerprint
                or existing["aggregate_id"] != run_id
            ):
                raise
            replay = self.get_run(
                tenant_id=identity.tenant_id,
                run_id=run_id,
            )
            if replay is None:
                raise IntegrityFailure(
                    "idempotency fact has no run projection"
                ) from None
            return replay.model_copy(update={"replayed": True})
        created = self.get_run(tenant_id=identity.tenant_id, run_id=run_id)
        if created is None:
            raise IntegrityFailure("run projection was not committed")
        return created

    def accept_signal(
        self,
        *,
        identity: IdentityContext,
        command: SignalCommand,
    ) -> RunView:
        actor_ref = stable_id("actor", identity.issuer, identity.subject_id, length=32)
        event_type = f"investigation.{command.command_type}_requested"
        message_type = f"investigation.{command.command_type}"
        for _ in range(3):
            current = self.get_run(
                tenant_id=identity.tenant_id,
                run_id=command.run_id,
            )
            existing = self.delivery(
                tenant_id=identity.tenant_id,
                direction="inbox",
                message_id=command.command_id,
            )
            if existing is not None:
                if (
                    existing.message_type != message_type
                    or existing.payload.get("run_id") != command.run_id
                ):
                    raise IdempotencyConflict(
                        "signal command id conflicts with an existing command"
                    )
                if current is None:
                    raise IntegrityFailure("signal fact has no run projection")
                return current.model_copy(update={"replayed": True})
            if current is None:
                raise IntegrityFailure("durable run does not exist")
            if (
                command.command_type == "resume"
                and self._signal_count(
                    tenant_id=identity.tenant_id,
                    run_id=command.run_id,
                    message_type=message_type,
                )
                >= 32
            ):
                raise PayloadRejected("run resume command bound exceeded")
            now = self._clock.now()
            try:
                self.append(
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
                            occurred_at=now,
                            actor_ref=actor_ref,
                            correlation_ref=current.request_ref,
                            causation_ref=command.command_id,
                            payload={
                                "command_ref": command.command_id,
                                "run_id": command.run_id,
                            },
                        ),
                    ),
                    outbox=(
                        OutboxDraft(
                            message_id=stable_id(
                                "outbox",
                                command.run_id,
                                command.command_id,
                                length=32,
                            ),
                            destination="temporal",
                            message_type=event_type,
                            available_at=now,
                            payload={
                                "command_ref": command.command_id,
                                "run_id": command.run_id,
                                "workflow_id": current.workflow_id,
                            },
                        ),
                    ),
                    inbox=(
                        InboxDraft(
                            message_id=command.command_id,
                            source="api",
                            message_type=message_type,
                            payload={
                                "actor_ref": actor_ref,
                                "command_id": command.command_id,
                                "run_id": command.run_id,
                            },
                        ),
                    ),
                    actor_binding=ActorBindingDraft(
                        actor_ref=actor_ref,
                        issuer=identity.issuer,
                        subject_id=identity.subject_id,
                        principal_kind=identity.principal_kind,
                    ),
                )
            except ConcurrencyConflict:
                continue
            except IdempotencyConflict:
                continue
            updated = self.get_run(
                tenant_id=identity.tenant_id,
                run_id=command.run_id,
            )
            if updated is None:
                raise IntegrityFailure("signal projection was not committed")
            return updated
        raise ConcurrencyConflict("signal raced with aggregate transitions")

    def get_run(self, *, tenant_id: str, run_id: str) -> RunView | None:
        with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
            row = connection.execute(
                """
                SELECT tenant_id, run_id, incident_id, request_ref, workflow_id,
                       status, version, last_cursor, created_at, updated_at,
                       failure_code
                FROM aegis.investigation_runs
                WHERE tenant_id = %s AND run_id = %s
                """,
                (tenant_id, run_id),
            ).fetchone()
        return RunView.model_validate(row) if row is not None else None

    def timeline(
        self,
        *,
        tenant_id: str,
        run_id: str,
        after_cursor: int,
        limit: int,
        cursor_codec: CursorCodec,
    ) -> TimelinePage:
        if limit < 1 or limit > 100:
            raise ValueError("timeline page limit is outside the permitted range")
        with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
            rows = connection.execute(
                """
                SELECT tenant_cursor AS cursor, event_type, occurred_at,
                       status, failure_code
                FROM aegis.investigation_timeline
                WHERE tenant_id = %s AND run_id = %s AND tenant_cursor > %s
                ORDER BY tenant_cursor
                LIMIT %s
                """,
                (tenant_id, run_id, after_cursor, limit + 1),
            ).fetchall()
        items = tuple(TimelineItem.model_validate(row) for row in rows[:limit])
        next_cursor = (
            cursor_codec.encode(
                tenant_id=tenant_id,
                run_id=run_id,
                cursor=items[-1].cursor,
            )
            if len(rows) > limit and items
            else None
        )
        return TimelinePage(items=items, next_cursor=next_cursor)

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
        current = self.get_run(tenant_id=tenant_id, run_id=run_id)
        if current is None:
            raise IntegrityFailure("durable run does not exist")
        payload: dict[str, JsonValue] = {"run_id": run_id}
        if attributes is not None:
            payload.update(attributes)
        if failure_code is not None:
            payload["failure_code"] = failure_code
        event_id = stable_id("event", run_id, event_type, operation_id, length=32)
        try:
            self.append(
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
            )
        except (ConcurrencyConflict, IdempotencyConflict):
            if not self._event_exists(tenant_id=tenant_id, event_id=event_id):
                raise
            replay = self.get_run(tenant_id=tenant_id, run_id=run_id)
            if replay is None:
                raise IntegrityFailure("activity event has no run projection") from None
            return replay.model_copy(update={"replayed": True})
        updated = self.get_run(tenant_id=tenant_id, run_id=run_id)
        if updated is None:
            raise IntegrityFailure("activity projection was not committed")
        return updated

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
        events = self.events(
            tenant_id=tenant_id,
            aggregate_type="investigation",
            aggregate_id=run_id,
        )
        matched = [event for event in events if event.event_type == event_type]
        return dict(matched[-1].payload) if matched else None

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
                    payload=dict(payload),
                )
            )
        return self.append(
            tenant_id=tenant_id,
            aggregate_type="investigation",
            aggregate_id=aggregate_id,
            expected_version=0,
            drafts=tuple(drafts),
        )

    def delivery(
        self, *, tenant_id: str, direction: str, message_id: str
    ) -> DeliveryRecord | None:
        with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
            if direction == "inbox":
                row = connection.execute(
                    """
                    SELECT tenant_id, message_id, message_type, payload, received_at
                    FROM aegis.inbox_messages
                    WHERE tenant_id = %s AND message_id = %s
                    """,
                    (tenant_id, message_id),
                ).fetchone()
                if row is None:
                    return None
                return DeliveryRecord(
                    tenant_id=row["tenant_id"],
                    message_id=row["message_id"],
                    direction="inbox",
                    destination="application",
                    message_type=row["message_type"],
                    status=DeliveryStatus.DELIVERED,
                    attempts=1,
                    available_at=row["received_at"],
                    payload=row["payload"],
                )
            if direction != "outbox":
                raise ValueError("delivery direction is invalid")
            row = connection.execute(
                """
                SELECT tenant_id, message_id, destination, message_type,
                       status, attempts, available_at, claim_token,
                       claim_until, last_error_code, payload
                FROM aegis.outbox_messages
                WHERE tenant_id = %s AND message_id = %s
                """,
                (tenant_id, message_id),
            ).fetchone()
        return (
            DeliveryRecord.model_validate({**row, "direction": "outbox"})
            if row is not None
            else None
        )

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
        idempotency: IdempotencyDraft | None = None,
        actor_binding: ActorBindingDraft | None = None,
    ) -> tuple[ApplicationEvent, ...]:
        if not drafts or len(drafts) > 32:
            raise ValueError("event batch is outside the permitted bound")
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                return self._append_in_transaction(
                    connection,
                    tenant_id=tenant_id,
                    aggregate_type=aggregate_type,
                    aggregate_id=aggregate_id,
                    expected_version=expected_version,
                    drafts=drafts,
                    outbox=outbox,
                    inbox=inbox,
                    idempotency=idempotency,
                    actor_binding=actor_binding,
                )
        except (
            ConcurrencyConflict,
            IdempotencyConflict,
            IntegrityFailure,
            RepositoryUnavailable,
        ):
            raise
        except Error as exc:
            raise RepositoryUnavailable("durable ledger append failed") from exc

    def _append_in_transaction(
        self,
        connection: DictConnection,
        *,
        tenant_id: str,
        aggregate_type: str,
        aggregate_id: str,
        expected_version: int,
        drafts: Sequence[EventDraft],
        outbox: Sequence[OutboxDraft],
        inbox: Sequence[InboxDraft],
        idempotency: IdempotencyDraft | None,
        actor_binding: ActorBindingDraft | None,
    ) -> tuple[ApplicationEvent, ...]:
        connection.execute(
            """
            INSERT INTO aegis.ledger_aggregate_heads (
                tenant_id, aggregate_type, aggregate_id
            )
            VALUES (%s, %s, %s)
            ON CONFLICT (tenant_id, aggregate_type, aggregate_id) DO NOTHING
            """,
            (tenant_id, aggregate_type, aggregate_id),
        )
        connection.execute(
            """
            INSERT INTO aegis.ledger_tenant_cursors (tenant_id)
            VALUES (%s)
            ON CONFLICT (tenant_id) DO NOTHING
            """,
            (tenant_id,),
        )
        aggregate_head = connection.execute(
            """
            SELECT last_sequence, last_hash
            FROM aegis.ledger_aggregate_heads
            WHERE tenant_id = %s
              AND aggregate_type = %s
              AND aggregate_id = %s
            FOR UPDATE
            """,
            (tenant_id, aggregate_type, aggregate_id),
        ).fetchone()
        tenant_head = connection.execute(
            """
            SELECT last_cursor, last_hash
            FROM aegis.ledger_tenant_cursors
            WHERE tenant_id = %s
            FOR UPDATE
            """,
            (tenant_id,),
        ).fetchone()
        if aggregate_head is None or tenant_head is None:
            raise IntegrityFailure("ledger heads are unavailable")
        if aggregate_head["last_sequence"] != expected_version:
            raise ConcurrencyConflict("aggregate version changed")
        if len({draft.event_id for draft in drafts}) != len(drafts):
            raise IdempotencyConflict("event batch contains duplicate event ids")
        if actor_binding is not None:
            connection.execute(
                """
                INSERT INTO aegis.durable_actor_bindings (
                    tenant_id, actor_ref, issuer, subject_id, principal_kind
                )
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, actor_ref) DO NOTHING
                """,
                (
                    tenant_id,
                    actor_binding.actor_ref,
                    actor_binding.issuer,
                    actor_binding.subject_id,
                    actor_binding.principal_kind.value,
                ),
            )
            bound = connection.execute(
                """
                SELECT issuer, subject_id, principal_kind
                FROM aegis.durable_actor_bindings
                WHERE tenant_id = %s AND actor_ref = %s
                """,
                (tenant_id, actor_binding.actor_ref),
            ).fetchone()
            if (
                bound is None
                or bound["issuer"] != actor_binding.issuer
                or bound["subject_id"] != actor_binding.subject_id
                or bound["principal_kind"] != actor_binding.principal_kind.value
            ):
                raise IdempotencyConflict("actor reference binding conflicts")

        aggregate_previous_hash = str(aggregate_head["last_hash"])
        tenant_previous_hash = str(tenant_head["last_hash"])
        events: list[ApplicationEvent] = []
        for offset, draft in enumerate(drafts, start=1):
            aggregate_sequence = expected_version + offset
            tenant_cursor = int(tenant_head["last_cursor"]) + offset
            record_hash = sha256(
                event_material(
                    tenant_id=tenant_id,
                    aggregate_type=aggregate_type,
                    aggregate_id=aggregate_id,
                    aggregate_sequence=aggregate_sequence,
                    tenant_cursor=tenant_cursor,
                    draft=draft,
                    aggregate_previous_hash=aggregate_previous_hash,
                    tenant_previous_hash=tenant_previous_hash,
                ).encode()
            ).hexdigest()
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
            try:
                connection.execute(
                    """
                    INSERT INTO aegis.application_events (
                        tenant_id, aggregate_type, aggregate_id,
                        aggregate_sequence, tenant_cursor, event_id, event_type,
                        occurred_at, actor_ref, correlation_ref, causation_ref,
                        schema_version, payload, aggregate_previous_hash,
                        tenant_previous_hash, record_hash
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s::jsonb, %s, %s, %s
                    )
                    """,
                    (
                        event.tenant_id,
                        event.aggregate_type,
                        event.aggregate_id,
                        event.aggregate_sequence,
                        event.tenant_cursor,
                        event.event_id,
                        event.event_type,
                        event.occurred_at,
                        event.actor_ref,
                        event.correlation_ref,
                        event.causation_ref,
                        event.schema_version,
                        _json(event.payload),
                        event.aggregate_previous_hash,
                        event.tenant_previous_hash,
                        event.record_hash,
                    ),
                )
            except IntegrityError as exc:
                raise IdempotencyConflict(
                    "event id or sequence already exists"
                ) from exc
            events.append(event)
            aggregate_previous_hash = record_hash
            tenant_previous_hash = record_hash

        connection.execute(
            """
            UPDATE aegis.ledger_aggregate_heads
            SET last_sequence = %s, last_hash = %s
            WHERE tenant_id = %s
              AND aggregate_type = %s
              AND aggregate_id = %s
            """,
            (
                events[-1].aggregate_sequence,
                events[-1].record_hash,
                tenant_id,
                aggregate_type,
                aggregate_id,
            ),
        )
        connection.execute(
            """
            UPDATE aegis.ledger_tenant_cursors
            SET last_cursor = %s, last_hash = %s
            WHERE tenant_id = %s
            """,
            (events[-1].tenant_cursor, events[-1].record_hash, tenant_id),
        )
        if idempotency is not None:
            try:
                connection.execute(
                    """
                    INSERT INTO aegis.durable_idempotency (
                        tenant_id, request_id, fingerprint,
                        aggregate_type, aggregate_id
                    )
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        tenant_id,
                        idempotency.request_id,
                        idempotency.fingerprint,
                        aggregate_type,
                        aggregate_id,
                    ),
                )
            except IntegrityError as exc:
                raise IdempotencyConflict("durable request id already exists") from exc
        for inbox_message in inbox:
            payload = _json(inbox_message.payload)
            try:
                connection.execute(
                    """
                    INSERT INTO aegis.inbox_messages (
                        tenant_id, message_id, source, message_type,
                        payload_hash, payload
                    )
                    VALUES (%s, %s, %s, %s, %s, %s::jsonb)
                    """,
                    (
                        tenant_id,
                        inbox_message.message_id,
                        inbox_message.source,
                        inbox_message.message_type,
                        sha256(payload.encode()).hexdigest(),
                        payload,
                    ),
                )
            except IntegrityError as exc:
                raise IdempotencyConflict("inbox message id already exists") from exc
        for message in outbox:
            try:
                connection.execute(
                    """
                    INSERT INTO aegis.outbox_messages (
                        tenant_id, message_id, destination, message_type,
                        payload, status, attempts, available_at
                    )
                    VALUES (%s, %s, %s, %s, %s::jsonb, 'pending', 0, %s)
                    """,
                    (
                        tenant_id,
                        message.message_id,
                        message.destination,
                        message.message_type,
                        _json(message.payload),
                        message.available_at,
                    ),
                )
            except IntegrityError as exc:
                raise IdempotencyConflict("outbox message id already exists") from exc
        self._project(connection, events)
        return tuple(events)

    def events(
        self,
        *,
        tenant_id: str,
        aggregate_type: str | None = None,
        aggregate_id: str | None = None,
        after_cursor: int = 0,
        limit: int = 500,
    ) -> tuple[ApplicationEvent, ...]:
        if limit < 1 or limit > 500:
            raise ValueError("event page limit is outside the permitted range")
        with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
            rows = connection.execute(
                """
                SELECT tenant_id, aggregate_type, aggregate_id,
                       aggregate_sequence, tenant_cursor, event_id, event_type,
                       occurred_at, actor_ref, correlation_ref, causation_ref,
                       schema_version, payload, aggregate_previous_hash,
                       tenant_previous_hash, record_hash
                FROM aegis.application_events
                WHERE tenant_id = %s
                  AND (%s::text IS NULL OR aggregate_type = %s::text)
                  AND (%s::text IS NULL OR aggregate_id = %s::text)
                  AND tenant_cursor > %s
                ORDER BY tenant_cursor
                LIMIT %s
                """,
                (
                    tenant_id,
                    aggregate_type,
                    aggregate_type,
                    aggregate_id,
                    aggregate_id,
                    after_cursor,
                    limit,
                ),
            ).fetchall()
        return tuple(ApplicationEvent.model_validate(row) for row in rows)

    def verify_integrity(
        self,
        *,
        tenant_id: str,
    ) -> bool:
        with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
            rows = connection.execute(
                """
                SELECT tenant_id, aggregate_type, aggregate_id,
                       aggregate_sequence, tenant_cursor, event_id, event_type,
                       occurred_at, actor_ref, correlation_ref, causation_ref,
                       schema_version, payload, aggregate_previous_hash,
                       tenant_previous_hash, record_hash
                FROM aegis.application_events
                WHERE tenant_id = %s
                ORDER BY tenant_cursor
                """,
                (tenant_id,),
            ).fetchall()
        aggregate_heads: dict[tuple[str, str], tuple[int, str]] = {}
        tenant_cursor = 0
        tenant_hash = _ZERO_HASH
        for row in rows:
            event = ApplicationEvent.model_validate(row)
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
            if (
                event.aggregate_sequence != sequence + 1
                or event.tenant_cursor != tenant_cursor + 1
                or event.aggregate_previous_hash != aggregate_hash
                or event.tenant_previous_hash != tenant_hash
                or event.record_hash != expected
            ):
                return False
            aggregate_heads[key] = (
                event.aggregate_sequence,
                event.record_hash,
            )
            tenant_cursor = event.tenant_cursor
            tenant_hash = event.record_hash
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
        with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
            rows = connection.execute(
                """
                SELECT current.tenant_id, current.aggregate_type,
                       current.aggregate_id, current.aggregate_sequence,
                       current.tenant_cursor, current.event_id,
                       current.event_type, current.occurred_at,
                       current.actor_ref, current.correlation_ref,
                       current.causation_ref, current.schema_version,
                       current.payload, current.aggregate_previous_hash,
                       current.tenant_previous_hash, current.record_hash,
                       previous.record_hash AS actual_tenant_previous_hash,
                       successor.tenant_previous_hash AS next_tenant_previous_hash,
                       aggregate_head.last_sequence AS head_sequence,
                       aggregate_head.last_hash AS head_hash,
                       tenant_head.last_cursor AS tenant_last_cursor,
                       tenant_head.last_hash AS tenant_last_hash
                FROM aegis.application_events AS current
                LEFT JOIN aegis.application_events AS previous
                  ON previous.tenant_id = current.tenant_id
                 AND previous.tenant_cursor = current.tenant_cursor - 1
                LEFT JOIN aegis.application_events AS successor
                  ON successor.tenant_id = current.tenant_id
                 AND successor.tenant_cursor = current.tenant_cursor + 1
                JOIN aegis.ledger_aggregate_heads AS aggregate_head
                  ON aggregate_head.tenant_id = current.tenant_id
                 AND aggregate_head.aggregate_type = current.aggregate_type
                 AND aggregate_head.aggregate_id = current.aggregate_id
                JOIN aegis.ledger_tenant_cursors AS tenant_head
                  ON tenant_head.tenant_id = current.tenant_id
                WHERE current.tenant_id = %s
                  AND current.aggregate_type = 'investigation'
                  AND current.aggregate_id = %s
                ORDER BY current.aggregate_sequence
                LIMIT %s
                """,
                (tenant_id, run_id, maximum_events + 1),
            ).fetchall()
        if not rows or len(rows) > maximum_events:
            return False
        aggregate_sequence = 0
        aggregate_hash = _ZERO_HASH
        head_sequence = 0
        head_hash = _ZERO_HASH
        for row in rows:
            material = dict(row)
            actual_tenant_previous_hash = material.pop("actual_tenant_previous_hash")
            next_tenant_previous_hash = material.pop("next_tenant_previous_hash")
            head_sequence = int(material.pop("head_sequence"))
            head_hash = str(material.pop("head_hash"))
            tenant_last_cursor = int(material.pop("tenant_last_cursor"))
            tenant_last_hash = str(material.pop("tenant_last_hash"))
            event = ApplicationEvent.model_validate(material)
            previous_tenant_hash = (
                _ZERO_HASH
                if event.tenant_cursor == 1
                else str(actual_tenant_previous_hash)
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
                event.aggregate_sequence != aggregate_sequence + 1
                or event.aggregate_previous_hash != aggregate_hash
                or event.tenant_previous_hash != previous_tenant_hash
                or event.record_hash != expected
            ):
                return False
            if event.tenant_cursor < tenant_last_cursor:
                if next_tenant_previous_hash != event.record_hash:
                    return False
            elif (
                event.tenant_cursor != tenant_last_cursor
                or tenant_last_hash != event.record_hash
            ):
                return False
            aggregate_sequence = event.aggregate_sequence
            aggregate_hash = event.record_hash
        return aggregate_sequence == head_sequence and aggregate_hash == head_hash

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
        with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
            connection.execute(
                """
                UPDATE aegis.outbox_messages
                SET status = 'dead_letter',
                    claim_token = NULL,
                    claim_until = NULL,
                    last_error_code = COALESCE(
                        last_error_code,
                        'claim_expired'
                    )
                WHERE tenant_id = %s
                  AND status = 'claimed'
                  AND claim_until <= %s
                  AND attempts >= %s
                """,
                (tenant_id, now, _MAX_DELIVERY_ATTEMPTS),
            )
            rows = connection.execute(
                """
                SELECT tenant_id, message_id, destination, message_type,
                       payload, attempts
                FROM aegis.outbox_messages
                WHERE tenant_id = %s
                  AND available_at <= %s
                  AND (
                    status = 'pending'
                    OR (status = 'claimed' AND claim_until <= %s)
                  )
                  AND attempts < %s
                ORDER BY available_at, message_id
                FOR UPDATE SKIP LOCKED
                LIMIT %s
                """,
                (tenant_id, now, now, _MAX_DELIVERY_ATTEMPTS, limit),
            ).fetchall()
            claims: list[DeliveryClaim] = []
            for row in rows:
                attempt = int(row["attempts"]) + 1
                token = _claim_token(
                    worker_ref=worker_ref,
                    tenant_id=tenant_id,
                    message_id=str(row["message_id"]),
                    attempt=attempt,
                )
                connection.execute(
                    """
                    UPDATE aegis.outbox_messages
                    SET status = 'claimed', attempts = %s,
                        claim_token = %s, claim_until = %s
                    WHERE tenant_id = %s AND message_id = %s
                    """,
                    (
                        attempt,
                        token,
                        claim_until,
                        tenant_id,
                        row["message_id"],
                    ),
                )
                claims.append(
                    DeliveryClaim(
                        tenant_id=tenant_id,
                        message_id=row["message_id"],
                        claim_token=token,
                        destination=row["destination"],
                        message_type=row["message_type"],
                        attempt=attempt,
                        payload=row["payload"],
                    )
                )
        return tuple(claims)

    def complete_outbox(self, claim: DeliveryClaim, *, now: datetime) -> None:
        self._finish_claim(
            claim,
            status=DeliveryStatus.DELIVERED,
            now=now,
            retry_at=None,
            error_code=None,
        )

    def fail_outbox(
        self,
        claim: DeliveryClaim,
        *,
        now: datetime,
        retry_at: datetime,
        error_code: str,
        permanent: bool = False,
    ) -> None:
        self._finish_claim(
            claim,
            status=(
                DeliveryStatus.DEAD_LETTER
                if permanent or claim.attempt >= _MAX_DELIVERY_ATTEMPTS
                else DeliveryStatus.PENDING
            ),
            now=now,
            retry_at=retry_at,
            error_code=error_code,
        )

    def _finish_claim(
        self,
        claim: DeliveryClaim,
        *,
        status: DeliveryStatus,
        now: datetime,
        retry_at: datetime | None,
        error_code: str | None,
    ) -> None:
        with tenant_transaction(self._pool, tenant_id=claim.tenant_id) as connection:
            updated = connection.execute(
                """
                UPDATE aegis.outbox_messages
                SET status = %s,
                    available_at = COALESCE(%s, available_at),
                    claim_token = NULL,
                    claim_until = NULL,
                    last_error_code = %s,
                    delivered_at = CASE WHEN %s = 'delivered' THEN %s ELSE NULL END
                WHERE tenant_id = %s
                  AND message_id = %s
                  AND status = 'claimed'
                  AND claim_token = %s
                  AND attempts = %s
                RETURNING message_id
                """,
                (
                    status.value,
                    retry_at,
                    error_code,
                    status.value,
                    now,
                    claim.tenant_id,
                    claim.message_id,
                    claim.claim_token,
                    claim.attempt,
                ),
            ).fetchone()
            if updated is None:
                raise MessageClaimConflict("outbox claim is stale or not owned")

    def rebuild_run(self, *, tenant_id: str, run_id: str) -> RunView:
        events: list[ApplicationEvent] = []
        after_cursor = 0
        while True:
            page = self.events(
                tenant_id=tenant_id,
                aggregate_type="investigation",
                aggregate_id=run_id,
                after_cursor=after_cursor,
                limit=500,
            )
            events.extend(page)
            if len(page) < 500:
                break
            after_cursor = page[-1].tenant_cursor
        if not events:
            raise ValueError("run does not exist")
        projection: RunView | None = None
        for event in events:
            if event.schema_version != 1:
                raise IntegrityFailure(
                    f"event {event.event_id!r} has unsupported "
                    f"schema_version {event.schema_version!r}; expected 1"
                )
            projection = reduce_run(projection, event)
        if projection is None:
            raise IntegrityFailure("run projection could not be rebuilt")
        with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
            self._upsert_run(connection, projection)
            connection.execute(
                """
                INSERT INTO aegis.projection_checkpoints (
                    tenant_id, projection_name, last_cursor,
                    last_event_hash, version
                )
                VALUES (%s, 'investigation-runs', %s, %s, 1)
                ON CONFLICT (tenant_id, projection_name) DO UPDATE
                SET last_cursor = EXCLUDED.last_cursor,
                    last_event_hash = EXCLUDED.last_event_hash,
                    version = aegis.projection_checkpoints.version + 1,
                    rebuilt_at = clock_timestamp()
                WHERE aegis.projection_checkpoints.last_cursor <= EXCLUDED.last_cursor
                """,
                (
                    tenant_id,
                    events[-1].tenant_cursor,
                    events[-1].record_hash,
                ),
            )
            current = connection.execute(
                """
                SELECT tenant_id, run_id, incident_id, request_ref, workflow_id,
                       status, version, last_cursor, created_at, updated_at,
                       failure_code
                FROM aegis.investigation_runs
                WHERE tenant_id = %s AND run_id = %s
                FOR UPDATE
                """,
                (tenant_id, run_id),
            ).fetchone()
        if current is None:
            raise IntegrityFailure("rebuilt run projection is unavailable")
        return RunView.model_validate(current)

    def _idempotency(
        self, *, tenant_id: str, request_id: str
    ) -> dict[str, object] | None:
        with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
            row = connection.execute(
                """
                SELECT fingerprint, aggregate_id
                FROM aegis.durable_idempotency
                WHERE tenant_id = %s AND request_id = %s
                """,
                (tenant_id, request_id),
            ).fetchone()
        return row

    def _event_exists(self, *, tenant_id: str, event_id: str) -> bool:
        with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
            row = connection.execute(
                """
                SELECT 1
                FROM aegis.application_events
                WHERE tenant_id = %s AND event_id = %s
                """,
                (tenant_id, event_id),
            ).fetchone()
        return row is not None

    def _signal_count(
        self,
        *,
        tenant_id: str,
        run_id: str,
        message_type: str,
    ) -> int:
        with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
            row = connection.execute(
                """
                SELECT count(*) AS count
                FROM aegis.inbox_messages
                WHERE tenant_id = %s
                  AND message_type = %s
                  AND payload ->> 'run_id' = %s
                """,
                (tenant_id, message_type, run_id),
            ).fetchone()
        return int(row["count"]) if row is not None else 0

    def _project(
        self,
        connection: DictConnection,
        events: Sequence[ApplicationEvent],
    ) -> None:
        if not events or events[0].aggregate_type != "investigation":
            return
        row = connection.execute(
            """
            SELECT tenant_id, run_id, incident_id, request_ref, workflow_id,
                   status, version, last_cursor, created_at, updated_at,
                   failure_code
            FROM aegis.investigation_runs
            WHERE tenant_id = %s AND run_id = %s
            """,
            (events[0].tenant_id, events[0].aggregate_id),
        ).fetchone()
        projection = RunView.model_validate(row) if row is not None else None
        for event in events:
            projection = reduce_run(projection, event)
            self._upsert_run(connection, projection)
            connection.execute(
                """
                INSERT INTO aegis.investigation_timeline (
                    tenant_id, run_id, tenant_cursor, event_type, status,
                    failure_code, occurred_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, run_id, tenant_cursor) DO NOTHING
                """,
                (
                    event.tenant_id,
                    event.aggregate_id,
                    event.tenant_cursor,
                    event.event_type,
                    projection.status.value,
                    projection.failure_code,
                    event.occurred_at,
                ),
            )

    @staticmethod
    def _upsert_run(
        connection: DictConnection,
        projection: RunView,
    ) -> None:
        connection.execute(
            """
            INSERT INTO aegis.investigation_runs (
                tenant_id, run_id, incident_id, request_ref, workflow_id,
                status, failure_code, version, last_cursor,
                created_at, updated_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (tenant_id, run_id) DO UPDATE
            SET status = EXCLUDED.status,
                failure_code = EXCLUDED.failure_code,
                version = EXCLUDED.version,
                last_cursor = EXCLUDED.last_cursor,
                updated_at = EXCLUDED.updated_at
            WHERE aegis.investigation_runs.version <= EXCLUDED.version
            """,
            (
                projection.tenant_id,
                projection.run_id,
                projection.incident_id,
                projection.request_ref,
                projection.workflow_id,
                projection.status.value,
                projection.failure_code,
                projection.version,
                projection.last_cursor,
                projection.created_at,
                projection.updated_at,
            ),
        )


class PostgresCurrentAuthority:
    """Resolve opaque workflow references into current tenant principal grants."""

    def __init__(
        self,
        *,
        pool: RuntimePool,
        repository: PostgresRepository,
        clock: ClockPort,
        tenant_references: TenantReferenceCodec,
    ) -> None:
        self._pool = pool
        self._repository = repository
        self._clock = clock
        self._tenant_references = tenant_references

    def tenant_id(self, *, tenant_ref: str) -> str | None:
        try:
            return self._tenant_references.decode(tenant_ref)
        except ValueError:
            return None

    def identity(
        self,
        *,
        tenant_id: str,
        actor_ref: str,
        request_ref: str,
    ) -> IdentityContext | None:
        with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
            binding = connection.execute(
                """
                SELECT issuer, subject_id, principal_kind
                FROM aegis.durable_actor_bindings
                WHERE tenant_id = %s AND actor_ref = %s
                """,
                (tenant_id, actor_ref),
            ).fetchone()
        if binding is None:
            return None
        principal = self._repository.resolve_principal(
            tenant_id=tenant_id,
            issuer=binding["issuer"],
            subject_id=binding["subject_id"],
        )
        tenant = self._repository.get_tenant(tenant_id=tenant_id)
        now = self._clock.now()
        if (
            principal is None
            or principal.status is not PrincipalStatus.ACTIVE
            or principal.principal_kind.value != binding["principal_kind"]
            or tenant is None
            or tenant.status is not TenantStatus.ACTIVE
        ):
            return None
        grants = tuple(
            sorted(
                self._repository.active_grants(
                    tenant_id=tenant_id,
                    issuer=principal.issuer,
                    subject_id=principal.subject_id,
                    now=now,
                ),
                key=lambda grant: (grant.purpose, grant.role, grant.grant_id),
            )
        )
        if not grants:
            return None
        grant_bindings: list[GrantBinding] = []
        for grant in grants:
            permissions = RoleCatalog.permissions_for(grant.role)
            if (
                grant.status is not GrantStatus.ACTIVE
                or grant.expires_at <= now
                or not permissions
            ):
                return None
            grant_bindings.append(
                GrantBinding(
                    role=grant.role,
                    purpose=grant.purpose,
                    permissions=permissions,
                    risk_ceiling=grant.risk_ceiling,
                    expires_at=grant.expires_at,
                )
            )
        return IdentityContext(
            tenant_id=tenant_id,
            issuer=principal.issuer,
            subject_id=principal.subject_id,
            principal_kind=principal.principal_kind,
            roles=tuple(sorted({binding.role for binding in grant_bindings})),
            permissions=tuple(
                sorted(
                    {
                        permission
                        for binding in grant_bindings
                        for permission in binding.permissions
                    }
                )
            ),
            purposes=tuple(sorted({binding.purpose for binding in grant_bindings})),
            grants=tuple(grant_bindings),
            grant_version=principal.grant_version,
            authenticated_at=now,
            expires_at=min(binding.expires_at for binding in grant_bindings),
            request_id=request_ref,
            trace_id=stable_id("trace", tenant_id, request_ref, length=32),
        )


def _json(value: Mapping[str, object]) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _claim_token(
    *,
    worker_ref: str,
    tenant_id: str,
    message_id: str,
    attempt: int,
) -> str:
    material = "\x00".join((worker_ref, tenant_id, message_id, str(attempt)))
    return f"claim:{sha256(material.encode()).hexdigest()[:32]}"
