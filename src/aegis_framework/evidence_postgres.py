"""PostgreSQL evidence configuration and rebuildable status projections."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime

from psycopg import Error
from psycopg.types.json import Jsonb
from pydantic import ValidationError

from aegis_framework.domain import stable_id
from aegis_framework.durability import EventDraft
from aegis_framework.durable_postgres import PostgresDurability
from aegis_framework.errors import IntegrityFailure, RepositoryUnavailable
from aegis_framework.evidence import (
    EvidenceCursorView,
    EvidenceQuery,
    EvidenceQueryView,
    EvidenceSource,
    QueryStatus,
)
from aegis_framework.ports import ClockPort
from aegis_framework.postgres import RuntimePool, tenant_transaction


class PostgresEvidenceRepository:
    """RLS-scoped source/status adapter; application events remain source truth."""

    def __init__(
        self,
        *,
        pool: RuntimePool,
        ledger: PostgresDurability,
        clock: ClockPort,
    ) -> None:
        self._pool = pool
        self._ledger = ledger
        self._clock = clock

    def current_source(
        self,
        *,
        tenant_id: str,
        source_id: str,
    ) -> EvidenceSource | None:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                row = connection.execute(
                    """
                    SELECT document
                    FROM aegis.evidence_sources
                    WHERE tenant_id = %s AND source_id = %s
                    """,
                    (tenant_id, source_id),
                ).fetchone()
        except Error as exc:
            raise RepositoryUnavailable("evidence source query failed") from exc
        if row is None:
            return None
        try:
            source = EvidenceSource.model_validate(row["document"])
        except ValidationError as exc:
            raise IntegrityFailure("evidence source projection is malformed") from exc
        if source.tenant_id != tenant_id or source.source_id != source_id:
            raise IntegrityFailure("evidence source projection binding is invalid")
        return source

    def query(self, *, tenant_id: str, query_id: str) -> EvidenceQuery:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                row = connection.execute(
                    """
                    SELECT query_document
                    FROM aegis.evidence_queries
                    WHERE tenant_id = %s AND query_id = %s
                    """,
                    (tenant_id, query_id),
                ).fetchone()
        except Error as exc:
            raise RepositoryUnavailable("evidence query load failed") from exc
        if row is None:
            raise IntegrityFailure("evidence query is unavailable")
        try:
            query = EvidenceQuery.model_validate(row["query_document"])
        except ValidationError as exc:
            raise IntegrityFailure("evidence query projection is malformed") from exc
        if query.tenant_id != tenant_id or query.query_id != query_id:
            raise IntegrityFailure("evidence query projection binding is invalid")
        return query

    def status(self, *, tenant_id: str, query_id: str) -> EvidenceQueryView | None:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                row = connection.execute(
                    """
                    SELECT query_id, incident_id, source_kind, status,
                           page_count, record_count, accepted_count,
                           quarantined_count, failure_code, cursor_available,
                           reconciliation_required, updated_at
                    FROM aegis.evidence_queries
                    WHERE tenant_id = %s AND query_id = %s
                    """,
                    (tenant_id, query_id),
                ).fetchone()
        except Error as exc:
            raise RepositoryUnavailable("evidence status query failed") from exc
        try:
            return EvidenceQueryView.model_validate(row) if row is not None else None
        except ValidationError as exc:
            raise IntegrityFailure("evidence status projection is malformed") from exc

    def cursor_status(
        self,
        *,
        tenant_id: str,
        query_id: str,
    ) -> EvidenceCursorView | None:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                row = connection.execute(
                    """
                    SELECT cursor.query_id, query.source_kind,
                           cursor.page_number, cursor.expires_at,
                           cursor.expires_at > clock_timestamp() AS available
                    FROM aegis.evidence_cursors AS cursor
                    JOIN aegis.evidence_queries AS query
                      ON query.tenant_id = cursor.tenant_id
                     AND query.query_id = cursor.query_id
                    WHERE cursor.tenant_id = %s AND cursor.query_id = %s
                    """,
                    (tenant_id, query_id),
                ).fetchone()
        except Error as exc:
            raise RepositoryUnavailable("evidence cursor status query failed") from exc
        try:
            return EvidenceCursorView.model_validate(row) if row is not None else None
        except ValidationError as exc:
            raise IntegrityFailure("evidence cursor projection is malformed") from exc

    def rebuild_projections(self, *, tenant_id: str) -> int:
        """Rebuild query status only from verified application events."""

        if not self._ledger.verify_integrity(tenant_id=tenant_id):
            raise IntegrityFailure("application ledger integrity verification failed")
        rows = self._evidence_events(tenant_id=tenant_id)
        grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
        for row in rows:
            grouped[str(row["aggregate_id"])].append(row)
        rebuilt: list[tuple[EvidenceQuery, EvidenceQueryView, str, int, datetime]] = []
        for query_id in sorted(grouped):
            events = grouped[query_id]
            query = _query_from_event(events[0], tenant_id=tenant_id, query_id=query_id)
            view = _rebuild_view(query, events)
            last = events[-1]
            event_id = last["event_id"]
            tenant_cursor = last["tenant_cursor"]
            occurred_at = last["occurred_at"]
            if (
                not isinstance(event_id, str)
                or not isinstance(tenant_cursor, int)
                or not isinstance(occurred_at, datetime)
            ):
                raise IntegrityFailure("evidence application event metadata is invalid")
            rebuilt.append((query, view, event_id, tenant_cursor, occurred_at))
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                for query, view, event_id, tenant_cursor, occurred_at in rebuilt:
                    connection.execute(
                        """
                        INSERT INTO aegis.evidence_queries (
                            tenant_id, query_id, incident_id, run_id,
                            source_id, source_kind, query_digest, query_document,
                            status, page_count, record_count, accepted_count,
                            quarantined_count, failure_code, cursor_available,
                            reconciliation_required, last_application_event_id,
                            last_tenant_cursor, created_at, updated_at
                        )
                        VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s
                        )
                        ON CONFLICT (tenant_id, query_id) DO UPDATE
                        SET incident_id = EXCLUDED.incident_id,
                            run_id = EXCLUDED.run_id,
                            source_id = EXCLUDED.source_id,
                            source_kind = EXCLUDED.source_kind,
                            query_digest = EXCLUDED.query_digest,
                            query_document = EXCLUDED.query_document,
                            status = EXCLUDED.status,
                            page_count = EXCLUDED.page_count,
                            record_count = EXCLUDED.record_count,
                            accepted_count = EXCLUDED.accepted_count,
                            quarantined_count = EXCLUDED.quarantined_count,
                            failure_code = EXCLUDED.failure_code,
                            cursor_available = EXCLUDED.cursor_available,
                            reconciliation_required =
                                EXCLUDED.reconciliation_required,
                            last_application_event_id =
                                EXCLUDED.last_application_event_id,
                            last_tenant_cursor = EXCLUDED.last_tenant_cursor,
                            created_at = EXCLUDED.created_at,
                            updated_at = EXCLUDED.updated_at
                        """,
                        (
                            tenant_id,
                            query.query_id,
                            query.incident_id,
                            query.run_id,
                            query.source.source_id,
                            query.source.kind.value,
                            query.digest,
                            Jsonb(query.model_dump(mode="json")),
                            view.status.value,
                            view.page_count,
                            view.record_count,
                            view.accepted_count,
                            view.quarantined_count,
                            view.failure_code,
                            view.cursor_available,
                            view.reconciliation_required,
                            event_id,
                            tenant_cursor,
                            query.created_at,
                            occurred_at,
                        ),
                    )
        except Error as exc:
            raise RepositoryUnavailable("evidence projection rebuild failed") from exc
        self._record_rebuild(tenant_id=tenant_id, rebuilt_count=len(rebuilt))
        return len(rebuilt)

    def _evidence_events(self, *, tenant_id: str) -> Sequence[dict[str, object]]:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                return tuple(
                    connection.execute(
                        """
                        SELECT aggregate_id, tenant_cursor, event_id, event_type,
                               occurred_at, payload
                        FROM aegis.application_events
                        WHERE tenant_id = %s
                          AND aggregate_type = 'evidence-query'
                        ORDER BY tenant_cursor
                        """,
                        (tenant_id,),
                    ).fetchall()
                )
        except Error as exc:
            raise RepositoryUnavailable("evidence event replay query failed") from exc

    def _record_rebuild(self, *, tenant_id: str, rebuilt_count: int) -> None:
        now = self._clock.now()
        aggregate_id = "evidence-query-projection"
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                row = connection.execute(
                    """
                    SELECT last_sequence
                    FROM aegis.ledger_aggregate_heads
                    WHERE tenant_id = %s
                      AND aggregate_type = 'evidence-projection'
                      AND aggregate_id = %s
                    """,
                    (tenant_id, aggregate_id),
                ).fetchone()
            version = int(row["last_sequence"]) if row is not None else 0
            event_id = stable_id(
                "event",
                tenant_id,
                aggregate_id,
                str(version + 1),
                length=32,
            )
            events = self._ledger.append(
                tenant_id=tenant_id,
                aggregate_type="evidence-projection",
                aggregate_id=aggregate_id,
                expected_version=version,
                drafts=(
                    EventDraft(
                        event_id=event_id,
                        event_type="evidence.projection_rebuilt",
                        occurred_at=now,
                        actor_ref="system:evidence-rebuilder",
                        correlation_ref=aggregate_id,
                        payload={"rebuilt_count": rebuilt_count},
                    ),
                ),
            )
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                connection.execute(
                    """
                    INSERT INTO aegis.evidence_projection_rebuilds (
                        tenant_id, rebuild_id, projection_name,
                        through_tenant_cursor, last_event_hash,
                        rebuilt_at, application_event_id
                    )
                    VALUES (%s, %s, 'evidence-queries', %s, %s, %s, %s)
                    """,
                    (
                        tenant_id,
                        stable_id("rebuild", tenant_id, event_id, length=32),
                        events[-1].tenant_cursor,
                        events[-1].record_hash,
                        now,
                        event_id,
                    ),
                )
        except Error as exc:
            raise RepositoryUnavailable(
                "evidence projection rebuild fact failed"
            ) from exc


def _query_from_event(
    event: dict[str, object],
    *,
    tenant_id: str,
    query_id: str,
) -> EvidenceQuery:
    if event.get("event_type") != "evidence.query.requested":
        raise IntegrityFailure("evidence event stream does not start with a request")
    payload = event.get("payload")
    if not isinstance(payload, dict):
        raise IntegrityFailure("evidence request event payload is malformed")
    try:
        query = EvidenceQuery.model_validate(payload["query"])
    except (KeyError, ValidationError) as exc:
        raise IntegrityFailure("evidence request event query is malformed") from exc
    if query.tenant_id != tenant_id or query.query_id != query_id:
        raise IntegrityFailure("evidence request event binding is invalid")
    return query


def _rebuild_view(
    query: EvidenceQuery,
    events: Sequence[dict[str, object]],
) -> EvidenceQueryView:
    view = EvidenceQueryView(
        query_id=query.query_id,
        incident_id=query.incident_id,
        source_kind=query.source.kind,
        status=QueryStatus.REQUESTED,
        page_count=0,
        record_count=0,
        accepted_count=0,
        quarantined_count=0,
        updated_at=query.created_at,
    )
    for event in events[1:]:
        event_type = event.get("event_type")
        occurred_at = event.get("occurred_at")
        payload = event.get("payload")
        if not isinstance(event_type, str) or not isinstance(occurred_at, datetime):
            raise IntegrityFailure("evidence application event is malformed")
        if not isinstance(payload, dict):
            raise IntegrityFailure("evidence application event payload is malformed")
        if event_type == "evidence.page.requested":
            view = view.model_copy(
                update={"status": QueryStatus.RUNNING, "updated_at": occurred_at}
            )
        elif event_type == "evidence.page.completed":
            view = view.model_copy(
                update={
                    "status": QueryStatus.RUNNING,
                    "page_count": view.page_count + 1,
                    "record_count": view.record_count
                    + _event_count(payload, "record_count"),
                    "accepted_count": view.accepted_count
                    + _event_count(payload, "accepted_count"),
                    "quarantined_count": view.quarantined_count
                    + _event_count(payload, "quarantined_count"),
                    "cursor_available": bool(payload.get("cursor_present", False)),
                    "updated_at": occurred_at,
                }
            )
        elif event_type == "evidence.query.completed":
            view = view.model_copy(
                update={
                    "status": QueryStatus.COMPLETED,
                    "cursor_available": False,
                    "updated_at": occurred_at,
                }
            )
        elif event_type.startswith("evidence.query."):
            try:
                status = QueryStatus(event_type.removeprefix("evidence.query."))
            except ValueError as exc:
                raise IntegrityFailure("unknown evidence query event") from exc
            failure_code = payload.get("failure_code")
            if not isinstance(failure_code, str):
                raise IntegrityFailure("evidence failure event is malformed")
            view = view.model_copy(
                update={
                    "status": status,
                    "failure_code": failure_code,
                    "reconciliation_required": (
                        status is QueryStatus.RECONCILIATION_REQUIRED
                    ),
                    "updated_at": occurred_at,
                }
            )
        else:
            raise IntegrityFailure("unknown evidence application event")
    return view


def _event_count(payload: dict[str, object], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise IntegrityFailure(f"evidence event {key} is invalid")
    return value
