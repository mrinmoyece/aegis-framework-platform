"""Application-owned evidence query ledger, cursor vault, and durable collector."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from threading import Lock
from typing import Literal, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import AwareDatetime, Field, JsonValue

from aegis_framework.connector_adapters import EvidenceConnector
from aegis_framework.domain import Identifier, StrictModel, stable_id
from aegis_framework.errors import (
    ConcurrencyConflict,
    ConnectorRejected,
    IdempotencyConflict,
    IntegrityFailure,
    ReconciliationRequired,
)
from aegis_framework.evidence import (
    EvidenceBundle,
    EvidenceCursor,
    EvidenceCursorView,
    EvidenceDisposition,
    EvidenceQuery,
    EvidenceQueryView,
    EvidenceSource,
    NormalizedEvidence,
    QueryStatus,
    build_bundle,
    canonical_digest,
)
from aegis_framework.ingestion import EvidenceIngestor
from aegis_framework.ports import ObservabilityPort

_ZERO_HASH = "0" * 64


class EvidenceApplicationEvent(StrictModel):
    tenant_id: Identifier
    query_id: Identifier
    sequence: int = Field(ge=1)
    event_id: Identifier
    event_type: Identifier
    operation_id: Identifier
    occurred_at: AwareDatetime
    payload: dict[str, JsonValue] = Field(default_factory=dict, max_length=32)
    previous_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    record_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class EvidenceAuthorityPort(Protocol):
    def current_source(
        self,
        *,
        tenant_id: str,
        source_id: str,
    ) -> EvidenceSource | None: ...

    def cancelled(self, *, tenant_id: str, run_id: str) -> bool: ...


class EvidenceControlStore(Protocol):
    def request(
        self,
        query: EvidenceQuery,
        *,
        operation_id: str,
    ) -> EvidenceQueryView: ...

    def query(self, *, tenant_id: str, query_id: str) -> EvidenceQuery: ...

    def begin_page(
        self,
        *,
        tenant_id: str,
        query_id: str,
        page_number: int,
        operation_id: str,
        cursor_ref: str | None,
        occurred_at: datetime,
    ) -> Literal["started", "completed"]: ...

    def complete_page(
        self,
        *,
        query: EvidenceQuery,
        page_number: int,
        operation_id: str,
        evidence: Sequence[NormalizedEvidence],
        next_cursor: str | None,
        occurred_at: datetime,
    ) -> EvidenceCursor | None: ...

    def complete_query(
        self,
        *,
        query: EvidenceQuery,
        operation_id: str,
        bundle: EvidenceBundle,
        occurred_at: datetime,
    ) -> EvidenceQueryView: ...

    def fail_query(
        self,
        *,
        tenant_id: str,
        query_id: str,
        operation_id: str,
        failure_code: str,
        status: QueryStatus,
        occurred_at: datetime,
    ) -> EvidenceQueryView: ...

    def cursor_value(
        self,
        *,
        tenant_id: str,
        query_id: str,
        cursor_ref: str,
    ) -> str: ...

    def evidence(
        self,
        *,
        tenant_id: str,
        query_id: str,
    ) -> Sequence[NormalizedEvidence]: ...

    def bundle(self, *, tenant_id: str, query_id: str) -> EvidenceBundle | None: ...

    def status(self, *, tenant_id: str, query_id: str) -> EvidenceQueryView | None: ...

    def cursor_status(
        self, *, tenant_id: str, query_id: str
    ) -> EvidenceCursorView | None: ...

    def current_cursor_ref(self, *, tenant_id: str, query_id: str) -> str | None: ...


class EvidenceStatusPort(Protocol):
    def status(self, *, tenant_id: str, query_id: str) -> EvidenceQueryView | None: ...

    def cursor_status(
        self, *, tenant_id: str, query_id: str
    ) -> EvidenceCursorView | None: ...


class CursorVault:
    def __init__(
        self,
        key: bytes,
        *,
        nonce_factory: Callable[[int], bytes] = os.urandom,
    ) -> None:
        if len(key) != 32:
            raise ValueError("evidence cursor encryption key must be 32 bytes")
        self._cipher = AESGCM(key)
        self._nonce_factory = nonce_factory

    def seal(
        self,
        value: str,
        *,
        tenant_id: str,
        query_id: str,
    ) -> bytes:
        if not value or len(value) > 4_096:
            raise ValueError("evidence cursor value is invalid")
        nonce = self._nonce_factory(12)
        if len(nonce) != 12:
            raise ValueError("evidence cursor nonce must be 12 bytes")
        aad = f"{tenant_id}\x00{query_id}".encode()
        return nonce + self._cipher.encrypt(nonce, value.encode(), aad)

    def open(
        self,
        value: bytes,
        *,
        tenant_id: str,
        query_id: str,
    ) -> str:
        if len(value) < 29 or len(value) > 4_128:
            raise IntegrityFailure("encrypted evidence cursor is malformed")
        nonce, ciphertext = value[:12], value[12:]
        try:
            decoded = self._cipher.decrypt(
                nonce,
                ciphertext,
                f"{tenant_id}\x00{query_id}".encode(),
            ).decode()
        except (InvalidTag, ValueError, UnicodeDecodeError) as exc:
            raise IntegrityFailure("encrypted evidence cursor is invalid") from exc
        if not decoded or len(decoded) > 4_096:
            raise IntegrityFailure("decrypted evidence cursor is invalid")
        return decoded


class InMemoryEvidenceControlStore:
    """Application-ledger reference adapter; never a production fallback."""

    def __init__(
        self,
        *,
        cursor_vault: CursorVault,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._cursor_vault = cursor_vault
        self._clock = clock
        self._queries: dict[tuple[str, str], EvidenceQuery] = {}
        self._events: dict[tuple[str, str], list[EvidenceApplicationEvent]] = {}
        self._views: dict[tuple[str, str], EvidenceQueryView] = {}
        self._page_intents: dict[tuple[str, str, int], str] = {}
        self._page_results: set[tuple[str, str, int]] = set()
        self._evidence: dict[tuple[str, str], list[NormalizedEvidence]] = {}
        self._cursors: dict[tuple[str, str], tuple[EvidenceCursor, bytes]] = {}
        self._bundles: dict[tuple[str, str], EvidenceBundle] = {}
        self._lock = Lock()

    def request(
        self,
        query: EvidenceQuery,
        *,
        operation_id: str,
    ) -> EvidenceQueryView:
        key = (query.tenant_id, query.query_id)
        with self._lock:
            existing = self._queries.get(key)
            if existing is not None:
                if existing.digest != query.digest:
                    raise IdempotencyConflict(
                        "evidence query id was reused with different input"
                    )
                return self._views[key]
            self._queries[key] = query
            self._evidence[key] = []
            return self._append(
                query.tenant_id,
                query.query_id,
                event_type="evidence.query.requested",
                operation_id=operation_id,
                occurred_at=query.created_at,
                payload={
                    "incident_id": query.incident_id,
                    "query": query.model_dump(mode="json"),
                    "query_digest": query.digest,
                    "source_kind": query.source.kind.value,
                },
            )

    def query(self, *, tenant_id: str, query_id: str) -> EvidenceQuery:
        try:
            return self._queries[(tenant_id, query_id)]
        except KeyError as exc:
            raise IntegrityFailure("evidence query is unavailable") from exc

    def begin_page(
        self,
        *,
        tenant_id: str,
        query_id: str,
        page_number: int,
        operation_id: str,
        cursor_ref: str | None,
        occurred_at: datetime,
    ) -> Literal["started", "completed"]:
        key = (tenant_id, query_id, page_number)
        with self._lock:
            if key in self._page_results:
                return "completed"
            previous = self._page_intents.get(key)
            if previous is not None:
                raise ReconciliationRequired(
                    "evidence page has unresolved external-call intent"
                )
            self._page_intents[key] = operation_id
            self._append(
                tenant_id,
                query_id,
                event_type="evidence.page.requested",
                operation_id=operation_id,
                occurred_at=occurred_at,
                payload={
                    "cursor_present": cursor_ref is not None,
                    "page_number": page_number,
                },
            )
            return "started"

    def complete_page(
        self,
        *,
        query: EvidenceQuery,
        page_number: int,
        operation_id: str,
        evidence: Sequence[NormalizedEvidence],
        next_cursor: str | None,
        occurred_at: datetime,
    ) -> EvidenceCursor | None:
        page_key = (query.tenant_id, query.query_id, page_number)
        query_key = (query.tenant_id, query.query_id)
        with self._lock:
            if page_key in self._page_results:
                return self._cursors.get(query_key, (None, b""))[0]
            if self._page_intents.get(page_key) != operation_id:
                raise ConcurrencyConflict("evidence page intent is not owned")
            self._page_results.add(page_key)
            # Update the deduplicated set incrementally so two records with the
            # same derived evidence ID in one page do not both get stored.
            current_ids: set[str] = {
                item.evidence_id for item in self._evidence.get(query_key, ())
            }
            new_items: list[NormalizedEvidence] = []
            for item in evidence:
                if item.evidence_id not in current_ids:
                    current_ids.add(item.evidence_id)
                    new_items.append(item)
            self._evidence.setdefault(query_key, []).extend(new_items)
            cursor = None
            if next_cursor is not None:
                digest = sha256(next_cursor.encode()).hexdigest()
                cursor_ref = stable_id(
                    "cursor",
                    query.tenant_id,
                    query.query_id,
                    str(page_number),
                    digest,
                    length=32,
                )
                cursor = EvidenceCursor(
                    tenant_id=query.tenant_id,
                    incident_id=query.incident_id,
                    query_id=query.query_id,
                    source_id=query.source.source_id,
                    page_number=page_number,
                    cursor_ref=cursor_ref,
                    cursor_digest=digest,
                    created_at=occurred_at,
                    expires_at=occurred_at + timedelta(minutes=5),
                )
                self._cursors[query_key] = (
                    cursor,
                    self._cursor_vault.seal(
                        next_cursor,
                        tenant_id=query.tenant_id,
                        query_id=query.query_id,
                    ),
                )
            else:
                self._cursors.pop(query_key, None)
            counts = _disposition_counts(evidence)
            self._append(
                query.tenant_id,
                query.query_id,
                event_type="evidence.page.completed",
                operation_id=operation_id,
                occurred_at=occurred_at,
                payload={
                    "accepted_count": counts["accepted"],
                    "cursor_present": cursor is not None,
                    "page_number": page_number,
                    "quarantined_count": counts["quarantined"],
                    "record_count": len(evidence),
                },
            )
            return cursor

    def complete_query(
        self,
        *,
        query: EvidenceQuery,
        operation_id: str,
        bundle: EvidenceBundle,
        occurred_at: datetime,
    ) -> EvidenceQueryView:
        key = (query.tenant_id, query.query_id)
        with self._lock:
            existing = self._bundles.get(key)
            if existing is not None:
                if existing.bundle_digest != bundle.bundle_digest:
                    raise IdempotencyConflict("evidence bundle result changed")
                return self._views[key]
            self._bundles[key] = bundle
            self._cursors.pop(key, None)
            return self._append(
                query.tenant_id,
                query.query_id,
                event_type="evidence.query.completed",
                operation_id=operation_id,
                occurred_at=occurred_at,
                payload={
                    "bundle_digest": bundle.bundle_digest,
                    "bundle_id": bundle.bundle_id,
                    "evidence_count": len(bundle.evidence),
                },
            )

    def fail_query(
        self,
        *,
        tenant_id: str,
        query_id: str,
        operation_id: str,
        failure_code: str,
        status: QueryStatus,
        occurred_at: datetime,
    ) -> EvidenceQueryView:
        if status not in {
            QueryStatus.CANCELLED,
            QueryStatus.FAILED,
            QueryStatus.RECONCILIATION_REQUIRED,
            QueryStatus.STALE,
        }:
            raise ValueError("invalid evidence query failure status")
        with self._lock:
            return self._append(
                tenant_id,
                query_id,
                event_type=f"evidence.query.{status.value}",
                operation_id=operation_id,
                occurred_at=occurred_at,
                payload={"failure_code": failure_code},
            )

    def cursor_value(
        self,
        *,
        tenant_id: str,
        query_id: str,
        cursor_ref: str,
    ) -> str:
        try:
            cursor, encrypted = self._cursors[(tenant_id, query_id)]
        except KeyError as exc:
            raise IntegrityFailure("evidence cursor is unavailable") from exc
        if cursor.cursor_ref != cursor_ref:
            raise IntegrityFailure("evidence cursor reference is invalid")
        if self._clock() >= cursor.expires_at:
            raise ReconciliationRequired("evidence cursor has expired")
        return self._cursor_vault.open(
            encrypted,
            tenant_id=tenant_id,
            query_id=query_id,
        )

    def evidence(
        self,
        *,
        tenant_id: str,
        query_id: str,
    ) -> Sequence[NormalizedEvidence]:
        return tuple(
            sorted(
                self._evidence.get((tenant_id, query_id), ()),
                key=lambda item: item.evidence_id,
            )
        )

    def bundle(self, *, tenant_id: str, query_id: str) -> EvidenceBundle | None:
        return self._bundles.get((tenant_id, query_id))

    def status(self, *, tenant_id: str, query_id: str) -> EvidenceQueryView | None:
        return self._views.get((tenant_id, query_id))

    def cursor_status(
        self, *, tenant_id: str, query_id: str
    ) -> EvidenceCursorView | None:
        item = self._cursors.get((tenant_id, query_id))
        if item is None:
            return None
        cursor, _ = item
        query = self.query(tenant_id=tenant_id, query_id=query_id)
        return EvidenceCursorView(
            query_id=query_id,
            source_kind=query.source.kind,
            page_number=cursor.page_number,
            expires_at=cursor.expires_at,
            available=cursor.expires_at > self._clock(),
        )

    def current_cursor_ref(self, *, tenant_id: str, query_id: str) -> str | None:
        item = self._cursors.get((tenant_id, query_id))
        if item is None:
            return None
        cursor, _ = item
        return cursor.cursor_ref

    def events(
        self, *, tenant_id: str, query_id: str
    ) -> tuple[EvidenceApplicationEvent, ...]:
        return tuple(self._events.get((tenant_id, query_id), ()))

    def rebuild(self, *, tenant_id: str, query_id: str) -> EvidenceQueryView:
        key = (tenant_id, query_id)
        events = self._events.get(key, ())
        if not events:
            raise IntegrityFailure("evidence query events are unavailable")
        view: EvidenceQueryView | None = None
        previous_hash = _ZERO_HASH
        for event in events:
            if event.previous_hash != previous_hash:
                raise IntegrityFailure("evidence query event hash chain is invalid")
            expected = _event_hash(event, exclude_record_hash=True)
            if event.record_hash != expected:
                raise IntegrityFailure("evidence query event record hash is invalid")
            view = _reduce_view(view, event, query=self._queries[key])
            previous_hash = event.record_hash
        if view is None:
            raise IntegrityFailure("evidence query projection could not be rebuilt")
        self._views[key] = view
        return view

    def _append(
        self,
        tenant_id: str,
        query_id: str,
        *,
        event_type: str,
        operation_id: str,
        occurred_at: datetime,
        payload: Mapping[str, JsonValue],
    ) -> EvidenceQueryView:
        key = (tenant_id, query_id)
        events = self._events.setdefault(key, [])
        if any(
            item.operation_id == operation_id and item.event_type == event_type
            for item in events
        ):
            return self._views[key]
        previous_hash = events[-1].record_hash if events else _ZERO_HASH
        sequence = len(events) + 1
        draft = EvidenceApplicationEvent(
            tenant_id=tenant_id,
            query_id=query_id,
            sequence=sequence,
            event_id=stable_id(
                "event",
                tenant_id,
                query_id,
                str(sequence),
                event_type,
                length=32,
            ),
            event_type=event_type,
            operation_id=operation_id,
            occurred_at=occurred_at,
            payload=dict(sorted(payload.items())),
            previous_hash=previous_hash,
            record_hash=_ZERO_HASH,
        )
        event = draft.model_copy(
            update={"record_hash": _event_hash(draft, exclude_record_hash=True)}
        )
        view = _reduce_view(
            self._views.get(key),
            event,
            query=self._queries[key],
        )
        events.append(event)
        self._views[key] = view
        return view


class EvidenceCollector:
    """Runs bounded pages under one durable intent/result owner."""

    def __init__(
        self,
        *,
        authority: EvidenceAuthorityPort,
        store: EvidenceControlStore,
        ingestor: EvidenceIngestor,
        clock: Callable[[], datetime],
        observability: ObservabilityPort | None = None,
    ) -> None:
        self._authority = authority
        self._store = store
        self._ingestor = ingestor
        self._clock = clock
        self._observability = observability

    def collect(
        self,
        query: EvidenceQuery,
        *,
        connector: EvidenceConnector,
    ) -> EvidenceBundle:
        if self._observability is None:
            return self._collect(query, connector=connector)
        with self._observability.evidence_query(
            tenant_id=query.tenant_id,
            attributes={"connector_kind": query.source.kind.value},
        ) as observation:
            try:
                bundle = self._collect(query, connector=connector)
            except Exception:
                status = self._store.status(
                    tenant_id=query.tenant_id,
                    query_id=query.query_id,
                )
                observation.finish(
                    status=status.status.value if status is not None else "failed",
                    attributes={
                        "connector_kind": query.source.kind.value,
                        "page_count": status.page_count if status is not None else 0,
                        "record_count": (
                            status.record_count if status is not None else 0
                        ),
                        "quarantined_count": (
                            status.quarantined_count if status is not None else 0
                        ),
                        "reconciliation_required": (
                            status.reconciliation_required
                            if status is not None
                            else False
                        ),
                    },
                )
                raise
            status = self._store.status(
                tenant_id=query.tenant_id,
                query_id=query.query_id,
            )
            observation.finish(
                status="completed",
                attributes={
                    "connector_kind": query.source.kind.value,
                    "page_count": status.page_count if status is not None else 0,
                    "record_count": status.record_count if status is not None else 0,
                    "quarantined_count": (
                        status.quarantined_count if status is not None else 0
                    ),
                },
            )
            return bundle

    def _collect(
        self,
        query: EvidenceQuery,
        *,
        connector: EvidenceConnector,
    ) -> EvidenceBundle:
        view = self._store.request(query, operation_id=f"request:{query.query_id}")
        if view.status is QueryStatus.COMPLETED:
            existing = self._store.bundle(
                tenant_id=query.tenant_id,
                query_id=query.query_id,
            )
            if existing is None:
                raise IntegrityFailure("completed evidence query has no stored bundle")
            return existing
        cursor: str | None = None
        cursor_ref: str | None = None
        total_records = 0
        total_bytes = 0
        try:
            for page_number in range(1, query.bounds.maximum_pages + 1):
                self._require_current(query)
                if self._authority.cancelled(
                    tenant_id=query.tenant_id,
                    run_id=query.run_id,
                ):
                    self._fail(
                        query,
                        "cancelled",
                        QueryStatus.CANCELLED,
                        operation_id=f"cancel:{query.query_id}:{page_number}",
                    )
                    raise ConnectorRejected("evidence query was cancelled")
                operation_id = f"page:{query.query_id}:{page_number}"
                state = self._store.begin_page(
                    tenant_id=query.tenant_id,
                    query_id=query.query_id,
                    page_number=page_number,
                    operation_id=operation_id,
                    cursor_ref=cursor_ref,
                    occurred_at=self._clock(),
                )
                if state == "completed":
                    current = self._store.cursor_status(
                        tenant_id=query.tenant_id,
                        query_id=query.query_id,
                    )
                    if current is None:
                        # Page already completed without a continuation cursor —
                        # the query finished before this restart.
                        break
                    # Page already completed with a cursor: reload it and
                    # continue rather than treating this resolved state as an
                    # unresolved intent.
                    cursor_ref = self._store.current_cursor_ref(
                        tenant_id=query.tenant_id,
                        query_id=query.query_id,
                    )
                    if cursor_ref is None:
                        raise IntegrityFailure(
                            "evidence cursor checkpoint lost after page completion"
                        )
                    cursor = self._store.cursor_value(
                        tenant_id=query.tenant_id,
                        query_id=query.query_id,
                        cursor_ref=cursor_ref,
                    )
                    continue
                page = connector.fetch_page(
                    query,
                    cursor=cursor,
                    page_number=page_number,
                    cancelled=lambda: self._authority.cancelled(
                        tenant_id=query.tenant_id,
                        run_id=query.run_id,
                    ),
                )
                self._require_current(query)
                # Reject the page if its binding fields do not match the
                # current query — a defective adapter cannot relabel pages
                # from another query/source/page under this query's provenance.
                if (
                    page.query_id != query.query_id
                    or page.source_id != query.source.source_id
                    or page.page_number != page_number
                ):
                    raise ConnectorRejected(
                        "connector page binding does not match evidence query"
                    )
                total_records += len(page.records)
                total_bytes += page.response_bytes
                if (
                    total_records > query.bounds.maximum_records
                    or total_bytes > query.bounds.maximum_total_bytes
                ):
                    raise ConnectorRejected("evidence query aggregate bounds exceeded")
                normalized = self._ingestor.ingest_page(
                    query,
                    page.records,
                    page_number=page_number,
                    retrieved_at=page.retrieved_at,
                )
                stored_cursor = self._store.complete_page(
                    query=query,
                    page_number=page_number,
                    operation_id=operation_id,
                    evidence=normalized,
                    next_cursor=page.next_cursor,
                    occurred_at=self._clock(),
                )
                if page.next_cursor is None:
                    break
                if stored_cursor is None:
                    raise IntegrityFailure(
                        "evidence cursor checkpoint was not committed"
                    )
                cursor_ref = stored_cursor.cursor_ref
                cursor = self._store.cursor_value(
                    tenant_id=query.tenant_id,
                    query_id=query.query_id,
                    cursor_ref=cursor_ref,
                )
            else:
                raise ConnectorRejected("evidence query page bound was exhausted")
        except ReconciliationRequired:
            self._fail(
                query,
                "ambiguous_connector_outcome",
                QueryStatus.RECONCILIATION_REQUIRED,
                operation_id=f"reconcile:{query.query_id}",
            )
            raise
        except ConnectorRejected:
            status_view = self._store.status(
                tenant_id=query.tenant_id,
                query_id=query.query_id,
            )
            if status_view is not None and status_view.status in {
                QueryStatus.CANCELLED,
                QueryStatus.RECONCILIATION_REQUIRED,
                QueryStatus.STALE,
            }:
                raise
            self._fail(
                query,
                "connector_result_rejected",
                QueryStatus.FAILED,
                operation_id=f"failure:{query.query_id}",
            )
            raise
        all_evidence = self._store.evidence(
            tenant_id=query.tenant_id,
            query_id=query.query_id,
        )
        created_at = self._clock()
        bundle_id = stable_id(
            "bundle",
            query.tenant_id,
            query.incident_id,
            query.query_id,
            canonical_digest(tuple(item.digest for item in all_evidence)),
            length=32,
        )
        bundle = build_bundle(
            bundle_id=bundle_id,
            tenant_id=query.tenant_id,
            incident_id=query.incident_id,
            run_id=query.run_id,
            query_ids=(query.query_id,),
            evidence=all_evidence,
            created_at=created_at,
        )
        self._store.complete_query(
            query=query,
            operation_id=f"complete:{query.query_id}",
            bundle=bundle,
            occurred_at=created_at,
        )
        return bundle

    def _require_current(self, query: EvidenceQuery) -> None:
        current = self._authority.current_source(
            tenant_id=query.tenant_id,
            source_id=query.source.source_id,
        )
        if (
            current is None
            or current.digest != query.source.digest
            or not current.enabled
        ):
            self._fail(
                query,
                "source_policy_or_credential_stale",
                QueryStatus.STALE,
                operation_id=f"stale:{query.query_id}",
            )
            raise ConnectorRejected("evidence source policy is stale or revoked")

    def _fail(
        self,
        query: EvidenceQuery,
        code: str,
        status: QueryStatus,
        *,
        operation_id: str,
    ) -> None:
        self._store.fail_query(
            tenant_id=query.tenant_id,
            query_id=query.query_id,
            operation_id=operation_id,
            failure_code=code,
            status=status,
            occurred_at=self._clock(),
        )


def _event_hash(
    event: EvidenceApplicationEvent,
    *,
    exclude_record_hash: bool,
) -> str:
    return canonical_digest(
        event.model_dump(
            mode="json",
            exclude={"record_hash"} if exclude_record_hash else set(),
        )
    )


def _reduce_view(
    current: EvidenceQueryView | None,
    event: EvidenceApplicationEvent,
    *,
    query: EvidenceQuery,
) -> EvidenceQueryView:
    payload = event.payload
    if current is None:
        if event.event_type != "evidence.query.requested":
            raise IntegrityFailure("evidence projection must start with query request")
        return EvidenceQueryView(
            query_id=query.query_id,
            incident_id=query.incident_id,
            source_kind=query.source.kind,
            status=QueryStatus.REQUESTED,
            page_count=0,
            record_count=0,
            accepted_count=0,
            quarantined_count=0,
            updated_at=event.occurred_at,
        )
    terminal = {
        QueryStatus.CANCELLED,
        QueryStatus.COMPLETED,
        QueryStatus.FAILED,
        QueryStatus.RECONCILIATION_REQUIRED,
        QueryStatus.STALE,
    }
    if current.status in terminal:
        if event.operation_id == event.event_id:
            return current
        raise IntegrityFailure("terminal evidence query cannot transition")
    if event.event_type == "evidence.page.requested":
        return current.model_copy(
            update={"status": QueryStatus.RUNNING, "updated_at": event.occurred_at}
        )
    if event.event_type == "evidence.page.completed":
        return current.model_copy(
            update={
                "status": QueryStatus.RUNNING,
                "page_count": current.page_count + 1,
                "record_count": current.record_count
                + _payload_int(payload, "record_count"),
                "accepted_count": current.accepted_count
                + _payload_int(payload, "accepted_count"),
                "quarantined_count": current.quarantined_count
                + _payload_int(payload, "quarantined_count"),
                "cursor_available": bool(payload.get("cursor_present", False)),
                "updated_at": event.occurred_at,
            }
        )
    if event.event_type == "evidence.query.completed":
        return current.model_copy(
            update={
                "status": QueryStatus.COMPLETED,
                "cursor_available": False,
                "updated_at": event.occurred_at,
            }
        )
    prefix = "evidence.query."
    if event.event_type.startswith(prefix):
        value = event.event_type.removeprefix(prefix)
        try:
            status = QueryStatus(value)
        except ValueError as exc:
            raise IntegrityFailure("unknown evidence query event type") from exc
        failure_code = payload.get("failure_code")
        if not isinstance(failure_code, str):
            raise IntegrityFailure("evidence query failure code is invalid")
        return current.model_copy(
            update={
                "status": status,
                "failure_code": failure_code,
                "reconciliation_required": (
                    status is QueryStatus.RECONCILIATION_REQUIRED
                ),
                "updated_at": event.occurred_at,
            }
        )
    raise IntegrityFailure("unknown evidence application event")


def _payload_int(payload: Mapping[str, JsonValue], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise IntegrityFailure(f"evidence event {key} is invalid")
    return value


def _disposition_counts(
    evidence: Sequence[NormalizedEvidence],
) -> dict[str, int]:
    return {
        "accepted": sum(
            item.disposition
            in {EvidenceDisposition.ACCEPTED, EvidenceDisposition.REDACTED}
            for item in evidence
        ),
        "quarantined": sum(
            item.disposition is EvidenceDisposition.QUARANTINED for item in evidence
        ),
    }
