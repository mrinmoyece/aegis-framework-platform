"""Forced-RLS PostgreSQL/pgvector memory ledger and derived index."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from datetime import datetime

from psycopg.types.json import Jsonb
from pydantic import Field, JsonValue, ValidationError

from aegis_framework.domain import StrictModel, stable_id
from aegis_framework.errors import (
    ConcurrencyConflict,
    IdempotencyConflict,
    IntegrityFailure,
    RepositoryUnavailable,
)
from aegis_framework.memory import (
    EmbeddingVector,
    MemoryChunk,
    MemoryFact,
    MemoryFactType,
    MemoryOperationFact,
    MemoryProjection,
    MemoryRecord,
    RetrievalQuery,
    canonical_digest,
    reduce_memory,
)
from aegis_framework.postgres import DictConnection, RuntimePool, tenant_transaction


class PgvectorCandidate(StrictModel):
    """Filtered derived candidate returned before application MMR and final bounds."""

    memory_id: str
    chunk_id: str
    ordinal: int = Field(ge=0, le=10_000)
    chunk_text: str = Field(min_length=1, max_length=65_536)
    content_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    citation_document: dict[str, JsonValue]
    embedding: tuple[float, ...] = Field(min_length=2, max_length=4_096)
    lexical_score: float = Field(ge=0.0, le=1.0)
    vector_score: float = Field(ge=0.0, le=1.0)
    recency_score: float = Field(ge=0.0, le=1.0)
    quality_score: float = Field(ge=0.0, le=1.0)
    combined_score: float = Field(ge=0.0, le=1.0)


class PostgresMemoryStore:
    """Application facts are truth; text, tsvectors, and vectors are derived."""

    def __init__(self, *, pool: RuntimePool) -> None:
        self._pool = pool

    def put_record(self, record: MemoryRecord) -> None:
        try:
            with tenant_transaction(
                self._pool,
                tenant_id=record.tenant_id,
            ) as connection:
                connection.execute(
                    """
                    INSERT INTO aegis.memory_records (
                        tenant_id, memory_id, incident_id, run_id, tier, status,
                        schema_version, record_digest, content_digest, source_id,
                        evidence_id, classification, trust, acl_document,
                        provenance_document, retention_document, blob_document,
                        record_document, expires_at, legal_hold_count, created_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    ON CONFLICT (tenant_id, memory_id) DO NOTHING
                    """,
                    (
                        record.tenant_id,
                        record.memory_id,
                        record.incident_id,
                        record.run_id,
                        record.tier.value,
                        record.status.value,
                        record.schema_version,
                        record.canonical_digest,
                        record.content_digest,
                        record.provenance.source_id,
                        record.provenance.evidence_id,
                        record.classification.value,
                        record.trust.value,
                        Jsonb(record.acl.model_dump(mode="json")),
                        Jsonb(record.provenance.model_dump(mode="json")),
                        Jsonb(record.retention.model_dump(mode="json")),
                        Jsonb(record.blob.model_dump(mode="json")),
                        Jsonb(record.model_dump(mode="json")),
                        record.retention.expires_at,
                        len(record.retention.legal_hold_refs),
                        record.created_at,
                    ),
                )
                row = connection.execute(
                    """
                    SELECT record_digest
                    FROM aegis.memory_records
                    WHERE tenant_id = %s AND memory_id = %s
                    """,
                    (record.tenant_id, record.memory_id),
                ).fetchone()
                if row is None or row["record_digest"] != record.canonical_digest:
                    raise IdempotencyConflict("memory record replay changed")
        except IdempotencyConflict:
            raise
        except Exception as exc:
            raise RepositoryUnavailable("memory record persistence failed") from exc

    def record(self, *, tenant_id: str, memory_id: str) -> MemoryRecord | None:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                row = connection.execute(
                    """
                    SELECT record_document
                    FROM aegis.memory_records
                    WHERE tenant_id = %s AND memory_id = %s
                    """,
                    (tenant_id, memory_id),
                ).fetchone()
                return (
                    MemoryRecord.model_validate(row["record_document"])
                    if row is not None
                    else None
                )
        except ValidationError as exc:
            raise IntegrityFailure("stored memory record is invalid") from exc
        except Exception as exc:
            raise RepositoryUnavailable("memory record read failed") from exc

    def append(
        self,
        *,
        tenant_id: str,
        memory_id: str,
        expected_version: int,
        fact_type: MemoryFactType,
        command_id: str,
        actor_ref: str,
        recorded_at: datetime,
        payload: Mapping[str, JsonValue],
    ) -> MemoryProjection:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (f"memory:{tenant_id}:{memory_id}",),
                )
                record = self._record_row(
                    connection,
                    tenant_id=tenant_id,
                    memory_id=memory_id,
                )
                replay = connection.execute(
                    """
                    SELECT fact_document
                    FROM aegis.memory_facts
                    WHERE tenant_id = %s AND command_id = %s
                    """,
                    (tenant_id, command_id),
                ).fetchone()
                if replay is not None:
                    fact = MemoryFact.model_validate(replay["fact_document"])
                    if (
                        fact.memory_id != memory_id
                        or fact.fact_type is not fact_type
                        or fact.payload != dict(payload)
                    ):
                        raise IdempotencyConflict("memory command replay changed")
                    projection = self._projection_row(
                        connection,
                        tenant_id=tenant_id,
                        memory_id=memory_id,
                    )
                    if projection is None:
                        raise IntegrityFailure("memory replay lost projection")
                    return projection
                current = self._projection_row(
                    connection,
                    tenant_id=tenant_id,
                    memory_id=memory_id,
                    for_update=True,
                )
                version = current.version if current is not None else 0
                if version != expected_version:
                    raise ConcurrencyConflict("memory aggregate version changed")
                previous = current.last_fact_digest if current is not None else "0" * 64
                material = {
                    "schema_version": 1,
                    "tenant_id": tenant_id,
                    "memory_id": memory_id,
                    "sequence": version + 1,
                    "fact_id": stable_id(
                        "memory-fact",
                        tenant_id,
                        memory_id,
                        str(version + 1),
                        command_id,
                        length=32,
                    ),
                    "fact_type": fact_type.value,
                    "command_id": command_id,
                    "actor_ref": actor_ref,
                    "recorded_at": recorded_at,
                    "payload": dict(sorted(payload.items())),
                    "previous_digest": previous,
                }
                fact = MemoryFact(
                    **material,
                    fact_digest=canonical_digest(material),
                )
                projection = reduce_memory(current, fact, record)
                connection.execute(
                    """
                    INSERT INTO aegis.memory_facts (
                        tenant_id, memory_id, sequence, fact_id, fact_type,
                        command_id, actor_ref, fact_document, previous_digest,
                        fact_digest, recorded_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        tenant_id,
                        memory_id,
                        fact.sequence,
                        fact.fact_id,
                        fact.fact_type.value,
                        command_id,
                        actor_ref,
                        Jsonb(fact.model_dump(mode="json")),
                        previous,
                        fact.fact_digest,
                        recorded_at,
                    ),
                )
                self._upsert_projection(connection, projection)
                return projection
        except (ConcurrencyConflict, IdempotencyConflict, IntegrityFailure):
            raise
        except ValidationError as exc:
            raise IntegrityFailure("stored memory state is invalid") from exc
        except Exception as exc:
            raise RepositoryUnavailable("memory fact append failed") from exc

    def projection(self, *, tenant_id: str, memory_id: str) -> MemoryProjection | None:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                return self._projection_row(
                    connection,
                    tenant_id=tenant_id,
                    memory_id=memory_id,
                )
        except ValidationError as exc:
            raise IntegrityFailure("stored memory projection is invalid") from exc
        except Exception as exc:
            raise RepositoryUnavailable("memory projection read failed") from exc

    def facts(self, *, tenant_id: str, memory_id: str) -> tuple[MemoryFact, ...]:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                rows = connection.execute(
                    """
                    SELECT fact_document
                    FROM aegis.memory_facts
                    WHERE tenant_id = %s AND memory_id = %s
                    ORDER BY sequence
                    """,
                    (tenant_id, memory_id),
                ).fetchall()
                return tuple(
                    MemoryFact.model_validate(row["fact_document"]) for row in rows
                )
        except ValidationError as exc:
            raise IntegrityFailure("stored memory fact is invalid") from exc
        except Exception as exc:
            raise RepositoryUnavailable("memory fact read failed") from exc

    def put_derived_chunks(
        self,
        *,
        record: MemoryRecord,
        chunks: Sequence[MemoryChunk],
        vectors: Sequence[EmbeddingVector],
        indexed_at: datetime,
    ) -> None:
        by_chunk = {vector.chunk_id: vector for vector in vectors}
        if len(by_chunk) != len(chunks):
            raise IntegrityFailure("memory vector set is incomplete")
        try:
            with tenant_transaction(
                self._pool,
                tenant_id=record.tenant_id,
            ) as connection:
                for chunk in chunks:
                    vector = by_chunk.get(chunk.chunk_id)
                    if (
                        vector is None
                        or vector.content_digest != chunk.content_digest
                        or len(vector.values) != record.embedding_dimensions
                        or any(not math.isfinite(value) for value in vector.values)
                    ):
                        raise IntegrityFailure("memory vector binding is invalid")
                    literal = (
                        "["
                        + ",".join(format(value, ".17g") for value in vector.values)
                        + "]"
                    )
                    connection.execute(
                        """
                        INSERT INTO aegis.memory_chunks (
                            tenant_id, chunk_id, memory_id, incident_id, run_id,
                            tier, ordinal, chunk_text, content_digest,
                            citation_document, acl_document, classification, trust,
                            quality, confidence, accepted_at, expires_at,
                            embedder_model, embedder_version, embedding_dimensions,
                            embedding, indexed_at
                        )
                        VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s::vector, %s
                        )
                        ON CONFLICT (tenant_id, chunk_id) DO UPDATE SET
                            embedding = EXCLUDED.embedding,
                            indexed_at = EXCLUDED.indexed_at
                        """,
                        (
                            record.tenant_id,
                            chunk.chunk_id,
                            record.memory_id,
                            record.incident_id,
                            record.run_id,
                            record.tier.value,
                            chunk.ordinal,
                            chunk.text,
                            chunk.content_digest,
                            Jsonb(chunk.citation.model_dump(mode="json")),
                            Jsonb(record.acl.model_dump(mode="json")),
                            record.classification.value,
                            record.trust.value,
                            record.quality,
                            record.confidence,
                            record.accepted_at,
                            record.retention.expires_at,
                            record.embedder_model,
                            record.embedder_version,
                            record.embedding_dimensions,
                            literal,
                            indexed_at,
                        ),
                    )
        except IntegrityFailure:
            raise
        except Exception as exc:
            raise RepositoryUnavailable("derived memory indexing failed") from exc

    def hybrid_candidates(
        self,
        query: RetrievalQuery,
        query_vector: Sequence[float],
    ) -> tuple[PgvectorCandidate, ...]:
        if (
            len(query_vector) != 64
            or any(not math.isfinite(value) for value in query_vector)
            or not math.isclose(
                math.sqrt(sum(value * value for value in query_vector)),
                1.0,
                rel_tol=1e-6,
                abs_tol=1e-6,
            )
        ):
            raise ValueError("pgvector query requires 64 finite normalized dimensions")
        vector_literal = (
            "[" + ",".join(format(value, ".17g") for value in query_vector) + "]"
        )
        try:
            with tenant_transaction(
                self._pool,
                tenant_id=query.tenant_id,
            ) as connection:
                rows = connection.execute(
                    """
                    WITH filtered AS (
                        SELECT chunk.memory_id, chunk.chunk_id, chunk.ordinal,
                               chunk.chunk_text, chunk.content_digest,
                               chunk.citation_document, chunk.embedding,
                               ts_rank_cd(
                                   chunk.lexical,
                                   plainto_tsquery('simple', %s),
                                   32
                               ) AS lexical_score,
                               greatest(
                                   0.0,
                                   least(
                                       1.0,
                                       1.0 - (
                                           chunk.embedding <=> %s::vector
                                       ) / 2.0
                                   )
                               ) AS vector_score,
                               least(
                                   1.0,
                                   greatest(
                                       0.0,
                                       1.0 - extract(
                                           epoch FROM (%s - chunk.indexed_at)
                                       ) / %s
                                   )
                               ) AS recency_score,
                               (chunk.quality + chunk.confidence) / 2.0
                                   AS quality_score
                        FROM aegis.memory_chunks AS chunk
                        JOIN aegis.memory_projections AS projection
                          ON projection.tenant_id = chunk.tenant_id
                         AND projection.memory_id = chunk.memory_id
                        WHERE chunk.tenant_id = %s
                          AND projection.status IN ('accepted', 'active')
                          AND NOT projection.tombstoned
                          AND chunk.classification = ANY(%s)
                          AND chunk.accepted_at <= %s
                          AND chunk.expires_at > %s
                          AND (
                              (
                                  jsonb_array_length(
                                      chunk.acl_document->'roles'
                                  ) = 0
                                  AND jsonb_array_length(
                                      chunk.acl_document->'principals'
                                  ) = 0
                              )
                              OR chunk.acl_document->'roles' ?| %s
                              OR chunk.acl_document->'principals' ? %s
                          )
                    ),
                    scored AS (
                        SELECT *,
                               least(
                                   1.0,
                                   greatest(
                                       0.0,
                                       lexical_score * %s
                                       + vector_score * %s
                                       + recency_score * %s
                                       + quality_score * %s
                                   )
                               ) AS combined_score
                        FROM filtered
                    )
                    SELECT memory_id, chunk_id, ordinal, chunk_text,
                           content_digest, citation_document,
                           embedding::text AS embedding,
                           lexical_score, vector_score, recency_score,
                           quality_score, combined_score
                    FROM scored
                    ORDER BY combined_score DESC, memory_id, ordinal, chunk_id
                    LIMIT %s
                    """,
                    (
                        query.text,
                        vector_literal,
                        query.as_of,
                        query.policy.freshness_seconds,
                        query.tenant_id,
                        [
                            classification.value
                            for classification in query.allowed_classifications
                        ],
                        query.as_of,
                        query.as_of,
                        list(query.roles),
                        query.principal_ref,
                        query.policy.lexical_weight,
                        query.policy.vector_weight,
                        query.policy.recency_weight,
                        query.policy.quality_weight,
                        query.policy.maximum_candidates,
                    ),
                ).fetchall()
                return tuple(
                    PgvectorCandidate(
                        **{
                            **row,
                            "embedding": _parse_vector(str(row["embedding"])),
                        }
                    )
                    for row in rows
                )
        except ValidationError as exc:
            raise IntegrityFailure("pgvector candidate is invalid") from exc
        except Exception as exc:
            raise RepositoryUnavailable("pgvector hybrid retrieval failed") from exc

    def append_operation(self, fact: MemoryOperationFact) -> None:
        try:
            with tenant_transaction(
                self._pool,
                tenant_id=fact.tenant_id,
            ) as connection:
                connection.execute(
                    """
                    INSERT INTO aegis.memory_operation_facts (
                        tenant_id, operation_id, run_id, incident_id, sequence,
                        fact_type, policy_digest, query_digest, result_digest,
                        fact_digest, recorded_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (tenant_id, operation_id, sequence) DO NOTHING
                    """,
                    (
                        fact.tenant_id,
                        fact.operation_id,
                        fact.run_id,
                        fact.incident_id,
                        fact.sequence,
                        fact.fact_type.value,
                        fact.policy_digest,
                        fact.query_digest,
                        fact.result_digest,
                        fact.fact_digest,
                        fact.recorded_at,
                    ),
                )
                row = connection.execute(
                    """
                    SELECT fact_digest
                    FROM aegis.memory_operation_facts
                    WHERE tenant_id = %s
                      AND operation_id = %s
                      AND sequence = %s
                    """,
                    (fact.tenant_id, fact.operation_id, fact.sequence),
                ).fetchone()
                if row is None or row["fact_digest"] != fact.fact_digest:
                    raise IdempotencyConflict("memory operation replay changed")
        except IdempotencyConflict:
            raise
        except Exception as exc:
            raise RepositoryUnavailable("memory operation persistence failed") from exc

    def operation_facts(
        self,
        *,
        tenant_id: str,
        operation_id: str,
    ) -> tuple[MemoryOperationFact, ...]:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                rows = connection.execute(
                    """
                    SELECT tenant_id, operation_id, run_id, incident_id, sequence,
                           fact_type, policy_digest, query_digest, result_digest,
                           fact_digest, recorded_at
                    FROM aegis.memory_operation_facts
                    WHERE tenant_id = %s AND operation_id = %s
                    ORDER BY sequence
                    """,
                    (tenant_id, operation_id),
                ).fetchall()
                return tuple(MemoryOperationFact.model_validate(row) for row in rows)
        except ValidationError as exc:
            raise IntegrityFailure("stored memory operation fact is invalid") from exc
        except Exception as exc:
            raise RepositoryUnavailable("memory operation read failed") from exc

    def purge_derived(self, *, tenant_id: str, memory_id: str) -> int:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                result = connection.execute(
                    """
                    DELETE FROM aegis.memory_chunks
                    WHERE tenant_id = %s AND memory_id = %s
                    """,
                    (tenant_id, memory_id),
                )
                connection.execute(
                    "DELETE FROM aegis.memory_cache WHERE tenant_id = %s",
                    (tenant_id,),
                )
                return result.rowcount
        except Exception as exc:
            raise RepositoryUnavailable("derived memory purge failed") from exc

    def rebuild(
        self,
        *,
        tenant_id: str,
        memory_id: str,
        rebuilt_at: datetime,
    ) -> MemoryProjection:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (f"memory:{tenant_id}:{memory_id}",),
                )
                record = self._record_row(
                    connection,
                    tenant_id=tenant_id,
                    memory_id=memory_id,
                )
                rows = connection.execute(
                    """
                    SELECT fact_document
                    FROM aegis.memory_facts
                    WHERE tenant_id = %s AND memory_id = %s
                    ORDER BY sequence
                    """,
                    (tenant_id, memory_id),
                ).fetchall()
                facts = tuple(
                    MemoryFact.model_validate(row["fact_document"]) for row in rows
                )
                projection: MemoryProjection | None = None
                for fact in facts:
                    projection = reduce_memory(projection, fact, record)
                if projection is None:
                    raise IntegrityFailure("cannot rebuild memory without facts")
                self._upsert_projection(connection, projection)
                source_digest = canonical_digest(facts)
                connection.execute(
                    """
                    INSERT INTO aegis.memory_rebuilds (
                        tenant_id, rebuild_id, memory_id, source_fact_count,
                        source_digest, projection_digest, rebuilt_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        tenant_id,
                        stable_id(
                            "memory-rebuild",
                            tenant_id,
                            memory_id,
                            source_digest,
                            length=40,
                        ),
                        memory_id,
                        len(facts),
                        source_digest,
                        canonical_digest(projection),
                        rebuilt_at,
                    ),
                )
                return projection
        except IntegrityFailure:
            raise
        except ValidationError as exc:
            raise IntegrityFailure("stored memory fact is invalid") from exc
        except Exception as exc:
            raise RepositoryUnavailable("memory rebuild failed") from exc

    @staticmethod
    def _record_row(
        connection: DictConnection,
        *,
        tenant_id: str,
        memory_id: str,
    ) -> MemoryRecord:
        row = connection.execute(
            """
            SELECT record_document
            FROM aegis.memory_records
            WHERE tenant_id = %s AND memory_id = %s
            """,
            (tenant_id, memory_id),
        ).fetchone()
        if row is None:
            raise IntegrityFailure("memory record is missing")
        return MemoryRecord.model_validate(row["record_document"])

    @staticmethod
    def _projection_row(
        connection: DictConnection,
        *,
        tenant_id: str,
        memory_id: str,
        for_update: bool = False,
    ) -> MemoryProjection | None:
        query = (
            """
            SELECT projection_document
            FROM aegis.memory_projections
            WHERE tenant_id = %s AND memory_id = %s
            FOR UPDATE
            """
            if for_update
            else """
            SELECT projection_document
            FROM aegis.memory_projections
            WHERE tenant_id = %s AND memory_id = %s
            """
        )
        row = connection.execute(query, (tenant_id, memory_id)).fetchone()
        return (
            MemoryProjection.model_validate(row["projection_document"])
            if row is not None
            else None
        )

    @staticmethod
    def _upsert_projection(
        connection: DictConnection,
        projection: MemoryProjection,
    ) -> None:
        connection.execute(
            """
            INSERT INTO aegis.memory_projections (
                tenant_id, memory_id, tier, status, version, record_digest,
                last_fact_digest, chunk_count, indexed, tombstoned,
                legal_hold_count, derived_purged, blob_erased,
                projection_document, updated_at
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            ON CONFLICT (tenant_id, memory_id) DO UPDATE SET
                status = EXCLUDED.status,
                version = EXCLUDED.version,
                last_fact_digest = EXCLUDED.last_fact_digest,
                chunk_count = EXCLUDED.chunk_count,
                indexed = EXCLUDED.indexed,
                tombstoned = EXCLUDED.tombstoned,
                legal_hold_count = EXCLUDED.legal_hold_count,
                derived_purged = EXCLUDED.derived_purged,
                blob_erased = EXCLUDED.blob_erased,
                projection_document = EXCLUDED.projection_document,
                updated_at = EXCLUDED.updated_at
            """,
            (
                projection.tenant_id,
                projection.memory_id,
                projection.tier.value,
                projection.status.value,
                projection.version,
                projection.record_digest,
                projection.last_fact_digest,
                projection.chunk_count,
                projection.indexed,
                projection.tombstoned,
                projection.legal_hold_count,
                projection.derived_purged,
                projection.blob_erased,
                Jsonb(projection.model_dump(mode="json")),
                projection.updated_at,
            ),
        )


def _parse_vector(value: str) -> tuple[float, ...]:
    if not value.startswith("[") or not value.endswith("]"):
        raise IntegrityFailure("pgvector text representation is invalid")
    try:
        result = tuple(float(item) for item in value[1:-1].split(","))
    except ValueError as exc:
        raise IntegrityFailure("pgvector text representation is invalid") from exc
    if not result or any(not math.isfinite(item) for item in result):
        raise IntegrityFailure("pgvector candidate contains an invalid vector")
    return result
