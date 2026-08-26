"""Forced-RLS PostgreSQL sandbox ledger, claims, artifacts, and rebuilds."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from psycopg.types.json import Jsonb
from pydantic import JsonValue, ValidationError

from aegis_framework.domain import stable_id
from aegis_framework.errors import (
    ConcurrencyConflict,
    IdempotencyConflict,
    IntegrityFailure,
    RepositoryUnavailable,
)
from aegis_framework.postgres import DictConnection, RuntimePool, tenant_transaction
from aegis_framework.sandbox import (
    ArtifactRecord,
    SandboxExecutionRequest,
    SandboxFact,
    SandboxFactType,
    SandboxProjection,
    canonical_digest,
    reduce_sandbox,
)


class PostgresSandboxStore:
    """Application truth independent of Temporal and Kubernetes histories."""

    def __init__(self, *, pool: RuntimePool) -> None:
        self._pool = pool

    def put_request(self, request: SandboxExecutionRequest) -> None:
        image_digest = request.spec.image.rsplit("@sha256:", maxsplit=1)[1]
        try:
            with tenant_transaction(
                self._pool, tenant_id=request.tenant_id
            ) as connection:
                connection.execute(
                    """
                    INSERT INTO aegis.sandbox_requests (
                        tenant_id, execution_id, run_id, task_id,
                        remediation_plan_id, approval_id, schema_version,
                        request_digest, spec_digest, policy_digest, approval_digest,
                        image_digest, idempotency_key, request_document, requested_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s
                    )
                    ON CONFLICT (tenant_id, execution_id) DO NOTHING
                    """,
                    (
                        request.tenant_id,
                        request.execution_id,
                        request.run_id,
                        request.task_id,
                        request.spec.approval.remediation_plan_id,
                        request.spec.approval.approval_id,
                        request.schema_version,
                        request.request_digest,
                        request.spec_digest,
                        request.policy_digest,
                        request.approval_digest,
                        image_digest,
                        request.idempotency_key,
                        Jsonb(request.model_dump(mode="json")),
                        request.requested_at,
                    ),
                )
                row = connection.execute(
                    """
                    SELECT request_digest
                    FROM aegis.sandbox_requests
                    WHERE tenant_id = %s AND execution_id = %s
                    """,
                    (request.tenant_id, request.execution_id),
                ).fetchone()
                if row is None or row["request_digest"] != request.request_digest:
                    raise IdempotencyConflict("sandbox request binding changed")
        except IdempotencyConflict:
            raise
        except Exception as exc:
            raise RepositoryUnavailable("sandbox request persistence failed") from exc

    def request(
        self,
        *,
        tenant_id: str,
        execution_id: str,
    ) -> SandboxExecutionRequest | None:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                row = connection.execute(
                    """
                    SELECT request_document
                    FROM aegis.sandbox_requests
                    WHERE tenant_id = %s AND execution_id = %s
                    """,
                    (tenant_id, execution_id),
                ).fetchone()
                return (
                    SandboxExecutionRequest.model_validate(row["request_document"])
                    if row is not None
                    else None
                )
        except ValidationError as exc:
            raise IntegrityFailure("stored sandbox request is invalid") from exc
        except IntegrityFailure:
            raise
        except Exception as exc:
            raise RepositoryUnavailable("sandbox request read failed") from exc

    def append(
        self,
        *,
        tenant_id: str,
        execution_id: str,
        expected_version: int,
        fact_type: SandboxFactType,
        command_id: str,
        actor_ref: str,
        recorded_at: datetime,
        payload: Mapping[str, JsonValue],
    ) -> SandboxProjection:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (f"sandbox:{tenant_id}:{execution_id}",),
                )
                request_row = connection.execute(
                    """
                    SELECT execution_id
                    FROM aegis.sandbox_requests
                    WHERE tenant_id = %s AND execution_id = %s
                    """,
                    (tenant_id, execution_id),
                ).fetchone()
                if request_row is None:
                    raise IntegrityFailure("sandbox request is missing")
                replay = connection.execute(
                    """
                    SELECT fact_document
                    FROM aegis.sandbox_facts
                    WHERE tenant_id = %s AND command_id = %s
                    """,
                    (tenant_id, command_id),
                ).fetchone()
                if replay is not None:
                    fact = SandboxFact.model_validate(replay["fact_document"])
                    if (
                        fact.execution_id != execution_id
                        or fact.fact_type is not fact_type
                        or fact.payload != dict(payload)
                    ):
                        raise IdempotencyConflict(
                            "sandbox command replay changed input"
                        )
                    projection = self._projection_row(
                        connection,
                        tenant_id=tenant_id,
                        execution_id=execution_id,
                        for_update=False,
                    )
                    if projection is None:
                        raise IntegrityFailure(
                            "replayed sandbox command lost projection"
                        )
                    return projection
                current = self._projection_row(
                    connection,
                    tenant_id=tenant_id,
                    execution_id=execution_id,
                    for_update=True,
                )
                version = current.version if current is not None else 0
                if version != expected_version:
                    raise ConcurrencyConflict("sandbox aggregate version changed")
                sequence = version + 1
                previous = current.last_fact_digest if current is not None else "0" * 64
                material: dict[str, JsonValue] = {
                    "schema_version": 1,
                    "tenant_id": tenant_id,
                    "execution_id": execution_id,
                    "sequence": sequence,
                    "fact_id": stable_id(
                        "sandbox-fact",
                        tenant_id,
                        execution_id,
                        str(sequence),
                        command_id,
                        length=32,
                    ),
                    "fact_type": fact_type.value,
                    "command_id": command_id,
                    "actor_ref": actor_ref,
                    "recorded_at": recorded_at.isoformat().replace("+00:00", "Z"),
                    "payload": dict(sorted(payload.items())),
                    "previous_digest": previous,
                }
                fact = SandboxFact(
                    tenant_id=tenant_id,
                    execution_id=execution_id,
                    sequence=sequence,
                    fact_id=str(material["fact_id"]),
                    fact_type=fact_type,
                    command_id=command_id,
                    actor_ref=actor_ref,
                    recorded_at=recorded_at,
                    payload=dict(sorted(payload.items())),
                    previous_digest=previous,
                    canonical_digest=canonical_digest(material),
                )
                projection = reduce_sandbox(current, fact)
                connection.execute(
                    """
                    INSERT INTO aegis.sandbox_facts (
                        tenant_id, execution_id, sequence, fact_id, fact_type,
                        command_id, actor_ref, fact_document, previous_digest,
                        fact_digest, recorded_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        tenant_id,
                        execution_id,
                        sequence,
                        fact.fact_id,
                        fact_type.value,
                        command_id,
                        actor_ref,
                        Jsonb(fact.model_dump(mode="json")),
                        previous,
                        fact.canonical_digest,
                        recorded_at,
                    ),
                )
                self._upsert_projection(connection, projection)
                return projection
        except (ConcurrencyConflict, IdempotencyConflict, IntegrityFailure):
            raise
        except ValidationError as exc:
            raise IntegrityFailure("stored sandbox state is invalid") from exc
        except Exception as exc:
            raise RepositoryUnavailable("sandbox fact append failed") from exc

    def projection(
        self,
        *,
        tenant_id: str,
        execution_id: str,
    ) -> SandboxProjection | None:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                return self._projection_row(
                    connection,
                    tenant_id=tenant_id,
                    execution_id=execution_id,
                    for_update=False,
                )
        except ValidationError as exc:
            raise IntegrityFailure("stored sandbox projection is invalid") from exc
        except IntegrityFailure:
            raise
        except Exception as exc:
            raise RepositoryUnavailable("sandbox projection read failed") from exc

    def facts(
        self,
        *,
        tenant_id: str,
        execution_id: str,
    ) -> tuple[SandboxFact, ...]:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                rows = connection.execute(
                    """
                    SELECT fact_document
                    FROM aegis.sandbox_facts
                    WHERE tenant_id = %s AND execution_id = %s
                    ORDER BY sequence
                    """,
                    (tenant_id, execution_id),
                ).fetchall()
                return tuple(
                    SandboxFact.model_validate(row["fact_document"]) for row in rows
                )
        except ValidationError as exc:
            raise IntegrityFailure("stored sandbox fact is invalid") from exc
        except IntegrityFailure:
            raise
        except Exception as exc:
            raise RepositoryUnavailable("sandbox fact read failed") from exc

    def rebuild(
        self,
        *,
        tenant_id: str,
        execution_id: str,
        rebuilt_at: datetime,
    ) -> SandboxProjection:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (f"sandbox:{tenant_id}:{execution_id}",),
                )
                request_row = connection.execute(
                    """
                    SELECT execution_id
                    FROM aegis.sandbox_requests
                    WHERE tenant_id = %s AND execution_id = %s
                    """,
                    (tenant_id, execution_id),
                ).fetchone()
                if request_row is None:
                    raise IntegrityFailure(
                        "cannot rebuild an unknown sandbox execution"
                    )
                rows = connection.execute(
                    """
                    SELECT fact_document
                    FROM aegis.sandbox_facts
                    WHERE tenant_id = %s AND execution_id = %s
                    ORDER BY sequence
                    """,
                    (tenant_id, execution_id),
                ).fetchall()
                facts = tuple(
                    SandboxFact.model_validate(row["fact_document"]) for row in rows
                )
                projection: SandboxProjection | None = None
                for fact in facts:
                    projection = reduce_sandbox(projection, fact)
                if projection is None:
                    raise IntegrityFailure(
                        "cannot rebuild an unknown sandbox execution"
                    )
                self._upsert_projection(connection, projection)
                source_digest = canonical_digest(facts)
                connection.execute(
                    """
                    INSERT INTO aegis.sandbox_projection_rebuilds (
                        tenant_id, rebuild_id, execution_id, source_fact_count,
                        source_digest, projection_digest, rebuilt_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        tenant_id,
                        stable_id(
                            "sandbox-rebuild",
                            tenant_id,
                            execution_id,
                            source_digest,
                            length=40,
                        ),
                        execution_id,
                        len(facts),
                        source_digest,
                        canonical_digest(projection),
                        rebuilt_at,
                    ),
                )
                return projection
        except ValidationError as exc:
            raise IntegrityFailure("stored sandbox fact is invalid") from exc
        except IntegrityFailure:
            raise
        except Exception as exc:
            raise RepositoryUnavailable("sandbox projection rebuild failed") from exc

    def put_artifact(self, artifact: ArtifactRecord, *, recorded_at: datetime) -> None:
        try:
            with tenant_transaction(
                self._pool,
                tenant_id=artifact.tenant_id,
            ) as connection:
                connection.execute(
                    """
                    INSERT INTO aegis.sandbox_artifacts (
                        tenant_id, artifact_id, run_id, task_id, execution_id,
                        logical_path, media_type, content_hash, size_bytes,
                        disposition, artifact_digest, artifact_document,
                        retention_expires_at, recorded_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s
                    )
                    ON CONFLICT (tenant_id, artifact_id) DO NOTHING
                    """,
                    (
                        artifact.tenant_id,
                        artifact.artifact_id,
                        artifact.run_id,
                        artifact.task_id,
                        artifact.execution_id,
                        artifact.logical_path,
                        artifact.media_type,
                        artifact.content_hash,
                        artifact.size_bytes,
                        artifact.disposition.value,
                        artifact.canonical_digest,
                        Jsonb(artifact.model_dump(mode="json")),
                        artifact.retention_expires_at,
                        recorded_at,
                    ),
                )
                row = connection.execute(
                    """
                    SELECT artifact_digest
                    FROM aegis.sandbox_artifacts
                    WHERE tenant_id = %s AND artifact_id = %s
                    """,
                    (artifact.tenant_id, artifact.artifact_id),
                ).fetchone()
                if row is None or row["artifact_digest"] != artifact.canonical_digest:
                    raise IdempotencyConflict("sandbox artifact replay changed")
        except IdempotencyConflict:
            raise
        except Exception as exc:
            raise RepositoryUnavailable("sandbox artifact persistence failed") from exc

    def artifacts(
        self,
        *,
        tenant_id: str,
        execution_id: str,
    ) -> tuple[ArtifactRecord, ...]:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                rows = connection.execute(
                    """
                    SELECT artifact_document
                    FROM aegis.sandbox_artifacts
                    WHERE tenant_id = %s AND execution_id = %s
                    ORDER BY logical_path
                    """,
                    (tenant_id, execution_id),
                ).fetchall()
                return tuple(
                    ArtifactRecord.model_validate(row["artifact_document"])
                    for row in rows
                )
        except ValidationError as exc:
            raise IntegrityFailure("stored sandbox artifact is invalid") from exc
        except IntegrityFailure:
            raise
        except Exception as exc:
            raise RepositoryUnavailable("sandbox artifact read failed") from exc

    @staticmethod
    def _projection_row(
        connection: DictConnection,
        *,
        tenant_id: str,
        execution_id: str,
        for_update: bool,
    ) -> SandboxProjection | None:
        query = (
            """
            SELECT tenant_id, execution_id, run_id, task_id, status, version,
                request_digest, spec_digest, policy_digest, approval_digest,
                fence_token, provider_uid, result_digest, manifest_digest,
                attestation_digest, cleanup_complete, last_fact_digest, updated_at
            FROM aegis.sandbox_projections
            WHERE tenant_id = %s AND execution_id = %s
            FOR UPDATE
            """
            if for_update
            else """
            SELECT tenant_id, execution_id, run_id, task_id, status, version,
                request_digest, spec_digest, policy_digest, approval_digest,
                fence_token, provider_uid, result_digest, manifest_digest,
                attestation_digest, cleanup_complete, last_fact_digest, updated_at
            FROM aegis.sandbox_projections
            WHERE tenant_id = %s AND execution_id = %s
            """
        )
        row = connection.execute(
            query,
            (tenant_id, execution_id),
        ).fetchone()
        return SandboxProjection.model_validate(row) if row is not None else None

    @staticmethod
    def _upsert_projection(
        connection: DictConnection,
        projection: SandboxProjection,
    ) -> None:
        connection.execute(
            """
            INSERT INTO aegis.sandbox_projections (
                tenant_id, execution_id, run_id, task_id, status, version,
                request_digest, spec_digest, policy_digest, approval_digest,
                fence_token, provider_uid, result_digest, manifest_digest,
                attestation_digest, cleanup_complete, last_fact_digest, updated_at
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s
            )
            ON CONFLICT (tenant_id, execution_id) DO UPDATE SET
                status = EXCLUDED.status,
                version = EXCLUDED.version,
                provider_uid = EXCLUDED.provider_uid,
                result_digest = EXCLUDED.result_digest,
                manifest_digest = EXCLUDED.manifest_digest,
                attestation_digest = EXCLUDED.attestation_digest,
                cleanup_complete = EXCLUDED.cleanup_complete,
                last_fact_digest = EXCLUDED.last_fact_digest,
                updated_at = EXCLUDED.updated_at
            """,
            (
                projection.tenant_id,
                projection.execution_id,
                projection.run_id,
                projection.task_id,
                projection.status.value,
                projection.version,
                projection.request_digest,
                projection.spec_digest,
                projection.policy_digest,
                projection.approval_digest,
                projection.fence_token,
                projection.provider_uid,
                projection.result_digest,
                projection.manifest_digest,
                projection.attestation_digest,
                projection.cleanup_complete,
                projection.last_fact_digest,
                projection.updated_at,
            ),
        )
