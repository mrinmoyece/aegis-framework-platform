"""PostgreSQL application ledger for governed orchestration facts."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from hashlib import sha256
from typing import cast

from psycopg import IntegrityError
from psycopg.types.json import Jsonb
from pydantic import JsonValue, ValidationError

from aegis_framework.domain import stable_id
from aegis_framework.errors import (
    IntegrityFailure,
    OrchestrationFailure,
    RepositoryUnavailable,
)
from aegis_framework.orchestration import (
    MAX_ARTIFACTS,
    AgentRole,
    ArtifactKind,
    ArtifactPage,
    ArtifactSummary,
    CoordinatorDecisionPayload,
    GovernanceArtifact,
    OrchestrationRunProjection,
    OrchestrationTerminalState,
    TaskDispatchClaim,
    TaskDispatchStatus,
    task_fence,
)
from aegis_framework.ports import ClockPort
from aegis_framework.postgres import RuntimePool, tenant_transaction


class PostgresOrchestrationLedger:
    """Persist dispatch and artifact facts independently of framework checkpoints."""

    def __init__(self, *, pool: RuntimePool, clock: ClockPort) -> None:
        self._pool = pool
        self._clock = clock

    def begin_run(
        self,
        *,
        tenant_id: str,
        incident_id: str,
        run_id: str,
        thread_ref: str,
        graph_version: str,
        input_digest: str,
    ) -> OrchestrationRunProjection:
        fence = stable_id(
            "fence", tenant_id, run_id, graph_version, input_digest, length=40
        )
        now = self._clock.now()
        document = {
            "graph_version": graph_version,
            "incident_id": incident_id,
            "input_digest": input_digest,
            "run_id": run_id,
            "thread_ref": thread_ref,
        }
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                inserted = connection.execute(
                    """
                    INSERT INTO aegis.orchestration_runs (
                        tenant_id, run_id, incident_id, thread_ref, graph_version,
                        input_digest, fence_token, status, artifact_count,
                        created_at, updated_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, 'running', 0, %s, %s)
                    ON CONFLICT (tenant_id, run_id) DO NOTHING
                    """,
                    (
                        tenant_id,
                        run_id,
                        incident_id,
                        thread_ref,
                        graph_version,
                        input_digest,
                        fence,
                        now,
                        now,
                    ),
                )
                created = inserted.rowcount == 1
                existing = connection.execute(
                    """
                    SELECT tenant_id, incident_id, run_id, thread_ref, graph_version,
                           input_digest, fence_token, status, cancelled, artifact_count
                    FROM aegis.orchestration_runs
                    WHERE tenant_id = %s AND run_id = %s
                    FOR UPDATE
                    """,
                    (tenant_id, run_id),
                ).fetchone()
                if existing is None:
                    raise IntegrityFailure("orchestration run intent was not persisted")
                if created:
                    self._insert_fact(
                        connection,
                        tenant_id=tenant_id,
                        run_id=run_id,
                        task_id=None,
                        fact_id=stable_id("fact", run_id, "run-intent", length=40),
                        fact_type="run.intent",
                        document=document,
                    )
                projection = _projection(existing)
                if (
                    projection.incident_id != incident_id
                    or projection.thread_ref != thread_ref
                    or projection.graph_version != graph_version
                    or projection.input_digest != input_digest
                ):
                    raise OrchestrationFailure("orchestration run binding changed")
                return projection
        except OrchestrationFailure:
            raise
        except IntegrityFailure:
            raise
        except IntegrityError as exc:
            raise IntegrityFailure("orchestration run/thread binding conflict") from exc
        except Exception as exc:
            raise RepositoryUnavailable(
                "orchestration run intent persistence failed"
            ) from exc

    def claim_task(
        self,
        *,
        tenant_id: str,
        run_id: str,
        task_id: str,
        role: AgentRole,
        input_digest: str,
    ) -> TaskDispatchClaim:
        initial_fence = task_fence(
            tenant_id=tenant_id,
            run_id=run_id,
            task_id=task_id,
            role=role,
            input_digest=input_digest,
            attempt=1,
        )
        now = self._clock.now()
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                run = connection.execute(
                    """
                    SELECT status, cancelled FROM aegis.orchestration_runs
                    WHERE tenant_id = %s AND run_id = %s
                    FOR UPDATE
                    """,
                    (tenant_id, run_id),
                ).fetchone()
                if run is None:
                    raise IntegrityFailure("orchestration run is unavailable")
                if bool(run["cancelled"]):
                    return TaskDispatchClaim(
                        status=TaskDispatchStatus.CANCELLED,
                        fence_token=initial_fence,
                    )
                existing = connection.execute(
                    """
                    SELECT role, input_digest, fence_token, attempt, status,
                           result_document
                    FROM aegis.orchestration_tasks
                    WHERE tenant_id = %s AND run_id = %s AND task_id = %s
                    FOR UPDATE
                    """,
                    (tenant_id, run_id, task_id),
                ).fetchone()
                if existing is None:
                    connection.execute(
                        """
                        INSERT INTO aegis.orchestration_tasks (
                            tenant_id, run_id, task_id, role, input_digest,
                            fence_token, attempt, status, updated_at
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, 1, 'started', %s)
                        """,
                        (
                            tenant_id,
                            run_id,
                            task_id,
                            role.value,
                            input_digest,
                            initial_fence,
                            now,
                        ),
                    )
                    self._insert_fact(
                        connection,
                        tenant_id=tenant_id,
                        run_id=run_id,
                        task_id=task_id,
                        fact_id=stable_id(
                            "fact", run_id, task_id, "dispatch", "1", length=40
                        ),
                        fact_type="task.dispatch",
                        document={
                            "attempt": 1,
                            "fence_token": initial_fence,
                            "input_digest": input_digest,
                            "role": role.value,
                            "status": TaskDispatchStatus.STARTED.value,
                            "task_id": task_id,
                        },
                    )
                    return TaskDispatchClaim(
                        status=TaskDispatchStatus.STARTED,
                        fence_token=initial_fence,
                    )
                if (
                    existing["role"] != role.value
                    or existing["input_digest"] != input_digest
                ):
                    raise IntegrityFailure("task dispatch binding changed")
                if existing["status"] == "completed":
                    result = existing["result_document"]
                    if not isinstance(result, dict):
                        raise IntegrityFailure("completed task result is malformed")
                    return TaskDispatchClaim(
                        status=TaskDispatchStatus.CACHED,
                        fence_token=str(existing["fence_token"]),
                        cached_result=cast(dict[str, JsonValue], result),
                    )
                if existing["status"] == "reconciliation_required":
                    return TaskDispatchClaim(
                        status=TaskDispatchStatus.RECONCILIATION_REQUIRED,
                        fence_token=str(existing["fence_token"]),
                    )
                attempt = int(existing["attempt"]) + 1
                fence = task_fence(
                    tenant_id=tenant_id,
                    run_id=run_id,
                    task_id=task_id,
                    role=role,
                    input_digest=input_digest,
                    attempt=attempt,
                )
                connection.execute(
                    """
                    UPDATE aegis.orchestration_tasks
                    SET status = 'reconciliation_required', fence_token = %s,
                        attempt = %s, updated_at = %s
                    WHERE tenant_id = %s AND run_id = %s AND task_id = %s
                    """,
                    (fence, attempt, now, tenant_id, run_id, task_id),
                )
                self._insert_fact(
                    connection,
                    tenant_id=tenant_id,
                    run_id=run_id,
                    task_id=task_id,
                    fact_id=stable_id(
                        "fact", run_id, task_id, "dispatch", str(attempt), length=40
                    ),
                    fact_type="task.fence_rotated",
                    document={
                        "attempt": attempt,
                        "fence_token": fence,
                        "input_digest": input_digest,
                        "role": role.value,
                        "status": TaskDispatchStatus.RECONCILIATION_REQUIRED.value,
                        "task_id": task_id,
                    },
                )
                return TaskDispatchClaim(
                    status=TaskDispatchStatus.RECONCILIATION_REQUIRED,
                    fence_token=fence,
                )
        except IntegrityFailure:
            raise
        except Exception as exc:
            raise RepositoryUnavailable("task dispatch persistence failed") from exc

    def complete_task(
        self,
        *,
        tenant_id: str,
        run_id: str,
        task_id: str,
        fence_token: str,
        result: Mapping[str, JsonValue],
    ) -> None:
        document = dict(result)
        digest = _digest(document)
        now = self._clock.now()
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                run = connection.execute(
                    """
                    SELECT status, cancelled FROM aegis.orchestration_runs
                    WHERE tenant_id = %s AND run_id = %s
                    FOR UPDATE
                    """,
                    (tenant_id, run_id),
                ).fetchone()
                if run is None or bool(run["cancelled"]):
                    raise IntegrityFailure("stale task result was rejected")
                task = connection.execute(
                    """
                    SELECT fence_token, status, result_digest
                    FROM aegis.orchestration_tasks
                    WHERE tenant_id = %s AND run_id = %s AND task_id = %s
                    FOR UPDATE
                    """,
                    (tenant_id, run_id, task_id),
                ).fetchone()
                if task is None or task["fence_token"] != fence_token:
                    raise IntegrityFailure("task result fence is stale")
                if task["status"] == "completed":
                    if task["result_digest"] != digest:
                        raise IntegrityFailure("completed task result changed")
                    return
                if task["status"] != "started":
                    raise IntegrityFailure("task result fence is stale")
                connection.execute(
                    """
                    UPDATE aegis.orchestration_tasks
                    SET status = 'completed', result_document = %s,
                        result_digest = %s, updated_at = %s
                    WHERE tenant_id = %s AND run_id = %s AND task_id = %s
                    """,
                    (Jsonb(document), digest, now, tenant_id, run_id, task_id),
                )
                self._insert_fact(
                    connection,
                    tenant_id=tenant_id,
                    run_id=run_id,
                    task_id=task_id,
                    fact_id=stable_id("fact", run_id, task_id, "result", length=40),
                    fact_type="task.result",
                    document={"result_digest": digest, "task_id": task_id},
                )
        except IntegrityFailure:
            raise
        except Exception as exc:
            raise RepositoryUnavailable("task result persistence failed") from exc

    def append_artifacts(
        self,
        *,
        tenant_id: str,
        run_id: str,
        fence_token: str,
        artifacts: Sequence[GovernanceArtifact],
    ) -> None:
        if len(artifacts) > MAX_ARTIFACTS:
            raise IntegrityFailure("artifact append exceeds run bound")
        now = self._clock.now()
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                run = connection.execute(
                    """
                    SELECT fence_token, status, cancelled
                    FROM aegis.orchestration_runs
                    WHERE tenant_id = %s AND run_id = %s
                    FOR UPDATE
                    """,
                    (tenant_id, run_id),
                ).fetchone()
                if (
                    run is None
                    or run["fence_token"] != fence_token
                    or bool(run["cancelled"])
                ):
                    raise IntegrityFailure("artifact fence is stale")
                decision: OrchestrationTerminalState | None = None
                for artifact in artifacts:
                    if artifact.tenant_id != tenant_id or artifact.run_id != run_id:
                        raise IntegrityFailure("artifact tenant/run binding mismatch")
                    document = artifact.model_dump(mode="json")
                    ordinal_owner = connection.execute(
                        """
                        SELECT artifact_id, canonical_digest
                        FROM aegis.orchestration_artifacts
                        WHERE tenant_id = %s AND run_id = %s AND ordinal = %s
                        """,
                        (tenant_id, run_id, artifact.ordinal),
                    ).fetchone()
                    if ordinal_owner is not None and (
                        ordinal_owner["artifact_id"] != artifact.artifact_id
                        or ordinal_owner["canonical_digest"]
                        != artifact.canonical_digest
                    ):
                        raise IntegrityFailure("artifact ordinal/digest conflict")
                    connection.execute(
                        """
                        INSERT INTO aegis.orchestration_artifacts (
                            tenant_id, run_id, artifact_id, task_id, ordinal,
                            artifact_kind, producer_role, schema_version,
                            artifact_document, canonical_digest, recorded_at
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (tenant_id, run_id, artifact_id) DO NOTHING
                        """,
                        (
                            tenant_id,
                            run_id,
                            artifact.artifact_id,
                            artifact.task_id,
                            artifact.ordinal,
                            artifact.payload.kind.value,
                            artifact.producer_role.value,
                            artifact.schema_version,
                            Jsonb(document),
                            artifact.canonical_digest,
                            now,
                        ),
                    )
                    stored = connection.execute(
                        """
                        SELECT canonical_digest
                        FROM aegis.orchestration_artifacts
                        WHERE tenant_id = %s AND run_id = %s AND artifact_id = %s
                        """,
                        (tenant_id, run_id, artifact.artifact_id),
                    ).fetchone()
                    if (
                        stored is None
                        or stored["canonical_digest"] != artifact.canonical_digest
                    ):
                        raise IntegrityFailure("immutable artifact changed")
                    fact_type = (
                        "decision.recorded"
                        if isinstance(artifact.payload, CoordinatorDecisionPayload)
                        else "artifact.recorded"
                    )
                    self._insert_fact(
                        connection,
                        tenant_id=tenant_id,
                        run_id=run_id,
                        task_id=artifact.task_id,
                        fact_id=stable_id(
                            "fact", run_id, artifact.artifact_id, length=40
                        ),
                        fact_type=fact_type,
                        document={
                            "artifact_digest": artifact.canonical_digest,
                            "artifact_id": artifact.artifact_id,
                            "artifact_kind": artifact.payload.kind.value,
                        },
                    )
                    if isinstance(artifact.payload, CoordinatorDecisionPayload):
                        decision = artifact.payload.decision
                count_row = connection.execute(
                    """
                    SELECT count(*) AS count
                    FROM aegis.orchestration_artifacts
                    WHERE tenant_id = %s AND run_id = %s
                    """,
                    (tenant_id, run_id),
                ).fetchone()
                count = int(count_row["count"]) if count_row is not None else 0
                if count > MAX_ARTIFACTS:
                    raise IntegrityFailure("artifact run bound exceeded")
                connection.execute(
                    """
                    UPDATE aegis.orchestration_runs
                    SET artifact_count = %s,
                        status = COALESCE(%s, status),
                        updated_at = %s
                    WHERE tenant_id = %s AND run_id = %s
                    """,
                    (
                        count,
                        decision.value if decision is not None else None,
                        now,
                        tenant_id,
                        run_id,
                    ),
                )
        except IntegrityFailure:
            raise
        except IntegrityError as exc:
            raise IntegrityFailure("artifact ordinal/digest conflict") from exc
        except Exception as exc:
            raise RepositoryUnavailable("artifact persistence failed") from exc

    def artifacts(
        self, *, tenant_id: str, run_id: str
    ) -> tuple[GovernanceArtifact, ...]:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                rows = connection.execute(
                    """
                    SELECT artifact_document
                    FROM aegis.orchestration_artifacts
                    WHERE tenant_id = %s AND run_id = %s
                    ORDER BY ordinal, artifact_id
                    """,
                    (tenant_id, run_id),
                ).fetchall()
            return tuple(
                GovernanceArtifact.model_validate(row["artifact_document"])
                for row in rows
            )
        except ValidationError as exc:
            raise IntegrityFailure(
                "stored orchestration artifact is malformed"
            ) from exc
        except Exception as exc:
            raise RepositoryUnavailable("artifact read failed") from exc

    def artifact_page(
        self,
        *,
        tenant_id: str,
        run_id: str,
        after_ordinal: int,
        limit: int,
    ) -> ArtifactPage:
        if after_ordinal < 0 or limit < 1 or limit > 100:
            raise ValueError("artifact page bounds are invalid")
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                run = connection.execute(
                    """
                    SELECT 1 FROM aegis.orchestration_runs
                    WHERE tenant_id = %s AND run_id = %s
                    """,
                    (tenant_id, run_id),
                ).fetchone()
                if run is None:
                    raise IntegrityFailure("orchestration run is unavailable")
                rows = connection.execute(
                    """
                    SELECT artifact_id, schema_version, ordinal, artifact_kind,
                           producer_role, task_id
                    FROM aegis.orchestration_artifacts
                    WHERE tenant_id = %s AND run_id = %s AND ordinal > %s
                    ORDER BY ordinal, artifact_id
                    LIMIT %s
                    """,
                    (tenant_id, run_id, after_ordinal, limit + 1),
                ).fetchall()
            page = rows[:limit]
            return ArtifactPage(
                items=tuple(
                    ArtifactSummary(
                        artifact_id=str(row["artifact_id"]),
                        schema_version=int(row["schema_version"]),
                        ordinal=int(row["ordinal"]),
                        kind=ArtifactKind(str(row["artifact_kind"])),
                        producer_role=AgentRole(str(row["producer_role"])),
                        task_id=(
                            str(row["task_id"]) if row["task_id"] is not None else None
                        ),
                    )
                    for row in page
                ),
                next_ordinal=(
                    int(page[-1]["ordinal"]) if len(rows) > limit and page else None
                ),
            )
        except IntegrityFailure:
            raise
        except Exception as exc:
            raise RepositoryUnavailable("artifact page read failed") from exc

    def projection(
        self, *, tenant_id: str, run_id: str
    ) -> OrchestrationRunProjection | None:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                row = connection.execute(
                    """
                    SELECT tenant_id, incident_id, run_id, thread_ref, graph_version,
                           input_digest, fence_token, status, cancelled, artifact_count
                    FROM aegis.orchestration_runs
                    WHERE tenant_id = %s AND run_id = %s
                    """,
                    (tenant_id, run_id),
                ).fetchone()
            return _projection(row) if row is not None else None
        except Exception as exc:
            raise RepositoryUnavailable("orchestration projection read failed") from exc

    def cancel(self, *, tenant_id: str, run_id: str) -> None:
        now = self._clock.now()
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                current = connection.execute(
                    """
                    SELECT status, cancelled
                    FROM aegis.orchestration_runs
                    WHERE tenant_id = %s AND run_id = %s
                    FOR UPDATE
                    """,
                    (tenant_id, run_id),
                ).fetchone()
                if current is None:
                    raise IntegrityFailure("orchestration run is unavailable")
                if bool(current["cancelled"]):
                    return
                connection.execute(
                    """
                    UPDATE aegis.orchestration_runs
                    SET cancelled = true, updated_at = %s
                    WHERE tenant_id = %s AND run_id = %s
                    """,
                    (now, tenant_id, run_id),
                )
                connection.execute(
                    """
                    UPDATE aegis.orchestration_tasks
                    SET status = CASE
                            WHEN status = 'completed' THEN status
                            ELSE 'cancelled'
                        END,
                        updated_at = %s
                    WHERE tenant_id = %s AND run_id = %s
                    """,
                    (now, tenant_id, run_id),
                )
                self._insert_fact(
                    connection,
                    tenant_id=tenant_id,
                    run_id=run_id,
                    task_id=None,
                    fact_id=stable_id("fact", run_id, "run-cancelled", length=40),
                    fact_type="run.cancelled",
                    document={"run_id": run_id, "status": "cancelled"},
                )
        except IntegrityFailure:
            raise
        except Exception as exc:
            raise RepositoryUnavailable(
                "orchestration cancellation persistence failed"
            ) from exc

    def rebuild_projection(
        self, *, tenant_id: str, run_id: str
    ) -> OrchestrationRunProjection:
        now = self._clock.now()
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                # Read artifacts inside the same transaction to prevent a TOCTOU race
                # where a new artifact is appended between reading and updating.
                artifact_rows = connection.execute(
                    """
                    SELECT artifact_document
                    FROM aegis.orchestration_artifacts
                    WHERE tenant_id = %s AND run_id = %s
                    ORDER BY ordinal, artifact_id
                    """,
                    (tenant_id, run_id),
                ).fetchall()
                try:
                    artifacts = tuple(
                        GovernanceArtifact.model_validate(row["artifact_document"])
                        for row in artifact_rows
                    )
                except ValidationError as exc:
                    raise IntegrityFailure(
                        "stored orchestration artifact is malformed"
                    ) from exc
                decision = next(
                    (
                        artifact.payload.decision
                        for artifact in reversed(artifacts)
                        if isinstance(artifact.payload, CoordinatorDecisionPayload)
                    ),
                    None,
                )
                source_digest = _digest(
                    {
                        "artifacts": [
                            artifact.canonical_digest for artifact in artifacts
                        ],
                        "decision": decision.value if decision is not None else None,
                    }
                )
                connection.execute(
                    """
                    UPDATE aegis.orchestration_runs
                    SET artifact_count = %s, status = COALESCE(%s, status),
                        updated_at = %s
                    WHERE tenant_id = %s AND run_id = %s
                    """,
                    (
                        len(artifacts),
                        decision.value if decision is not None else None,
                        now,
                        tenant_id,
                        run_id,
                    ),
                )
                rebuild_id = stable_id("rebuild", run_id, source_digest, length=40)
                connection.execute(
                    """
                    INSERT INTO aegis.orchestration_projection_rebuilds (
                        tenant_id, run_id, rebuild_id, artifact_count, decision,
                        source_digest, rebuilt_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (tenant_id, rebuild_id) DO NOTHING
                    """,
                    (
                        tenant_id,
                        run_id,
                        rebuild_id,
                        len(artifacts),
                        decision.value if decision is not None else None,
                        source_digest,
                        now,
                    ),
                )
                self._insert_fact(
                    connection,
                    tenant_id=tenant_id,
                    run_id=run_id,
                    task_id=None,
                    fact_id=stable_id(
                        "fact", run_id, "projection-rebuilt", source_digest, length=40
                    ),
                    fact_type="projection.rebuilt",
                    document={
                        "artifact_count": len(artifacts),
                        "source_digest": source_digest,
                    },
                )
            projection = self.projection(tenant_id=tenant_id, run_id=run_id)
            if projection is None:
                raise IntegrityFailure("orchestration projection is unavailable")
            return projection
        except IntegrityFailure:
            raise
        except Exception as exc:
            raise RepositoryUnavailable(
                "orchestration projection rebuild failed"
            ) from exc

    def _insert_fact(
        self,
        connection: object,
        *,
        tenant_id: str,
        run_id: str,
        task_id: str | None,
        fact_id: str,
        fact_type: str,
        document: Mapping[str, JsonValue],
    ) -> None:
        from aegis_framework.postgres import DictConnection

        typed = cast(DictConnection, connection)
        digest = _digest(document)
        typed.execute(
            """
            INSERT INTO aegis.orchestration_facts (
                tenant_id, fact_id, run_id, task_id, fact_type, schema_version,
                document, canonical_digest, recorded_at
            )
            VALUES (%s, %s, %s, %s, %s, 1, %s, %s, %s)
            ON CONFLICT (tenant_id, fact_id) DO NOTHING
            """,
            (
                tenant_id,
                fact_id,
                run_id,
                task_id,
                fact_type,
                Jsonb(dict(document)),
                digest,
                self._clock.now(),
            ),
        )
        row = typed.execute(
            """
            SELECT canonical_digest
            FROM aegis.orchestration_facts
            WHERE tenant_id = %s AND fact_id = %s
            """,
            (tenant_id, fact_id),
        ).fetchone()
        if row is None or row["canonical_digest"] != digest:
            raise IntegrityFailure("immutable orchestration fact changed")


def _projection(row: Mapping[str, object]) -> OrchestrationRunProjection:
    status = str(row["status"])
    decision = (
        OrchestrationTerminalState(status)
        if status not in {"running", "cancelled"}
        else None
    )
    return OrchestrationRunProjection(
        tenant_id=str(row["tenant_id"]),
        incident_id=str(row["incident_id"]),
        run_id=str(row["run_id"]),
        thread_ref=str(row["thread_ref"]),
        graph_version=str(row["graph_version"]),
        input_digest=str(row["input_digest"]),
        fence_token=str(row["fence_token"]),
        artifact_count=int(str(row["artifact_count"])),
        cancelled=bool(row["cancelled"]) or status == "cancelled",
        decision=decision,
    )


def _digest(value: Mapping[str, JsonValue]) -> str:
    return sha256(
        json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()
