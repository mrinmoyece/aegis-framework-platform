"""PostgreSQL authority repositories and tenant-scoped LangGraph checkpoints."""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from langgraph.checkpoint.postgres import PostgresSaver
from psycopg import Connection, Error, IntegrityError, sql
from psycopg.pq import TransactionStatus
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from aegis_framework.access import (
    AuditEventView,
    GrantRecord,
    PolicyRecord,
    PrincipalRecord,
    QuotaRecord,
    SecretReference,
    TenantRecord,
)
from aegis_framework.checkpointing import strict_checkpoint_serializer
from aegis_framework.domain import (
    IdentityContext,
    InvestigationRequest,
    RiskLevel,
    stable_id,
)
from aegis_framework.errors import (
    AuditFailure,
    ConcurrencyConflict,
    IdempotencyConflict,
    MigrationFailure,
    OrchestrationFailure,
    RepositoryUnavailable,
)
from aegis_framework.graph import LangGraphInvestigator
from aegis_framework.ports import BudgetDecision, ClockPort, StructuredModelPort
from aegis_framework.safety import safe_audit_attributes

type DictConnection = Connection[dict[str, Any]]
type RuntimePool = ConnectionPool[DictConnection]

_ROOT = Path(__file__).resolve().parents[2]
_MIGRATION = _ROOT / "migrations/0001_layer2.sql"
_CHECKPOINT_TABLES = ("checkpoints", "checkpoint_blobs", "checkpoint_writes")


class MigrationRunner:
    """Apply exact migration content under the SQL advisory lock and verify drift."""

    def __init__(self, path: Path = _MIGRATION) -> None:
        self._path = path

    def apply(self, connection: DictConnection) -> None:
        script = self._path.read_text(encoding="utf-8")
        checksum = sha256(script.encode()).hexdigest()
        try:
            existing = connection.execute(
                """
                SELECT checksum
                FROM aegis.schema_migrations
                WHERE version = 1
                """
            ).fetchone()
        except Error:
            connection.rollback()
            existing = None
        if existing is not None:
            connection.rollback()
            if existing["checksum"] != checksum:
                raise MigrationFailure("applied Layer 2 migration checksum changed")
            return
        connection.rollback()
        try:
            connection.execute(script, prepare=False)
            connection.execute(
                """
                INSERT INTO aegis.schema_migrations (version, filename, checksum)
                VALUES (1, %s, %s)
                ON CONFLICT (version) DO NOTHING
                """,
                (self._path.name, checksum),
            )
            connection.commit()
            recorded = connection.execute(
                "SELECT checksum FROM aegis.schema_migrations WHERE version = 1"
            ).fetchone()
        except Error as exc:
            connection.rollback()
            raise MigrationFailure("Layer 2 migration failed") from exc
        if recorded is None or recorded["checksum"] != checksum:
            raise MigrationFailure("Layer 2 migration was not recorded safely")


def setup_postgres(*, admin_dsn: str) -> None:
    """Administrative setup is separate from the non-superuser runtime path."""

    try:
        with Connection.connect(
            admin_dsn,
            autocommit=False,
            prepare_threshold=0,
            row_factory=dict_row,
        ) as connection:
            MigrationRunner().apply(connection)
        with Connection.connect(
            admin_dsn,
            autocommit=True,
            prepare_threshold=0,
            row_factory=dict_row,
        ) as connection:
            PostgresSaver(
                connection,
                serde=strict_checkpoint_serializer(),
            ).setup()
            _secure_checkpoint_tables(connection)
    except MigrationFailure:
        raise
    except Error as exc:
        raise MigrationFailure("PostgreSQL setup failed") from exc


def _secure_checkpoint_tables(connection: DictConnection) -> None:
    for table in _CHECKPOINT_TABLES:
        policy = f"aegis_{table}_tenant_isolation"
        connection.execute(
            sql.SQL("ALTER TABLE public.{} ENABLE ROW LEVEL SECURITY").format(
                sql.Identifier(table)
            )
        )
        connection.execute(
            sql.SQL("ALTER TABLE public.{} FORCE ROW LEVEL SECURITY").format(
                sql.Identifier(table)
            )
        )
        connection.execute(
            sql.SQL("DROP POLICY IF EXISTS {} ON public.{}").format(
                sql.Identifier(policy), sql.Identifier(table)
            )
        )
        connection.execute(
            sql.SQL(
                """
            CREATE POLICY {} ON public.{}
            USING (
                EXISTS (
                    SELECT 1
                    FROM aegis.checkpoint_threads AS owner
                    WHERE owner.thread_ref = {}.thread_id
                      AND owner.tenant_id = aegis.current_tenant_id()
                )
            )
            WITH CHECK (
                EXISTS (
                    SELECT 1
                    FROM aegis.checkpoint_threads AS owner
                    WHERE owner.thread_ref = {}.thread_id
                      AND owner.tenant_id = aegis.current_tenant_id()
                )
            )
            """
            ).format(
                sql.Identifier(policy),
                sql.Identifier(table),
                sql.Identifier(table),
                sql.Identifier(table),
            )
        )
        connection.execute(
            sql.SQL(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON public.{} TO aegis_runtime"
            ).format(sql.Identifier(table))
        )
    connection.execute("GRANT SELECT ON public.checkpoint_migrations TO aegis_runtime")


def open_runtime_pool(
    *,
    dsn: str,
    minimum_size: int = 1,
    maximum_size: int = 10,
) -> RuntimePool:
    if minimum_size < 0 or maximum_size < 1 or minimum_size > maximum_size:
        raise ValueError("PostgreSQL pool bounds are invalid")
    pool: RuntimePool = ConnectionPool(
        conninfo=dsn,
        min_size=minimum_size,
        max_size=maximum_size,
        kwargs={
            "autocommit": False,
            "prepare_threshold": 0,
            "row_factory": dict_row,
        },
        configure=_configure_runtime_connection,
        reset=_reset_runtime_connection,
        open=False,
        name="aegis-runtime",
    )
    try:
        pool.open(wait=True)
    except Exception as exc:
        raise RepositoryUnavailable("PostgreSQL runtime pool failed to open") from exc
    return pool


def _configure_runtime_connection(connection: DictConnection) -> None:
    connection.execute("SET ROLE aegis_runtime")
    connection.execute("SET row_security = on")
    connection.execute("SET statement_timeout = '10s'")
    connection.execute("SET lock_timeout = '3s'")
    connection.execute("SET idle_in_transaction_session_timeout = '15s'")
    role = connection.execute(
        """
        SELECT rolsuper, rolbypassrls
        FROM pg_roles
        WHERE rolname = current_user
        """
    ).fetchone()
    row_security = connection.execute("SHOW row_security").fetchone()
    if (
        role is None
        or bool(role["rolsuper"])
        or bool(role["rolbypassrls"])
        or row_security is None
        or row_security["row_security"] != "on"
    ):
        raise RepositoryUnavailable("runtime database role can bypass tenant RLS")
    connection.commit()


def _reset_runtime_connection(connection: DictConnection) -> None:
    if connection.info.transaction_status is not TransactionStatus.IDLE:
        connection.rollback()
    leaked = connection.execute(
        "SELECT NULLIF(current_setting('aegis.tenant_id', true), '') AS tenant_id"
    ).fetchone()
    connection.rollback()
    if leaked is not None and leaked["tenant_id"] is not None:
        connection.execute("RESET aegis.tenant_id")
        connection.commit()
        raise RepositoryUnavailable("tenant context leaked across pool checkout")


@contextmanager
def tenant_transaction(
    pool: RuntimePool,
    *,
    tenant_id: str,
) -> Iterator[DictConnection]:
    """Set tenant context only for one transaction; SET LOCAL clears on exit."""

    try:
        with pool.connection() as connection:
            with connection.transaction():
                selected = connection.execute(
                    "SELECT set_config('aegis.tenant_id', %s, true) AS tenant_id",
                    (tenant_id,),
                ).fetchone()
                if selected is None or selected["tenant_id"] != tenant_id:
                    raise RepositoryUnavailable("tenant context was not established")
                yield connection
            leaked = connection.execute(
                """
                SELECT NULLIF(current_setting('aegis.tenant_id', true), '')
                    AS tenant_id
                """
            ).fetchone()
            connection.rollback()
            if leaked is not None and leaked["tenant_id"] is not None:
                raise RepositoryUnavailable("transaction tenant context did not reset")
    except RepositoryUnavailable:
        raise
    except Error as exc:
        raise RepositoryUnavailable("tenant database transaction failed") from exc


class PostgresRepository:
    """Application-owned identity, policy, quota, secret, and audit repository."""

    def __init__(self, *, pool: RuntimePool, clock: ClockPort) -> None:
        self._pool = pool
        self._clock = clock

    def ready(self) -> bool:
        try:
            with self._pool.connection() as connection:
                row = connection.execute(
                    """
                    SELECT
                        current_user = 'aegis_runtime'
                        AND current_setting('row_security') = 'on'
                        AND to_regclass('aegis.principals') IS NOT NULL
                        AND to_regclass('aegis.policies') IS NOT NULL
                        AND to_regclass('aegis.audit_events') IS NOT NULL
                        AND (
                            SELECT relforcerowsecurity
                            FROM pg_class
                            WHERE oid = 'aegis.audit_events'::regclass
                        ) AS ready
                    """
                ).fetchone()
                connection.rollback()
                return row is not None and row["ready"] == 1
        except (Error, RepositoryUnavailable):
            return False

    def resolve_principal(
        self,
        *,
        tenant_id: str,
        issuer: str,
        subject_id: str,
    ) -> PrincipalRecord | None:
        with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
            row = connection.execute(
                """
                SELECT tenant_id, issuer, subject_id, principal_kind, status,
                       grant_version, version
                FROM aegis.principals
                WHERE tenant_id = %s AND issuer = %s AND subject_id = %s
                """,
                (tenant_id, issuer, subject_id),
            ).fetchone()
        return PrincipalRecord.model_validate(row) if row is not None else None

    def active_grants(
        self,
        *,
        tenant_id: str,
        issuer: str,
        subject_id: str,
        now: datetime,
    ) -> Sequence[GrantRecord]:
        with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
            rows = connection.execute(
                """
                SELECT grant_id, tenant_id, issuer, subject_id, role, purpose,
                       risk_ceiling, status, expires_at, version
                FROM aegis.grants
                WHERE tenant_id = %s
                  AND issuer = %s
                  AND subject_id = %s
                  AND status = 'active'
                  AND expires_at > %s
                ORDER BY purpose, role, grant_id
                """,
                (tenant_id, issuer, subject_id, now),
            ).fetchall()
        return tuple(GrantRecord.model_validate(row) for row in rows)

    def get_tenant(self, *, tenant_id: str) -> TenantRecord | None:
        with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
            row = connection.execute(
                """
                SELECT tenant_id, display_name, status, version
                FROM aegis.tenants
                WHERE tenant_id = %s
                """,
                (tenant_id,),
            ).fetchone()
        return TenantRecord.model_validate(row) if row is not None else None

    def current_policy(self, *, tenant_id: str) -> PolicyRecord | None:
        with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
            row = connection.execute(
                """
                SELECT policy_id, tenant_id, revision, allowed_actions,
                       allowed_purposes, max_risk, version
                FROM aegis.policies
                WHERE tenant_id = %s
                ORDER BY revision DESC
                LIMIT 1
                """,
                (tenant_id,),
            ).fetchone()
        return PolicyRecord.model_validate(row) if row is not None else None

    def get_quota(self, *, tenant_id: str, quota_key: str) -> QuotaRecord | None:
        with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
            row = connection.execute(
                """
                SELECT tenant_id, quota_key, limit_units, used_units,
                       period_start, period_end, version
                FROM aegis.quotas
                WHERE tenant_id = %s AND quota_key = %s
                """,
                (tenant_id, quota_key),
            ).fetchone()
        return QuotaRecord.model_validate(row) if row is not None else None

    def get_secret_reference(
        self, *, tenant_id: str, name: str
    ) -> SecretReference | None:
        with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
            row = connection.execute(
                """
                SELECT tenant_id, name, provider, reference, version
                FROM aegis.secret_references
                WHERE tenant_id = %s AND name = %s
                """,
                (tenant_id, name),
            ).fetchone()
        return SecretReference.model_validate(row) if row is not None else None

    def replace_policy(
        self,
        *,
        policy: PolicyRecord,
        expected_version: int,
    ) -> PolicyRecord:
        with tenant_transaction(self._pool, tenant_id=policy.tenant_id) as connection:
            row = connection.execute(
                """
                UPDATE aegis.policies
                SET revision = %s,
                    allowed_actions = %s,
                    allowed_purposes = %s,
                    max_risk = %s,
                    version = version + 1,
                    updated_at = clock_timestamp()
                WHERE tenant_id = %s
                  AND policy_id = %s
                  AND version = %s
                RETURNING policy_id, tenant_id, revision, allowed_actions,
                          allowed_purposes, max_risk, version
                """,
                (
                    policy.revision,
                    list(policy.allowed_actions),
                    list(policy.allowed_purposes),
                    policy.max_risk.value,
                    policy.tenant_id,
                    policy.policy_id,
                    expected_version,
                ),
            ).fetchone()
            if row is None:
                raise ConcurrencyConflict("policy version changed")
        return PolicyRecord.model_validate(row)

    def replace_quota(
        self,
        *,
        quota: QuotaRecord,
        expected_version: int,
    ) -> QuotaRecord:
        with tenant_transaction(self._pool, tenant_id=quota.tenant_id) as connection:
            row = connection.execute(
                """
                UPDATE aegis.quotas
                SET limit_units = %s,
                    period_start = %s,
                    period_end = %s,
                    version = version + 1,
                    updated_at = clock_timestamp()
                WHERE tenant_id = %s
                  AND quota_key = %s
                  AND version = %s
                  AND used_units <= %s
                RETURNING tenant_id, quota_key, limit_units, used_units,
                          period_start, period_end, version
                """,
                (
                    quota.limit_units,
                    quota.period_start,
                    quota.period_end,
                    quota.tenant_id,
                    quota.quota_key,
                    expected_version,
                    quota.limit_units,
                ),
            ).fetchone()
            if row is None:
                raise ConcurrencyConflict(
                    "quota version changed or usage exceeds limit"
                )
        return QuotaRecord.model_validate(row)

    def reserve(
        self,
        identity: IdentityContext,
        *,
        reservation_id: str,
        units: int,
    ) -> BudgetDecision:
        if units <= 0:
            raise ValueError("budget reservation units must be positive")
        with tenant_transaction(self._pool, tenant_id=identity.tenant_id) as connection:
            connection.execute(
                """
                SELECT pg_advisory_xact_lock(
                    hashtextextended(
                        jsonb_build_array(%s::text, %s::text)::text,
                        0
                    )
                )
                """,
                (identity.tenant_id, reservation_id),
            )
            existing = connection.execute(
                """
                SELECT requested_units, allowed, remaining_units, reason
                FROM aegis.quota_reservations
                WHERE tenant_id = %s
                  AND quota_key = 'investigation-units'
                  AND reservation_id = %s
                """,
                (identity.tenant_id, reservation_id),
            ).fetchone()
            if existing is not None:
                if existing["requested_units"] != units:
                    raise IdempotencyConflict(
                        "quota reservation was reused with different units"
                    )
                return BudgetDecision(
                    allowed=existing["allowed"],
                    reservation_id=reservation_id,
                    requested_units=units,
                    remaining_units=existing["remaining_units"],
                    reason=existing["reason"],
                )
            quota = connection.execute(
                """
                SELECT limit_units, used_units
                FROM aegis.quotas
                WHERE tenant_id = %s
                  AND quota_key = 'investigation-units'
                  AND period_start <= %s
                  AND period_end > %s
                FOR UPDATE
                """,
                (identity.tenant_id, self._clock.now(), self._clock.now()),
            ).fetchone()
            if quota is None:
                raise RepositoryUnavailable("active investigation quota is missing")
            allowed = quota["used_units"] + units <= quota["limit_units"]
            remaining = (
                quota["limit_units"] - quota["used_units"] - units
                if allowed
                else quota["limit_units"] - quota["used_units"]
            )
            if allowed:
                connection.execute(
                    """
                    UPDATE aegis.quotas
                    SET used_units = used_units + %s,
                        version = version + 1,
                        updated_at = clock_timestamp()
                    WHERE tenant_id = %s AND quota_key = 'investigation-units'
                    """,
                    (units, identity.tenant_id),
                )
            reason = "reserved" if allowed else "tenant_budget_exhausted"
            try:
                connection.execute(
                    """
                    INSERT INTO aegis.quota_reservations (
                        tenant_id, quota_key, reservation_id, requested_units,
                        allowed, remaining_units, reason
                    )
                    VALUES (%s, 'investigation-units', %s, %s, %s, %s, %s)
                    """,
                    (
                        identity.tenant_id,
                        reservation_id,
                        units,
                        allowed,
                        remaining,
                        reason,
                    ),
                )
            except IntegrityError as exc:
                raise IdempotencyConflict("quota reservation raced") from exc
        return BudgetDecision(
            allowed=allowed,
            reservation_id=reservation_id,
            requested_units=units,
            remaining_units=remaining,
            reason=reason,
        )

    def append(
        self,
        *,
        identity: IdentityContext,
        event_type: str,
        attributes: Mapping[str, str | int | bool],
    ) -> None:
        recorded_at = self._clock.now()
        actor_ref = stable_id("actor", identity.issuer, identity.subject_id, length=32)
        safe_attributes = safe_audit_attributes(attributes)
        try:
            with tenant_transaction(
                self._pool, tenant_id=identity.tenant_id
            ) as connection:
                connection.execute(
                    """
                    INSERT INTO aegis.audit_heads (tenant_id)
                    VALUES (%s)
                    ON CONFLICT (tenant_id) DO NOTHING
                    """,
                    (identity.tenant_id,),
                )
                head = connection.execute(
                    """
                    SELECT last_sequence, last_hash
                    FROM aegis.audit_heads
                    WHERE tenant_id = %s
                    FOR UPDATE
                    """,
                    (identity.tenant_id,),
                ).fetchone()
                if head is None:
                    raise AuditFailure("tenant audit head is unavailable")
                sequence = head["last_sequence"] + 1
                event_id = stable_id(
                    "audit",
                    identity.tenant_id,
                    str(sequence),
                    event_type,
                    recorded_at.isoformat(),
                    length=32,
                )
                material = _audit_material(
                    tenant_id=identity.tenant_id,
                    sequence=sequence,
                    event_id=event_id,
                    event_type=event_type,
                    actor_ref=actor_ref,
                    principal_kind=identity.principal_kind.value,
                    recorded_at=recorded_at,
                    attributes=safe_attributes,
                    previous_hash=head["last_hash"],
                )
                record_hash = sha256(material.encode()).hexdigest()
                connection.execute(
                    """
                    INSERT INTO aegis.audit_events (
                        tenant_id, sequence, event_id, event_type, actor_ref,
                        principal_kind, recorded_at, attributes, previous_hash,
                        record_hash
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                    """,
                    (
                        identity.tenant_id,
                        sequence,
                        event_id,
                        event_type,
                        actor_ref,
                        identity.principal_kind.value,
                        recorded_at,
                        json.dumps(
                            safe_attributes, separators=(",", ":"), sort_keys=True
                        ),
                        head["last_hash"],
                        record_hash,
                    ),
                )
                connection.execute(
                    """
                    UPDATE aegis.audit_heads
                    SET last_sequence = %s, last_hash = %s
                    WHERE tenant_id = %s
                    """,
                    (sequence, record_hash, identity.tenant_id),
                )
        except AuditFailure:
            raise
        except RepositoryUnavailable as exc:
            raise AuditFailure("durable audit append failed") from exc

    def list_audit(
        self,
        *,
        identity: IdentityContext,
        limit: int,
    ) -> Sequence[AuditEventView]:
        if limit < 1 or limit > 100:
            raise ValueError("audit limit is outside the permitted range")
        with tenant_transaction(self._pool, tenant_id=identity.tenant_id) as connection:
            rows = connection.execute(
                """
                SELECT event_id, sequence, event_type, actor_ref, principal_kind,
                       recorded_at, attributes, previous_hash, record_hash
                FROM aegis.audit_events
                WHERE tenant_id = %s
                ORDER BY sequence DESC
                LIMIT %s
                """,
                (identity.tenant_id, limit),
            ).fetchall()
        return tuple(AuditEventView.model_validate(row) for row in reversed(rows))


class TenantPostgresOrchestrator:
    """Bind every saver call to an RLS transaction and registered thread owner."""

    def __init__(self, *, pool: RuntimePool, model: StructuredModelPort) -> None:
        self._pool = pool
        self._model = model

    def run(
        self,
        *,
        tenant_id: str,
        request: InvestigationRequest,
        request_id: str,
        thread_ref: str,
        evidence: Sequence[Any],
    ) -> Any:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                self._claim_thread(
                    connection, tenant_id=tenant_id, thread_ref=thread_ref
                )
                investigator = self._investigator(connection)
                return investigator.run(
                    tenant_id=tenant_id,
                    request=request,
                    request_id=request_id,
                    thread_ref=thread_ref,
                    evidence=evidence,
                )
        except RepositoryUnavailable as exc:
            raise OrchestrationFailure("tenant checkpoint transaction failed") from exc

    def checkpoint_count(self, *, tenant_id: str, thread_ref: str) -> int:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                owned = connection.execute(
                    """
                    SELECT 1
                    FROM aegis.checkpoint_threads
                    WHERE tenant_id = %s AND thread_ref = %s
                    """,
                    (tenant_id, thread_ref),
                ).fetchone()
                if owned is None:
                    return 0
                return self._investigator(connection).checkpoint_count(
                    tenant_id=tenant_id,
                    thread_ref=thread_ref,
                )
        except RepositoryUnavailable as exc:
            raise OrchestrationFailure("tenant checkpoint read failed") from exc

    @staticmethod
    def _claim_thread(
        connection: DictConnection,
        *,
        tenant_id: str,
        thread_ref: str,
    ) -> None:
        try:
            connection.execute(
                """
                INSERT INTO aegis.checkpoint_threads (tenant_id, thread_ref)
                VALUES (%s, %s)
                ON CONFLICT (tenant_id, thread_ref) DO NOTHING
                """,
                (tenant_id, thread_ref),
            )
        except IntegrityError as exc:
            raise OrchestrationFailure(
                "checkpoint thread belongs to another tenant"
            ) from exc

    def _investigator(self, connection: DictConnection) -> LangGraphInvestigator:
        return LangGraphInvestigator(
            model=self._model,
            checkpointer=PostgresSaver(
                connection,
                serde=strict_checkpoint_serializer(),
            ),
        )


def _audit_material(
    *,
    tenant_id: str,
    sequence: int,
    event_id: str,
    event_type: str,
    actor_ref: str,
    principal_kind: str,
    recorded_at: datetime,
    attributes: Mapping[str, str | int | bool],
    previous_hash: str,
) -> str:
    return json.dumps(
        {
            "actor_ref": actor_ref,
            "attributes": dict(sorted(attributes.items())),
            "event_id": event_id,
            "event_type": event_type,
            "previous_hash": previous_hash,
            "principal_kind": principal_kind,
            "recorded_at": recorded_at.isoformat(),
            "sequence": sequence,
            "tenant_id": tenant_id,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def risk_value(value: str) -> RiskLevel:
    """Expose strict conversion for repository tests and migration probes."""

    return RiskLevel(value)
