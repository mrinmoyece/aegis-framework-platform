from __future__ import annotations

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import pytest
from psycopg import Connection, Error
from psycopg.pq import TransactionStatus
from psycopg.rows import dict_row

from aegis_framework.activity_runtime import DurableActivityRuntime
from aegis_framework.adapters import FixedClock
from aegis_framework.authorization import EnterprisePolicy
from aegis_framework.domain import stable_id
from aegis_framework.durability import (
    CursorCodec,
    EventDraft,
    OutboxDraft,
    SignalCommand,
)
from aegis_framework.durable_postgres import (
    IdempotencyDraft,
    PostgresCurrentAuthority,
    PostgresDurability,
)
from aegis_framework.errors import (
    ConcurrencyConflict,
    OrchestrationFailure,
    RepositoryUnavailable,
)
from aegis_framework.fixtures import (
    DEMO_TIME,
    build_demo_bundle,
    demo_identity,
    demo_request,
)
from aegis_framework.model import DeterministicStructuredModel
from aegis_framework.postgres import (
    PostgresRepository,
    RuntimePool,
    TenantPostgresOrchestrator,
    _reset_runtime_connection,
    open_runtime_pool,
    setup_postgres,
    tenant_transaction,
)
from aegis_framework.references import TenantReferenceCodec
from aegis_framework.temporal import TemporalActivityInput

_MIGRATION = Path("migrations/0001_layer2.sql")
_LAYER3_MIGRATION = Path("migrations/0002_layer3.sql")
_TENANT_ALPHA = "test-tenant-alpha"
_TENANT_BETA = "test-tenant-beta"


def test_migration_declares_required_rls_indexes_roles_and_immutability() -> None:
    migration = _MIGRATION.read_text(encoding="utf-8")
    for table in (
        "tenants",
        "principals",
        "grants",
        "policies",
        "quotas",
        "quota_reservations",
        "secret_references",
        "audit_events",
        "checkpoint_threads",
    ):
        assert f"CREATE TABLE IF NOT EXISTS aegis.{table}" in migration
    assert "FORCE ROW LEVEL SECURITY" in migration
    assert "NOBYPASSRLS" in migration
    assert "NOSUPERUSER" in migration
    assert "aegis.current_tenant_id()" in migration
    assert "audit_events_immutable" in migration
    assert "REVOKE UPDATE, DELETE, TRUNCATE ON aegis.audit_events" in migration
    assert "grants_tenant_principal_active_idx" in migration
    assert "audit_events_tenant_recorded_idx" in migration
    assert "PASSWORD" not in migration
    layer3 = _LAYER3_MIGRATION.read_text(encoding="utf-8")
    for table in (
        "ledger_aggregate_heads",
        "ledger_tenant_cursors",
        "application_events",
        "durable_idempotency",
        "durable_actor_bindings",
        "inbox_messages",
        "outbox_messages",
        "projection_checkpoints",
        "investigation_runs",
        "investigation_timeline",
    ):
        assert f"CREATE TABLE IF NOT EXISTS aegis.{table}" in layer3
    assert "application_events_immutable" in layer3
    assert "inbox_messages_immutable" in layer3
    assert "FORCE ROW LEVEL SECURITY" in layer3
    assert "FOR UPDATE SKIP LOCKED" not in layer3
    assert "PASSWORD" not in layer3


def _integration_dsns() -> tuple[str, str]:
    admin = os.getenv("AEGIS_TEST_POSTGRES_ADMIN_DSN")
    runtime = os.getenv("AEGIS_TEST_POSTGRES_RUNTIME_DSN")
    if not admin or not runtime:
        pytest.skip("local PostgreSQL integration environment is not configured")
    return admin, runtime


def _prepare_database(admin_dsn: str) -> None:
    setup_postgres(admin_dsn=admin_dsn)
    with Connection.connect(
        admin_dsn,
        autocommit=True,
        prepare_threshold=0,
        row_factory=dict_row,
    ) as connection:
        for tenant_id in (_TENANT_ALPHA, _TENANT_BETA):
            connection.execute(
                """
                INSERT INTO aegis.tenants (
                    tenant_id, display_name, status, version
                )
                VALUES (%s, %s, 'active', 1)
                ON CONFLICT (tenant_id) DO UPDATE
                SET display_name = EXCLUDED.display_name,
                    status = 'active'
                """,
                (tenant_id, tenant_id),
            )
            connection.execute(
                """
                INSERT INTO aegis.policies (
                    tenant_id, policy_id, revision, allowed_actions,
                    allowed_purposes, max_risk, version
                )
                VALUES (
                    %s, 'policy-current', 1,
                    ARRAY['investigation:run', 'investigation:read',
                          'tenant:read', 'policy:read', 'quota:read',
                          'audit:read'],
                    ARRAY['incident-response'], 'medium', 1
                )
                ON CONFLICT (tenant_id, policy_id) DO UPDATE
                SET revision = 1,
                    allowed_actions = EXCLUDED.allowed_actions,
                    allowed_purposes = EXCLUDED.allowed_purposes,
                    max_risk = 'medium'
                """,
                (tenant_id,),
            )
            subject_id = (
                "responder-alpha" if tenant_id == _TENANT_ALPHA else "responder-beta"
            )
            connection.execute(
                """
                INSERT INTO aegis.principals (
                    tenant_id, issuer, subject_id, principal_kind,
                    status, grant_version, version
                )
                VALUES (
                    %s, 'https://demo.aegis.invalid', %s, 'human',
                    'active', 1, 1
                )
                ON CONFLICT (tenant_id, issuer, subject_id) DO UPDATE
                SET status = 'active', grant_version = 1
                """,
                (tenant_id, subject_id),
            )
            connection.execute(
                """
                INSERT INTO aegis.grants (
                    tenant_id, grant_id, issuer, subject_id, role, purpose,
                    risk_ceiling, status, expires_at, version
                )
                VALUES (
                    %s, 'grant-integration', 'https://demo.aegis.invalid', %s,
                    'incident-responder', 'incident-response', 'medium',
                    'active', %s, 1
                )
                ON CONFLICT (tenant_id, grant_id) DO UPDATE
                SET status = 'active', expires_at = EXCLUDED.expires_at,
                    revoked_at = NULL
                """,
                (tenant_id, subject_id, DEMO_TIME.replace(year=2027)),
            )
            connection.execute(
                """
                INSERT INTO aegis.quotas (
                    tenant_id, quota_key, limit_units, used_units,
                    period_start, period_end, version
                )
                VALUES (
                    %s, 'investigation-units', 5, 0,
                    %s, %s, 1
                )
                ON CONFLICT (tenant_id, quota_key) DO UPDATE
                SET limit_units = 5,
                    used_units = 0,
                    period_start = EXCLUDED.period_start,
                    period_end = EXCLUDED.period_end,
                    version = aegis.quotas.version + 1
                """,
                (
                    tenant_id,
                    DEMO_TIME,
                    DEMO_TIME.replace(year=2027),
                ),
            )
            connection.execute(
                "DELETE FROM aegis.quota_reservations WHERE tenant_id = %s",
                (tenant_id,),
            )


def _repository_context() -> tuple[str, RuntimePool, PostgresRepository]:
    admin_dsn, runtime_dsn = _integration_dsns()
    _prepare_database(admin_dsn)
    pool = open_runtime_pool(dsn=runtime_dsn, minimum_size=1, maximum_size=12)
    repository = PostgresRepository(pool=pool, clock=FixedClock(DEMO_TIME))
    return admin_dsn, pool, repository


class _FakeCursorResult:
    def __init__(self, row: dict[str, object] | None) -> None:
        self._row = row

    def fetchone(self) -> dict[str, object] | None:
        return self._row


class _FakeConnectionInfo:
    def __init__(self) -> None:
        self.transaction_status = TransactionStatus.IDLE


class _FakeConnection:
    def __init__(
        self,
        *,
        tenant_id: str | None = None,
        current_user: str = "aegis_runtime",
        row_security: str = "on",
    ) -> None:
        self.info = _FakeConnectionInfo()
        self._tenant_id = tenant_id
        self._current_user = current_user
        self._row_security = row_security
        self.rollbacks = 0
        self.commits = 0

    def execute(
        self, query: str, parameters: tuple[object, ...] | None = None
    ) -> _FakeCursorResult:
        del parameters
        if "current_setting('aegis.tenant_id'" in query:
            return _FakeCursorResult({"tenant_id": self._tenant_id})
        if query == "RESET aegis.tenant_id":
            self._tenant_id = None
            return _FakeCursorResult(None)
        if "SELECT current_user AS current_user" in query:
            return _FakeCursorResult(
                {
                    "current_user": self._current_user,
                    "rolsuper": False,
                    "rolbypassrls": False,
                }
            )
        if "session_rolsuper" in query:
            return _FakeCursorResult(
                {"session_rolsuper": False, "session_rolbypassrls": False}
            )
        if query == "SHOW row_security":
            return _FakeCursorResult({"row_security": self._row_security})
        raise AssertionError(f"unexpected query: {query}")

    def rollback(self) -> None:
        self.rollbacks += 1

    def commit(self) -> None:
        self.commits += 1


def test_pool_reset_detects_leaked_tenant_and_session_drift() -> None:
    leaked = _FakeConnection(tenant_id="tenant-acme")
    with pytest.raises(RepositoryUnavailable, match="tenant context leaked"):
        _reset_runtime_connection(leaked)  # pyright: ignore[reportArgumentType]
    assert leaked._tenant_id is None
    assert leaked.commits == 1

    drifted = _FakeConnection(row_security="off")
    with pytest.raises(RepositoryUnavailable, match="secure defaults"):
        _reset_runtime_connection(drifted)  # pyright: ignore[reportArgumentType]


@pytest.mark.postgres
def test_live_forced_rls_pool_reset_and_audit_immutability() -> None:
    admin_dsn, pool, repository = _repository_context()
    try:
        with tenant_transaction(pool, tenant_id=_TENANT_ALPHA) as connection:
            own = connection.execute(
                "SELECT tenant_id FROM aegis.tenants ORDER BY tenant_id"
            ).fetchall()
            assert [row["tenant_id"] for row in own] == [_TENANT_ALPHA]
        with pool.connection() as connection:
            context = connection.execute(
                """
                SELECT NULLIF(current_setting('aegis.tenant_id', true), '')
                    AS tenant_id
                """
            ).fetchone()
            connection.rollback()
            assert context is not None
            assert context["tenant_id"] is None
            rls = connection.execute(
                """
                SELECT relrowsecurity, relforcerowsecurity
                FROM pg_class
                WHERE oid = 'aegis.audit_events'::regclass
                """
            ).fetchone()
            connection.rollback()
            assert rls == {"relrowsecurity": True, "relforcerowsecurity": True}

        identity = demo_identity(tenant_id=_TENANT_ALPHA)
        repository.append(
            identity=identity,
            event_type="integration.audit",
            attributes={"request_ref": "request:integration"},
        )
        events = repository.list_audit(identity=identity, limit=10)
        assert events[-1].event_type == "integration.audit"
        with (
            Connection.connect(admin_dsn, autocommit=True) as admin,
            pytest.raises(Error, match="immutable"),
        ):
            admin.execute(
                """
                    UPDATE aegis.audit_events
                    SET event_type = 'integration.tampered'
                    WHERE tenant_id = %s AND event_id = %s
                    """,
                (_TENANT_ALPHA, events[-1].event_id),
            )
    finally:
        pool.close()


@pytest.mark.postgres
def test_live_quota_races_are_atomic_and_retry_idempotent() -> None:
    _, pool, repository = _repository_context()
    identity = demo_identity(tenant_id=_TENANT_ALPHA)
    try:

        def reserve(index: int) -> bool:
            return repository.reserve(
                identity,
                reservation_id=f"quota-race-{index}",
                units=1,
            ).allowed

        with ThreadPoolExecutor(max_workers=10) as executor:
            allowed = tuple(executor.map(reserve, range(10)))
        assert sum(allowed) == 5

        reservation = f"quota-retry-{uuid4().hex}"
        first = repository.reserve(
            demo_identity(tenant_id=_TENANT_BETA),
            reservation_id=reservation,
            units=2,
        )
        second = repository.reserve(
            demo_identity(tenant_id=_TENANT_BETA),
            reservation_id=reservation,
            units=2,
        )
        assert first == second
    finally:
        pool.close()


@pytest.mark.postgres
def test_live_checkpoint_rls_prevents_cross_tenant_reads_and_rebinding() -> None:
    _, pool, _ = _repository_context()
    orchestrator = TenantPostgresOrchestrator(
        pool=pool,
        model=DeterministicStructuredModel(),
    )
    thread_ref = f"thread:{uuid4().hex}"
    try:
        result = orchestrator.run(
            tenant_id=_TENANT_ALPHA,
            request=demo_request(),
            request_id="postgres-checkpoint",
            thread_ref=thread_ref,
            evidence=(),
        )
        assert result.status.value == "abstained"
        assert (
            orchestrator.checkpoint_count(
                tenant_id=_TENANT_ALPHA,
                thread_ref=thread_ref,
            )
            == 5
        )
        assert (
            orchestrator.checkpoint_count(
                tenant_id=_TENANT_BETA,
                thread_ref=thread_ref,
            )
            == 0
        )
        with pytest.raises(OrchestrationFailure, match="another tenant"):
            orchestrator.run(
                tenant_id=_TENANT_BETA,
                request=demo_request(),
                request_id="postgres-cross-tenant",
                thread_ref=thread_ref,
                evidence=(),
            )
    finally:
        pool.close()


@pytest.mark.postgres
def test_live_ledger_outbox_projection_rls_and_immutability() -> None:
    admin_dsn, pool, repository = _repository_context()
    tenant_references = TenantReferenceCodec(b"postgres-reference-key-test-00001")
    durability = PostgresDurability(
        pool=pool,
        clock=FixedClock(DEMO_TIME),
        tenant_references=tenant_references,
    )
    suffix = uuid4().hex
    run_id = f"run:{suffix}"
    event_id = f"event:{suffix}"
    outbox_id = f"outbox:{suffix}"
    request_id = f"request:{suffix}"
    try:
        appended = durability.append(
            tenant_id=_TENANT_ALPHA,
            aggregate_type="investigation",
            aggregate_id=run_id,
            expected_version=0,
            drafts=(
                EventDraft(
                    event_id=event_id,
                    event_type="investigation.requested",
                    occurred_at=DEMO_TIME,
                    actor_ref="actor:integration",
                    correlation_ref=request_id,
                    payload={
                        "incident_id": "incident:integration",
                        "request": demo_request(
                            incident_id="incident:integration"
                        ).model_dump(mode="json"),
                        "request_ref": request_id,
                        "run_id": run_id,
                        "tenant_ref": "tenant:opaque",
                        "wait_for_signal": False,
                        "workflow_id": f"workflow:{suffix}",
                    },
                ),
            ),
            outbox=(
                OutboxDraft(
                    message_id=outbox_id,
                    destination="temporal",
                    message_type="investigation.start",
                    available_at=DEMO_TIME,
                    payload={"run_id": run_id},
                ),
            ),
            idempotency=IdempotencyDraft(
                request_id=request_id,
                fingerprint="a" * 64,
            ),
        )
        assert appended[0].aggregate_sequence == 1
        assert durability.verify_integrity(tenant_id=_TENANT_ALPHA)
        assert (
            durability.rebuild_run(
                tenant_id=_TENANT_ALPHA,
                run_id=run_id,
            ).status.value
            == "queued"
        )
        with pytest.raises(ConcurrencyConflict):
            durability.append(
                tenant_id=_TENANT_ALPHA,
                aggregate_type="investigation",
                aggregate_id=run_id,
                expected_version=0,
                drafts=(
                    EventDraft(
                        event_id=f"event:stale:{suffix}",
                        event_type="investigation.started",
                        occurred_at=DEMO_TIME,
                        actor_ref="actor:integration",
                        correlation_ref=request_id,
                    ),
                ),
            )

        claims = durability.claim_outbox(
            tenant_id=_TENANT_ALPHA,
            worker_ref="worker:integration",
            now=DEMO_TIME,
            claim_until=DEMO_TIME.replace(year=2027),
            limit=10,
        )
        assert len(claims) == 1
        durability.complete_outbox(claims[0], now=DEMO_TIME)

        identity = demo_identity(
            tenant_id=_TENANT_ALPHA,
            subject_id="responder-alpha",
            request_id=f"durable:{suffix}",
        )
        durable_run = durability.accept_run(
            identity=identity,
            request=demo_request(incident_id=f"incident:{suffix}"),
            wait_for_signal=True,
        )
        replay = durability.accept_run(
            identity=identity,
            request=demo_request(incident_id=f"incident:{suffix}"),
            wait_for_signal=True,
        )
        assert replay.replayed
        assert replay.run_id == durable_run.run_id
        signal = durability.accept_signal(
            identity=identity,
            command=SignalCommand(
                command_id=f"resume:{suffix}",
                run_id=durable_run.run_id,
                command_type="resume",
            ),
        )
        assert signal.version == 2
        duplicate_signal = durability.accept_signal(
            identity=identity,
            command=SignalCommand(
                command_id=f"resume:{suffix}",
                run_id=durable_run.run_id,
                command_type="resume",
            ),
        )
        assert duplicate_signal.replayed
        timeline = durability.timeline(
            tenant_id=_TENANT_ALPHA,
            run_id=durable_run.run_id,
            after_cursor=0,
            limit=10,
            cursor_codec=CursorCodec(b"integration-cursor-signing-key-001"),
        )
        assert [item.event_type for item in timeline.items] == [
            "investigation.requested",
            "investigation.resume_requested",
        ]
        authority = PostgresCurrentAuthority(
            pool=pool,
            repository=PostgresRepository(
                pool=pool,
                clock=FixedClock(DEMO_TIME),
            ),
            clock=FixedClock(DEMO_TIME),
            tenant_references=tenant_references,
        )
        requested = durability.events(
            tenant_id=_TENANT_ALPHA,
            aggregate_type="investigation",
            aggregate_id=durable_run.run_id,
            limit=1,
        )[0]
        tenant_ref = requested.payload["tenant_ref"]
        assert isinstance(tenant_ref, str)
        assert authority.tenant_id(tenant_ref=tenant_ref) == _TENANT_ALPHA
        current = authority.identity(
            tenant_id=_TENANT_ALPHA,
            actor_ref=stable_id(
                "actor",
                identity.issuer,
                identity.subject_id,
                length=32,
            ),
            request_ref=durable_run.request_ref,
        )
        assert current is not None
        assert current.roles == ("incident-responder",)
        bundle = build_demo_bundle()
        runtime = DurableActivityRuntime(
            authority=authority,
            policy=EnterprisePolicy(
                policies=repository,
                clock=FixedClock(DEMO_TIME),
            ),
            budget=repository,
            evidence=bundle.service._evidence,
            orchestrator=bundle.orchestrator,
            store=durability,
        )
        authorized = asyncio.run(
            runtime.authorize(
                TemporalActivityInput(
                    tenant_ref=tenant_ref,
                    actor_ref=stable_id(
                        "actor",
                        identity.issuer,
                        identity.subject_id,
                        length=32,
                    ),
                    request_ref=durable_run.request_ref,
                    run_id=durable_run.run_id,
                    operation_id=f"authorize:{suffix}",
                )
            )
        )
        assert authorized.outcome == "authorized"
        with tenant_transaction(pool, tenant_id=_TENANT_BETA) as connection:
            hidden = connection.execute(
                """
                SELECT count(*) AS count
                FROM aegis.application_events
                WHERE event_id = %s
                """,
                (event_id,),
            ).fetchone()
            assert hidden == {"count": 0}
        with (
            Connection.connect(admin_dsn, autocommit=True) as admin,
            pytest.raises(Error, match="immutable"),
        ):
            admin.execute(
                """
                UPDATE aegis.application_events
                SET event_type = 'investigation.tampered'
                WHERE tenant_id = %s AND event_id = %s
                """,
                (_TENANT_ALPHA, event_id),
            )
    finally:
        pool.close()
