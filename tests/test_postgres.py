from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import pytest
from psycopg import Connection, Error
from psycopg.rows import dict_row

from aegis_framework.adapters import FixedClock
from aegis_framework.errors import OrchestrationFailure
from aegis_framework.fixtures import DEMO_TIME, demo_identity, demo_request
from aegis_framework.model import DeterministicStructuredModel
from aegis_framework.postgres import (
    PostgresRepository,
    RuntimePool,
    TenantPostgresOrchestrator,
    open_runtime_pool,
    setup_postgres,
    tenant_transaction,
)

_MIGRATION = Path("migrations/0001_layer2.sql")
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
