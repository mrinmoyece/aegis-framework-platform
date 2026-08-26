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
from aegis_framework.domain import RiskLevel, stable_id
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
    IntegrityFailure,
    OrchestrationFailure,
    PolicyDenied,
    RepositoryUnavailable,
)
from aegis_framework.fixtures import (
    DEMO_TIME,
    build_demo_bundle,
    demo_identity,
    demo_request,
)
from aegis_framework.model import DeterministicStructuredModel
from aegis_framework.model_gateway import (
    BillingDisposition,
    CredentialReference,
    DataClassification,
    ModelCallBinding,
    ModelCapability,
    ModelCatalogEntry,
    ModelFinishReason,
    ModelMessage,
    ModelPrice,
    ModelProvider,
    ModelRequest,
    ModelRole,
    ModelRoute,
    ModelUsage,
    TenantModelPolicy,
    TextContent,
)
from aegis_framework.model_postgres import PostgresModelControlStore
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
_LAYER4_MIGRATION = Path("migrations/0003_layer4.sql")
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
    layer4 = _LAYER4_MIGRATION.read_text(encoding="utf-8")
    for table in (
        "model_policies",
        "model_catalog",
        "model_budgets",
        "model_reservations",
        "model_reservation_settlements",
        "model_call_events",
        "model_usage_projection",
        "provider_health_projection",
    ):
        assert f"CREATE TABLE IF NOT EXISTS aegis.{table}" in layer4
    assert "model_call_events_immutable" in layer4
    assert "model_reservations_immutable" in layer4
    assert "model_reservation_settlements_immutable" in layer4
    assert "aegis-layer4-schema" in layer4
    assert "FORCE ROW LEVEL SECURITY" in layer4
    assert "PASSWORD" not in layer4


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


def _seed_model_control(
    admin_dsn: str,
    *,
    tenant_id: str = _TENANT_ALPHA,
) -> tuple[TenantModelPolicy, ModelCatalogEntry]:
    """Insert a model policy and catalog entry for integration tests."""
    entry = ModelCatalogEntry(
        tenant_id=tenant_id,
        provider=ModelProvider.FAKE,
        model="model-a",
        region="eu-west-1",
        capabilities=frozenset({ModelCapability.JSON_SCHEMA}),
        context_tokens=8_192,
        maximum_output_tokens=1_024,
        tokenizer=None,
        tokenizer_limitations="Conservative estimate.",
        usage_limitations="Provider-reported after settlement.",
        price=ModelPrice(
            version="price-model-a-v1",
            currency="USD",
            input_microunits_per_million_tokens=2_000,
            output_microunits_per_million_tokens=4_000,
            cache_read_microunits_per_million_tokens=500,
            cache_write_microunits_per_million_tokens=1_000,
        ),
        credential=CredentialReference(reference="secret:fake-model-a", version=1),
        enabled=True,
    )
    policy = TenantModelPolicy(
        tenant_id=tenant_id,
        policy_id="model-policy-alpha",
        revision=1,
        allowed_providers=frozenset({ModelProvider.FAKE}),
        allowed_models=frozenset({"model-a"}),
        allowed_regions=frozenset({"eu-west-1"}),
        allowed_data_classifications=frozenset({DataClassification.INTERNAL}),
        allowed_purposes=frozenset({"incident-response"}),
        required_capabilities=frozenset({ModelCapability.JSON_SCHEMA}),
        risk_ceiling=RiskLevel.MEDIUM,
        routes=(
            ModelRoute(
                provider=ModelProvider.FAKE,
                model="model-a",
                region="eu-west-1",
                priority=1,
            ),
        ),
        maximum_input_tokens=4_096,
        maximum_output_tokens=1_024,
        maximum_cost_microunits=100_000,
        maximum_calls_per_run=5,
        repair_attempts=1,
        fallback_on_ambiguous_billing=False,
    )
    with Connection.connect(admin_dsn, autocommit=True) as admin:
        admin.execute(
            """
            INSERT INTO aegis.model_catalog
                (tenant_id, provider, model, region, document, enabled)
            VALUES (%s, %s, %s, %s, %s::jsonb, true)
            ON CONFLICT (tenant_id, provider, model, region) DO UPDATE
                SET document = EXCLUDED.document, enabled = true
            """,
            (
                tenant_id,
                entry.provider.value,
                entry.model,
                entry.region,
                entry.model_dump_json(),
            ),
        )
        admin.execute(
            """
            INSERT INTO aegis.model_policies
                (tenant_id, policy_id, revision, document, active)
            VALUES (%s, %s, %s, %s::jsonb, true)
            ON CONFLICT (tenant_id) WHERE active DO UPDATE
                SET policy_id = EXCLUDED.policy_id,
                    revision = EXCLUDED.revision,
                    document = EXCLUDED.document,
                    active = true
            """,
            (tenant_id, policy.policy_id, policy.revision, policy.model_dump_json()),
        )
        admin.execute(
            """
            INSERT INTO aegis.model_budgets
                (tenant_id, limit_microunits, reserved_microunits,
                 reconciled_microunits, version)
            VALUES (%s, 100000, 0, 0, 1)
            ON CONFLICT (tenant_id) DO UPDATE
                SET limit_microunits = EXCLUDED.limit_microunits,
                    reserved_microunits = 0,
                    reconciled_microunits = 0,
                    version = aegis.model_budgets.version + 1
            """,
            (tenant_id,),
        )
    return policy, entry


def _model_request(
    call_id: str,
    *,
    tenant_id: str = _TENANT_ALPHA,
    run_id: str = "run:one",
    purpose: str = "incident-response",
) -> ModelRequest:
    return ModelRequest(
        binding=ModelCallBinding(
            tenant_id=tenant_id,
            run_id=run_id,
            call_id=call_id,
            purpose=purpose,
            data_classification=DataClassification.INTERNAL,
            risk=RiskLevel.MEDIUM,
        ),
        messages=(
            ModelMessage(
                role=ModelRole.USER,
                content=(TextContent(text="Analyze the evidence."),),
            ),
        ),
        max_output_tokens=100,
        tools=(),
        allowed_tool_names=(),
        structured_output=None,
    )


@pytest.mark.postgres
def test_live_model_reservation_reconciliation_rls_and_rebuild() -> None:
    admin_dsn, pool, _ = _repository_context()
    policy, entry = _seed_model_control(admin_dsn)
    control = PostgresModelControlStore(pool=pool)
    suffix = uuid4().hex
    run_id = f"run:model-race-{suffix}"
    try:
        assert control.current_policy(tenant_id=_TENANT_ALPHA) == policy
        assert control.catalog_entry(tenant_id=_TENANT_ALPHA, key=entry.key) == entry

        def reserve(index: int) -> bool:
            try:
                control.reserve(
                    request=_model_request(
                        f"call:model-race-{suffix}-{index}",
                        run_id=run_id,
                    ),
                    policy=policy,
                    maximum_input_tokens=100,
                    maximum_cost_microunits=1,
                    now=DEMO_TIME,
                )
            except PolicyDenied:
                return False
            return True

        with ThreadPoolExecutor(max_workers=10) as executor:
            allowed = tuple(executor.map(reserve, range(10)))
        assert sum(allowed) == 5

        with Connection.connect(admin_dsn, autocommit=True) as admin:
            expected_reserved = admin.execute(
                """
                SELECT COALESCE(sum(CASE
                    WHEN settlement.reservation_id IS NULL
                        THEN reservation.reserved_cost_microunits
                    WHEN settlement.ambiguous_billing
                         AND EXISTS (
                             SELECT 1
                             FROM aegis.model_call_events AS ambiguous
                             WHERE ambiguous.tenant_id =
                                    reservation.tenant_id
                               AND ambiguous.call_id =
                                    reservation.reservation_id
                               AND ambiguous.event_type = 'settled'
                               AND ambiguous.record->>'billing' = 'ambiguous'
                               AND NOT EXISTS (
                                   SELECT 1
                                   FROM aegis.model_call_events AS correction
                                   WHERE correction.tenant_id =
                                            ambiguous.tenant_id
                                     AND correction.attempt_id =
                                            ambiguous.attempt_id
                                     AND correction.event_type = 'corrected'
                               )
                         )
                        THEN greatest(
                            reservation.reserved_cost_microunits
                            - settlement.billed_cost_microunits,
                            0
                        )
                    ELSE 0
                END), 0)
                FROM aegis.model_reservations AS reservation
                LEFT JOIN aegis.model_reservation_settlements AS settlement
                  ON settlement.tenant_id = reservation.tenant_id
                 AND settlement.reservation_id = reservation.reservation_id
                WHERE reservation.tenant_id = %s
                """,
                (_TENANT_ALPHA,),
            ).fetchone()
            admin.execute(
                """
                UPDATE aegis.model_budgets
                SET limit_microunits = 10,
                    reserved_microunits = 0,
                    reconciled_microunits = 0,
                    version = version + 1
                WHERE tenant_id = %s
                """,
                (_TENANT_ALPHA,),
            )

        call_id = f"call:model-crash-{suffix}"
        request = _model_request(call_id, run_id=f"run:model-crash-{suffix}")
        reservation = control.reserve(
            request=request,
            policy=policy,
            maximum_input_tokens=100,
            maximum_cost_microunits=2,
            now=DEMO_TIME,
        )
        attempt_id = f"{call_id}:r1:a1"
        control.append_requested(
            reservation=reservation,
            request=request,
            entry=entry,
            attempt_id=attempt_id,
            now=DEMO_TIME,
        )
        pending = control.usage(
            tenant_id=_TENANT_ALPHA,
            run_id=request.binding.run_id,
        )
        assert pending.call_count == 1
        assert pending.ambiguous_cost_microunits == 2

        usage = ModelUsage(
            input_tokens=10,
            output_tokens=2,
            provider_reported=True,
        )
        settled = control.reconcile(
            tenant_id=_TENANT_ALPHA,
            attempt_id=attempt_id,
            outcome=ModelFinishReason.STOP.value,
            billing=BillingDisposition.BILLED,
            usage=usage,
            cost_microunits=1,
            error_code=None,
            now=DEMO_TIME,
        )
        assert (
            control.reconcile(
                tenant_id=_TENANT_ALPHA,
                attempt_id=attempt_id,
                outcome=ModelFinishReason.STOP.value,
                billing=BillingDisposition.BILLED,
                usage=usage,
                cost_microunits=1,
                error_code=None,
                now=DEMO_TIME,
            )
            == settled
        )
        control.finalize(reservation=reservation, now=DEMO_TIME)
        reconciled = control.usage(
            tenant_id=_TENANT_ALPHA,
            run_id=request.binding.run_id,
        )
        assert reconciled.reconciled_cost_microunits == 1
        assert reconciled.ambiguous_cost_microunits == 0
        assert reconciled.input_tokens == 10
        with Connection.connect(admin_dsn, autocommit=True) as admin:
            budget = admin.execute(
                """
                SELECT reserved_microunits, reconciled_microunits
                FROM aegis.model_budgets
                WHERE tenant_id = %s
                """,
                (_TENANT_ALPHA,),
            ).fetchone()
        assert budget == (0, 1)
        assert control.health(tenant_id=_TENANT_ALPHA)[0].status == "healthy"
        assert (
            control.usage(
                tenant_id=_TENANT_BETA,
                run_id=request.binding.run_id,
            ).call_count
            == 0
        )

        ambiguous_call = f"call:model-ambiguous-{suffix}"
        ambiguous_request = _model_request(
            ambiguous_call,
            run_id=f"run:model-ambiguous-{suffix}",
        )
        ambiguous_reservation = control.reserve(
            request=ambiguous_request,
            policy=policy,
            maximum_input_tokens=100,
            maximum_cost_microunits=2,
            now=DEMO_TIME,
        )
        ambiguous_attempt = f"{ambiguous_call}:r1:a1"
        second_ambiguous_attempt = f"{ambiguous_call}:r2:a1"
        control.append_requested(
            reservation=ambiguous_reservation,
            request=ambiguous_request,
            entry=entry,
            attempt_id=ambiguous_attempt,
            now=DEMO_TIME,
        )
        control.append_requested(
            reservation=ambiguous_reservation,
            request=ambiguous_request,
            entry=entry,
            attempt_id=second_ambiguous_attempt,
            now=DEMO_TIME,
        )
        with pytest.raises(IntegrityFailure, match="pending"):
            control.finalize(
                reservation=ambiguous_reservation,
                now=DEMO_TIME,
            )
        control.reconcile(
            tenant_id=_TENANT_ALPHA,
            attempt_id=ambiguous_attempt,
            outcome="timeout",
            billing=BillingDisposition.AMBIGUOUS,
            usage=None,
            cost_microunits=None,
            error_code=None,
            now=DEMO_TIME,
        )
        control.reconcile(
            tenant_id=_TENANT_ALPHA,
            attempt_id=second_ambiguous_attempt,
            outcome="timeout",
            billing=BillingDisposition.AMBIGUOUS,
            usage=None,
            cost_microunits=None,
            error_code=None,
            now=DEMO_TIME,
        )
        control.finalize(
            reservation=ambiguous_reservation,
            now=DEMO_TIME,
        )
        corrected = control.reconcile(
            tenant_id=_TENANT_ALPHA,
            attempt_id=ambiguous_attempt,
            outcome=ModelFinishReason.STOP.value,
            billing=BillingDisposition.BILLED,
            usage=usage,
            cost_microunits=1,
            error_code=None,
            now=DEMO_TIME,
        )
        assert corrected.billing is BillingDisposition.BILLED
        with Connection.connect(admin_dsn, autocommit=True) as admin:
            partially_corrected_budget = admin.execute(
                """
                SELECT reserved_microunits
                FROM aegis.model_budgets
                WHERE tenant_id = %s
                """,
                (_TENANT_ALPHA,),
            ).fetchone()
        assert partially_corrected_budget == (1,)
        control.reconcile(
            tenant_id=_TENANT_ALPHA,
            attempt_id=second_ambiguous_attempt,
            outcome="not_billed",
            billing=BillingDisposition.NOT_BILLED,
            usage=None,
            cost_microunits=None,
            error_code=None,
            now=DEMO_TIME,
        )
        corrected_usage = control.usage(
            tenant_id=_TENANT_ALPHA,
            run_id=ambiguous_request.binding.run_id,
        )
        assert corrected_usage.reconciled_cost_microunits == 1
        assert corrected_usage.ambiguous_cost_microunits == 0
        with Connection.connect(admin_dsn, autocommit=True) as admin:
            fully_corrected_budget = admin.execute(
                """
                SELECT reserved_microunits
                FROM aegis.model_budgets
                WHERE tenant_id = %s
                """,
                (_TENANT_ALPHA,),
            ).fetchone()
        assert fully_corrected_budget == (0,)

        with Connection.connect(admin_dsn, autocommit=True) as admin:
            admin.execute(
                """
                UPDATE aegis.model_usage_projection
                SET reconciled_cost_microunits = 999
                WHERE tenant_id = %s AND run_id = %s
                """,
                (_TENANT_ALPHA, request.binding.run_id),
            )
            admin.execute(
                """
                UPDATE aegis.model_budgets
                SET reserved_microunits = 999
                WHERE tenant_id = %s
                """,
                (_TENANT_ALPHA,),
            )
        control.rebuild_projections(tenant_id=_TENANT_ALPHA)
        rebuilt = control.usage(
            tenant_id=_TENANT_ALPHA,
            run_id=request.binding.run_id,
        )
        assert rebuilt.reconciled_cost_microunits == 1
        with Connection.connect(admin_dsn, autocommit=True) as admin:
            rebuilt_budget = admin.execute(
                """
                SELECT reserved_microunits
                FROM aegis.model_budgets
                WHERE tenant_id = %s
                """,
                (_TENANT_ALPHA,),
            ).fetchone()
        assert rebuilt_budget == expected_reserved

        with (
            Connection.connect(admin_dsn, autocommit=True) as admin,
            pytest.raises(Error, match="immutable"),
        ):
            admin.execute(
                """
                UPDATE aegis.model_call_events
                SET event_type = 'settled'
                WHERE tenant_id = %s AND attempt_id = %s
                  AND event_type = 'requested'
                """,
                (_TENANT_ALPHA, attempt_id),
            )
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
            limit=100,
        )
        claim = next(item for item in claims if item.message_id == outbox_id)
        durability.complete_outbox(claim, now=DEMO_TIME)

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
