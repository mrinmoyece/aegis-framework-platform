"""PostgreSQL model policy, reservation, usage, and health projections."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from psycopg import Error
from pydantic import ValidationError

from aegis_framework.errors import (
    IdempotencyConflict,
    IntegrityFailure,
    PolicyDenied,
    RepositoryUnavailable,
)
from aegis_framework.model_gateway import (
    BillingDisposition,
    ModelCallRecord,
    ModelCatalogEntry,
    ModelErrorCode,
    ModelProvider,
    ModelRequest,
    ModelReservation,
    ModelUsage,
    ModelUsageView,
    ProviderHealthView,
    TenantModelPolicy,
)
from aegis_framework.postgres import DictConnection, RuntimePool, tenant_transaction


class PostgresModelControlStore:
    """Application-owned model facts under forced tenant RLS."""

    def __init__(self, *, pool: RuntimePool) -> None:
        self._pool = pool

    def current_policy(self, *, tenant_id: str) -> TenantModelPolicy | None:
        with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
            row = connection.execute(
                """
                SELECT policy_id, revision, document
                FROM aegis.model_policies
                WHERE tenant_id = %s AND active
                ORDER BY revision DESC
                LIMIT 1
                """,
                (tenant_id,),
            ).fetchone()
        if row is None:
            return None
        policy = TenantModelPolicy.model_validate(row["document"])
        if (
            policy.tenant_id != tenant_id
            or policy.policy_id != row["policy_id"]
            or policy.revision != row["revision"]
        ):
            raise IntegrityFailure("model policy tenant binding is invalid")
        return policy

    def catalog_entry(self, *, tenant_id: str, key: str) -> ModelCatalogEntry | None:
        parts = key.split(":")
        if len(parts) != 3:
            raise ValueError("model catalog key is malformed")
        provider, model, region = parts
        with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
            row = connection.execute(
                """
                SELECT provider, model, region, document
                FROM aegis.model_catalog
                WHERE tenant_id = %s AND provider = %s AND model = %s
                  AND region = %s AND enabled
                """,
                (tenant_id, provider, model, region),
            ).fetchone()
        return (
            self._validated_catalog_document(
                row["document"],
                tenant_id=tenant_id,
                provider=row["provider"],
                model=row["model"],
                region=row["region"],
            )
            if row is not None
            else None
        )

    def reserve(
        self,
        *,
        request: ModelRequest,
        policy: TenantModelPolicy,
        maximum_input_tokens: int,
        maximum_cost_microunits: int,
        now: datetime,
    ) -> ModelReservation:
        tenant_id = request.binding.tenant_id
        reservation = ModelReservation(
            tenant_id=tenant_id,
            run_id=request.binding.run_id,
            reservation_id=request.binding.call_id,
            requested_input_tokens=maximum_input_tokens,
            requested_output_tokens=request.max_output_tokens,
            reserved_cost_microunits=maximum_cost_microunits,
            policy_id=policy.policy_id,
            policy_revision=policy.revision,
            policy_digest=policy.canonical_digest(),
            created_at=now,
        )
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (f"{tenant_id}:model-state",),
                )
                existing = connection.execute(
                    """
                    SELECT tenant_id, run_id, reservation_id,
                           requested_input_tokens, requested_output_tokens,
                           reserved_cost_microunits, policy_id, policy_revision,
                           policy_digest, created_at
                    FROM aegis.model_reservations
                    WHERE tenant_id = %s AND reservation_id = %s
                    """,
                    (tenant_id, request.binding.call_id),
                ).fetchone()
                if existing is not None:
                    persisted = ModelReservation.model_validate(existing)
                    if persisted.model_dump(exclude={"created_at"}) != (
                        reservation.model_dump(exclude={"created_at"})
                    ):
                        raise IdempotencyConflict(
                            "model reservation parameters changed"
                        )
                    return persisted
                budget = connection.execute(
                    """
                    SELECT limit_microunits, reserved_microunits,
                           reconciled_microunits
                    FROM aegis.model_budgets
                    WHERE tenant_id = %s
                    FOR UPDATE
                    """,
                    (tenant_id,),
                ).fetchone()
                if budget is None:
                    raise PolicyDenied("tenant model budget is unavailable")
                calls = connection.execute(
                    """
                    SELECT count(*) AS count
                    FROM aegis.model_reservations
                    WHERE tenant_id = %s AND run_id = %s
                    """,
                    (tenant_id, request.binding.run_id),
                ).fetchone()
                if calls is None or int(calls["count"]) >= policy.maximum_calls_per_run:
                    raise PolicyDenied("model run call limit exhausted")
                if maximum_cost_microunits > policy.maximum_cost_microunits:
                    raise PolicyDenied("model call exceeds policy cost ceiling")
                if int(budget["reserved_microunits"]) + int(
                    budget["reconciled_microunits"]
                ) + maximum_cost_microunits > int(budget["limit_microunits"]):
                    raise PolicyDenied("tenant model budget exhausted")
                connection.execute(
                    """
                    INSERT INTO aegis.model_reservations (
                        tenant_id, run_id, reservation_id,
                        requested_input_tokens, requested_output_tokens,
                        reserved_cost_microunits, policy_id, policy_revision,
                        policy_digest, created_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        tenant_id,
                        request.binding.run_id,
                        request.binding.call_id,
                        maximum_input_tokens,
                        request.max_output_tokens,
                        maximum_cost_microunits,
                        policy.policy_id,
                        policy.revision,
                        policy.canonical_digest(),
                        now,
                    ),
                )
                connection.execute(
                    """
                    UPDATE aegis.model_budgets
                    SET reserved_microunits =
                            reserved_microunits + %s,
                        version = version + 1
                    WHERE tenant_id = %s
                    """,
                    (maximum_cost_microunits, tenant_id),
                )
        except (IdempotencyConflict, PolicyDenied):
            raise
        except Error as exc:
            raise RepositoryUnavailable("model reservation transaction failed") from exc
        return reservation

    def append_requested(
        self,
        *,
        reservation: ModelReservation,
        request: ModelRequest,
        entry: ModelCatalogEntry,
        attempt_id: str,
        now: datetime,
    ) -> ModelCallRecord:
        record = ModelCallRecord(
            tenant_id=request.binding.tenant_id,
            run_id=request.binding.run_id,
            call_id=request.binding.call_id,
            attempt_id=attempt_id,
            request_digest=request.canonical_digest(),
            catalog_key=entry.key,
            price_version=entry.price.version,
            policy_revision=reservation.policy_revision,
            requested_at=now,
            outcome="requested",
            billing=BillingDisposition.AMBIGUOUS,
        )
        tenant_id = request.binding.tenant_id
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (f"{tenant_id}:model-state",),
                )
                connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (f"{tenant_id}:{attempt_id}",),
                )
                existing = connection.execute(
                    """
                    SELECT record
                    FROM aegis.model_call_events
                    WHERE tenant_id = %s AND attempt_id = %s
                      AND event_type = 'requested'
                    """,
                    (tenant_id, attempt_id),
                ).fetchone()
                if existing is not None:
                    persisted = ModelCallRecord.model_validate(existing["record"])
                    if persisted.request_digest != record.request_digest:
                        raise IdempotencyConflict(
                            "model attempt id was reused with different input"
                        )
                    raise IdempotencyConflict(
                        "model attempt already has durable intent; "
                        "reconcile before retry"
                    )
                connection.execute(
                    """
                    INSERT INTO aegis.model_call_events (
                        tenant_id, run_id, call_id, attempt_id,
                        event_type, occurred_at, record
                    )
                    VALUES (%s, %s, %s, %s, 'requested', %s, %s::jsonb)
                    """,
                    (
                        tenant_id,
                        request.binding.run_id,
                        request.binding.call_id,
                        attempt_id,
                        now,
                        record.model_dump_json(),
                    ),
                )
        except IdempotencyConflict:
            raise
        except Error as exc:
            raise RepositoryUnavailable("model call intent append failed") from exc
        return record

    def reconcile(
        self,
        *,
        tenant_id: str,
        attempt_id: str,
        outcome: str,
        billing: BillingDisposition,
        usage: ModelUsage | None,
        cost_microunits: int | None,
        error_code: ModelErrorCode | None,
        now: datetime,
    ) -> ModelCallRecord:
        if billing is BillingDisposition.BILLED and (
            usage is None or cost_microunits is None
        ):
            raise IntegrityFailure("billed model outcome requires usage and cost")
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (f"{tenant_id}:model-state",),
                )
                connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (f"{tenant_id}:{attempt_id}",),
                )
                corrected = connection.execute(
                    """
                    SELECT record
                    FROM aegis.model_call_events
                    WHERE tenant_id = %s AND attempt_id = %s
                      AND event_type = 'corrected'
                    """,
                    (tenant_id, attempt_id),
                ).fetchone()
                if corrected is not None:
                    return ModelCallRecord.model_validate(corrected["record"])
                settled = connection.execute(
                    """
                    SELECT record
                    FROM aegis.model_call_events
                    WHERE tenant_id = %s AND attempt_id = %s
                      AND event_type = 'settled'
                    """,
                    (tenant_id, attempt_id),
                ).fetchone()
                if settled is not None:
                    existing = ModelCallRecord.model_validate(settled["record"])
                    if (
                        existing.billing is BillingDisposition.AMBIGUOUS
                        and billing is not BillingDisposition.AMBIGUOUS
                    ):
                        return self._correct_ambiguous(
                            connection=connection,
                            existing=existing,
                            outcome=outcome,
                            billing=billing,
                            usage=usage,
                            cost_microunits=cost_microunits,
                            error_code=error_code,
                            now=now,
                        )
                    return existing
                requested = connection.execute(
                    """
                    SELECT record
                    FROM aegis.model_call_events
                    WHERE tenant_id = %s AND attempt_id = %s
                      AND event_type = 'requested'
                    """,
                    (tenant_id, attempt_id),
                ).fetchone()
                if requested is None:
                    raise IntegrityFailure("model call intent is unavailable")
                current = ModelCallRecord.model_validate(requested["record"])
                connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (f"{tenant_id}:{current.call_id}:finalize",),
                )
                record = current.model_copy(
                    update={
                        "completed_at": now,
                        "outcome": outcome,
                        "billing": billing,
                        "usage": usage,
                        "cost_microunits": cost_microunits,
                        "error_code": error_code,
                    }
                )
                connection.execute(
                    """
                    INSERT INTO aegis.model_call_events (
                        tenant_id, run_id, call_id, attempt_id,
                        event_type, occurred_at, record
                    )
                    VALUES (%s, %s, %s, %s, 'settled', %s, %s::jsonb)
                    """,
                    (
                        tenant_id,
                        current.run_id,
                        current.call_id,
                        attempt_id,
                        now,
                        record.model_dump_json(),
                    ),
                )
                reserved = connection.execute(
                    """
                    SELECT reserved_cost_microunits
                    FROM aegis.model_reservations
                    WHERE tenant_id = %s AND reservation_id = %s
                    """,
                    (tenant_id, current.call_id),
                ).fetchone()
                if reserved is None:
                    raise IntegrityFailure("model reservation is unavailable")
                ambiguous = 0
                billed = (
                    cost_microunits or 0 if billing is BillingDisposition.BILLED else 0
                )
                connection.execute(
                    """
                    INSERT INTO aegis.model_usage_projection (
                        tenant_id, run_id, reconciled_cost_microunits,
                        ambiguous_cost_microunits, input_tokens,
                        output_tokens, call_count, version
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, 1, 1)
                    ON CONFLICT (tenant_id, run_id) DO UPDATE
                    SET reconciled_cost_microunits =
                            aegis.model_usage_projection.reconciled_cost_microunits
                            + EXCLUDED.reconciled_cost_microunits,
                        ambiguous_cost_microunits =
                            aegis.model_usage_projection.ambiguous_cost_microunits
                            + EXCLUDED.ambiguous_cost_microunits,
                        input_tokens =
                            aegis.model_usage_projection.input_tokens
                            + EXCLUDED.input_tokens,
                        output_tokens =
                            aegis.model_usage_projection.output_tokens
                            + EXCLUDED.output_tokens,
                        call_count =
                            aegis.model_usage_projection.call_count + 1,
                        version = aegis.model_usage_projection.version + 1
                    """,
                    (
                        tenant_id,
                        current.run_id,
                        billed,
                        ambiguous,
                        usage.input_tokens if usage is not None else 0,
                        usage.output_tokens if usage is not None else 0,
                    ),
                )
                provider, model, region = current.catalog_key.split(":")
                connection.execute(
                    """
                    INSERT INTO aegis.provider_health_projection (
                        tenant_id, provider, model, region,
                        observed_calls, failure_count, updated_at
                    )
                    VALUES (%s, %s, %s, %s, 1, %s, %s)
                    ON CONFLICT (tenant_id, provider, model, region) DO UPDATE
                    SET observed_calls =
                            aegis.provider_health_projection.observed_calls + 1,
                        failure_count =
                            aegis.provider_health_projection.failure_count
                            + EXCLUDED.failure_count,
                        updated_at = EXCLUDED.updated_at
                    """,
                    (
                        tenant_id,
                        provider,
                        model,
                        region,
                        int(error_code is not None),
                        now,
                    ),
                )
                if billed:
                    connection.execute(
                        """
                        UPDATE aegis.model_budgets
                        SET reconciled_microunits =
                                reconciled_microunits + %s,
                            version = version + 1
                        WHERE tenant_id = %s
                        """,
                        (billed, tenant_id),
                    )
                return record
        except IntegrityFailure:
            raise
        except (Error, ValidationError, ValueError) as exc:
            raise RepositoryUnavailable("model reconciliation failed") from exc

    def _correct_ambiguous(
        self,
        *,
        connection: DictConnection,
        existing: ModelCallRecord,
        outcome: str,
        billing: BillingDisposition,
        usage: ModelUsage | None,
        cost_microunits: int | None,
        error_code: ModelErrorCode | None,
        now: datetime,
    ) -> ModelCallRecord:
        tenant_id = existing.tenant_id
        connection.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (f"{tenant_id}:{existing.call_id}:finalize",),
        )
        held = connection.execute(
            """
            SELECT greatest(
                reservation.reserved_cost_microunits
                - COALESCE((
                    SELECT sum(
                        (latest.record->>'cost_microunits')::bigint
                    )
                    FROM (
                        SELECT DISTINCT ON (attempt_id)
                            attempt_id, record
                        FROM aegis.model_call_events
                        WHERE tenant_id = reservation.tenant_id
                          AND call_id = reservation.reservation_id
                          AND event_type IN ('settled', 'corrected')
                        ORDER BY attempt_id,
                            CASE event_type
                                WHEN 'corrected' THEN 1 ELSE 0
                            END DESC
                    ) AS latest
                    WHERE latest.record->>'billing' = 'billed'
                ), 0),
                0
            ) AS held_microunits
            FROM aegis.model_reservations AS reservation
            WHERE reservation.tenant_id = %s
              AND reservation.reservation_id = %s
            """,
            (tenant_id, existing.call_id),
        ).fetchone()
        if held is None:
            raise IntegrityFailure("model reservation is unavailable")
        held_before = int(held["held_microunits"])
        corrected = existing.model_copy(
            update={
                "completed_at": now,
                "outcome": outcome,
                "billing": billing,
                "usage": usage,
                "cost_microunits": cost_microunits,
                "error_code": error_code,
            }
        )
        connection.execute(
            """
            INSERT INTO aegis.model_call_events (
                tenant_id, run_id, call_id, attempt_id,
                event_type, occurred_at, record
            )
            VALUES (%s, %s, %s, %s, 'corrected', %s, %s::jsonb)
            """,
            (
                tenant_id,
                existing.run_id,
                existing.call_id,
                existing.attempt_id,
                now,
                corrected.model_dump_json(),
            ),
        )
        old_usage = existing.usage or ModelUsage(
            input_tokens=0,
            output_tokens=0,
            provider_reported=False,
        )
        new_usage = usage or ModelUsage(
            input_tokens=0,
            output_tokens=0,
            provider_reported=False,
        )
        old_billed = (
            existing.cost_microunits or 0
            if existing.billing is BillingDisposition.BILLED
            else 0
        )
        new_billed = cost_microunits or 0 if billing is BillingDisposition.BILLED else 0
        connection.execute(
            """
            UPDATE aegis.model_usage_projection
            SET reconciled_cost_microunits =
                    reconciled_cost_microunits + %s,
                input_tokens = input_tokens + %s,
                output_tokens = output_tokens + %s,
                version = version + 1
            WHERE tenant_id = %s AND run_id = %s
            """,
            (
                new_billed - old_billed,
                new_usage.input_tokens - old_usage.input_tokens,
                new_usage.output_tokens - old_usage.output_tokens,
                tenant_id,
                existing.run_id,
            ),
        )
        provider, model, region = existing.catalog_key.split(":")
        connection.execute(
            """
            UPDATE aegis.provider_health_projection
            SET failure_count = greatest(failure_count + %s, 0),
                updated_at = %s
            WHERE tenant_id = %s AND provider = %s
              AND model = %s AND region = %s
            """,
            (
                int(error_code is not None) - int(existing.error_code is not None),
                now,
                tenant_id,
                provider,
                model,
                region,
            ),
        )
        connection.execute(
            """
            UPDATE aegis.model_budgets
            SET reconciled_microunits =
                    reconciled_microunits + %s,
                version = version + 1
            WHERE tenant_id = %s
            """,
            (new_billed - old_billed, tenant_id),
        )
        billed_delta = max(new_billed - old_billed, 0)
        reserve_transfer = min(billed_delta, held_before)
        if reserve_transfer:
            connection.execute(
                """
                UPDATE aegis.model_budgets
                SET reserved_microunits =
                        greatest(reserved_microunits - %s, 0),
                    version = version + 1
                WHERE tenant_id = %s
                """,
                (reserve_transfer, tenant_id),
            )
        unresolved = connection.execute(
            """
            SELECT count(*) AS count
            FROM aegis.model_call_events AS settled
            WHERE settled.tenant_id = %s
              AND settled.call_id = %s
              AND settled.event_type = 'settled'
              AND settled.record->>'billing' = 'ambiguous'
              AND NOT EXISTS (
                  SELECT 1
                  FROM aegis.model_call_events AS correction
                  WHERE correction.tenant_id = settled.tenant_id
                    AND correction.attempt_id = settled.attempt_id
                    AND correction.event_type = 'corrected'
              )
            """,
            (tenant_id, existing.call_id),
        ).fetchone()
        if unresolved is not None and int(unresolved["count"]) == 0:
            settlement = connection.execute(
                """
                SELECT reservation.reserved_cost_microunits,
                       COALESCE((
                           SELECT sum(
                               (latest.record->>'cost_microunits')::bigint
                           )
                           FROM (
                               SELECT DISTINCT ON (attempt_id)
                                   attempt_id, record
                               FROM aegis.model_call_events
                               WHERE tenant_id = reservation.tenant_id
                                 AND call_id = reservation.reservation_id
                                 AND event_type IN ('settled', 'corrected')
                               ORDER BY attempt_id,
                                   CASE event_type
                                       WHEN 'corrected' THEN 1 ELSE 0
                                   END DESC
                           ) AS latest
                           WHERE latest.record->>'billing' = 'billed'
                       ), 0) AS billed_cost_microunits
                FROM aegis.model_reservations AS reservation
                JOIN aegis.model_reservation_settlements AS settled
                  ON settled.tenant_id = reservation.tenant_id
                 AND settled.reservation_id = reservation.reservation_id
                WHERE reservation.tenant_id = %s
                  AND reservation.reservation_id = %s
                  AND settled.ambiguous_billing
                """,
                (tenant_id, existing.call_id),
            ).fetchone()
            if settlement is not None:
                release = max(
                    int(settlement["reserved_cost_microunits"])
                    - int(settlement["billed_cost_microunits"]),
                    0,
                )
                connection.execute(
                    """
                    UPDATE aegis.model_budgets
                    SET reserved_microunits =
                            greatest(reserved_microunits - %s, 0),
                        version = version + 1
                    WHERE tenant_id = %s
                    """,
                    (release, tenant_id),
                )
        return corrected

    def finalize(
        self,
        *,
        reservation: ModelReservation,
        now: datetime,
    ) -> None:
        tenant_id = reservation.tenant_id
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (f"{tenant_id}:model-state",),
                )
                connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (f"{tenant_id}:{reservation.reservation_id}:finalize",),
                )
                existing = connection.execute(
                    """
                    SELECT 1
                    FROM aegis.model_reservation_settlements
                    WHERE tenant_id = %s AND reservation_id = %s
                    """,
                    (tenant_id, reservation.reservation_id),
                ).fetchone()
                if existing is not None:
                    return
                totals = connection.execute(
                    """
                    SELECT
                        COALESCE(sum(
                            CASE WHEN record->>'billing' = 'billed'
                                 THEN (record->>'cost_microunits')::bigint
                                 ELSE 0 END
                        ), 0) AS billed,
                        bool_or(record->>'billing' = 'ambiguous') AS ambiguous
                    FROM (
                        SELECT DISTINCT ON (tenant_id, attempt_id)
                            tenant_id, call_id, attempt_id, record
                        FROM aegis.model_call_events
                        WHERE tenant_id = %s AND call_id = %s
                          AND event_type IN ('settled', 'corrected')
                        ORDER BY tenant_id, attempt_id,
                            CASE event_type
                                WHEN 'corrected' THEN 1 ELSE 0
                            END DESC
                    ) AS latest
                    """,
                    (tenant_id, reservation.reservation_id),
                ).fetchone()
                if totals is None:
                    raise IntegrityFailure("model settlement totals are unavailable")
                pending = connection.execute(
                    """
                    SELECT count(*) AS count
                    FROM aegis.model_call_events AS requested
                    WHERE requested.tenant_id = %s
                      AND requested.call_id = %s
                      AND requested.event_type = 'requested'
                      AND NOT EXISTS (
                          SELECT 1
                          FROM aegis.model_call_events AS settled
                          WHERE settled.tenant_id = requested.tenant_id
                            AND settled.attempt_id = requested.attempt_id
                            AND settled.event_type IN ('settled', 'corrected')
                      )
                    """,
                    (tenant_id, reservation.reservation_id),
                ).fetchone()
                if pending is None or int(pending["count"]) > 0:
                    raise IntegrityFailure("model reservation has pending attempts")
                billed = int(totals["billed"])
                ambiguous = bool(totals["ambiguous"])
                connection.execute(
                    """
                    INSERT INTO aegis.model_reservation_settlements (
                        tenant_id, reservation_id, ambiguous_billing,
                        billed_cost_microunits, settled_at
                    )
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        tenant_id,
                        reservation.reservation_id,
                        ambiguous,
                        billed,
                        now,
                    ),
                )
                release = (
                    min(billed, reservation.reserved_cost_microunits)
                    if ambiguous
                    else reservation.reserved_cost_microunits
                )
                released = connection.execute(
                    """
                    UPDATE aegis.model_budgets
                    SET reserved_microunits =
                            reserved_microunits - %s,
                        version = version + 1
                    WHERE tenant_id = %s
                      AND reserved_microunits >= %s
                    """,
                    (release, tenant_id, release),
                )
                if released.rowcount != 1:
                    raise IntegrityFailure("model reservation budget release failed")
        except IntegrityFailure:
            raise
        except Error as exc:
            raise RepositoryUnavailable(
                "model reservation finalization failed"
            ) from exc

    def usage(self, *, tenant_id: str, run_id: str) -> ModelUsageView:
        with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
            row = connection.execute(
                """
                SELECT
                    COALESCE((
                        SELECT sum(reserved_cost_microunits)
                        FROM aegis.model_reservations
                        WHERE tenant_id = %s AND run_id = %s
                    ), 0) AS reserved_cost_microunits,
                    COALESCE(usage.reconciled_cost_microunits, 0)
                        AS reconciled_cost_microunits,
                    COALESCE(ambiguous.ambiguous_cost_microunits, 0)
                        AS ambiguous_cost_microunits,
                    COALESCE(usage.input_tokens, 0) AS input_tokens,
                    COALESCE(usage.output_tokens, 0) AS output_tokens,
                    COALESCE(usage.call_count, 0)
                        + COALESCE(pending.call_count, 0) AS call_count
                FROM (SELECT 1) AS seed
                LEFT JOIN aegis.model_usage_projection AS usage
                  ON usage.tenant_id = %s AND usage.run_id = %s
                LEFT JOIN (
                    SELECT sum(reservation.reserved_cost_microunits)
                        AS ambiguous_cost_microunits
                    FROM aegis.model_reservations AS reservation
                    WHERE reservation.tenant_id = %s
                      AND reservation.run_id = %s
                      AND (
                          EXISTS (
                              SELECT 1
                              FROM aegis.model_call_events AS requested
                              WHERE requested.tenant_id = reservation.tenant_id
                                AND requested.call_id =
                                    reservation.reservation_id
                                AND requested.event_type = 'requested'
                                AND NOT EXISTS (
                                    SELECT 1
                                    FROM aegis.model_call_events AS settled
                                    WHERE settled.tenant_id =
                                            requested.tenant_id
                                      AND settled.attempt_id =
                                            requested.attempt_id
                                      AND settled.event_type = 'settled'
                                )
                          )
                          OR EXISTS (
                              SELECT 1
                              FROM aegis.model_call_events AS settled
                              WHERE settled.tenant_id = reservation.tenant_id
                                AND settled.call_id =
                                    reservation.reservation_id
                                AND settled.event_type = 'settled'
                                AND settled.record->>'billing' = 'ambiguous'
                                AND NOT EXISTS (
                                    SELECT 1
                                    FROM aegis.model_call_events AS correction
                                    WHERE correction.tenant_id =
                                            settled.tenant_id
                                      AND correction.attempt_id =
                                            settled.attempt_id
                                      AND correction.event_type = 'corrected'
                                )
                          )
                      )
                ) AS ambiguous ON true
                LEFT JOIN (
                    SELECT
                        count(*) AS call_count
                    FROM (
                        SELECT DISTINCT requested.call_id
                        FROM aegis.model_call_events AS requested
                        WHERE requested.tenant_id = %s
                          AND requested.run_id = %s
                          AND requested.event_type = 'requested'
                          AND NOT EXISTS (
                              SELECT 1
                              FROM aegis.model_call_events AS settled
                              WHERE settled.tenant_id = requested.tenant_id
                                AND settled.attempt_id = requested.attempt_id
                                AND settled.event_type = 'settled'
                          )
                    ) AS pending_call
                    JOIN aegis.model_reservations AS reservation
                      ON reservation.tenant_id = %s
                     AND reservation.reservation_id = pending_call.call_id
                ) AS pending ON true
                """,
                (
                    tenant_id,
                    run_id,
                    tenant_id,
                    run_id,
                    tenant_id,
                    run_id,
                    tenant_id,
                    run_id,
                    tenant_id,
                ),
            ).fetchone()
        if row is None:
            raise RepositoryUnavailable("model usage projection query failed")
        return ModelUsageView(run_id=run_id, **row)

    def health(self, *, tenant_id: str) -> Sequence[ProviderHealthView]:
        with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
            rows = connection.execute(
                """
                SELECT provider, model, region, observed_calls, failure_count
                FROM aegis.provider_health_projection
                WHERE tenant_id = %s
                ORDER BY provider, model, region
                """,
                (tenant_id,),
            ).fetchall()
        return tuple(
            ProviderHealthView(
                provider=ModelProvider(row["provider"]),
                model=row["model"],
                region=row["region"],
                status=("degraded" if int(row["failure_count"]) else "healthy"),
                observed_calls=row["observed_calls"],
                failure_count=row["failure_count"],
            )
            for row in rows
        )

    def catalog(self, *, tenant_id: str) -> Sequence[ModelCatalogEntry]:
        with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
            rows = connection.execute(
                """
                SELECT provider, model, region, document
                FROM aegis.model_catalog
                WHERE tenant_id = %s AND enabled
                ORDER BY provider, model, region
                """,
                (tenant_id,),
            ).fetchall()
        return tuple(
            self._validated_catalog_document(
                row["document"],
                tenant_id=tenant_id,
                provider=row["provider"],
                model=row["model"],
                region=row["region"],
            )
            for row in rows
        )

    @staticmethod
    def _validated_catalog_document(
        document: object,
        *,
        tenant_id: str,
        provider: str,
        model: str,
        region: str,
    ) -> ModelCatalogEntry:
        entry = ModelCatalogEntry.model_validate(document)
        if (
            entry.tenant_id != tenant_id
            or entry.provider.value != provider
            or entry.model != model
            or entry.region != region
        ):
            raise IntegrityFailure("model catalog tenant binding is invalid")
        return entry

    def rebuild_projections(self, *, tenant_id: str) -> None:
        """Rebuild replaceable usage and health views from immutable call facts."""

        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (f"{tenant_id}:model-state",),
                )
                connection.execute(
                    "DELETE FROM aegis.model_usage_projection WHERE tenant_id = %s",
                    (tenant_id,),
                )
                connection.execute(
                    """
                    INSERT INTO aegis.model_usage_projection (
                        tenant_id, run_id, reconciled_cost_microunits,
                        ambiguous_cost_microunits, input_tokens,
                        output_tokens, call_count, version
                    )
                    SELECT
                        event.tenant_id,
                        event.run_id,
                        sum(
                            CASE WHEN record->>'billing' = 'billed'
                                 THEN COALESCE(
                                     (record->>'cost_microunits')::bigint, 0
                                 )
                                 ELSE 0 END
                        ),
                        0::bigint,
                        sum(COALESCE(
                            (record->'usage'->>'input_tokens')::bigint, 0
                        )),
                        sum(COALESCE(
                            (record->'usage'->>'output_tokens')::bigint, 0
                        )),
                        count(*),
                        1
                    FROM (
                        SELECT DISTINCT ON (tenant_id, attempt_id)
                            tenant_id, run_id, call_id, attempt_id,
                            occurred_at, record
                        FROM aegis.model_call_events
                        WHERE tenant_id = %s
                          AND event_type IN ('settled', 'corrected')
                        ORDER BY tenant_id, attempt_id,
                            CASE event_type
                                WHEN 'corrected' THEN 1 ELSE 0
                            END DESC
                    ) AS event
                    JOIN aegis.model_reservations AS reservation
                      ON reservation.tenant_id = event.tenant_id
                     AND reservation.reservation_id = event.call_id
                    WHERE event.tenant_id = %s
                    GROUP BY event.tenant_id, event.run_id
                    """,
                    (tenant_id, tenant_id),
                )
                connection.execute(
                    """
                    DELETE FROM aegis.provider_health_projection
                    WHERE tenant_id = %s
                    """,
                    (tenant_id,),
                )
                connection.execute(
                    """
                    INSERT INTO aegis.provider_health_projection (
                        tenant_id, provider, model, region,
                        observed_calls, failure_count, updated_at
                    )
                    SELECT
                        tenant_id,
                        split_part(record->>'catalog_key', ':', 1),
                        split_part(record->>'catalog_key', ':', 2),
                        split_part(record->>'catalog_key', ':', 3),
                        count(*),
                        count(*) FILTER (
                            WHERE record->>'error_code' IS NOT NULL
                        ),
                        max(occurred_at)
                    FROM (
                        SELECT DISTINCT ON (tenant_id, attempt_id)
                            tenant_id, attempt_id, occurred_at, record
                        FROM aegis.model_call_events
                        WHERE tenant_id = %s
                          AND event_type IN ('settled', 'corrected')
                        ORDER BY tenant_id, attempt_id,
                            CASE event_type
                                WHEN 'corrected' THEN 1 ELSE 0
                            END DESC
                    ) AS latest
                    WHERE tenant_id = %s
                    GROUP BY
                        tenant_id,
                        split_part(record->>'catalog_key', ':', 1),
                        split_part(record->>'catalog_key', ':', 2),
                        split_part(record->>'catalog_key', ':', 3)
                    """,
                    (tenant_id, tenant_id),
                )
                connection.execute(
                    """
                    UPDATE aegis.model_budgets
                    SET reserved_microunits = COALESCE((
                            SELECT sum(CASE
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
                                           AND ambiguous.record->>'billing' =
                                                'ambiguous'
                                           AND NOT EXISTS (
                                               SELECT 1
                                               FROM aegis.model_call_events
                                                    AS correction
                                               WHERE correction.tenant_id =
                                                        ambiguous.tenant_id
                                                 AND correction.attempt_id =
                                                        ambiguous.attempt_id
                                                 AND correction.event_type =
                                                        'corrected'
                                           )
                                     )
                                    THEN greatest(
                                        reservation.reserved_cost_microunits
                                        - COALESCE((
                                            SELECT sum(
                                                (latest.record
                                                    ->>'cost_microunits')::bigint
                                            )
                                            FROM (
                                                SELECT DISTINCT ON (attempt_id)
                                                    attempt_id, record
                                                FROM aegis.model_call_events
                                                WHERE tenant_id =
                                                    reservation.tenant_id
                                                  AND call_id =
                                                    reservation.reservation_id
                                                  AND event_type IN (
                                                      'settled', 'corrected'
                                                  )
                                                ORDER BY attempt_id,
                                                    CASE event_type
                                                        WHEN 'corrected'
                                                            THEN 1
                                                        ELSE 0
                                                    END DESC
                                            ) AS latest
                                            WHERE latest.record->>'billing' =
                                                'billed'
                                        ), 0),
                                        0
                                    )
                                ELSE 0
                            END)
                            FROM aegis.model_reservations AS reservation
                            LEFT JOIN aegis.model_reservation_settlements
                                AS settlement
                              ON settlement.tenant_id = reservation.tenant_id
                             AND settlement.reservation_id =
                                reservation.reservation_id
                            WHERE reservation.tenant_id = %s
                              AND (
                                  settlement.reservation_id IS NULL
                                  OR settlement.ambiguous_billing
                              )
                        ), 0),
                        reconciled_microunits = COALESCE((
                            SELECT sum(
                                (record->>'cost_microunits')::bigint
                            )
                            FROM (
                                SELECT DISTINCT ON (tenant_id, attempt_id)
                                    tenant_id, attempt_id, record
                                FROM aegis.model_call_events
                                WHERE tenant_id = %s
                                  AND event_type IN ('settled', 'corrected')
                                ORDER BY tenant_id, attempt_id,
                                    CASE event_type
                                        WHEN 'corrected' THEN 1 ELSE 0
                                    END DESC
                            ) AS latest
                            WHERE record->>'billing' = 'billed'
                        ), 0),
                        version = version + 1
                    WHERE tenant_id = %s
                    """,
                    (tenant_id, tenant_id, tenant_id),
                )
        except Error as exc:
            raise RepositoryUnavailable("model projection rebuild failed") from exc
