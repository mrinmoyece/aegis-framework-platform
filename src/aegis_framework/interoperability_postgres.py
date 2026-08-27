"""Forced-RLS PostgreSQL store for Layer 13 trust and protocol projections."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime

from psycopg import IntegrityError
from pydantic import JsonValue

from aegis_framework.errors import (
    ConcurrencyConflict,
    IdempotencyConflict,
    RepositoryUnavailable,
)
from aegis_framework.interoperability import (
    InteroperabilityFact,
    InvocationProjection,
    TrustEntry,
    digest_value,
    reject_raw_ledger_payload,
)
from aegis_framework.postgres import RuntimePool, tenant_transaction


class PostgresInteroperabilityStore:
    """Persist redacted contracts; raw protocol content is never accepted."""

    def __init__(self, pool: RuntimePool) -> None:
        self._pool = pool

    def register_trust(self, *, tenant_id: str, entry: TrustEntry) -> None:
        document = entry.model_dump(mode="json")
        reject_raw_ledger_payload(document)
        try:
            with tenant_transaction(  # noqa: SIM117
                self._pool, tenant_id=tenant_id
            ) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO aegis.interop_trust_registry (
                            tenant_id, peer_id, revision, protocol, owner_ref,
                            environment, trust_tier, status, card_digest,
                            schema_digest, certificate_digest, key_digest,
                            change_digest, trust_document, expires_at,
                            review_after, reviewed_at, recorded_at
                        ) VALUES (
                            %(tenant_id)s, %(peer_id)s, %(revision)s,
                            %(protocol)s, %(owner_ref)s, %(environment)s,
                            %(trust_tier)s, %(status)s, %(card_digest)s,
                            %(schema_digest)s, %(certificate_digest)s,
                            %(key_digest)s, %(change_digest)s,
                            %(trust_document)s::jsonb, %(expires_at)s,
                            %(review_after)s, %(reviewed_at)s, %(recorded_at)s
                        )
                        """,
                        {
                            "tenant_id": tenant_id,
                            "peer_id": entry.peer_id,
                            "revision": entry.revision,
                            "protocol": entry.protocol.value,
                            "owner_ref": entry.owner_ref,
                            "environment": entry.environment,
                            "trust_tier": entry.trust_tier.value,
                            "status": entry.status.value,
                            "card_digest": entry.card_digest,
                            "schema_digest": entry.schema_digest,
                            "certificate_digest": entry.certificate_digest,
                            "key_digest": entry.key_digest,
                            "change_digest": entry.change_digest,
                            "trust_document": _json(document),
                            "expires_at": entry.expires_at,
                            "review_after": entry.review_after,
                            "reviewed_at": entry.reviewed_at,
                            "recorded_at": entry.reviewed_at
                            or datetime.fromisoformat("1970-01-01T00:00:00+00:00"),
                        },
                    )
        except IntegrityError as exc:
            raise ConcurrencyConflict("peer trust revision already exists") from exc
        except Exception as exc:
            if isinstance(exc, ConcurrencyConflict):
                raise
            raise RepositoryUnavailable("peer trust store is unavailable") from exc

    def append_fact(
        self,
        *,
        tenant_id: str,
        fact: InteroperabilityFact,
    ) -> None:
        reject_raw_ledger_payload(fact.payload)
        try:
            with tenant_transaction(  # noqa: SIM117
                self._pool, tenant_id=tenant_id
            ) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO aegis.interop_facts (
                            tenant_id, operation_id, sequence, fact_id,
                            fact_type, command_ref, actor_ref, peer_id,
                            payload_document, previous_digest, fact_digest,
                            recorded_at
                        ) VALUES (
                            %(tenant_id)s, %(operation_id)s, %(sequence)s,
                            %(fact_id)s, %(fact_type)s, %(command_ref)s,
                            %(actor_ref)s, %(peer_id)s,
                            %(payload)s::jsonb, %(previous_digest)s,
                            %(fact_digest)s, %(recorded_at)s
                        )
                        """,
                        {
                            "tenant_id": tenant_id,
                            "operation_id": fact.operation_id,
                            "sequence": fact.sequence,
                            "fact_id": fact.fact_id,
                            "fact_type": fact.fact_type.value,
                            "command_ref": fact.command_ref,
                            "actor_ref": fact.actor_ref,
                            "peer_id": fact.peer_id,
                            "payload": _json(fact.payload),
                            "previous_digest": fact.previous_digest,
                            "fact_digest": fact.fact_digest,
                            "recorded_at": fact.recorded_at,
                        },
                    )
        except IntegrityError as exc:
            raise IdempotencyConflict("interoperability fact already exists") from exc
        except Exception as exc:
            if isinstance(exc, IdempotencyConflict):
                raise
            raise RepositoryUnavailable(
                "interoperability fact store is unavailable"
            ) from exc

    def put_projection(
        self,
        *,
        tenant_id: str,
        projection: InvocationProjection,
        idempotency_key_digest: str,
        created_at: datetime,
    ) -> None:
        try:
            with tenant_transaction(  # noqa: SIM117
                self._pool, tenant_id=tenant_id
            ) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO aegis.interop_invocations (
                            tenant_id, operation_id, peer_id, protocol,
                            capability_id, risk, trust_revision, state,
                            version, request_digest,
                            trust_digest, policy_digest,
                            idempotency_key_digest, fence_token,
                            result_digest, cursor_digest, error_code,
                            ambiguous, cancellation_requested,
                            created_at, updated_at
                        ) VALUES (
                            %(tenant_id)s, %(operation_id)s, %(peer_id)s,
                            %(protocol)s, %(capability_id)s, %(risk)s,
                            %(trust_revision)s, %(state)s,
                            %(version)s, %(request_digest)s, %(trust_digest)s,
                            %(policy_digest)s, %(idempotency_key_digest)s,
                            %(fence_token)s, %(result_digest)s,
                            %(cursor_digest)s, %(error_code)s, %(ambiguous)s,
                            %(cancellation_requested)s, %(created_at)s,
                            %(updated_at)s
                        )
                        ON CONFLICT (tenant_id, operation_id) DO UPDATE SET
                            state = EXCLUDED.state,
                            version = EXCLUDED.version,
                            result_digest = EXCLUDED.result_digest,
                            cursor_digest = EXCLUDED.cursor_digest,
                            error_code = EXCLUDED.error_code,
                            ambiguous = EXCLUDED.ambiguous,
                            cancellation_requested =
                                EXCLUDED.cancellation_requested,
                            updated_at = EXCLUDED.updated_at
                        WHERE aegis.interop_invocations.version
                            = EXCLUDED.version - 1
                          AND aegis.interop_invocations.request_digest
                            = EXCLUDED.request_digest
                          AND aegis.interop_invocations.trust_digest
                            = EXCLUDED.trust_digest
                          AND aegis.interop_invocations.policy_digest
                            = EXCLUDED.policy_digest
                          AND aegis.interop_invocations.fence_token
                            = EXCLUDED.fence_token
                        RETURNING version
                        """,
                        {
                            "tenant_id": tenant_id,
                            "operation_id": projection.operation_id,
                            "peer_id": projection.peer_id,
                            "protocol": projection.protocol.value,
                            "capability_id": projection.capability_id,
                            "risk": projection.risk.value,
                            "trust_revision": projection.trust_revision,
                            "state": projection.state.value,
                            "version": projection.version,
                            "request_digest": projection.request_digest,
                            "trust_digest": projection.trust_digest,
                            "policy_digest": projection.policy_digest,
                            "idempotency_key_digest": idempotency_key_digest,
                            "fence_token": projection.fence_token,
                            "result_digest": projection.result_digest,
                            "cursor_digest": projection.cursor_digest,
                            "error_code": projection.error_code,
                            "ambiguous": projection.ambiguous,
                            "cancellation_requested": (
                                projection.cancellation_requested
                            ),
                            "created_at": created_at,
                            "updated_at": projection.updated_at,
                        },
                    )
                    if cursor.fetchone() is None:
                        raise ConcurrencyConflict(
                            "interoperability projection version is stale"
                        )
        except (ConcurrencyConflict, IntegrityError):
            raise
        except Exception as exc:
            raise RepositoryUnavailable(
                "interoperability projection store is unavailable"
            ) from exc

    def reserve_quota(
        self,
        *,
        tenant_id: str,
        peer_id: str,
        period_start: datetime,
        request_units: int,
        cost_units: int,
    ) -> None:
        if request_units < 1 or cost_units < 0:
            raise ValueError("interoperability quota reservation is invalid")
        try:
            with tenant_transaction(  # noqa: SIM117
                self._pool, tenant_id=tenant_id
            ) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        UPDATE aegis.interop_quotas
                        SET requests_reserved = requests_reserved + %(requests)s,
                            cost_reserved = cost_reserved + %(cost)s
                        WHERE tenant_id = %(tenant_id)s
                          AND peer_id = %(peer_id)s
                          AND period_start = %(period_start)s
                          AND requests_reserved + %(requests)s <= request_limit
                          AND cost_reserved + %(cost)s <= cost_limit
                        RETURNING requests_reserved
                        """,
                        {
                            "tenant_id": tenant_id,
                            "peer_id": peer_id,
                            "period_start": period_start,
                            "requests": request_units,
                            "cost": cost_units,
                        },
                    )
                    if cursor.fetchone() is None:
                        raise ConcurrencyConflict(
                            "interoperability quota is exhausted or unavailable"
                        )
        except ConcurrencyConflict:
            raise
        except Exception as exc:
            raise RepositoryUnavailable(
                "interoperability quota store is unavailable"
            ) from exc


def projection_digest(value: Mapping[str, JsonValue]) -> str:
    reject_raw_ledger_payload(value)
    return digest_value(dict(value))


def _json(value: object) -> str:
    return json.dumps(
        value,
        separators=(",", ":"),
        sort_keys=True,
    )
