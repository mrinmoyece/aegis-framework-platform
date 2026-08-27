"""PostgreSQL remediation contracts, immutable facts, claims, and rebuilds."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from psycopg import IntegrityError
from psycopg.types.json import Jsonb
from pydantic import JsonValue, ValidationError

from aegis_framework.domain import stable_id
from aegis_framework.errors import (
    ConcurrencyConflict,
    EffectConflict,
    IdempotencyConflict,
    IntegrityFailure,
    RepositoryUnavailable,
)
from aegis_framework.postgres import DictConnection, RuntimePool, tenant_transaction
from aegis_framework.remediation import (
    ActionApprovalRequest,
    ActionIntent,
    ActionReceipt,
    ApprovalDecision,
    EffectClaimRecord,
    EffectOutcome,
    EffectQuotaDecision,
    RemediationFact,
    RemediationFactType,
    RemediationPlan,
    RemediationProjection,
    RemediationStatus,
    VerificationRecord,
    canonical_digest,
    reduce_remediation,
)


class PostgresRemediationStore:
    """Application repository independent of Temporal and LangGraph histories."""

    def __init__(self, *, pool: RuntimePool) -> None:
        self._pool = pool

    def put_plan(self, plan: RemediationPlan) -> None:
        try:
            with tenant_transaction(self._pool, tenant_id=plan.tenant_id) as connection:
                connection.execute(
                    """
                    INSERT INTO aegis.remediation_plans (
                        tenant_id, plan_id, run_id, incident_id, schema_version,
                        plan_digest, target_fingerprint, risk, blast_radius,
                        policy_digest, plan_document, created_at, expires_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    ON CONFLICT (tenant_id, plan_id) DO NOTHING
                    """,
                    (
                        plan.tenant_id,
                        plan.plan_id,
                        plan.run_id,
                        plan.incident_id,
                        plan.schema_version,
                        plan.plan_digest,
                        plan.target_fingerprint,
                        plan.risk.value,
                        plan.blast_radius.value,
                        plan.policy_snapshot.policy_digest,
                        Jsonb(plan.model_dump(mode="json")),
                        plan.created_at,
                        plan.expires_at,
                    ),
                )
                existing = connection.execute(
                    """
                    SELECT plan_digest, plan_document
                    FROM aegis.remediation_plans
                    WHERE tenant_id = %s AND plan_id = %s
                    """,
                    (plan.tenant_id, plan.plan_id),
                ).fetchone()
                if existing is None or existing["plan_digest"] != plan.plan_digest:
                    raise IdempotencyConflict("plan binding changed")
        except IdempotencyConflict:
            raise
        except Exception as exc:
            raise RepositoryUnavailable("remediation plan persistence failed") from exc

    def plan(self, *, tenant_id: str, plan_id: str) -> RemediationPlan | None:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                row = connection.execute(
                    """
                    SELECT plan_document
                    FROM aegis.remediation_plans
                    WHERE tenant_id = %s AND plan_id = %s
                    """,
                    (tenant_id, plan_id),
                ).fetchone()
                return (
                    RemediationPlan.model_validate(row["plan_document"])
                    if row is not None
                    else None
                )
        except ValidationError as exc:
            raise IntegrityFailure("stored remediation plan is invalid") from exc
        except IntegrityFailure:
            raise
        except Exception as exc:
            raise RepositoryUnavailable("remediation plan read failed") from exc

    def put_approval(self, approval: ActionApprovalRequest) -> None:
        try:
            with tenant_transaction(
                self._pool,
                tenant_id=approval.tenant_id,
            ) as connection:
                connection.execute(
                    """
                    INSERT INTO aegis.action_approvals (
                        tenant_id, approval_id, plan_id, approval_digest,
                        plan_digest, target_fingerprint, policy_digest, quorum,
                        requested_by_ref, approval_document, requested_at, expires_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (tenant_id, approval_id) DO NOTHING
                    """,
                    (
                        approval.tenant_id,
                        approval.approval_id,
                        approval.plan_id,
                        approval.canonical_digest,
                        approval.plan_digest,
                        approval.target_fingerprint,
                        approval.policy_snapshot.policy_digest,
                        approval.requirement.quorum,
                        approval.requested_by_ref,
                        Jsonb(approval.model_dump(mode="json")),
                        approval.requested_at,
                        approval.expires_at,
                    ),
                )
                row = connection.execute(
                    """
                    SELECT approval_digest
                    FROM aegis.action_approvals
                    WHERE tenant_id = %s AND approval_id = %s
                    """,
                    (approval.tenant_id, approval.approval_id),
                ).fetchone()
                if row is None or row["approval_digest"] != approval.canonical_digest:
                    raise IdempotencyConflict("approval binding changed")
        except IdempotencyConflict:
            raise
        except Exception as exc:
            raise RepositoryUnavailable("approval persistence failed") from exc

    def approval(
        self,
        *,
        tenant_id: str,
        approval_id: str,
    ) -> ActionApprovalRequest | None:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                row = connection.execute(
                    """
                    SELECT approval_document
                    FROM aegis.action_approvals
                    WHERE tenant_id = %s AND approval_id = %s
                    """,
                    (tenant_id, approval_id),
                ).fetchone()
                return (
                    ActionApprovalRequest.model_validate(row["approval_document"])
                    if row is not None
                    else None
                )
        except ValidationError as exc:
            raise IntegrityFailure("stored approval is invalid") from exc
        except IntegrityFailure:
            raise
        except Exception as exc:
            raise RepositoryUnavailable("approval read failed") from exc

    def add_decision(self, decision: ApprovalDecision) -> None:
        try:
            with tenant_transaction(
                self._pool,
                tenant_id=decision.tenant_id,
            ) as connection:
                connection.execute(
                    """
                    INSERT INTO aegis.approval_decisions (
                        tenant_id, decision_id, command_id, approval_id,
                        approver_ref, approver_role, disposition, plan_digest,
                        approval_digest, policy_digest, role_revision, rationale,
                        decision_digest, decision_document, decided_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s
                    )
                    ON CONFLICT (tenant_id, command_id) DO NOTHING
                    """,
                    (
                        decision.tenant_id,
                        decision.decision_id,
                        decision.command_id,
                        decision.approval_id,
                        decision.approver_ref,
                        decision.approver_role,
                        decision.disposition.value,
                        decision.plan_digest,
                        decision.approval_digest,
                        decision.policy_digest,
                        decision.role_revision,
                        decision.rationale,
                        decision.canonical_digest,
                        Jsonb(decision.model_dump(mode="json")),
                        decision.decided_at,
                    ),
                )
                row = connection.execute(
                    """
                    SELECT decision_digest
                    FROM aegis.approval_decisions
                    WHERE tenant_id = %s AND command_id = %s
                    """,
                    (decision.tenant_id, decision.command_id),
                ).fetchone()
                if row is None or row["decision_digest"] != decision.canonical_digest:
                    raise IdempotencyConflict("approval decision replay changed")
        except IdempotencyConflict:
            raise
        except IntegrityError as exc:
            raise IdempotencyConflict("approver already decided") from exc
        except Exception as exc:
            raise RepositoryUnavailable("approval decision persistence failed") from exc

    def decisions(
        self,
        *,
        tenant_id: str,
        approval_id: str,
    ) -> tuple[ApprovalDecision, ...]:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                rows = connection.execute(
                    """
                    SELECT decision_document
                    FROM aegis.approval_decisions
                    WHERE tenant_id = %s AND approval_id = %s
                    ORDER BY decided_at, decision_id
                    """,
                    (tenant_id, approval_id),
                ).fetchall()
                return tuple(
                    ApprovalDecision.model_validate(row["decision_document"])
                    for row in rows
                )
        except ValidationError as exc:
            raise IntegrityFailure("stored approval decision is invalid") from exc
        except IntegrityFailure:
            raise
        except Exception as exc:
            raise RepositoryUnavailable("approval decision read failed") from exc

    def put_verification(self, verification: VerificationRecord) -> None:
        try:
            with tenant_transaction(
                self._pool,
                tenant_id=verification.tenant_id,
            ) as connection:
                connection.execute(
                    """
                    INSERT INTO aegis.verification_records (
                        tenant_id, verification_id, plan_id, action_id,
                        effect_receipt_digest, verification_digest,
                        postconditions_satisfied, verification_document, verified_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (tenant_id, verification_id) DO NOTHING
                    """,
                    (
                        verification.tenant_id,
                        verification.verification_id,
                        verification.plan_id,
                        verification.action_id,
                        verification.effect_receipt_digest,
                        verification.canonical_digest,
                        verification.postconditions_satisfied,
                        Jsonb(verification.model_dump(mode="json")),
                        verification.verified_at,
                    ),
                )
                row = connection.execute(
                    """
                    SELECT verification_digest
                    FROM aegis.verification_records
                    WHERE tenant_id = %s AND verification_id = %s
                    """,
                    (verification.tenant_id, verification.verification_id),
                ).fetchone()
                if (
                    row is None
                    or row["verification_digest"] != verification.canonical_digest
                ):
                    raise IdempotencyConflict("verification replay changed")
        except IdempotencyConflict:
            raise
        except Exception as exc:
            raise RepositoryUnavailable("verification persistence failed") from exc

    def verification(
        self,
        *,
        tenant_id: str,
        verification_id: str,
    ) -> VerificationRecord | None:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                row = connection.execute(
                    """
                    SELECT verification_document
                    FROM aegis.verification_records
                    WHERE tenant_id = %s AND verification_id = %s
                    """,
                    (tenant_id, verification_id),
                ).fetchone()
                return (
                    VerificationRecord.model_validate(row["verification_document"])
                    if row is not None
                    else None
                )
        except ValidationError as exc:
            raise IntegrityFailure("stored verification is invalid") from exc
        except IntegrityFailure:
            raise
        except Exception as exc:
            raise RepositoryUnavailable("verification read failed") from exc

    def append(
        self,
        *,
        tenant_id: str,
        plan_id: str,
        expected_version: int,
        fact_type: RemediationFactType,
        command_id: str,
        actor_ref: str,
        recorded_at: datetime,
        payload: Mapping[str, JsonValue],
    ) -> RemediationProjection:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                existing_command = connection.execute(
                    """
                    SELECT fact_type, fact_document
                    FROM aegis.remediation_facts
                    WHERE tenant_id = %s AND command_id = %s
                    """,
                    (tenant_id, command_id),
                ).fetchone()
                if existing_command is not None:
                    fact = RemediationFact.model_validate(
                        existing_command["fact_document"]
                    )
                    if fact.fact_type is not fact_type or fact.payload != dict(payload):
                        raise IdempotencyConflict(
                            "remediation command replay changed input"
                        )
                    projection = self._projection_row(
                        connection,
                        tenant_id=tenant_id,
                        plan_id=plan_id,
                        for_update=False,
                    )
                    if projection is None:
                        raise IntegrityFailure(
                            "replayed remediation command lost projection"
                        )
                    return projection

                current = self._projection_row(
                    connection,
                    tenant_id=tenant_id,
                    plan_id=plan_id,
                    for_update=True,
                )
                version = current.version if current is not None else 0
                if version != expected_version:
                    raise ConcurrencyConflict("remediation aggregate version changed")
                sequence = version + 1
                previous = current.last_fact_digest if current is not None else "0" * 64
                fact_id = stable_id(
                    "remediation-fact",
                    tenant_id,
                    plan_id,
                    str(sequence),
                    command_id,
                    length=32,
                )
                document: dict[str, JsonValue] = dict(sorted(payload.items()))
                material: dict[str, object] = {
                    "schema_version": 1,
                    "tenant_id": tenant_id,
                    "plan_id": plan_id,
                    "sequence": sequence,
                    "fact_id": fact_id,
                    "fact_type": fact_type.value,
                    "command_id": command_id,
                    "actor_ref": actor_ref,
                    "recorded_at": recorded_at,
                    "payload": document,
                    "previous_digest": previous,
                }
                fact = RemediationFact(
                    **material,
                    canonical_digest=canonical_digest(material),
                )
                projection = reduce_remediation(current, fact)
                connection.execute(
                    """
                    INSERT INTO aegis.remediation_facts (
                        tenant_id, plan_id, sequence, fact_id, fact_type,
                        command_id, actor_ref, fact_document, previous_digest,
                        fact_digest, recorded_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        tenant_id,
                        plan_id,
                        sequence,
                        fact_id,
                        fact_type.value,
                        command_id,
                        actor_ref,
                        Jsonb(fact.model_dump(mode="json")),
                        previous,
                        fact.canonical_digest,
                        recorded_at,
                    ),
                )
                self._write_projection(connection, projection)
                return projection
        except (
            ConcurrencyConflict,
            IdempotencyConflict,
            IntegrityFailure,
        ):
            raise
        except ValidationError as exc:
            raise IntegrityFailure("stored remediation state is invalid") from exc
        except IntegrityError as exc:
            raise IdempotencyConflict("remediation fact binding conflict") from exc
        except Exception as exc:
            raise RepositoryUnavailable("remediation append failed") from exc

    def projection(
        self,
        *,
        tenant_id: str,
        plan_id: str,
    ) -> RemediationProjection | None:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                return self._projection_row(
                    connection,
                    tenant_id=tenant_id,
                    plan_id=plan_id,
                    for_update=False,
                )
        except ValidationError as exc:
            raise IntegrityFailure("stored remediation projection is invalid") from exc
        except IntegrityFailure:
            raise
        except Exception as exc:
            raise RepositoryUnavailable("remediation projection read failed") from exc

    def facts(
        self,
        *,
        tenant_id: str,
        plan_id: str,
    ) -> tuple[RemediationFact, ...]:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                rows = connection.execute(
                    """
                    SELECT fact_document
                    FROM aegis.remediation_facts
                    WHERE tenant_id = %s AND plan_id = %s
                    ORDER BY sequence
                    """,
                    (tenant_id, plan_id),
                ).fetchall()
                return tuple(
                    RemediationFact.model_validate(row["fact_document"]) for row in rows
                )
        except ValidationError as exc:
            raise IntegrityFailure("stored remediation fact is invalid") from exc
        except IntegrityFailure:
            raise
        except Exception as exc:
            raise RepositoryUnavailable("remediation facts read failed") from exc

    def rebuild(
        self,
        *,
        tenant_id: str,
        plan_id: str,
        rebuilt_at: datetime,
    ) -> RemediationProjection:
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                rows = connection.execute(
                    """
                    SELECT fact_document
                    FROM aegis.remediation_facts
                    WHERE tenant_id = %s AND plan_id = %s
                    ORDER BY sequence
                    FOR SHARE
                    """,
                    (tenant_id, plan_id),
                ).fetchall()
                projection: RemediationProjection | None = None
                facts = tuple(
                    RemediationFact.model_validate(row["fact_document"]) for row in rows
                )
                for fact in facts:
                    projection = reduce_remediation(projection, fact)
                if projection is None:
                    raise IntegrityFailure("cannot rebuild unknown remediation")
                self._write_projection(connection, projection)
                source_digest = canonical_digest(
                    {"facts": [fact.canonical_digest for fact in facts]}
                )
                projection_digest = canonical_digest(projection.model_dump(mode="json"))
                connection.execute(
                    """
                    INSERT INTO aegis.remediation_projection_rebuilds (
                        tenant_id, rebuild_id, plan_id, source_fact_count,
                        source_digest, projection_digest, rebuilt_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        tenant_id,
                        stable_id(
                            "remediation-rebuild",
                            tenant_id,
                            plan_id,
                            source_digest,
                            length=32,
                        ),
                        plan_id,
                        len(facts),
                        source_digest,
                        projection_digest,
                        rebuilt_at,
                    ),
                )
                return projection
        except IntegrityFailure:
            raise
        except ValidationError as exc:
            raise IntegrityFailure("rebuild source is invalid") from exc
        except IntegrityError as exc:
            raise IdempotencyConflict("rebuild was already recorded") from exc
        except Exception as exc:
            raise RepositoryUnavailable("remediation rebuild failed") from exc

    def reserve_effect_quota(
        self,
        *,
        tenant_id: str,
        plan_id: str,
        reservation_id: str,
        amount: int,
        policy_digest: str,
        reserved_at: datetime,
    ) -> None:
        if amount < 1:
            raise ValueError("effect quota reservation must be positive")
        try:
            with tenant_transaction(self._pool, tenant_id=tenant_id) as connection:
                existing = connection.execute(
                    """
                    SELECT plan_id, amount, policy_digest
                    FROM aegis.effect_quota_reservations
                    WHERE tenant_id = %s AND reservation_id = %s
                    """,
                    (tenant_id, reservation_id),
                ).fetchone()
                if existing is not None:
                    if (
                        existing["plan_id"] != plan_id
                        or existing["amount"] != amount
                        or existing["policy_digest"] != policy_digest
                    ):
                        raise IdempotencyConflict(
                            "effect quota reservation binding changed"
                        )
                    return
                quota = connection.execute(
                    """
                    SELECT limit_count, reserved_count, settled_count, version
                    FROM aegis.effect_quotas
                    WHERE tenant_id = %s AND quota_key = 'effects'
                    FOR UPDATE
                    """,
                    (tenant_id,),
                ).fetchone()
                if quota is None or (
                    quota["reserved_count"] + quota["settled_count"] + amount
                    > quota["limit_count"]
                ):
                    raise EffectConflict("effect quota exhausted")
                connection.execute(
                    """
                    INSERT INTO aegis.effect_quota_reservations (
                        tenant_id, reservation_id, quota_key, plan_id, amount,
                        policy_digest, status, reserved_at
                    )
                    VALUES (%s, %s, 'effects', %s, %s, %s, 'reserved', %s)
                    """,
                    (
                        tenant_id,
                        reservation_id,
                        plan_id,
                        amount,
                        policy_digest,
                        reserved_at,
                    ),
                )
                connection.execute(
                    """
                    UPDATE aegis.effect_quotas
                    SET reserved_count = reserved_count + %s, version = version + 1
                    WHERE tenant_id = %s AND quota_key = 'effects'
                    """,
                    (amount, tenant_id),
                )
        except (EffectConflict, IdempotencyConflict):
            raise
        except Exception as exc:
            raise RepositoryUnavailable("effect quota reservation failed") from exc

    def reserve(
        self,
        *,
        tenant_id: str,
        plan_id: str,
        reservation_id: str,
        policy_digest: str,
        units: int,
        requested_at: datetime,
    ) -> EffectQuotaDecision:
        try:
            self.reserve_effect_quota(
                tenant_id=tenant_id,
                plan_id=plan_id,
                reservation_id=reservation_id,
                amount=units,
                policy_digest=policy_digest,
                reserved_at=requested_at,
            )
        except EffectConflict:
            return EffectQuotaDecision(
                allowed=False,
                reservation_id=reservation_id,
                units=units,
                reason="effect_quota_exhausted",
            )
        return EffectQuotaDecision(
            allowed=True,
            reservation_id=reservation_id,
            units=units,
            reason="reserved",
        )

    def claim(
        self,
        intent: ActionIntent,
        *,
        worker_ref: str,
        now: datetime,
        claim_until: datetime,
    ) -> EffectClaimRecord:
        if claim_until <= now:
            raise ValueError("effect claim expiry must follow claim time")
        claim_token = stable_id(
            "effect-claim",
            intent.tenant_id,
            intent.operation_id,
            worker_ref,
            str(intent.attempt),
            intent.fence_token,
            length=40,
        )
        try:
            with tenant_transaction(
                self._pool,
                tenant_id=intent.tenant_id,
            ) as connection:
                connection.execute(
                    """
                    INSERT INTO aegis.effect_attempts (
                        tenant_id, plan_id, action_id, operation_id, attempt,
                        idempotency_key, action_digest, plan_digest,
                        approval_digest, policy_digest, target_fingerprint,
                        fence_token, status, requested_at, updated_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, 'requested', %s, %s
                    )
                    ON CONFLICT (tenant_id, operation_id) DO NOTHING
                    """,
                    (
                        intent.tenant_id,
                        intent.plan_id,
                        intent.action.action_id,
                        intent.operation_id,
                        intent.attempt,
                        intent.action.idempotency_key,
                        intent.action.canonical_digest,
                        intent.plan_digest,
                        intent.approval_digest,
                        intent.policy_digest,
                        intent.action.target.resource_fingerprint,
                        intent.fence_token,
                        intent.requested_at,
                        intent.requested_at,
                    ),
                )
                row = connection.execute(
                    """
                    SELECT action_digest, plan_digest, approval_digest,
                           policy_digest, target_fingerprint, fence_token,
                           attempt, status, claim_token, claim_until, receipt_digest,
                           receipt_document
                    FROM aegis.effect_attempts
                    WHERE tenant_id = %s AND operation_id = %s
                    FOR UPDATE
                    """,
                    (intent.tenant_id, intent.operation_id),
                ).fetchone()
                if row is None:
                    raise IntegrityFailure("effect intent was not persisted")
                expected = (
                    intent.action.canonical_digest,
                    intent.plan_digest,
                    intent.approval_digest,
                    intent.policy_digest,
                    intent.action.target.resource_fingerprint,
                    intent.fence_token,
                )
                actual = (
                    row["action_digest"],
                    row["plan_digest"],
                    row["approval_digest"],
                    row["policy_digest"],
                    row["target_fingerprint"],
                    row["fence_token"],
                )
                if actual != expected:
                    raise EffectConflict("effect attempt exact binding changed")
                if row["receipt_digest"] is not None:
                    receipt = ActionReceipt.model_validate(row["receipt_document"])
                    return EffectClaimRecord(
                        claim_token=row["claim_token"] or claim_token,
                        fence_token=intent.fence_token,
                        attempt=intent.attempt,
                        replayed=True,
                        receipt=receipt,
                    )
                if (
                    row["status"] == "claimed"
                    and row["claim_until"] is not None
                    and row["claim_until"] > now
                    and row["claim_token"] != claim_token
                ):
                    raise ConcurrencyConflict("effect attempt is actively claimed")
                if (
                    row["receipt_digest"] is None
                    and row["claim_until"] is not None
                    and row["claim_until"] <= now
                    and intent.attempt <= row["attempt"]
                ):
                    raise ConcurrencyConflict("effect retry attempt did not advance")
                updated = connection.execute(
                    """
                    UPDATE aegis.effect_attempts
                    SET status = 'claimed', claim_token = %s, claim_until = %s,
                        worker_ref = %s, attempt = %s, updated_at = %s
                    WHERE tenant_id = %s AND operation_id = %s
                      AND fence_token = %s
                    """,
                    (
                        claim_token,
                        claim_until,
                        worker_ref,
                        intent.attempt,
                        now,
                        intent.tenant_id,
                        intent.operation_id,
                        intent.fence_token,
                    ),
                )
                if updated.rowcount != 1:
                    raise ConcurrencyConflict("stale effect worker fence rejected")
                return EffectClaimRecord(
                    claim_token=claim_token,
                    fence_token=intent.fence_token,
                    attempt=intent.attempt,
                    replayed=False,
                )
        except (
            ConcurrencyConflict,
            EffectConflict,
            IntegrityFailure,
        ):
            raise
        except IntegrityError as exc:
            raise IdempotencyConflict("effect idempotency key conflict") from exc
        except Exception as exc:
            raise RepositoryUnavailable("effect claim failed") from exc

    def complete(
        self,
        receipt: ActionReceipt,
        *,
        claim_token: str,
        now: datetime,
    ) -> None:
        status = {
            EffectOutcome.SUCCEEDED: "succeeded",
            EffectOutcome.DUPLICATE: "succeeded",
            EffectOutcome.FAILED: "failed",
            EffectOutcome.CONFLICT: "failed",
            EffectOutcome.AMBIGUOUS: "ambiguous",
            EffectOutcome.COMPENSATED: "compensated",
        }.get(receipt.outcome)
        if status is None:
            raise EffectConflict("dry-run receipt cannot complete an effect claim")
        try:
            with tenant_transaction(
                self._pool,
                tenant_id=receipt.tenant_id,
            ) as connection:
                updated = connection.execute(
                    """
                    UPDATE aegis.effect_attempts
                    SET status = %s, receipt_digest = %s, receipt_document = %s,
                        updated_at = %s
                    WHERE tenant_id = %s AND operation_id = %s
                      AND claim_token = %s AND fence_token = %s
                      AND attempt = %s AND status = 'claimed'
                    """,
                    (
                        status,
                        receipt.canonical_digest,
                        Jsonb(receipt.model_dump(mode="json")),
                        now,
                        receipt.tenant_id,
                        receipt.operation_id,
                        claim_token,
                        receipt.fence_token,
                        receipt.attempt,
                    ),
                )
                if updated.rowcount != 1:
                    raise ConcurrencyConflict("stale effect claim completion rejected")
                connection.execute(
                    """
                    INSERT INTO aegis.effect_receipts (
                        tenant_id, plan_id, action_id, operation_id,
                        receipt_digest, outcome, receipt_document, recorded_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        receipt.tenant_id,
                        receipt.plan_id,
                        receipt.action_id,
                        receipt.operation_id,
                        receipt.canonical_digest,
                        receipt.outcome.value,
                        Jsonb(receipt.model_dump(mode="json")),
                        receipt.recorded_at,
                    ),
                )
        except ConcurrencyConflict:
            raise
        except IntegrityError as exc:
            raise IdempotencyConflict("effect receipt already exists") from exc
        except Exception as exc:
            raise RepositoryUnavailable("effect claim completion failed") from exc

    @staticmethod
    def _projection_row(
        connection: DictConnection,
        *,
        tenant_id: str,
        plan_id: str,
        for_update: bool,
    ) -> RemediationProjection | None:
        query = """
            SELECT tenant_id, plan_id, run_id, status, version, plan_digest,
                   approval_id, approval_digest, effect_receipt_digest,
                   verification_digest, fence_token, last_fact_digest, updated_at
            FROM aegis.remediation_projections
            WHERE tenant_id = %s AND plan_id = %s
        """
        if for_update:
            query += " FOR UPDATE"
        row = connection.execute(query, (tenant_id, plan_id)).fetchone()
        if row is None:
            return None
        return RemediationProjection(
            tenant_id=row["tenant_id"],
            plan_id=row["plan_id"],
            run_id=row["run_id"],
            status=RemediationStatus(row["status"]),
            version=row["version"],
            plan_digest=row["plan_digest"],
            approval_id=row["approval_id"],
            approval_digest=row["approval_digest"],
            effect_receipt_digest=row["effect_receipt_digest"],
            verification_digest=row["verification_digest"],
            fence_token=row["fence_token"],
            last_fact_digest=row["last_fact_digest"],
            updated_at=row["updated_at"],
        )

    @staticmethod
    def _write_projection(
        connection: DictConnection,
        projection: RemediationProjection,
    ) -> None:
        connection.execute(
            """
            INSERT INTO aegis.remediation_projections (
                tenant_id, plan_id, run_id, status, version, plan_digest,
                approval_id, approval_digest, effect_receipt_digest,
                verification_digest, fence_token, last_fact_digest, updated_at
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            ON CONFLICT (tenant_id, plan_id) DO UPDATE
            SET status = EXCLUDED.status,
                version = EXCLUDED.version,
                approval_id = EXCLUDED.approval_id,
                approval_digest = EXCLUDED.approval_digest,
                effect_receipt_digest = EXCLUDED.effect_receipt_digest,
                verification_digest = EXCLUDED.verification_digest,
                fence_token = EXCLUDED.fence_token,
                last_fact_digest = EXCLUDED.last_fact_digest,
                updated_at = EXCLUDED.updated_at
            WHERE aegis.remediation_projections.version < EXCLUDED.version
               OR aegis.remediation_projections.last_fact_digest
                    = EXCLUDED.last_fact_digest
            """,
            (
                projection.tenant_id,
                projection.plan_id,
                projection.run_id,
                projection.status.value,
                projection.version,
                projection.plan_digest,
                projection.approval_id,
                projection.approval_digest,
                projection.effect_receipt_digest,
                projection.verification_digest,
                projection.fence_token,
                projection.last_fact_digest,
                projection.updated_at,
            ),
        )
