"""Application-owned approval, effect, reconciliation, and verification controls."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from threading import Lock
from typing import Literal, Protocol

from pydantic import AwareDatetime, Field, JsonValue, model_validator

from aegis_framework.domain import (
    Citation,
    Identifier,
    IdentityContext,
    RiskLevel,
    Sha256Digest,
    StrictModel,
    stable_id,
)
from aegis_framework.errors import (
    ApprovalDenied,
    ApprovalExpired,
    ApprovalRevoked,
    ConcurrencyConflict,
    EffectAmbiguous,
    EffectConflict,
    IdempotencyConflict,
    IntegrityFailure,
    PolicyDenied,
    VerificationFailed,
)
from aegis_framework.ports import Action, ActionPort, ClockPort, PolicyPort

_MAX_FACTS = 500
_RISK_ORDER = {RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3}


def canonical_digest(value: StrictModel | Mapping[str, object]) -> str:
    """Hash a strict contract without relying on framework serialization order."""

    if isinstance(value, StrictModel):
        excluded = {"canonical_digest"}
        if type(value).__name__ == "RemediationPlan":
            excluded.add("plan_digest")
        if type(value).__name__ == "ActionPolicy":
            excluded.add("policy_digest")
        document: object = value.model_dump(mode="json", exclude=excluded)
    else:
        document = value
    return sha256(
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=_canonical_json_default,
        ).encode()
    ).hexdigest()


def _canonical_json_default(value: object) -> object:
    if isinstance(value, StrictModel):
        return value.model_dump(mode="json")
    if isinstance(value, datetime):
        encoded = value.isoformat()
        return encoded.replace("+00:00", "Z") if encoded.endswith("+00:00") else encoded
    raise TypeError(f"unsupported canonical value: {type(value).__name__}")


class BlastRadius(StrEnum):
    ONE_REPLICA_SET = "one-replica-set"
    ONE_SERVICE = "one-service"
    MULTI_SERVICE = "multi-service"


class RemediationStatus(StrEnum):
    PROPOSED = "proposed"
    APPROVAL_PENDING = "approval_pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"
    PREFLIGHT = "preflight"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    AMBIGUOUS = "ambiguous"
    RECONCILING = "reconciling"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    CANCELLED = "cancelled"
    VERIFIED = "verified"
    VERIFICATION_FAILED = "verification_failed"
    ESCALATED = "escalated"


class ApprovalDisposition(StrEnum):
    GRANT = "grant"
    DENY = "deny"
    REVOKE = "revoke"


class EffectOutcome(StrEnum):
    DRY_RUN_SUCCEEDED = "dry_run_succeeded"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    AMBIGUOUS = "ambiguous"
    DUPLICATE = "duplicate"
    CONFLICT = "conflict"
    COMPENSATED = "compensated"


class ObservationState(StrEnum):
    BEFORE = "before"
    APPLIED = "applied"
    NOT_APPLIED = "not_applied"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"
    RECOVERED = "recovered"


class Condition(StrictModel):
    fact: Identifier
    operator: Literal["equals", "not_equals", "greater_than", "less_than"]
    expected: str | int | float | bool


class KubernetesTarget(StrictModel):
    provider: Literal["kubernetes"] = "kubernetes"
    cluster_ref: Identifier
    namespace: Identifier
    kind: Literal["Deployment"] = "Deployment"
    name: Identifier
    uid: Identifier
    resource_version: Identifier
    resource_fingerprint: Sha256Digest


class RetryContract(StrictModel):
    owner: Literal["temporal"] = "temporal"
    maximum_attempts: int = Field(ge=1, le=5)
    attempt_timeout_seconds: int = Field(ge=5, le=900)
    schedule_timeout_seconds: int = Field(ge=5, le=3_600)
    heartbeat_timeout_seconds: int = Field(ge=5, le=120)
    observe_before_retry: Literal[True] = True


class CompensationContract(StrictModel):
    enabled: bool = False
    action: Literal["observe_only", "rollback_revision"] = "observe_only"
    rollback_revision: Identifier | None = None
    requires_fresh_approval: bool = True

    @model_validator(mode="after")
    def bind_rollback_revision(self) -> CompensationContract:
        if self.action == "rollback_revision" and self.rollback_revision is None:
            raise ValueError("rollback revision is required")
        if not self.enabled and self.action != "observe_only":
            raise ValueError("disabled compensation must be observe-only")
        return self


class ActionDefinition(StrictModel):
    schema_version: Literal[1] = 1
    action_id: Identifier
    action_type: Literal["kubernetes.rollout_restart"]
    target: KubernetesTarget
    risk: RiskLevel
    blast_radius: BlastRadius
    preconditions: tuple[Condition, ...] = Field(min_length=1, max_length=16)
    postconditions: tuple[Condition, ...] = Field(min_length=1, max_length=16)
    dry_run_required: Literal[True] = True
    retry: RetryContract
    idempotency_key: Identifier
    compensation: CompensationContract
    canonical_digest: Sha256Digest

    @model_validator(mode="after")
    def verify_digest(self) -> ActionDefinition:
        if self.canonical_digest != canonical_digest(self):
            raise ValueError("action canonical digest mismatch")
        return self


class PolicySnapshot(StrictModel):
    policy_id: Identifier
    revision: int = Field(ge=1)
    role_revision: int = Field(ge=1)
    quota_revision: int = Field(ge=1)
    policy_digest: Sha256Digest


class RemediationPlan(StrictModel):
    schema_version: Literal[1] = 1
    plan_id: Identifier
    tenant_id: Identifier
    run_id: Identifier
    incident_id: Identifier
    proposer_ref: Identifier
    target_fingerprint: Sha256Digest
    risk: RiskLevel
    blast_radius: BlastRadius
    rationale: str = Field(min_length=1, max_length=2_000)
    actions: tuple[ActionDefinition, ...] = Field(min_length=1, max_length=8)
    evidence: tuple[Citation, ...] = Field(min_length=1, max_length=64)
    critic_status: Literal["accepted"]
    policy_snapshot: PolicySnapshot
    created_at: AwareDatetime
    expires_at: AwareDatetime
    plan_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_plan(self) -> RemediationPlan:
        if self.expires_at <= self.created_at:
            raise ValueError("plan expiry must follow creation")
        if len({action.action_id for action in self.actions}) != len(self.actions):
            raise ValueError("action identifiers must be unique")
        if any(
            action.target.resource_fingerprint != self.target_fingerprint
            for action in self.actions
        ):
            raise ValueError("every action must bind the exact plan target")
        if any(
            _RISK_ORDER[action.risk] > _RISK_ORDER[self.risk] for action in self.actions
        ):
            raise ValueError("action risk cannot exceed plan risk")
        if self.plan_digest != canonical_digest(self):
            raise ValueError("plan canonical digest mismatch")
        return self


class ApprovalRequirement(StrictModel):
    quorum: int = Field(ge=1, le=5)
    required_roles: tuple[Identifier, ...] = Field(min_length=1, max_length=8)
    distinct_approvers: Literal[True] = True
    prohibit_self_approval: bool = True
    rationale_min_length: int = Field(ge=1, le=256)
    rationale_max_length: int = Field(ge=16, le=2_000)

    @model_validator(mode="after")
    def validate_rationale_bounds(self) -> ApprovalRequirement:
        if self.rationale_min_length > self.rationale_max_length:
            raise ValueError("approval rationale bounds are inverted")
        return self


class ActionApprovalRequest(StrictModel):
    schema_version: Literal[1] = 1
    approval_id: Identifier
    tenant_id: Identifier
    plan_id: Identifier
    run_id: Identifier
    plan_digest: Sha256Digest
    action_digests: tuple[Sha256Digest, ...] = Field(min_length=1, max_length=8)
    target_fingerprint: Sha256Digest
    policy_snapshot: PolicySnapshot
    requirement: ApprovalRequirement
    requested_by_ref: Identifier
    requested_at: AwareDatetime
    expires_at: AwareDatetime
    canonical_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_request(self) -> ActionApprovalRequest:
        if self.expires_at <= self.requested_at:
            raise ValueError("approval expiry must follow request")
        if self.canonical_digest != canonical_digest(self):
            raise ValueError("approval request digest mismatch")
        return self


class ApprovalDecision(StrictModel):
    schema_version: Literal[1] = 1
    decision_id: Identifier
    command_id: Identifier
    approval_id: Identifier
    tenant_id: Identifier
    disposition: Literal[ApprovalDisposition.GRANT, ApprovalDisposition.DENY]
    approver_ref: Identifier
    approver_role: Identifier
    purpose: Literal["incident-response"] = "incident-response"
    plan_digest: Sha256Digest
    approval_digest: Sha256Digest
    policy_digest: Sha256Digest
    role_revision: int = Field(ge=1)
    rationale: str = Field(min_length=1, max_length=2_000)
    decided_at: AwareDatetime
    canonical_digest: Sha256Digest

    @model_validator(mode="after")
    def verify_digest(self) -> ApprovalDecision:
        if self.canonical_digest != canonical_digest(self):
            raise ValueError("approval decision digest mismatch")
        return self


class ApprovalView(StrictModel):
    approval: ActionApprovalRequest
    decisions: tuple[ApprovalDecision, ...]
    status: RemediationStatus
    version: int = Field(ge=1)
    grants: int = Field(ge=0)


class ActionIntent(StrictModel):
    schema_version: Literal[1] = 1
    tenant_id: Identifier
    run_id: Identifier
    plan_id: Identifier
    action: ActionDefinition
    plan_digest: Sha256Digest
    approval_digest: Sha256Digest
    policy_digest: Sha256Digest
    operation_id: Identifier
    attempt: int = Field(ge=1, le=16)
    fence_token: Identifier
    requested_at: AwareDatetime
    dry_run: bool = False


class ActionObservation(StrictModel):
    schema_version: Literal[1] = 1
    tenant_id: Identifier
    plan_id: Identifier
    action_id: Identifier
    operation_id: Identifier
    target_fingerprint: Sha256Digest
    state: ObservationState
    facts: dict[Identifier, str | int | float | bool] = Field(max_length=32)
    observed_at: AwareDatetime
    provider_receipt_ref: Identifier | None = None
    attempt_fence: Identifier


class ActionReceipt(StrictModel):
    schema_version: Literal[1] = 1
    tenant_id: Identifier
    plan_id: Identifier
    action_id: Identifier
    operation_id: Identifier
    idempotency_key: Identifier
    fence_token: Identifier
    attempt: int = Field(ge=1, le=16)
    outcome: EffectOutcome
    provider_receipt_ref: Identifier | None = None
    target_fingerprint: Sha256Digest
    recorded_at: AwareDatetime
    detail_code: Identifier
    canonical_digest: Sha256Digest

    @model_validator(mode="after")
    def verify_digest(self) -> ActionReceipt:
        if self.canonical_digest != canonical_digest(self):
            raise ValueError("effect receipt digest mismatch")
        return self


class VerificationRecord(StrictModel):
    schema_version: Literal[1] = 1
    verification_id: Identifier
    tenant_id: Identifier
    plan_id: Identifier
    action_id: Identifier
    effect_receipt_digest: Sha256Digest
    fresh_evidence: tuple[Citation, ...] = Field(min_length=1, max_length=32)
    observation: ActionObservation
    postconditions_satisfied: bool
    verified_at: AwareDatetime
    canonical_digest: Sha256Digest

    @model_validator(mode="after")
    def verify_digest(self) -> VerificationRecord:
        if self.canonical_digest != canonical_digest(self):
            raise ValueError("verification record digest mismatch")
        return self


class RemediationFactType(StrEnum):
    PROPOSAL_RECORDED = "remediation.proposal_recorded"
    POLICY_DECIDED = "remediation.policy_decided"
    APPROVAL_REQUESTED = "remediation.approval_requested"
    APPROVAL_GRANTED = "remediation.approval_granted"
    APPROVAL_DENIED = "remediation.approval_denied"
    APPROVAL_EXPIRED = "remediation.approval_expired"
    APPROVAL_REVOKED = "remediation.approval_revoked"
    PREFLIGHT_REQUESTED = "remediation.preflight_requested"
    DRY_RUN_SUCCEEDED = "remediation.dry_run_succeeded"
    EXECUTION_REQUESTED = "remediation.execution_requested"
    EXECUTION_STARTED = "remediation.execution_started"
    EXECUTION_SUCCEEDED = "remediation.execution_succeeded"
    EXECUTION_FAILED = "remediation.execution_failed"
    EXECUTION_AMBIGUOUS = "remediation.execution_ambiguous"
    RECONCILIATION_STARTED = "remediation.reconciliation_started"
    RECONCILIATION_RESOLVED = "remediation.reconciliation_resolved"
    ROLLBACK_REQUESTED = "remediation.rollback_requested"
    ROLLBACK_SUCCEEDED = "remediation.rollback_succeeded"
    ROLLBACK_FAILED = "remediation.rollback_failed"
    CANCELLATION_REQUESTED = "remediation.cancellation_requested"
    CANCELLED = "remediation.cancelled"
    VERIFICATION_REQUESTED = "remediation.verification_requested"
    VERIFIED = "remediation.verified"
    VERIFICATION_FAILED = "remediation.verification_failed"
    ESCALATED = "remediation.escalated"


class RemediationFact(StrictModel):
    schema_version: Literal[1] = 1
    tenant_id: Identifier
    plan_id: Identifier
    sequence: int = Field(ge=1)
    fact_id: Identifier
    fact_type: RemediationFactType
    command_id: Identifier
    actor_ref: Identifier
    recorded_at: AwareDatetime
    payload: dict[str, JsonValue] = Field(default_factory=dict, max_length=32)
    previous_digest: Sha256Digest
    canonical_digest: Sha256Digest


class RemediationProjection(StrictModel):
    tenant_id: Identifier
    plan_id: Identifier
    run_id: Identifier
    status: RemediationStatus
    version: int = Field(ge=1)
    plan_digest: Sha256Digest
    approval_id: Identifier | None = None
    approval_digest: Sha256Digest | None = None
    effect_receipt_digest: Sha256Digest | None = None
    verification_digest: Sha256Digest | None = None
    fence_token: Identifier
    last_fact_digest: Sha256Digest
    updated_at: AwareDatetime


class ActionPolicy(StrictModel):
    tenant_id: Identifier
    policy_id: Identifier
    revision: int = Field(ge=1)
    role_revision: int = Field(ge=1)
    quota_revision: int = Field(ge=1)
    enabled: bool = False
    allowed_action_types: tuple[Identifier, ...] = ()
    allowed_target_fingerprints: tuple[Sha256Digest, ...] = ()
    allowed_namespaces: tuple[Identifier, ...] = ()
    maintenance_window_start: AwareDatetime
    maintenance_window_end: AwareDatetime
    max_risk: RiskLevel
    max_blast_radius: BlastRadius
    remaining_effects: int = Field(ge=0)
    high_risk_quorum: int = Field(ge=2, le=5)
    normal_quorum: int = Field(ge=1, le=5)
    approver_roles: tuple[Identifier, ...] = Field(min_length=1, max_length=8)
    prohibit_self_approval: bool = True
    require_accepted_critic: Literal[True] = True
    policy_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_policy(self) -> ActionPolicy:
        if self.maintenance_window_end <= self.maintenance_window_start:
            raise ValueError("maintenance window is invalid")
        if self.policy_digest != canonical_digest(self):
            raise ValueError("action policy digest mismatch")
        return self

    def snapshot(self) -> PolicySnapshot:
        return PolicySnapshot(
            policy_id=self.policy_id,
            revision=self.revision,
            role_revision=self.role_revision,
            quota_revision=self.quota_revision,
            policy_digest=self.policy_digest,
        )


class ActionPolicyStore(Protocol):
    def current(self, *, tenant_id: str) -> ActionPolicy | None: ...


class EffectQuotaDecision(StrictModel):
    allowed: bool
    reservation_id: Identifier
    units: int = Field(ge=1)
    reason: Identifier


class EffectQuotaPort(Protocol):
    def reserve(
        self,
        *,
        tenant_id: str,
        plan_id: str,
        reservation_id: str,
        policy_digest: str,
        units: int,
        requested_at: datetime,
    ) -> EffectQuotaDecision: ...


class EffectClaimRecord(StrictModel):
    claim_token: Identifier
    fence_token: Identifier
    attempt: int = Field(ge=1, le=16)
    replayed: bool
    receipt: ActionReceipt | None = None


class EffectClaimPort(Protocol):
    def claim(
        self,
        intent: ActionIntent,
        *,
        worker_ref: str,
        now: datetime,
        claim_until: datetime,
    ) -> EffectClaimRecord: ...

    def complete(
        self,
        receipt: ActionReceipt,
        *,
        claim_token: str,
        now: datetime,
    ) -> None: ...


class _InMemoryEffectClaim(StrictModel):
    action_digest: Sha256Digest
    plan_digest: Sha256Digest
    approval_digest: Sha256Digest
    policy_digest: Sha256Digest
    target_fingerprint: Sha256Digest
    fence_token: Identifier
    attempt: int = Field(ge=1, le=16)
    claim_token: Identifier
    claim_until: AwareDatetime
    receipt: ActionReceipt | None = None


class InMemoryEffectClaims:
    def __init__(self) -> None:
        self._claims: dict[tuple[str, str], _InMemoryEffectClaim] = {}
        self._lock = Lock()

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
        key = (intent.tenant_id, intent.operation_id)
        token = stable_id(
            "effect-claim",
            intent.tenant_id,
            intent.operation_id,
            worker_ref,
            str(intent.attempt),
            intent.fence_token,
            length=40,
        )
        binding = (
            intent.action.canonical_digest,
            intent.plan_digest,
            intent.approval_digest,
            intent.policy_digest,
            intent.action.target.resource_fingerprint,
            intent.fence_token,
        )
        with self._lock:
            existing = self._claims.get(key)
            if existing is not None:
                existing_binding = (
                    existing.action_digest,
                    existing.plan_digest,
                    existing.approval_digest,
                    existing.policy_digest,
                    existing.target_fingerprint,
                    existing.fence_token,
                )
                if existing_binding != binding:
                    raise EffectConflict("effect claim exact binding changed")
                if (
                    existing.receipt is None
                    and existing.claim_until > now
                    and existing.claim_token != token
                ):
                    raise ConcurrencyConflict("effect attempt is actively claimed")
                if existing.receipt is None and existing.claim_until <= now:
                    if intent.attempt <= existing.attempt:
                        raise ConcurrencyConflict(
                            "effect retry attempt did not advance"
                        )
                    existing = existing.model_copy(
                        update={
                            "attempt": intent.attempt,
                            "claim_token": token,
                            "claim_until": claim_until,
                        }
                    )
                    self._claims[key] = existing
                return EffectClaimRecord(
                    claim_token=existing.claim_token,
                    fence_token=existing.fence_token,
                    attempt=existing.attempt,
                    replayed=True,
                    receipt=existing.receipt,
                )
            self._claims[key] = _InMemoryEffectClaim(
                action_digest=intent.action.canonical_digest,
                plan_digest=intent.plan_digest,
                approval_digest=intent.approval_digest,
                policy_digest=intent.policy_digest,
                target_fingerprint=intent.action.target.resource_fingerprint,
                fence_token=intent.fence_token,
                attempt=intent.attempt,
                claim_token=token,
                claim_until=claim_until,
            )
            return EffectClaimRecord(
                claim_token=token,
                fence_token=intent.fence_token,
                attempt=intent.attempt,
                replayed=False,
            )

    def complete(
        self,
        receipt: ActionReceipt,
        *,
        claim_token: str,
        now: datetime,
    ) -> None:
        del now
        key = (receipt.tenant_id, receipt.operation_id)
        with self._lock:
            existing = self._claims.get(key)
            if (
                existing is None
                or existing.claim_token != claim_token
                or existing.fence_token != receipt.fence_token
                or existing.attempt != receipt.attempt
            ):
                raise ConcurrencyConflict("stale effect claim completion rejected")
            if existing.receipt is not None:
                if existing.receipt.canonical_digest != receipt.canonical_digest:
                    raise IdempotencyConflict("effect claim receipt changed")
                return
            self._claims[key] = existing.model_copy(update={"receipt": receipt})


class InMemoryEffectQuota:
    def __init__(self, limits: Mapping[str, int]) -> None:
        self._remaining = dict(limits)
        self._reservations: dict[tuple[str, str], EffectQuotaDecision] = {}
        self._lock = Lock()

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
        del plan_id, policy_digest, requested_at
        if units < 1:
            raise ValueError("effect quota units must be positive")
        key = (tenant_id, reservation_id)
        with self._lock:
            existing = self._reservations.get(key)
            if existing is not None:
                return existing
            remaining = self._remaining.get(tenant_id, 0)
            allowed = remaining >= units
            decision = EffectQuotaDecision(
                allowed=allowed,
                reservation_id=reservation_id,
                units=units,
                reason="reserved" if allowed else "effect_quota_exhausted",
            )
            self._reservations[key] = decision
            if allowed:
                self._remaining[tenant_id] = remaining - units
            return decision


class InMemoryActionPolicyStore:
    def __init__(self, policies: Sequence[ActionPolicy] = ()) -> None:
        self._policies = {policy.tenant_id: policy for policy in policies}
        self._lock = Lock()

    def current(self, *, tenant_id: str) -> ActionPolicy | None:
        with self._lock:
            return self._policies.get(tenant_id)

    def replace(self, policy: ActionPolicy) -> None:
        with self._lock:
            current = self._policies.get(policy.tenant_id)
            if current is not None and policy.revision <= current.revision:
                raise ConcurrencyConflict("action policy revision did not advance")
            self._policies[policy.tenant_id] = policy


class RemediationLedger(Protocol):
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
    ) -> RemediationProjection: ...

    def projection(
        self, *, tenant_id: str, plan_id: str
    ) -> RemediationProjection | None: ...

    def facts(self, *, tenant_id: str, plan_id: str) -> tuple[RemediationFact, ...]: ...


class InMemoryRemediationLedger:
    """Reference append-only ledger with pure deterministic projection replay."""

    def __init__(self) -> None:
        self._facts: dict[tuple[str, str], list[RemediationFact]] = {}
        self._commands: dict[tuple[str, str], tuple[str, str]] = {}
        self._projections: dict[tuple[str, str], RemediationProjection] = {}
        self._lock = Lock()

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
        key = (tenant_id, plan_id)
        fingerprint = canonical_digest(
            {
                "fact_type": fact_type.value,
                "payload": dict(payload),
            }
        )
        with self._lock:
            command_key = (tenant_id, command_id)
            existing_command = self._commands.get(command_key)
            if existing_command is not None:
                if existing_command != (plan_id, fingerprint):
                    raise IdempotencyConflict(
                        "command id was replayed with different remediation input"
                    )
                return self._projections[key]
            facts = self._facts.setdefault(key, [])
            if len(facts) >= _MAX_FACTS:
                raise IntegrityFailure("remediation fact bound exceeded")
            if len(facts) != expected_version:
                raise ConcurrencyConflict("remediation aggregate version changed")
            previous = facts[-1].canonical_digest if facts else "0" * 64
            sequence = len(facts) + 1
            document: dict[str, JsonValue] = dict(sorted(payload.items()))
            material: dict[str, JsonValue] = {
                "actor_ref": actor_ref,
                "command_id": command_id,
                "fact_id": stable_id(
                    "remediation-fact",
                    tenant_id,
                    plan_id,
                    str(sequence),
                    command_id,
                    length=32,
                ),
                "fact_type": fact_type.value,
                "payload": document,
                "plan_id": plan_id,
                "previous_digest": previous,
                "recorded_at": recorded_at.isoformat(),
                "schema_version": 1,
                "sequence": sequence,
                "tenant_id": tenant_id,
            }
            fact = RemediationFact(
                tenant_id=tenant_id,
                plan_id=plan_id,
                sequence=sequence,
                fact_id=str(material["fact_id"]),
                fact_type=fact_type,
                command_id=command_id,
                actor_ref=actor_ref,
                recorded_at=recorded_at,
                payload=document,
                previous_digest=previous,
                canonical_digest=canonical_digest(material),
            )
            projection = reduce_remediation(
                self._projections.get(key),
                fact,
            )
            facts.append(fact)
            self._commands[command_key] = (plan_id, fingerprint)
            self._projections[key] = projection
            return projection

    def projection(
        self, *, tenant_id: str, plan_id: str
    ) -> RemediationProjection | None:
        with self._lock:
            return self._projections.get((tenant_id, plan_id))

    def facts(self, *, tenant_id: str, plan_id: str) -> tuple[RemediationFact, ...]:
        with self._lock:
            return tuple(self._facts.get((tenant_id, plan_id), ()))

    def rebuild(self, *, tenant_id: str, plan_id: str) -> RemediationProjection:
        with self._lock:
            projection: RemediationProjection | None = None
            for fact in self._facts.get((tenant_id, plan_id), ()):
                projection = reduce_remediation(projection, fact)
            if projection is None:
                raise IntegrityFailure("cannot rebuild an unknown remediation plan")
            return projection


def reduce_remediation(
    current: RemediationProjection | None,
    fact: RemediationFact,
) -> RemediationProjection:
    """Pure fold over additive facts; framework history is never consulted."""

    status_by_fact = {
        RemediationFactType.PROPOSAL_RECORDED: RemediationStatus.PROPOSED,
        RemediationFactType.POLICY_DECIDED: RemediationStatus.PROPOSED,
        RemediationFactType.APPROVAL_REQUESTED: RemediationStatus.APPROVAL_PENDING,
        RemediationFactType.APPROVAL_GRANTED: RemediationStatus.APPROVED,
        RemediationFactType.APPROVAL_DENIED: RemediationStatus.DENIED,
        RemediationFactType.APPROVAL_EXPIRED: RemediationStatus.EXPIRED,
        RemediationFactType.APPROVAL_REVOKED: RemediationStatus.REVOKED,
        RemediationFactType.PREFLIGHT_REQUESTED: RemediationStatus.PREFLIGHT,
        RemediationFactType.DRY_RUN_SUCCEEDED: RemediationStatus.PREFLIGHT,
        RemediationFactType.EXECUTION_REQUESTED: RemediationStatus.EXECUTING,
        RemediationFactType.EXECUTION_STARTED: RemediationStatus.EXECUTING,
        RemediationFactType.EXECUTION_SUCCEEDED: RemediationStatus.SUCCEEDED,
        RemediationFactType.EXECUTION_FAILED: RemediationStatus.FAILED,
        RemediationFactType.EXECUTION_AMBIGUOUS: RemediationStatus.AMBIGUOUS,
        RemediationFactType.RECONCILIATION_STARTED: RemediationStatus.RECONCILING,
        RemediationFactType.RECONCILIATION_RESOLVED: RemediationStatus.SUCCEEDED,
        RemediationFactType.ROLLBACK_REQUESTED: RemediationStatus.ROLLING_BACK,
        RemediationFactType.ROLLBACK_SUCCEEDED: RemediationStatus.ROLLED_BACK,
        RemediationFactType.ROLLBACK_FAILED: RemediationStatus.ESCALATED,
        RemediationFactType.CANCELLATION_REQUESTED: RemediationStatus.CANCELLED,
        RemediationFactType.CANCELLED: RemediationStatus.CANCELLED,
        RemediationFactType.VERIFICATION_REQUESTED: RemediationStatus.SUCCEEDED,
        RemediationFactType.VERIFIED: RemediationStatus.VERIFIED,
        RemediationFactType.VERIFICATION_FAILED: RemediationStatus.VERIFICATION_FAILED,
        RemediationFactType.ESCALATED: RemediationStatus.ESCALATED,
    }
    status = status_by_fact[fact.fact_type]
    if current is None:
        if fact.fact_type is not RemediationFactType.PROPOSAL_RECORDED:
            raise IntegrityFailure("remediation replay must start with proposal")
        try:
            return RemediationProjection(
                tenant_id=fact.tenant_id,
                plan_id=fact.plan_id,
                run_id=str(fact.payload["run_id"]),
                status=status,
                version=1,
                plan_digest=str(fact.payload["plan_digest"]),
                fence_token=str(fact.payload["fence_token"]),
                last_fact_digest=fact.canonical_digest,
                updated_at=fact.recorded_at,
            )
        except KeyError as exc:
            raise IntegrityFailure("proposal fact is incomplete") from exc
    if fact.sequence != current.version + 1:
        raise IntegrityFailure("remediation replay sequence is not contiguous")
    if fact.previous_digest != current.last_fact_digest:
        raise IntegrityFailure("remediation fact chain is invalid")
    _validate_transition(current.status, status)
    changes: dict[str, object] = {
        "status": status,
        "version": fact.sequence,
        "last_fact_digest": fact.canonical_digest,
        "updated_at": fact.recorded_at,
    }
    if fact.fact_type is RemediationFactType.APPROVAL_REQUESTED:
        changes["approval_id"] = str(fact.payload["approval_id"])
        changes["approval_digest"] = str(fact.payload["approval_digest"])
    if fact.fact_type in {
        RemediationFactType.EXECUTION_SUCCEEDED,
        RemediationFactType.RECONCILIATION_RESOLVED,
        RemediationFactType.ROLLBACK_SUCCEEDED,
    }:
        receipt = fact.payload.get("effect_receipt_digest")
        if isinstance(receipt, str):
            changes["effect_receipt_digest"] = receipt
    if fact.fact_type in {
        RemediationFactType.VERIFIED,
        RemediationFactType.VERIFICATION_FAILED,
    }:
        verification = fact.payload.get("verification_digest")
        if isinstance(verification, str):
            changes["verification_digest"] = verification
    return current.model_copy(update=changes)


def _validate_transition(
    previous: RemediationStatus,
    current: RemediationStatus,
) -> None:
    terminal = {
        RemediationStatus.DENIED,
        RemediationStatus.EXPIRED,
        RemediationStatus.REVOKED,
        RemediationStatus.ROLLED_BACK,
        RemediationStatus.CANCELLED,
        RemediationStatus.VERIFIED,
        RemediationStatus.ESCALATED,
    }
    if previous in terminal:
        raise IntegrityFailure("terminal remediation state cannot advance")
    allowed: dict[RemediationStatus, frozenset[RemediationStatus]] = {
        RemediationStatus.PROPOSED: frozenset(
            {RemediationStatus.PROPOSED, RemediationStatus.APPROVAL_PENDING}
        ),
        RemediationStatus.APPROVAL_PENDING: frozenset(
            {
                RemediationStatus.APPROVAL_PENDING,
                RemediationStatus.APPROVED,
                RemediationStatus.DENIED,
                RemediationStatus.EXPIRED,
                RemediationStatus.REVOKED,
                RemediationStatus.CANCELLED,
            }
        ),
        RemediationStatus.APPROVED: frozenset(
            {
                RemediationStatus.PREFLIGHT,
                RemediationStatus.REVOKED,
                RemediationStatus.CANCELLED,
            }
        ),
        RemediationStatus.PREFLIGHT: frozenset(
            {
                RemediationStatus.PREFLIGHT,
                RemediationStatus.EXECUTING,
                RemediationStatus.FAILED,
                RemediationStatus.CANCELLED,
            }
        ),
        RemediationStatus.EXECUTING: frozenset(
            {
                RemediationStatus.EXECUTING,
                RemediationStatus.SUCCEEDED,
                RemediationStatus.FAILED,
                RemediationStatus.AMBIGUOUS,
                RemediationStatus.CANCELLED,
            }
        ),
        RemediationStatus.SUCCEEDED: frozenset(
            {
                RemediationStatus.SUCCEEDED,
                RemediationStatus.VERIFIED,
                RemediationStatus.VERIFICATION_FAILED,
                RemediationStatus.ROLLING_BACK,
            }
        ),
        RemediationStatus.FAILED: frozenset(
            {
                RemediationStatus.ROLLING_BACK,
                RemediationStatus.ESCALATED,
            }
        ),
        RemediationStatus.AMBIGUOUS: frozenset(
            {RemediationStatus.RECONCILING, RemediationStatus.ESCALATED}
        ),
        RemediationStatus.RECONCILING: frozenset(
            {
                RemediationStatus.SUCCEEDED,
                RemediationStatus.FAILED,
                RemediationStatus.ESCALATED,
            }
        ),
        RemediationStatus.ROLLING_BACK: frozenset(
            {RemediationStatus.ROLLED_BACK, RemediationStatus.ESCALATED}
        ),
        RemediationStatus.VERIFICATION_FAILED: frozenset(
            {RemediationStatus.ROLLING_BACK, RemediationStatus.ESCALATED}
        ),
    }
    if current not in allowed.get(previous, frozenset()):
        raise IntegrityFailure(
            f"illegal remediation transition {previous.value}->{current.value}"
        )


class RemediationControlStore(Protocol):
    def put_plan(self, plan: RemediationPlan) -> None: ...

    def plan(self, *, tenant_id: str, plan_id: str) -> RemediationPlan | None: ...

    def put_approval(self, approval: ActionApprovalRequest) -> None: ...

    def approval(
        self, *, tenant_id: str, approval_id: str
    ) -> ActionApprovalRequest | None: ...

    def add_decision(self, decision: ApprovalDecision) -> None: ...

    def decisions(
        self, *, tenant_id: str, approval_id: str
    ) -> tuple[ApprovalDecision, ...]: ...

    def put_verification(self, verification: VerificationRecord) -> None: ...

    def verification(
        self, *, tenant_id: str, verification_id: str
    ) -> VerificationRecord | None: ...


class InMemoryRemediationControlStore:
    def __init__(self) -> None:
        self._plans: dict[tuple[str, str], RemediationPlan] = {}
        self._approvals: dict[tuple[str, str], ActionApprovalRequest] = {}
        self._decisions: dict[tuple[str, str], list[ApprovalDecision]] = {}
        self._decision_commands: dict[tuple[str, str], str] = {}
        self._verifications: dict[tuple[str, str], VerificationRecord] = {}
        self._lock = Lock()

    def put_plan(self, plan: RemediationPlan) -> None:
        with self._lock:
            key = (plan.tenant_id, plan.plan_id)
            existing = self._plans.get(key)
            if existing is not None and existing.plan_digest != plan.plan_digest:
                raise IdempotencyConflict("plan id was reused with different content")
            self._plans[key] = plan

    def plan(self, *, tenant_id: str, plan_id: str) -> RemediationPlan | None:
        with self._lock:
            return self._plans.get((tenant_id, plan_id))

    def put_approval(self, approval: ActionApprovalRequest) -> None:
        with self._lock:
            key = (approval.tenant_id, approval.approval_id)
            existing = self._approvals.get(key)
            if (
                existing is not None
                and existing.canonical_digest != approval.canonical_digest
            ):
                raise IdempotencyConflict(
                    "approval id was reused with different exact scope"
                )
            self._approvals[key] = approval

    def approval(
        self, *, tenant_id: str, approval_id: str
    ) -> ActionApprovalRequest | None:
        with self._lock:
            return self._approvals.get((tenant_id, approval_id))

    def add_decision(self, decision: ApprovalDecision) -> None:
        with self._lock:
            command_key = (decision.tenant_id, decision.command_id)
            existing = self._decision_commands.get(command_key)
            if existing is not None:
                if existing != decision.canonical_digest:
                    raise IdempotencyConflict(
                        "approval command replay changed immutable decision"
                    )
                return
            key = (decision.tenant_id, decision.approval_id)
            decisions = self._decisions.setdefault(key, [])
            if any(item.approver_ref == decision.approver_ref for item in decisions):
                raise IdempotencyConflict("approver already decided this approval")
            decisions.append(decision)
            self._decision_commands[command_key] = decision.canonical_digest

    def decisions(
        self, *, tenant_id: str, approval_id: str
    ) -> tuple[ApprovalDecision, ...]:
        with self._lock:
            return tuple(self._decisions.get((tenant_id, approval_id), ()))

    def put_verification(self, verification: VerificationRecord) -> None:
        with self._lock:
            key = (verification.tenant_id, verification.verification_id)
            existing = self._verifications.get(key)
            if (
                existing is not None
                and existing.canonical_digest != verification.canonical_digest
            ):
                raise IdempotencyConflict("verification replay changed")
            self._verifications[key] = verification

    def verification(
        self,
        *,
        tenant_id: str,
        verification_id: str,
    ) -> VerificationRecord | None:
        with self._lock:
            return self._verifications.get((tenant_id, verification_id))


class ApprovalService:
    """Exact-scope authenticated approval with SoD, quorum, and replay guards."""

    def __init__(
        self,
        *,
        policy: PolicyPort,
        action_policies: ActionPolicyStore,
        ledger: RemediationLedger,
        store: RemediationControlStore,
        clock: ClockPort,
    ) -> None:
        self._policy = policy
        self._action_policies = action_policies
        self._ledger = ledger
        self._store = store
        self._clock = clock

    def propose(
        self,
        identity: IdentityContext,
        plan: RemediationPlan,
        *,
        command_id: str,
    ) -> RemediationProjection:
        self._authorize(identity, Action.REMEDIATION_PROPOSE, plan.risk)
        if plan.tenant_id != identity.tenant_id:
            raise PolicyDenied("tenant_mismatch")
        current = self._require_action_policy(plan, consume_quota=False)
        if current.snapshot() != plan.policy_snapshot:
            raise PolicyDenied("plan_policy_snapshot_is_not_current")
        self._store.put_plan(plan)
        fence = stable_id(
            "effect-fence",
            plan.tenant_id,
            plan.plan_id,
            plan.plan_digest,
            length=32,
        )
        actor = _actor_ref(identity)
        projection = self._ledger.append(
            tenant_id=plan.tenant_id,
            plan_id=plan.plan_id,
            expected_version=0,
            fact_type=RemediationFactType.PROPOSAL_RECORDED,
            command_id=command_id,
            actor_ref=actor,
            recorded_at=self._clock.now(),
            payload={
                "run_id": plan.run_id,
                "plan_digest": plan.plan_digest,
                "fence_token": fence,
            },
        )
        return self._ledger.append(
            tenant_id=plan.tenant_id,
            plan_id=plan.plan_id,
            expected_version=projection.version,
            fact_type=RemediationFactType.POLICY_DECIDED,
            command_id=f"{command_id}:policy",
            actor_ref=actor,
            recorded_at=self._clock.now(),
            payload={
                "allowed": True,
                "policy_digest": current.policy_digest,
                "policy_revision": current.revision,
            },
        )

    def request_approval(
        self,
        identity: IdentityContext,
        *,
        plan_id: str,
        expected_version: int,
        command_id: str,
    ) -> ApprovalView:
        self._authorize(identity, Action.APPROVAL_REQUEST, RiskLevel.HIGH)
        plan = self._require_plan(identity.tenant_id, plan_id)
        current = self._require_action_policy(plan, consume_quota=False)
        quorum = (
            current.high_risk_quorum
            if plan.risk is RiskLevel.HIGH
            else current.normal_quorum
        )
        now = self._clock.now()
        requirement = ApprovalRequirement(
            quorum=quorum,
            required_roles=current.approver_roles,
            prohibit_self_approval=current.prohibit_self_approval,
            rationale_min_length=12,
            rationale_max_length=1_000,
        )
        material = {
            "schema_version": 1,
            "approval_id": stable_id(
                "approval", plan.tenant_id, plan.plan_id, plan.plan_digest, length=32
            ),
            "tenant_id": plan.tenant_id,
            "plan_id": plan.plan_id,
            "run_id": plan.run_id,
            "plan_digest": plan.plan_digest,
            "action_digests": tuple(action.canonical_digest for action in plan.actions),
            "target_fingerprint": plan.target_fingerprint,
            "policy_snapshot": current.snapshot(),
            "requirement": requirement,
            "requested_by_ref": _actor_ref(identity),
            "requested_at": now,
            "expires_at": min(plan.expires_at, now + timedelta(hours=2)),
        }
        approval = ActionApprovalRequest(
            **material,
            canonical_digest=canonical_digest(material),
        )
        self._store.put_approval(approval)
        projection = self._ledger.append(
            tenant_id=plan.tenant_id,
            plan_id=plan.plan_id,
            expected_version=expected_version,
            fact_type=RemediationFactType.APPROVAL_REQUESTED,
            command_id=command_id,
            actor_ref=_actor_ref(identity),
            recorded_at=now,
            payload={
                "approval_id": approval.approval_id,
                "approval_digest": approval.canonical_digest,
                "expires_at": approval.expires_at.isoformat(),
                "quorum": quorum,
            },
        )
        return ApprovalView(
            approval=approval,
            decisions=(),
            status=projection.status,
            version=projection.version,
            grants=0,
        )

    def decide(
        self,
        identity: IdentityContext,
        *,
        approval_id: str,
        disposition: Literal[ApprovalDisposition.GRANT, ApprovalDisposition.DENY],
        rationale: str,
        expected_version: int,
        command_id: str,
        plan_digest: str,
        approval_digest: str,
    ) -> ApprovalView:
        self._authorize(identity, Action.APPROVAL_DECIDE, RiskLevel.HIGH)
        if identity.principal_kind.value != "human":
            raise PolicyDenied("approval_requires_human_principal")
        approval = self._require_approval(identity.tenant_id, approval_id)
        plan = self._require_plan(identity.tenant_id, approval.plan_id)
        projection = self._ledger.projection(
            tenant_id=identity.tenant_id,
            plan_id=plan.plan_id,
        )
        if projection is None or projection.approval_id != approval_id:
            raise IntegrityFailure("approval projection binding is invalid")
        if projection.version != expected_version:
            raise ConcurrencyConflict("approval aggregate version changed")
        if projection.status is not RemediationStatus.APPROVAL_PENDING:
            raise IntegrityFailure("approval is already terminal")
        policy = self._require_action_policy(plan, consume_quota=False)
        now = self._clock.now()
        if approval.expires_at <= now or plan.expires_at <= now:
            self._ledger.append(
                tenant_id=plan.tenant_id,
                plan_id=plan.plan_id,
                expected_version=expected_version,
                fact_type=RemediationFactType.APPROVAL_EXPIRED,
                command_id=command_id,
                actor_ref=_actor_ref(identity),
                recorded_at=now,
                payload={"approval_id": approval_id},
            )
            raise ApprovalExpired("approval has expired")
        if plan_digest != plan.plan_digest or approval.plan_digest != plan.plan_digest:
            raise PolicyDenied("plan_digest_changed")
        if (
            approval_digest != approval.canonical_digest
            or approval.policy_snapshot != policy.snapshot()
        ):
            raise PolicyDenied("approval_or_policy_digest_changed")
        actor = _actor_ref(identity)
        if approval.requirement.prohibit_self_approval and actor == plan.proposer_ref:
            raise PolicyDenied("self_approval_prohibited")
        matching_roles = sorted(
            set(identity.roles).intersection(approval.requirement.required_roles)
        )
        if not matching_roles:
            raise PolicyDenied("approver_role_not_permitted")
        if not (
            approval.requirement.rationale_min_length
            <= len(rationale)
            <= approval.requirement.rationale_max_length
        ):
            raise PolicyDenied("approval_rationale_outside_bounds")
        material = {
            "schema_version": 1,
            "decision_id": stable_id(
                "decision",
                identity.tenant_id,
                approval_id,
                actor,
                command_id,
                length=32,
            ),
            "command_id": command_id,
            "approval_id": approval_id,
            "tenant_id": identity.tenant_id,
            "disposition": disposition,
            "approver_ref": actor,
            "approver_role": matching_roles[0],
            "purpose": "incident-response",
            "plan_digest": plan.plan_digest,
            "approval_digest": approval.canonical_digest,
            "policy_digest": policy.policy_digest,
            "role_revision": policy.role_revision,
            "rationale": rationale,
            "decided_at": now,
        }
        decision = ApprovalDecision(
            **material,
            canonical_digest=canonical_digest(material),
        )
        self._store.add_decision(decision)
        decisions = self._store.decisions(
            tenant_id=identity.tenant_id,
            approval_id=approval_id,
        )
        if disposition is ApprovalDisposition.DENY:
            fact_type = RemediationFactType.APPROVAL_DENIED
            status = RemediationStatus.DENIED
        else:
            grants = {
                item.approver_ref
                for item in decisions
                if item.disposition is ApprovalDisposition.GRANT
            }
            fact_type = (
                RemediationFactType.APPROVAL_GRANTED
                if len(grants) >= approval.requirement.quorum
                else RemediationFactType.APPROVAL_REQUESTED
            )
            status = (
                RemediationStatus.APPROVED
                if fact_type is RemediationFactType.APPROVAL_GRANTED
                else RemediationStatus.APPROVAL_PENDING
            )
        projection = self._ledger.append(
            tenant_id=plan.tenant_id,
            plan_id=plan.plan_id,
            expected_version=expected_version,
            fact_type=fact_type,
            command_id=command_id,
            actor_ref=actor,
            recorded_at=now,
            payload={
                "approval_id": approval_id,
                "approval_digest": approval.canonical_digest,
                "decision_digest": decision.canonical_digest,
                "grant_count": sum(
                    item.disposition is ApprovalDisposition.GRANT for item in decisions
                ),
            },
        )
        if projection.status is not status:
            raise IntegrityFailure("approval projection status mismatch")
        return ApprovalView(
            approval=approval,
            decisions=decisions,
            status=projection.status,
            version=projection.version,
            grants=sum(
                item.disposition is ApprovalDisposition.GRANT for item in decisions
            ),
        )

    def revoke(
        self,
        identity: IdentityContext,
        *,
        approval_id: str,
        expected_version: int,
        command_id: str,
        rationale: str,
    ) -> RemediationProjection:
        self._authorize(identity, Action.APPROVAL_REVOKE, RiskLevel.HIGH)
        if len(rationale) < 12:
            raise PolicyDenied("revocation_rationale_too_short")
        approval = self._require_approval(identity.tenant_id, approval_id)
        projection = self._ledger.projection(
            tenant_id=identity.tenant_id,
            plan_id=approval.plan_id,
        )
        if projection is None or projection.approval_id != approval_id:
            raise IntegrityFailure("approval projection binding is invalid")
        if projection.version != expected_version:
            raise ConcurrencyConflict("approval aggregate version changed")
        if projection.status not in {
            RemediationStatus.APPROVAL_PENDING,
            RemediationStatus.APPROVED,
        }:
            raise IntegrityFailure("approval is already terminal")
        return self._ledger.append(
            tenant_id=identity.tenant_id,
            plan_id=approval.plan_id,
            expected_version=expected_version,
            fact_type=RemediationFactType.APPROVAL_REVOKED,
            command_id=command_id,
            actor_ref=_actor_ref(identity),
            recorded_at=self._clock.now(),
            payload={"approval_id": approval_id, "reason_code": "human_revocation"},
        )

    def get(
        self,
        identity: IdentityContext,
        *,
        approval_id: str,
    ) -> ApprovalView | None:
        self._authorize(identity, Action.REMEDIATION_READ, RiskLevel.LOW)
        approval = self._store.approval(
            tenant_id=identity.tenant_id,
            approval_id=approval_id,
        )
        if approval is None:
            return None
        projection = self._ledger.projection(
            tenant_id=identity.tenant_id,
            plan_id=approval.plan_id,
        )
        if projection is None:
            raise IntegrityFailure("approval has no remediation projection")
        decisions = self._store.decisions(
            tenant_id=identity.tenant_id,
            approval_id=approval_id,
        )
        return ApprovalView(
            approval=approval,
            decisions=decisions,
            status=projection.status,
            version=projection.version,
            grants=sum(
                item.disposition is ApprovalDisposition.GRANT for item in decisions
            ),
        )

    def _authorize(
        self,
        identity: IdentityContext,
        action: Action,
        risk: RiskLevel,
    ) -> None:
        decision = self._policy.authorize(
            identity,
            action,
            resource_tenant_id=identity.tenant_id,
            purpose="incident-response",
            risk=risk,
        )
        if not decision.allowed:
            raise PolicyDenied(decision.reason)

    def _require_action_policy(
        self,
        plan: RemediationPlan,
        *,
        consume_quota: bool,
    ) -> ActionPolicy:
        policy = self._action_policies.current(tenant_id=plan.tenant_id)
        now = self._clock.now()
        if policy is None:
            raise PolicyDenied("no_current_action_policy")
        reason: str | None = None
        if not policy.enabled:
            reason = "effects_disabled"
        elif (
            now < policy.maintenance_window_start
            or now >= policy.maintenance_window_end
        ):
            reason = "outside_maintenance_window"
        elif _RISK_ORDER[plan.risk] > _RISK_ORDER[policy.max_risk]:
            reason = "risk_exceeds_action_policy"
        elif _blast_order(plan.blast_radius) > _blast_order(policy.max_blast_radius):
            reason = "blast_radius_exceeds_action_policy"
        elif consume_quota and policy.remaining_effects < 1:
            reason = "effect_quota_exhausted"
        elif any(
            action.action_type not in policy.allowed_action_types
            or action.target.resource_fingerprint
            not in policy.allowed_target_fingerprints
            or action.target.namespace not in policy.allowed_namespaces
            for action in plan.actions
        ):
            reason = "action_or_exact_target_not_allowlisted"
        if reason is not None:
            raise PolicyDenied(reason)
        return policy

    def _require_plan(self, tenant_id: str, plan_id: str) -> RemediationPlan:
        plan = self._store.plan(tenant_id=tenant_id, plan_id=plan_id)
        if plan is None:
            raise PolicyDenied("remediation_not_available")
        return plan

    def _require_approval(
        self,
        tenant_id: str,
        approval_id: str,
    ) -> ActionApprovalRequest:
        approval = self._store.approval(
            tenant_id=tenant_id,
            approval_id=approval_id,
        )
        if approval is None:
            raise PolicyDenied("remediation_not_available")
        return approval


class EffectService:
    """Executes only current-policy, exact-digest, quorum-approved action intents."""

    def __init__(
        self,
        *,
        policy: PolicyPort,
        action_policies: ActionPolicyStore,
        ledger: RemediationLedger,
        store: RemediationControlStore,
        actions: ActionPort,
        quotas: EffectQuotaPort,
        claims: EffectClaimPort,
        clock: ClockPort,
    ) -> None:
        self._policy = policy
        self._action_policies = action_policies
        self._ledger = ledger
        self._store = store
        self._actions = actions
        self._quotas = quotas
        self._claims = claims
        self._clock = clock

    def preflight(
        self,
        identity: IdentityContext,
        *,
        plan_id: str,
        action_id: str,
        expected_version: int,
        operation_id: str,
        attempt: int,
    ) -> ActionReceipt:
        plan, approval, policy, projection = self._validated_scope(
            identity,
            plan_id,
            action_id,
            allowed_statuses={
                RemediationStatus.APPROVED,
                RemediationStatus.PREFLIGHT,
            },
        )
        intent = self._intent(
            plan,
            approval,
            policy,
            projection,
            action_id=action_id,
            operation_id=operation_id,
            attempt=attempt,
            dry_run=True,
        )
        actor = _actor_ref(identity)
        started = self._ledger.append(
            tenant_id=plan.tenant_id,
            plan_id=plan.plan_id,
            expected_version=expected_version,
            fact_type=RemediationFactType.PREFLIGHT_REQUESTED,
            command_id=f"{operation_id}:intent",
            actor_ref=actor,
            recorded_at=self._clock.now(),
            payload={
                "action_id": action_id,
                "action_digest": intent.action.canonical_digest,
            },
        )
        receipt = self._actions.dry_run(intent)
        if receipt.outcome is not EffectOutcome.DRY_RUN_SUCCEEDED:
            self._ledger.append(
                tenant_id=plan.tenant_id,
                plan_id=plan.plan_id,
                expected_version=started.version,
                fact_type=RemediationFactType.EXECUTION_FAILED,
                command_id=f"{operation_id}:result",
                actor_ref=actor,
                recorded_at=self._clock.now(),
                payload={"detail_code": receipt.detail_code},
            )
            raise EffectConflict("action dry-run did not succeed")
        self._ledger.append(
            tenant_id=plan.tenant_id,
            plan_id=plan.plan_id,
            expected_version=started.version,
            fact_type=RemediationFactType.DRY_RUN_SUCCEEDED,
            command_id=f"{operation_id}:result",
            actor_ref=actor,
            recorded_at=self._clock.now(),
            payload={"effect_receipt_digest": receipt.canonical_digest},
        )
        return receipt

    def execute(
        self,
        identity: IdentityContext,
        *,
        plan_id: str,
        action_id: str,
        expected_version: int,
        operation_id: str,
        attempt: int,
    ) -> ActionReceipt:
        plan, approval, policy, projection = self._validated_scope(
            identity,
            plan_id,
            action_id,
            allowed_statuses={
                RemediationStatus.PREFLIGHT,
                RemediationStatus.EXECUTING,
                RemediationStatus.SUCCEEDED,
            },
        )
        intent = self._intent(
            plan,
            approval,
            policy,
            projection,
            action_id=action_id,
            operation_id=operation_id,
            attempt=attempt,
            dry_run=False,
        )
        actor = _actor_ref(identity)
        requested = self._ledger.append(
            tenant_id=plan.tenant_id,
            plan_id=plan.plan_id,
            expected_version=expected_version,
            fact_type=RemediationFactType.EXECUTION_REQUESTED,
            command_id=f"{operation_id}:intent",
            actor_ref=actor,
            recorded_at=self._clock.now(),
            payload={
                "action_id": action_id,
                "idempotency_key": intent.action.idempotency_key,
                "fence_token": projection.fence_token,
            },
        )
        now = self._clock.now()
        claim = self._claims.claim(
            intent,
            worker_ref=actor,
            now=now,
            claim_until=now
            + timedelta(seconds=intent.action.retry.attempt_timeout_seconds),
        )
        receipt = claim.receipt
        result_version = requested.version
        if receipt is None:
            started = self._ledger.append(
                tenant_id=plan.tenant_id,
                plan_id=plan.plan_id,
                expected_version=requested.version,
                fact_type=RemediationFactType.EXECUTION_STARTED,
                command_id=f"{operation_id}:started:{attempt}",
                actor_ref=actor,
                recorded_at=self._clock.now(),
                payload={"attempt": attempt},
            )
            result_version = started.version
            before = self._actions.observe(intent)
            if before.state is ObservationState.APPLIED:
                receipt = _synthetic_receipt(
                    intent,
                    EffectOutcome.DUPLICATE,
                    "already_applied",
                    self._clock.now(),
                    provider_receipt_ref=before.provider_receipt_ref,
                )
            elif before.state not in {
                ObservationState.BEFORE,
                ObservationState.NOT_APPLIED,
            }:
                receipt = _synthetic_receipt(
                    intent,
                    EffectOutcome.CONFLICT,
                    "observe_before_execute_conflict",
                    self._clock.now(),
                )
            elif not all(
                _condition_matches(condition, before.facts)
                for condition in intent.action.preconditions
            ):
                receipt = _synthetic_receipt(
                    intent,
                    EffectOutcome.CONFLICT,
                    "precondition_failed",
                    self._clock.now(),
                )
            else:
                receipt = self._actions.execute(intent)
            self._claims.complete(
                receipt,
                claim_token=claim.claim_token,
                now=self._clock.now(),
            )
        fact_type = {
            EffectOutcome.SUCCEEDED: RemediationFactType.EXECUTION_SUCCEEDED,
            EffectOutcome.DUPLICATE: RemediationFactType.EXECUTION_SUCCEEDED,
            EffectOutcome.FAILED: RemediationFactType.EXECUTION_FAILED,
            EffectOutcome.CONFLICT: RemediationFactType.EXECUTION_FAILED,
            EffectOutcome.AMBIGUOUS: RemediationFactType.EXECUTION_AMBIGUOUS,
        }.get(receipt.outcome)
        if fact_type is None:
            raise IntegrityFailure("action adapter returned an invalid execute outcome")
        self._ledger.append(
            tenant_id=plan.tenant_id,
            plan_id=plan.plan_id,
            expected_version=result_version,
            fact_type=fact_type,
            command_id=f"{operation_id}:result",
            actor_ref=actor,
            recorded_at=self._clock.now(),
            payload={
                "effect_receipt_digest": receipt.canonical_digest,
                "detail_code": receipt.detail_code,
            },
        )
        if receipt.outcome is EffectOutcome.AMBIGUOUS:
            raise EffectAmbiguous("external action outcome requires reconciliation")
        if receipt.outcome not in {EffectOutcome.SUCCEEDED, EffectOutcome.DUPLICATE}:
            raise EffectConflict("external action failed safely")
        return receipt

    def reconcile(
        self,
        identity: IdentityContext,
        *,
        plan_id: str,
        action_id: str,
        expected_version: int,
        operation_id: str,
        attempt: int,
    ) -> ActionReceipt:
        plan, approval, policy, projection = self._validated_scope(
            identity,
            plan_id,
            action_id,
            allowed_statuses={
                RemediationStatus.AMBIGUOUS,
                RemediationStatus.RECONCILING,
                RemediationStatus.SUCCEEDED,
            },
        )
        intent = self._intent(
            plan,
            approval,
            policy,
            projection,
            action_id=action_id,
            operation_id=operation_id,
            attempt=attempt,
            dry_run=False,
        )
        actor = _actor_ref(identity)
        current_version = expected_version
        if projection.status is RemediationStatus.AMBIGUOUS:
            reconciling = self._ledger.append(
                tenant_id=plan.tenant_id,
                plan_id=plan.plan_id,
                expected_version=expected_version,
                fact_type=RemediationFactType.RECONCILIATION_STARTED,
                command_id=f"{operation_id}:intent",
                actor_ref=actor,
                recorded_at=self._clock.now(),
                payload={"action_id": action_id},
            )
            current_version = reconciling.version
        now = self._clock.now()
        claim = self._claims.claim(
            intent,
            worker_ref=actor,
            now=now,
            claim_until=now
            + timedelta(seconds=intent.action.retry.attempt_timeout_seconds),
        )
        receipt = claim.receipt
        if receipt is None:
            observed = self._actions.observe(intent)
            if observed.state is ObservationState.APPLIED:
                receipt = _synthetic_receipt(
                    intent,
                    EffectOutcome.SUCCEEDED,
                    "reconciled_applied",
                    self._clock.now(),
                    provider_receipt_ref=observed.provider_receipt_ref,
                )
            else:
                receipt = _synthetic_receipt(
                    intent,
                    EffectOutcome.AMBIGUOUS,
                    "reconciliation_inconclusive",
                    self._clock.now(),
                )
            self._claims.complete(
                receipt,
                claim_token=claim.claim_token,
                now=self._clock.now(),
            )
        if receipt.outcome is EffectOutcome.SUCCEEDED:
            self._ledger.append(
                tenant_id=plan.tenant_id,
                plan_id=plan.plan_id,
                expected_version=current_version,
                fact_type=RemediationFactType.RECONCILIATION_RESOLVED,
                command_id=f"{operation_id}:result",
                actor_ref=actor,
                recorded_at=self._clock.now(),
                payload={"effect_receipt_digest": receipt.canonical_digest},
            )
            return receipt
        self._ledger.append(
            tenant_id=plan.tenant_id,
            plan_id=plan.plan_id,
            expected_version=current_version,
            fact_type=RemediationFactType.ESCALATED,
            command_id=f"{operation_id}:escalate",
            actor_ref=actor,
            recorded_at=self._clock.now(),
            payload={"reason_code": "reconciliation_inconclusive"},
        )
        raise EffectAmbiguous("reconciliation could not prove the external outcome")

    def verify(
        self,
        identity: IdentityContext,
        *,
        plan_id: str,
        action_id: str,
        expected_version: int,
        operation_id: str,
        effect_receipt: ActionReceipt,
        fresh_evidence: Sequence[Citation],
        attempt: int,
    ) -> VerificationRecord:
        plan, approval, policy, projection = self._validated_scope(
            identity,
            plan_id,
            action_id,
            allowed_statuses={
                RemediationStatus.SUCCEEDED,
                RemediationStatus.VERIFIED,
                RemediationStatus.VERIFICATION_FAILED,
            },
        )
        intent = self._intent(
            plan,
            approval,
            policy,
            projection,
            action_id=action_id,
            operation_id=operation_id,
            attempt=attempt,
            dry_run=False,
        )
        actor = _actor_ref(identity)
        if (
            projection.effect_receipt_digest != effect_receipt.canonical_digest
            or effect_receipt.tenant_id != plan.tenant_id
            or effect_receipt.plan_id != plan.plan_id
            or effect_receipt.action_id != action_id
            or effect_receipt.fence_token != projection.fence_token
        ):
            raise IntegrityFailure("verification receipt binding is invalid")
        requested = self._ledger.append(
            tenant_id=plan.tenant_id,
            plan_id=plan.plan_id,
            expected_version=expected_version,
            fact_type=RemediationFactType.VERIFICATION_REQUESTED,
            command_id=f"{operation_id}:intent",
            actor_ref=actor,
            recorded_at=self._clock.now(),
            payload={"effect_receipt_digest": effect_receipt.canonical_digest},
        )
        action = intent.action
        verification_id = stable_id(
            "verification",
            plan.tenant_id,
            plan.plan_id,
            action_id,
            operation_id,
            length=32,
        )
        record = self._store.verification(
            tenant_id=plan.tenant_id,
            verification_id=verification_id,
        )
        if record is None:
            observed = self._actions.observe(intent)
            satisfied = (
                observed.observed_at > effect_receipt.recorded_at
                and bool(fresh_evidence)
                and all(
                    _condition_matches(item, observed.facts)
                    for item in action.postconditions
                )
            )
            material = {
                "schema_version": 1,
                "verification_id": verification_id,
                "tenant_id": plan.tenant_id,
                "plan_id": plan.plan_id,
                "action_id": action_id,
                "effect_receipt_digest": effect_receipt.canonical_digest,
                "fresh_evidence": tuple(fresh_evidence),
                "observation": observed,
                "postconditions_satisfied": satisfied,
                "verified_at": self._clock.now(),
            }
            record = VerificationRecord(
                **material,
                canonical_digest=canonical_digest(material),
            )
            self._store.put_verification(record)
        satisfied = record.postconditions_satisfied
        self._ledger.append(
            tenant_id=plan.tenant_id,
            plan_id=plan.plan_id,
            expected_version=requested.version,
            fact_type=(
                RemediationFactType.VERIFIED
                if satisfied
                else RemediationFactType.VERIFICATION_FAILED
            ),
            command_id=f"{operation_id}:result",
            actor_ref=actor,
            recorded_at=self._clock.now(),
            payload={"verification_digest": record.canonical_digest},
        )
        if not satisfied:
            raise VerificationFailed("fresh evidence did not satisfy postconditions")
        return record

    def rollback(
        self,
        identity: IdentityContext,
        *,
        plan_id: str,
        action_id: str,
        expected_version: int,
        operation_id: str,
        attempt: int,
    ) -> ActionReceipt:
        plan, approval, policy, projection = self._validated_scope(
            identity,
            plan_id,
            action_id,
            allowed_statuses={
                RemediationStatus.FAILED,
                RemediationStatus.SUCCEEDED,
                RemediationStatus.VERIFICATION_FAILED,
                RemediationStatus.ROLLED_BACK,
            },
        )
        action = next(item for item in plan.actions if item.action_id == action_id)
        if not action.compensation.enabled:
            raise PolicyDenied("compensation_not_enabled")
        intent = self._intent(
            plan,
            approval,
            policy,
            projection,
            action_id=action_id,
            operation_id=operation_id,
            attempt=attempt,
            dry_run=False,
        )
        actor = _actor_ref(identity)
        requested = self._ledger.append(
            tenant_id=plan.tenant_id,
            plan_id=plan.plan_id,
            expected_version=expected_version,
            fact_type=RemediationFactType.ROLLBACK_REQUESTED,
            command_id=f"{operation_id}:intent",
            actor_ref=actor,
            recorded_at=self._clock.now(),
            payload={"action_id": action_id},
        )
        now = self._clock.now()
        claim = self._claims.claim(
            intent,
            worker_ref=actor,
            now=now,
            claim_until=now
            + timedelta(seconds=intent.action.retry.attempt_timeout_seconds),
        )
        receipt = claim.receipt
        if receipt is None:
            receipt = self._actions.compensate(intent)
            self._claims.complete(
                receipt,
                claim_token=claim.claim_token,
                now=self._clock.now(),
            )
        succeeded = receipt.outcome is EffectOutcome.COMPENSATED
        self._ledger.append(
            tenant_id=plan.tenant_id,
            plan_id=plan.plan_id,
            expected_version=requested.version,
            fact_type=(
                RemediationFactType.ROLLBACK_SUCCEEDED
                if succeeded
                else RemediationFactType.ROLLBACK_FAILED
            ),
            command_id=f"{operation_id}:result",
            actor_ref=actor,
            recorded_at=self._clock.now(),
            payload={
                "effect_receipt_digest": receipt.canonical_digest,
                "detail_code": receipt.detail_code,
            },
        )
        if not succeeded:
            raise EffectConflict("rollback failed and requires operator escalation")
        return receipt

    def _validated_scope(
        self,
        identity: IdentityContext,
        plan_id: str,
        action_id: str,
        *,
        allowed_statuses: set[RemediationStatus] | None = None,
    ) -> tuple[
        RemediationPlan,
        ActionApprovalRequest,
        ActionPolicy,
        RemediationProjection,
    ]:
        decision = self._policy.authorize(
            identity,
            Action.EFFECT_EXECUTE,
            resource_tenant_id=identity.tenant_id,
            purpose="incident-response",
            risk=RiskLevel.HIGH,
        )
        if not decision.allowed:
            raise PolicyDenied(decision.reason)
        plan = self._store.plan(tenant_id=identity.tenant_id, plan_id=plan_id)
        projection = self._ledger.projection(
            tenant_id=identity.tenant_id,
            plan_id=plan_id,
        )
        if plan is None or projection is None or projection.approval_id is None:
            raise PolicyDenied("remediation_not_available")
        if not any(action.action_id == action_id for action in plan.actions):
            raise PolicyDenied("action_not_in_exact_plan")
        approval = self._store.approval(
            tenant_id=identity.tenant_id,
            approval_id=projection.approval_id,
        )
        if approval is None:
            raise IntegrityFailure("approved remediation omitted approval record")
        current = self._action_policies.current(tenant_id=identity.tenant_id)
        if current is None:
            raise PolicyDenied("no_current_action_policy")
        if (
            approval.plan_digest != plan.plan_digest
            or approval.canonical_digest != projection.approval_digest
            or approval.policy_snapshot != current.snapshot()
            or plan.policy_snapshot != current.snapshot()
            or approval.expires_at <= self._clock.now()
            or plan.expires_at <= self._clock.now()
        ):
            raise ApprovalExpired("approval exact scope is stale")
        decisions = self._store.decisions(
            tenant_id=identity.tenant_id,
            approval_id=approval.approval_id,
        )
        if any(item.disposition is ApprovalDisposition.DENY for item in decisions):
            raise ApprovalDenied("approval was denied")
        grants = {
            item.approver_ref
            for item in decisions
            if item.disposition is ApprovalDisposition.GRANT
            and item.plan_digest == plan.plan_digest
            and item.approval_digest == approval.canonical_digest
            and item.policy_digest == current.policy_digest
            and item.role_revision == current.role_revision
        }
        if len(grants) < approval.requirement.quorum:
            raise ApprovalDenied("approval quorum is not satisfied")
        allowed = allowed_statuses or {
            RemediationStatus.APPROVED,
            RemediationStatus.PREFLIGHT,
        }
        if projection.status not in allowed:
            if projection.status is RemediationStatus.REVOKED:
                raise ApprovalRevoked("approval was revoked")
            raise EffectConflict("remediation state does not permit this operation")
        ApprovalService(
            policy=self._policy,
            action_policies=self._action_policies,
            ledger=self._ledger,
            store=self._store,
            clock=self._clock,
        )._require_action_policy(plan, consume_quota=True)
        quota = self._quotas.reserve(
            tenant_id=plan.tenant_id,
            plan_id=plan.plan_id,
            reservation_id=stable_id(
                "effect-quota",
                plan.tenant_id,
                plan.plan_id,
                action_id,
                length=32,
            ),
            policy_digest=current.policy_digest,
            units=1,
            requested_at=self._clock.now(),
        )
        if not quota.allowed:
            raise PolicyDenied(quota.reason)
        return plan, approval, current, projection

    def _intent(
        self,
        plan: RemediationPlan,
        approval: ActionApprovalRequest,
        policy: ActionPolicy,
        projection: RemediationProjection,
        *,
        action_id: str,
        operation_id: str,
        attempt: int,
        dry_run: bool,
    ) -> ActionIntent:
        return ActionIntent(
            tenant_id=plan.tenant_id,
            run_id=plan.run_id,
            plan_id=plan.plan_id,
            action=next(item for item in plan.actions if item.action_id == action_id),
            plan_digest=plan.plan_digest,
            approval_digest=approval.canonical_digest,
            policy_digest=policy.policy_digest,
            operation_id=operation_id,
            attempt=attempt,
            fence_token=projection.fence_token,
            requested_at=self._clock.now(),
            dry_run=dry_run,
        )


def _actor_ref(identity: IdentityContext) -> str:
    return stable_id("actor", identity.issuer, identity.subject_id, length=32)


def _blast_order(value: BlastRadius) -> int:
    return {
        BlastRadius.ONE_REPLICA_SET: 1,
        BlastRadius.ONE_SERVICE: 2,
        BlastRadius.MULTI_SERVICE: 3,
    }[value]


def _condition_matches(
    condition: Condition,
    facts: Mapping[str, str | int | float | bool],
) -> bool:
    actual = facts.get(condition.fact)
    expected = condition.expected
    if condition.fact not in facts:
        return False
    if condition.operator == "equals":
        return actual == expected
    if condition.operator == "not_equals":
        return actual != expected
    if not isinstance(actual, int | float) or not isinstance(expected, int | float):
        return False
    if condition.operator == "greater_than":
        return actual > expected
    return actual < expected


def _synthetic_receipt(
    intent: ActionIntent,
    outcome: EffectOutcome,
    detail_code: str,
    recorded_at: datetime,
    *,
    provider_receipt_ref: str | None = None,
) -> ActionReceipt:
    material = {
        "schema_version": 1,
        "tenant_id": intent.tenant_id,
        "plan_id": intent.plan_id,
        "action_id": intent.action.action_id,
        "operation_id": intent.operation_id,
        "idempotency_key": intent.action.idempotency_key,
        "fence_token": intent.fence_token,
        "attempt": intent.attempt,
        "outcome": outcome,
        "provider_receipt_ref": provider_receipt_ref,
        "target_fingerprint": intent.action.target.resource_fingerprint,
        "recorded_at": recorded_at,
        "detail_code": detail_code,
    }
    return ActionReceipt(**material, canonical_digest=canonical_digest(material))
