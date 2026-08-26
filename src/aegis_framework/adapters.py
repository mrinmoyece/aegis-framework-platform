"""Deterministic local adapters for enterprise-owned application ports."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from threading import Lock
from typing import ClassVar

from pydantic import AwareDatetime, Field

from aegis_framework.access import (
    AuditEventView,
    GrantRecord,
    GrantStatus,
    PolicyRecord,
    PrincipalRecord,
    QuotaRecord,
    TenantRecord,
)
from aegis_framework.domain import (
    ApprovalGrant,
    ApprovalRequest,
    EffectReceipt,
    Evidence,
    IdentityContext,
    InvestigationRequest,
    InvestigationResult,
    PrincipalKind,
    RemediationProposal,
    RiskLevel,
    StrictModel,
    stable_id,
)
from aegis_framework.errors import (
    ApprovalBoundaryFailure,
    ConcurrencyConflict,
    EffectsDisabled,
    IdempotencyConflict,
)
from aegis_framework.ports import (
    Action,
    BudgetDecision,
    PolicyDecision,
    RunClaim,
    RunClaimStatus,
)
from aegis_framework.safety import safe_audit_attributes


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class FixedClock:
    def __init__(self, value: datetime) -> None:
        if value.tzinfo is None:
            raise ValueError("FixedClock requires an aware datetime")
        self._value = value

    def now(self) -> datetime:
        return self._value


class InMemoryIdentityRepository:
    def __init__(
        self,
        *,
        tenants: Sequence[TenantRecord],
        principals: Sequence[PrincipalRecord],
        grants: Sequence[GrantRecord],
    ) -> None:
        self._tenants = {tenant.tenant_id: tenant for tenant in tenants}
        self._principals = {
            (principal.issuer, principal.subject_id): principal
            for principal in principals
        }
        self._grants = tuple(grants)

    def resolve_principal(
        self, *, tenant_id: str, issuer: str, subject_id: str
    ) -> PrincipalRecord | None:
        principal = self._principals.get((issuer, subject_id))
        return (
            principal
            if principal is not None and principal.tenant_id == tenant_id
            else None
        )

    def active_grants(
        self,
        *,
        tenant_id: str,
        issuer: str,
        subject_id: str,
        now: datetime,
    ) -> Sequence[GrantRecord]:
        return tuple(
            grant
            for grant in self._grants
            if grant.tenant_id == tenant_id
            and grant.issuer == issuer
            and grant.subject_id == subject_id
            and grant.status is GrantStatus.ACTIVE
            and grant.expires_at > now
        )

    def get_tenant(self, *, tenant_id: str) -> TenantRecord | None:
        return self._tenants.get(tenant_id)


class DenyAllPolicy:
    def authorize(
        self,
        identity: IdentityContext,
        action: Action,
        *,
        resource_tenant_id: str,
        purpose: str,
        risk: RiskLevel,
    ) -> PolicyDecision:
        del identity, action, resource_tenant_id
        return PolicyDecision(
            allowed=False,
            policy_id="deny-all:v1",
            policy_revision=1,
            purpose=purpose,
            risk=risk,
            reason="no_explicit_grant",
        )


class RolePolicy:
    """Small local policy double; it is deliberately separate from graph state."""

    _ROLE_GRANTS: ClassVar[dict[str, frozenset[Action]]] = {
        "incident-responder": frozenset(
            {Action.INVESTIGATION_RUN, Action.INVESTIGATION_READ}
        ),
        "incident-viewer": frozenset({Action.INVESTIGATION_READ}),
    }

    def authorize(
        self,
        identity: IdentityContext,
        action: Action,
        *,
        resource_tenant_id: str,
        purpose: str,
        risk: RiskLevel,
    ) -> PolicyDecision:
        if identity.tenant_id != resource_tenant_id:
            return PolicyDecision(
                allowed=False,
                policy_id="role-policy:v1",
                policy_revision=1,
                purpose=purpose,
                risk=risk,
                reason="tenant_mismatch",
            )
        grant = next(
            (
                binding
                for binding in identity.grants
                if binding.purpose == purpose and action.value in binding.permissions
            ),
            None,
        )
        if grant is None:
            return PolicyDecision(
                allowed=False,
                policy_id="role-policy:v1",
                policy_revision=1,
                purpose=purpose,
                risk=risk,
                reason="action_or_purpose_not_granted",
            )
        return PolicyDecision(
            allowed=True,
            policy_id="role-policy:v1",
            policy_revision=1,
            purpose=purpose,
            risk=risk,
            reason="explicit_role_grant",
        )


class InMemoryBudget:
    def __init__(
        self,
        limits: Mapping[str, int],
        *,
        default_limit: int = 0,
    ) -> None:
        self._remaining = dict(limits)
        self._default_limit = default_limit
        self._reservations: dict[tuple[str, str], BudgetDecision] = {}
        self._lock = Lock()

    def reserve(
        self,
        identity: IdentityContext,
        *,
        reservation_id: str,
        units: int,
    ) -> BudgetDecision:
        if units <= 0:
            raise ValueError("budget reservation units must be positive")
        key = (identity.tenant_id, reservation_id)
        with self._lock:
            existing = self._reservations.get(key)
            if existing is not None:
                return existing
            remaining = self._remaining.get(identity.tenant_id, self._default_limit)
            allowed = remaining >= units
            new_remaining = remaining - units if allowed else remaining
            decision = BudgetDecision(
                allowed=allowed,
                reservation_id=reservation_id,
                requested_units=units,
                remaining_units=new_remaining,
                reason="reserved" if allowed else "tenant_budget_exhausted",
            )
            self._reservations[key] = decision
            if allowed:
                self._remaining[identity.tenant_id] = new_remaining
            return decision


class InMemoryEvidence:
    def __init__(
        self,
        items: Mapping[tuple[str, str], Sequence[Evidence]],
    ) -> None:
        self._items = {key: tuple(value) for key, value in items.items()}

    def collect(
        self,
        identity: IdentityContext,
        request: InvestigationRequest,
    ) -> Sequence[Evidence]:
        return tuple(
            sorted(
                self._items.get((identity.tenant_id, request.incident_id), ()),
                key=lambda item: item.evidence_id,
            )
        )


class AuditRecord(StrictModel):
    event_id: str
    sequence: int = Field(ge=1)
    tenant_id: str
    event_type: str
    actor_ref: str
    principal_kind: PrincipalKind
    recorded_at: AwareDatetime
    attributes: dict[str, str | int | bool]
    previous_hash: str
    record_hash: str


class HashChainAudit:
    """Educational append-only audit double; PostgreSQL durability comes later."""

    def __init__(self, clock: FixedClock | SystemClock) -> None:
        self._clock = clock
        self._records: list[AuditRecord] = []
        self._tenant_heads: dict[str, tuple[int, str]] = {}
        self._lock = Lock()

    def append(
        self,
        *,
        identity: IdentityContext,
        event_type: str,
        attributes: Mapping[str, str | int | bool],
    ) -> None:
        with self._lock:
            previous_sequence, previous_hash = self._tenant_heads.get(
                identity.tenant_id, (0, "0" * 64)
            )
            sequence = previous_sequence + 1
            recorded_at = self._clock.now()
            actor_ref = stable_id(
                "actor", identity.issuer, identity.subject_id, length=32
            )
            event_id = stable_id(
                "audit",
                identity.tenant_id,
                str(sequence),
                event_type,
                recorded_at.isoformat(),
                length=32,
            )
            safe_attributes = safe_audit_attributes(attributes)
            canonical = json.dumps(
                {
                    "event_id": event_id,
                    "sequence": sequence,
                    "tenant_id": identity.tenant_id,
                    "event_type": event_type,
                    "actor_ref": actor_ref,
                    "principal_kind": identity.principal_kind.value,
                    "recorded_at": recorded_at.isoformat(),
                    "attributes": safe_attributes,
                    "previous_hash": previous_hash,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
            self._records.append(
                AuditRecord(
                    event_id=event_id,
                    sequence=sequence,
                    tenant_id=identity.tenant_id,
                    event_type=event_type,
                    actor_ref=actor_ref,
                    principal_kind=identity.principal_kind,
                    recorded_at=recorded_at,
                    attributes=safe_attributes,
                    previous_hash=previous_hash,
                    record_hash=sha256(canonical.encode()).hexdigest(),
                )
            )
            self._tenant_heads[identity.tenant_id] = (
                sequence,
                self._records[-1].record_hash,
            )

    def records_for(self, tenant_id: str) -> tuple[AuditRecord, ...]:
        return tuple(
            record for record in self._records if record.tenant_id == tenant_id
        )

    def verify(self) -> bool:
        heads: dict[str, tuple[int, str]] = {}
        for record in self._records:
            previous_sequence, previous_hash = heads.get(
                record.tenant_id, (0, "0" * 64)
            )
            canonical = json.dumps(
                {
                    "event_id": record.event_id,
                    "sequence": record.sequence,
                    "tenant_id": record.tenant_id,
                    "event_type": record.event_type,
                    "actor_ref": record.actor_ref,
                    "principal_kind": record.principal_kind.value,
                    "recorded_at": record.recorded_at.isoformat(),
                    "attributes": dict(sorted(record.attributes.items())),
                    "previous_hash": previous_hash,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
            expected = sha256(canonical.encode()).hexdigest()
            if (
                record.sequence != previous_sequence + 1
                or record.previous_hash != previous_hash
                or record.record_hash != expected
            ):
                return False
            heads[record.tenant_id] = (record.sequence, record.record_hash)
        return True


class InMemoryGovernance:
    def __init__(
        self,
        *,
        tenants: Sequence[TenantRecord],
        policies: Sequence[PolicyRecord],
        quotas: Sequence[QuotaRecord],
        audit: HashChainAudit,
    ) -> None:
        self._tenants = {tenant.tenant_id: tenant for tenant in tenants}
        self._policies = {policy.tenant_id: policy for policy in policies}
        self._quotas = {(quota.tenant_id, quota.quota_key): quota for quota in quotas}
        self._audit = audit
        self._lock = Lock()

    def ready(self) -> bool:
        return True

    def get_tenant(self, *, tenant_id: str) -> TenantRecord | None:
        return self._tenants.get(tenant_id)

    def current_policy(self, *, tenant_id: str) -> PolicyRecord | None:
        return self._policies.get(tenant_id)

    def get_quota(self, *, tenant_id: str, quota_key: str) -> QuotaRecord | None:
        return self._quotas.get((tenant_id, quota_key))

    def list_audit(
        self, *, identity: IdentityContext, limit: int
    ) -> Sequence[AuditEventView]:
        if limit < 1 or limit > 100:
            raise ValueError("audit limit is outside the permitted range")
        records = self._audit.records_for(identity.tenant_id)[-limit:]
        return tuple(
            AuditEventView(
                event_id=record.event_id,
                sequence=record.sequence,
                event_type=record.event_type,
                actor_ref=record.actor_ref,
                principal_kind=record.principal_kind,
                recorded_at=record.recorded_at,
                attributes=record.attributes,
                previous_hash=record.previous_hash,
                record_hash=record.record_hash,
            )
            for record in records
        )

    def replace_policy(
        self,
        *,
        policy: PolicyRecord,
        expected_version: int,
    ) -> PolicyRecord:
        with self._lock:
            current = self._policies.get(policy.tenant_id)
            if current is None or current.version != expected_version:
                raise ConcurrencyConflict("policy version changed")
            updated = policy.model_copy(update={"version": expected_version + 1})
            self._policies[policy.tenant_id] = updated
            return updated

    def replace_quota(
        self,
        *,
        quota: QuotaRecord,
        expected_version: int,
    ) -> QuotaRecord:
        with self._lock:
            key = (quota.tenant_id, quota.quota_key)
            current = self._quotas.get(key)
            if current is None or current.version != expected_version:
                raise ConcurrencyConflict("quota version changed")
            updated = quota.model_copy(update={"version": expected_version + 1})
            self._quotas[key] = updated
            return updated


@dataclass
class _RunRecord:
    fingerprint: str
    attempt: int
    status: str
    result: InvestigationResult | None = None
    failure_code: str | None = None


class InMemoryIdempotency:
    def __init__(self) -> None:
        self._records: dict[tuple[str, str], _RunRecord] = {}
        self._lock = Lock()

    def acquire(
        self,
        *,
        tenant_id: str,
        request_id: str,
        fingerprint: str,
    ) -> RunClaim:
        key = (tenant_id, request_id)
        with self._lock:
            record = self._records.get(key)
            if record is None:
                self._records[key] = _RunRecord(
                    fingerprint=fingerprint,
                    attempt=1,
                    status="in_progress",
                )
                return RunClaim(status=RunClaimStatus.STARTED, attempt=1)
            if record.fingerprint != fingerprint:
                raise IdempotencyConflict("request_id was reused with different input")
            if record.status == "completed":
                if record.result is None:
                    raise IdempotencyConflict("completed request has no stored result")
                return RunClaim(
                    status=RunClaimStatus.COMPLETED,
                    attempt=record.attempt,
                    result=record.result,
                )
            if record.status == "in_progress":
                return RunClaim(
                    status=RunClaimStatus.IN_PROGRESS,
                    attempt=record.attempt,
                )
            record.attempt += 1
            record.status = "in_progress"
            record.failure_code = None
            return RunClaim(status=RunClaimStatus.RETRY, attempt=record.attempt)

    def complete(
        self,
        *,
        tenant_id: str,
        request_id: str,
        result: InvestigationResult,
    ) -> None:
        key = (tenant_id, request_id)
        with self._lock:
            record = self._records.get(key)
            if record is None or record.status != "in_progress":
                raise IdempotencyConflict("request is not owned by an active run")
            record.status = "completed"
            record.result = result

    def fail(self, *, tenant_id: str, request_id: str, code: str) -> None:
        key = (tenant_id, request_id)
        with self._lock:
            record = self._records.get(key)
            if record is None or record.status != "in_progress":
                raise IdempotencyConflict("request is not owned by an active run")
            record.status = "failed"
            record.failure_code = code


class InMemoryApprovalBoundary:
    def __init__(self, clock: FixedClock | SystemClock) -> None:
        self._clock = clock
        self._requests: dict[tuple[str, str], ApprovalRequest] = {}

    def open_request(
        self,
        identity: IdentityContext,
        proposal: RemediationProposal,
    ) -> ApprovalRequest:
        if not proposal.requires_approval:
            raise ApprovalBoundaryFailure("proposal unexpectedly bypassed approval")
        key = (identity.tenant_id, proposal.proposal_id)
        existing = self._requests.get(key)
        if existing is not None:
            return existing
        approval = ApprovalRequest(
            approval_id=stable_id("approval", identity.tenant_id, proposal.proposal_id),
            proposal_id=proposal.proposal_id,
            tenant_id=identity.tenant_id,
            required_roles=("incident-commander",),
            created_at=self._clock.now(),
        )
        self._requests[key] = approval
        return approval


class DisabledEffectAdapter:
    """Layer 1 has no execution implementation, even with a forged grant."""

    def execute(
        self,
        identity: IdentityContext,
        proposal: RemediationProposal,
        approval: ApprovalGrant,
    ) -> EffectReceipt:
        del identity, proposal, approval
        raise EffectsDisabled("production effects are disabled in Layer 1")
