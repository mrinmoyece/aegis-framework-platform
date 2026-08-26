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

from aegis_framework.domain import (
    ApprovalGrant,
    ApprovalRequest,
    EffectReceipt,
    Evidence,
    IdentityContext,
    InvestigationRequest,
    InvestigationResult,
    RemediationProposal,
    StrictModel,
    stable_id,
)
from aegis_framework.errors import (
    ApprovalBoundaryFailure,
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


class DenyAllPolicy:
    def authorize(
        self,
        identity: IdentityContext,
        action: Action,
        *,
        resource_tenant_id: str,
    ) -> PolicyDecision:
        del identity, action, resource_tenant_id
        return PolicyDecision(
            allowed=False,
            policy_id="deny-all:v1",
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
    ) -> PolicyDecision:
        if identity.tenant_id != resource_tenant_id:
            return PolicyDecision(
                allowed=False,
                policy_id="role-policy:v1",
                reason="tenant_mismatch",
            )
        granted = {
            candidate
            for role in identity.roles
            for candidate in self._ROLE_GRANTS.get(role, frozenset())
        }
        if action not in granted:
            return PolicyDecision(
                allowed=False,
                policy_id="role-policy:v1",
                reason="action_not_granted",
            )
        return PolicyDecision(
            allowed=True,
            policy_id="role-policy:v1",
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
    sequence: int = Field(ge=1)
    tenant_id: str
    event_type: str
    recorded_at: AwareDatetime
    attributes: dict[str, str | int | bool]
    previous_hash: str
    record_hash: str


class HashChainAudit:
    """Educational append-only audit double; PostgreSQL durability comes later."""

    def __init__(self, clock: FixedClock | SystemClock) -> None:
        self._clock = clock
        self._records: list[AuditRecord] = []
        self._lock = Lock()

    def append(
        self,
        *,
        identity: IdentityContext,
        event_type: str,
        attributes: Mapping[str, str | int | bool],
    ) -> None:
        with self._lock:
            sequence = len(self._records) + 1
            previous_hash = self._records[-1].record_hash if self._records else "0" * 64
            recorded_at = self._clock.now()
            canonical = json.dumps(
                {
                    "sequence": sequence,
                    "tenant_id": identity.tenant_id,
                    "event_type": event_type,
                    "recorded_at": recorded_at.isoformat(),
                    "attributes": dict(sorted(attributes.items())),
                    "previous_hash": previous_hash,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
            self._records.append(
                AuditRecord(
                    sequence=sequence,
                    tenant_id=identity.tenant_id,
                    event_type=event_type,
                    recorded_at=recorded_at,
                    attributes=dict(attributes),
                    previous_hash=previous_hash,
                    record_hash=sha256(canonical.encode()).hexdigest(),
                )
            )

    def records_for(self, tenant_id: str) -> tuple[AuditRecord, ...]:
        return tuple(
            record for record in self._records if record.tenant_id == tenant_id
        )

    def verify(self) -> bool:
        previous_hash = "0" * 64
        for record in self._records:
            canonical = json.dumps(
                {
                    "sequence": record.sequence,
                    "tenant_id": record.tenant_id,
                    "event_type": record.event_type,
                    "recorded_at": record.recorded_at.isoformat(),
                    "attributes": dict(sorted(record.attributes.items())),
                    "previous_hash": previous_hash,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
            expected = sha256(canonical.encode()).hexdigest()
            if record.previous_hash != previous_hash or record.record_hash != expected:
                return False
            previous_hash = record.record_hash
        return True


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
