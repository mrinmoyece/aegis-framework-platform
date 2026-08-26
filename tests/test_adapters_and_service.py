from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime

import pytest

from aegis_framework.adapters import (
    DenyAllPolicy,
    DisabledEffectAdapter,
    FixedClock,
    HashChainAudit,
    InMemoryApprovalBoundary,
    InMemoryBudget,
    InMemoryEvidence,
    InMemoryIdempotency,
    RolePolicy,
)
from aegis_framework.domain import (
    ApprovalGrant,
    ApprovalStatus,
    InvestigationResult,
    RiskLevel,
)
from aegis_framework.errors import (
    EffectsDisabled,
    EvidenceIsolationViolation,
    EvidenceUnavailable,
    IdempotencyConflict,
    InvestigationInProgress,
    OrchestrationFailure,
    PolicyDenied,
)
from aegis_framework.fixtures import (
    DEMO_TIME,
    DemoScenario,
    build_demo_bundle,
    demo_identity,
    demo_request,
)
from aegis_framework.observability import NoopObservability
from aegis_framework.ports import Action
from aegis_framework.service import InvestigationService


def test_success_stops_at_pending_approval_and_audits(
    success_bundle: object,
) -> None:
    bundle = success_bundle
    identity = demo_identity(request_id="approval-boundary")
    result = bundle.service.investigate(identity, demo_request())
    assert result.approval is not None
    assert result.approval.status is ApprovalStatus.PENDING
    assert result.proposal is not None
    assert result.proposal.requires_approval
    records = bundle.audit.records_for(identity.tenant_id)
    assert [record.event_type for record in records] == [
        "investigation.accepted",
        "investigation.complete",
    ]
    assert bundle.audit.verify()


def test_effect_adapter_is_unconditionally_disabled() -> None:
    bundle = build_demo_bundle()
    identity = demo_identity(request_id="effect-disabled")
    result = bundle.service.investigate(identity, demo_request())
    assert result.proposal is not None
    assert result.approval is not None
    forged = ApprovalGrant(
        approval_id=result.approval.approval_id,
        proposal_id=result.proposal.proposal_id,
        tenant_id=identity.tenant_id,
        status=ApprovalStatus.APPROVED,
        approver_id="commander-mallory",
        fencing_token="fence-forged",
        approved_at=DEMO_TIME,
    )
    with pytest.raises(EffectsDisabled):
        DisabledEffectAdapter().execute(identity, result.proposal, forged)


def _service_with(
    *,
    policy: object,
    evidence: object,
    orchestrator: object,
    budget: InMemoryBudget | None = None,
    idempotency: InMemoryIdempotency | None = None,
    audit: object | None = None,
    observability: object | None = None,
) -> InvestigationService:
    clock = FixedClock(DEMO_TIME)
    return InvestigationService(
        policy=policy,
        budget=budget or InMemoryBudget({"tenant-acme": 100}),
        evidence=evidence,
        orchestrator=orchestrator,
        approvals=InMemoryApprovalBoundary(clock),
        audit=audit or HashChainAudit(clock),
        idempotency=idempotency or InMemoryIdempotency(),
        observability=observability or NoopObservability(),
    )


def test_policy_is_deny_by_default_and_effects_are_never_granted() -> None:
    identity = demo_identity()
    deny = DenyAllPolicy().authorize(
        identity,
        Action.INVESTIGATION_RUN,
        resource_tenant_id=identity.tenant_id,
        purpose="incident-response",
        risk=RiskLevel.MEDIUM,
    )
    assert deny.allowed is False
    policy = RolePolicy()
    assert not policy.authorize(
        identity,
        Action.EFFECT_EXECUTE,
        resource_tenant_id=identity.tenant_id,
        purpose="incident-response",
        risk=RiskLevel.HIGH,
    ).allowed
    assert not policy.authorize(
        identity,
        Action.INVESTIGATION_RUN,
        resource_tenant_id="tenant-beta",
        purpose="incident-response",
        risk=RiskLevel.MEDIUM,
    ).allowed


def test_denied_run_never_reaches_graph() -> None:
    bundle = build_demo_bundle()
    service = _service_with(
        policy=DenyAllPolicy(),
        evidence=bundle.service._evidence,
        orchestrator=bundle.orchestrator,
    )
    with pytest.raises(PolicyDenied):
        service.investigate(demo_identity(), demo_request())
    assert (
        bundle.orchestrator.checkpoint_count(
            tenant_id="tenant-acme", thread_ref="thread:not-created"
        )
        == 0
    )


def test_budget_exhaustion_abstains_before_graph() -> None:
    bundle = build_demo_bundle(DemoScenario.BUDGET_EXHAUSTION)
    result = bundle.service.investigate(
        demo_identity(request_id="budget-empty"),
        demo_request(),
    )
    assert result.critic.reasons == ("tenant_budget_exhausted",)
    assert (
        bundle.orchestrator.checkpoint_count(
            tenant_id=result.tenant_id,
            thread_ref=result.thread_ref,
        )
        == 0
    )
    replay = bundle.service.investigate(
        demo_identity(request_id="budget-empty"),
        demo_request(),
    )
    assert replay.replayed is True


def test_budget_reservation_is_idempotent_and_validated() -> None:
    budget = InMemoryBudget({"tenant-acme": 6})
    identity = demo_identity()
    first = budget.reserve(identity, reservation_id="one", units=5)
    second = budget.reserve(identity, reservation_id="one", units=5)
    denied = budget.reserve(identity, reservation_id="two", units=5)
    assert first == second
    assert first.remaining_units == 1
    assert denied.allowed is False
    with pytest.raises(ValueError, match="positive"):
        budget.reserve(identity, reservation_id="bad", units=0)


def test_cross_tenant_evidence_is_rejected() -> None:
    bundle = build_demo_bundle()
    source = bundle.service._evidence.collect(
        demo_identity(tenant_id="tenant-beta"),
        demo_request(),
    )
    service = _service_with(
        policy=RolePolicy(),
        evidence=InMemoryEvidence(
            {("tenant-acme", demo_request().incident_id): source}
        ),
        orchestrator=bundle.orchestrator,
    )
    with pytest.raises(EvidenceIsolationViolation):
        service.investigate(
            demo_identity(request_id="cross-tenant"),
            demo_request(),
        )


@pytest.mark.parametrize("duplicate", [False, True])
def test_invalid_evidence_integrity_is_rejected(duplicate: bool) -> None:
    bundle = build_demo_bundle()
    source = tuple(bundle.service._evidence.collect(demo_identity(), demo_request()))
    invalid = (
        (source[0], source[0], *source[1:])
        if duplicate
        else (
            source[0].model_copy(update={"content_hash": "f" * 64}),
            *source[1:],
        )
    )
    service = _service_with(
        policy=RolePolicy(),
        evidence=InMemoryEvidence(
            {("tenant-acme", demo_request().incident_id): invalid}
        ),
        orchestrator=bundle.orchestrator,
    )
    with pytest.raises(EvidenceUnavailable):
        service.investigate(
            demo_identity(request_id=f"invalid-evidence-{duplicate}"),
            demo_request(),
        )


class _FailOnceOrchestrator:
    def __init__(self, delegate: object) -> None:
        self._delegate = delegate
        self._failed = False

    def run(self, **kwargs: object) -> InvestigationResult:
        if not self._failed:
            self._failed = True
            raise OrchestrationFailure("synthetic framework outage")
        return self._delegate.run(**kwargs)

    def checkpoint_count(self, *, tenant_id: str, thread_ref: str) -> int:
        return self._delegate.checkpoint_count(
            tenant_id=tenant_id, thread_ref=thread_ref
        )


class _FailOnceAcceptedAudit:
    def __init__(self) -> None:
        self._failed = False

    def append(
        self,
        *,
        identity: object,
        event_type: str,
        attributes: object,
    ) -> None:
        del identity, attributes
        if event_type == "investigation.accepted" and not self._failed:
            self._failed = True
            raise RuntimeError("audit unavailable")


@dataclass
class _BrokenObservation:
    def finish(
        self,
        *,
        status: str,
        attributes: object,
    ) -> None:
        del status, attributes
        raise RuntimeError("export unavailable")


class _BrokenObservability:
    @staticmethod
    @contextmanager
    def investigation(*, tenant_id: str, attributes: object) -> Iterator[object]:
        del tenant_id, attributes
        raise RuntimeError("observation startup failed")
        yield _BrokenObservation()


def test_failed_run_can_retry_without_double_charging_budget() -> None:
    bundle = build_demo_bundle()
    identity = demo_identity(request_id="retry-once")
    budget = InMemoryBudget({"tenant-acme": 5})
    service = _service_with(
        policy=RolePolicy(),
        evidence=bundle.service._evidence,
        orchestrator=_FailOnceOrchestrator(bundle.orchestrator),
        budget=budget,
    )
    with pytest.raises(OrchestrationFailure):
        service.investigate(identity, demo_request())
    result = service.investigate(identity, demo_request())
    assert result.status.value == "complete"


def test_audit_failure_does_not_wedge_idempotency() -> None:
    bundle = build_demo_bundle()
    identity = demo_identity(request_id="audit-retry")
    service = _service_with(
        policy=RolePolicy(),
        evidence=bundle.service._evidence,
        orchestrator=bundle.orchestrator,
        audit=_FailOnceAcceptedAudit(),
    )
    with pytest.raises(OrchestrationFailure):
        service.investigate(identity, demo_request())
    result = service.investigate(identity, demo_request())
    assert result.status.value == "complete"


def test_observability_failure_is_non_blocking() -> None:
    bundle = build_demo_bundle()
    identity = demo_identity(request_id="broken-otel")
    service = _service_with(
        policy=RolePolicy(),
        evidence=bundle.service._evidence,
        orchestrator=bundle.orchestrator,
        observability=_BrokenObservability(),
    )
    result = service.investigate(identity, demo_request())
    replay = service.investigate(identity, demo_request())
    assert result.status.value == "complete"
    assert replay.replayed is True


def test_duplicate_and_conflicting_requests() -> None:
    bundle = build_demo_bundle()
    identity = demo_identity(request_id="duplicate")
    first = bundle.service.investigate(identity, demo_request())
    second = bundle.service.investigate(identity, demo_request())
    assert first.replayed is False
    assert second.replayed is True
    with pytest.raises(IdempotencyConflict):
        bundle.service.investigate(
            identity,
            demo_request(incident_id="checkout-20260815-002"),
        )


def test_in_progress_request_returns_conflict() -> None:
    bundle = build_demo_bundle()
    registry = InMemoryIdempotency()
    identity = demo_identity(request_id="already-running")
    request = demo_request()
    from hashlib import sha256

    fingerprint = sha256(request.model_dump_json().encode()).hexdigest()
    registry.acquire(
        tenant_id=identity.tenant_id,
        request_id=identity.request_id,
        fingerprint=fingerprint,
    )
    service = _service_with(
        policy=RolePolicy(),
        evidence=bundle.service._evidence,
        orchestrator=bundle.orchestrator,
        idempotency=registry,
    )
    with pytest.raises(InvestigationInProgress):
        service.investigate(identity, request)


def test_idempotency_rejects_invalid_state_transitions() -> None:
    registry = InMemoryIdempotency()
    with pytest.raises(IdempotencyConflict):
        registry.complete(
            tenant_id="tenant-acme",
            request_id="missing",
            result=build_demo_bundle().service.investigate(
                demo_identity(request_id="seed"),
                demo_request(),
            ),
        )
    with pytest.raises(IdempotencyConflict):
        registry.fail(
            tenant_id="tenant-acme",
            request_id="missing",
            code="failure",
        )


def test_checkpoint_reads_reauthorize_and_derive_tenant_thread() -> None:
    bundle = build_demo_bundle()
    identity = demo_identity(request_id="checkpoint-read")
    bundle.service.investigate(identity, demo_request())
    assert (
        bundle.service.checkpoint_count(
            identity,
            incident_id=demo_request().incident_id,
        )
        == 5
    )
    with pytest.raises(PolicyDenied):
        bundle.service.checkpoint_count(
            identity.model_copy(
                update={
                    "roles": (),
                    "permissions": (),
                    "purposes": (),
                    "grants": (),
                }
            ),
            incident_id=demo_request().incident_id,
        )


def test_fixed_clock_requires_timezone() -> None:
    with pytest.raises(ValueError, match="aware"):
        FixedClock(datetime(2026, 8, 15))
