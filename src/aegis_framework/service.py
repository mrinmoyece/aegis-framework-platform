"""Application service enforcing authority before and after framework execution."""

from __future__ import annotations

from contextlib import ExitStack, suppress
from hashlib import sha256

from aegis_framework.domain import (
    CriticDecision,
    CriticVerdict,
    Evidence,
    IdentityContext,
    InvestigationRequest,
    InvestigationResult,
    InvestigationStatus,
    RiskLevel,
    evidence_hash,
    stable_id,
)
from aegis_framework.errors import (
    ApprovalBoundaryFailure,
    EvidenceIsolationViolation,
    EvidenceUnavailable,
    InvestigationInProgress,
    OrchestrationFailure,
    PolicyDenied,
)
from aegis_framework.ports import (
    Action,
    ApprovalPort,
    AuditPort,
    BudgetPort,
    EvidencePort,
    IdempotencyPort,
    ObservabilityPort,
    OrchestratorPort,
    PolicyPort,
    RunClaimStatus,
)

_INVESTIGATION_BUDGET_UNITS = 5


class _NullObservation:
    """Fallback when the observability context manager fails to start."""

    def finish(self, *, status: str, attributes: object) -> None:
        del status, attributes


class InvestigationService:
    """Coordinates enterprise controls around a replaceable graph adapter."""

    def __init__(
        self,
        *,
        policy: PolicyPort,
        budget: BudgetPort,
        evidence: EvidencePort,
        orchestrator: OrchestratorPort,
        approvals: ApprovalPort,
        audit: AuditPort,
        idempotency: IdempotencyPort,
        observability: ObservabilityPort,
    ) -> None:
        self._policy = policy
        self._budget = budget
        self._evidence = evidence
        self._orchestrator = orchestrator
        self._approvals = approvals
        self._audit = audit
        self._idempotency = idempotency
        self._observability = observability

    def investigate(
        self,
        identity: IdentityContext,
        request: InvestigationRequest,
    ) -> InvestigationResult:
        decision = self._policy.authorize(
            identity,
            Action.INVESTIGATION_RUN,
            resource_tenant_id=identity.tenant_id,
            purpose="incident-response",
            risk=RiskLevel.MEDIUM,
        )
        if not decision.allowed:
            self._audit.append(
                identity=identity,
                event_type="investigation.denied",
                attributes={
                    "request_ref": _request_ref(identity),
                    "reason": decision.reason,
                    "policy_id": decision.policy_id,
                    "policy_revision": decision.policy_revision,
                },
            )
            raise PolicyDenied(decision.reason)

        fingerprint = sha256(request.model_dump_json().encode()).hexdigest()
        claim = self._idempotency.acquire(
            tenant_id=identity.tenant_id,
            request_id=identity.request_id,
            fingerprint=fingerprint,
        )
        if claim.status is RunClaimStatus.COMPLETED:
            if claim.result is None:
                raise OrchestrationFailure(
                    "idempotency record omitted completed result"
                )
            self._audit.append(
                identity=identity,
                event_type="investigation.replayed",
                attributes={
                    "request_ref": _request_ref(identity),
                    "attempt": claim.attempt,
                },
            )
            return claim.result.model_copy(update={"replayed": True})
        if claim.status is RunClaimStatus.IN_PROGRESS:
            raise InvestigationInProgress("an identical request is already running")

        thread_ref = stable_id(
            "thread",
            identity.tenant_id,
            request.incident_id,
            identity.request_id,
            length=32,
        )
        with ExitStack() as stack:
            try:
                observation = stack.enter_context(
                    self._observability.investigation(
                        tenant_id=identity.tenant_id,
                        attributes={"replayed": False},
                    )
                )
            except Exception:
                observation = _NullObservation()
            try:
                self._audit.append(
                    identity=identity,
                    event_type="investigation.accepted",
                    attributes={
                        "request_ref": _request_ref(identity),
                        "attempt": claim.attempt,
                    },
                )
                budget = self._budget.reserve(
                    identity,
                    reservation_id=thread_ref,
                    units=_INVESTIGATION_BUDGET_UNITS,
                )
                if not budget.allowed:
                    result = _budget_abstention(identity, request, thread_ref)
                    self._idempotency.complete(
                        tenant_id=identity.tenant_id,
                        request_id=identity.request_id,
                        result=result,
                    )
                    self._audit.append(
                        identity=identity,
                        event_type="investigation.abstained",
                        attributes={
                            "request_ref": _request_ref(identity),
                            "reason": budget.reason,
                        },
                    )
                    with suppress(Exception):
                        observation.finish(
                            status=result.status.value,
                            attributes={
                                "evidence_count": 0,
                                "finding_count": 0,
                                "citation_count": 0,
                            },
                        )
                    return result

                collected = tuple(self._evidence.collect(identity, request))
                validate_evidence(identity, collected)
                result = self._orchestrator.run(
                    tenant_id=identity.tenant_id,
                    request=request,
                    request_id=identity.request_id,
                    run_id=run_id,
                    thread_ref=thread_ref,
                    evidence=collected,
                )
                if result.proposal is not None:
                    approval = self._approvals.open_request(identity, result.proposal)
                    result = result.model_copy(update={"approval": approval})
                self._idempotency.complete(
                    tenant_id=identity.tenant_id,
                    request_id=identity.request_id,
                    result=result,
                )
            except (
                ApprovalBoundaryFailure,
                EvidenceIsolationViolation,
                EvidenceUnavailable,
                OrchestrationFailure,
            ) as exc:
                code = type(exc).__name__
                with suppress(Exception):
                    self._idempotency.fail(
                        tenant_id=identity.tenant_id,
                        request_id=identity.request_id,
                        code=code,
                    )
                with suppress(Exception):
                    self._audit.append(
                        identity=identity,
                        event_type="investigation.failed",
                        attributes={
                            "request_ref": _request_ref(identity),
                            "error_code": code,
                        },
                    )
                with suppress(Exception):
                    observation.finish(status="failed", attributes={"error_code": code})
                raise
            except Exception as exc:
                code = "unexpected_failure"
                with suppress(Exception):
                    self._idempotency.fail(
                        tenant_id=identity.tenant_id,
                        request_id=identity.request_id,
                        code=code,
                    )
                with suppress(Exception):
                    self._audit.append(
                        identity=identity,
                        event_type="investigation.failed",
                        attributes={
                            "request_ref": _request_ref(identity),
                            "error_code": code,
                        },
                    )
                with suppress(Exception):
                    observation.finish(status="failed", attributes={"error_code": code})
                raise OrchestrationFailure(
                    f"unexpected adapter error: {type(exc).__name__}"
                ) from exc

            self._audit.append(
                identity=identity,
                event_type=f"investigation.{result.status.value}",
                attributes={
                    "request_ref": _request_ref(identity),
                    "evidence_count": len(collected),
                    "citation_count": result.critic.checked_citations,
                    "approval_required": result.approval is not None,
                },
            )
            with suppress(Exception):
                observation.finish(
                    status=result.status.value,
                    attributes={
                        "evidence_count": len(collected),
                        "finding_count": len(result.hypotheses),
                        "citation_count": result.critic.checked_citations,
                        "injection_detected": result.critic.injection_contained,
                    },
                )
            return result

    def checkpoint_count(
        self,
        identity: IdentityContext,
        *,
        incident_id: str,
    ) -> int:
        decision = self._policy.authorize(
            identity,
            Action.INVESTIGATION_READ,
            resource_tenant_id=identity.tenant_id,
            purpose="incident-response",
            risk=RiskLevel.LOW,
        )
        if not decision.allowed:
            raise PolicyDenied(decision.reason)
        thread_ref = stable_id(
            "thread",
            identity.tenant_id,
            incident_id,
            identity.request_id,
            length=32,
        )
        return self._orchestrator.checkpoint_count(
            tenant_id=identity.tenant_id,
            thread_ref=thread_ref,
        )


def _budget_abstention(
    identity: IdentityContext,
    request: InvestigationRequest,
    run_id: str,
    thread_ref: str,
) -> InvestigationResult:
    return InvestigationResult(
        status=InvestigationStatus.ABSTAINED,
        tenant_id=identity.tenant_id,
        incident_id=request.incident_id,
        run_id=run_id,
        request_id=identity.request_id,
        thread_ref=thread_ref,
        hypotheses=(),
        critic=CriticVerdict(
            decision=CriticDecision.ABSTAINED,
            reasons=("tenant_budget_exhausted",),
            checked_citations=0,
        ),
        proposal=None,
    )


def validate_evidence(
    identity: IdentityContext,
    collected: tuple[Evidence, ...],
) -> None:
    if any(item.tenant_id != identity.tenant_id for item in collected):
        raise EvidenceIsolationViolation("evidence adapter returned cross-tenant data")
    evidence_ids = tuple(item.evidence_id for item in collected)
    if len(evidence_ids) != len(set(evidence_ids)):
        raise EvidenceUnavailable("evidence adapter returned duplicate evidence ids")
    for item in collected:
        if item.provenance_digest is not None:
            if (
                item.untrusted_text is None
                or sha256(item.untrusted_text.encode()).hexdigest() != item.content_hash
            ):
                raise EvidenceUnavailable(
                    "normalized evidence content hash validation failed"
                )
            continue
        expected_hash = evidence_hash(
            tenant_id=item.tenant_id,
            kind=item.kind,
            locator=item.locator,
            observed_at=item.observed_at,
            facts=dict(item.facts),
            summary=item.summary,
            untrusted_text=item.untrusted_text,
        )
        if item.content_hash != expected_hash:
            raise EvidenceUnavailable("evidence content hash validation failed")


def _request_ref(identity: IdentityContext) -> str:
    return stable_id(
        "request",
        identity.tenant_id,
        identity.request_id,
        length=32,
    )
