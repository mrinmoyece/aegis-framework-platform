"""Application control implementation invoked by Temporal Activities."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from typing import Protocol

from pydantic import ValidationError

from aegis_framework.domain import (
    Evidence,
    IdentityContext,
    InvestigationResult,
    RiskLevel,
    stable_id,
)
from aegis_framework.durability import DurabilityPort, RunStatus
from aegis_framework.errors import IntegrityFailure, PolicyDenied
from aegis_framework.ports import (
    Action,
    BudgetPort,
    EvidencePort,
    OrchestratorPort,
    PolicyPort,
)
from aegis_framework.service import validate_evidence
from aegis_framework.temporal import (
    ActivityOperations,
    ActivityOutcome,
    TemporalActivityInput,
)

_INVESTIGATION_BUDGET_UNITS = 5


class CurrentAuthorityPort(Protocol):
    """Resolve opaque workflow references against current application authority."""

    def tenant_id(self, *, tenant_ref: str) -> str | None: ...

    def identity(
        self,
        *,
        tenant_id: str,
        actor_ref: str,
        request_ref: str,
    ) -> IdentityContext | None: ...


class InMemoryCurrentAuthority:
    """Mutable authority registry used by deterministic tests and evals."""

    def __init__(self, identities: Sequence[IdentityContext]) -> None:
        self._tenants: dict[str, str] = {}
        self._identities: dict[tuple[str, str], IdentityContext] = {}
        for identity in identities:
            tenant_ref = stable_id("tenant", identity.tenant_id, length=32)
            actor_ref = stable_id(
                "actor", identity.issuer, identity.subject_id, length=32
            )
            self._tenants[tenant_ref] = identity.tenant_id
            self._identities[(identity.tenant_id, actor_ref)] = identity

    def tenant_id(self, *, tenant_ref: str) -> str | None:
        return self._tenants.get(tenant_ref)

    def identity(
        self,
        *,
        tenant_id: str,
        actor_ref: str,
        request_ref: str,
    ) -> IdentityContext | None:
        identity = self._identities.get((tenant_id, actor_ref))
        if identity is None:
            return None
        return identity.model_copy(
            update={
                "request_id": request_ref,
                "trace_id": stable_id("trace", tenant_id, request_ref, length=32),
            }
        )

    def replace(self, identity: IdentityContext) -> None:
        tenant_ref = stable_id("tenant", identity.tenant_id, length=32)
        actor_ref = stable_id("actor", identity.issuer, identity.subject_id, length=32)
        self._tenants[tenant_ref] = identity.tenant_id
        self._identities[(identity.tenant_id, actor_ref)] = identity

    def revoke(self, *, tenant_id: str, actor_ref: str) -> None:
        self._identities.pop((tenant_id, actor_ref), None)


class DurableActivityRuntime(ActivityOperations):
    """Reauthorizes and persists intent/result around every framework Activity."""

    def __init__(
        self,
        *,
        authority: CurrentAuthorityPort,
        policy: PolicyPort,
        budget: BudgetPort,
        evidence: EvidencePort,
        orchestrator: OrchestratorPort,
        store: DurabilityPort,
    ) -> None:
        self._authority = authority
        self._policy = policy
        self._budget = budget
        self._evidence = evidence
        self._orchestrator = orchestrator
        self._store = store

    async def authorize(self, value: TemporalActivityInput) -> ActivityOutcome:
        return await asyncio.to_thread(self._authorize_blocking, value)

    def _authorize_blocking(self, value: TemporalActivityInput) -> ActivityOutcome:
        tenant_id, identity = self._authorized(value)
        budget = self._budget.reserve(
            identity,
            reservation_id=value.run_id,
            units=_INVESTIGATION_BUDGET_UNITS,
        )
        if not budget.allowed:
            self._store.record_transition(
                tenant_id=tenant_id,
                run_id=value.run_id,
                event_type="investigation.failed",
                operation_id=value.operation_id,
                actor_ref=value.actor_ref,
                request_ref=value.request_ref,
                failure_code="tenant_budget_exhausted",
            )
            return ActivityOutcome(outcome="denied")
        self._store.record_transition(
            tenant_id=tenant_id,
            run_id=value.run_id,
            event_type="investigation.started",
            operation_id=value.operation_id,
            actor_ref=value.actor_ref,
            request_ref=value.request_ref,
        )
        return ActivityOutcome(outcome="authorized")

    async def collect_evidence(self, value: TemporalActivityInput) -> ActivityOutcome:
        return await asyncio.to_thread(self._collect_evidence_blocking, value)

    def _collect_evidence_blocking(
        self, value: TemporalActivityInput
    ) -> ActivityOutcome:
        tenant_id, identity = self._authorized(value)
        request = self._store.run_request(tenant_id=tenant_id, run_id=value.run_id)
        collected = tuple(self._evidence.collect(identity, request))
        validate_evidence(identity, collected)
        artifact_ref = stable_id("artifact", value.run_id, "evidence", length=32)
        self._store.record_transition(
            tenant_id=tenant_id,
            run_id=value.run_id,
            event_type="investigation.evidence_collected",
            operation_id=value.operation_id,
            actor_ref=value.actor_ref,
            request_ref=value.request_ref,
            attributes={
                "artifact_ref": artifact_ref,
                "evidence": [
                    item.model_dump(mode="json")
                    for item in sorted(
                        collected, key=lambda evidence: evidence.evidence_id
                    )
                ],
            },
        )
        return ActivityOutcome(
            outcome="evidence_ready",
            result_ref=artifact_ref,
        )

    async def run_graph(self, value: TemporalActivityInput) -> ActivityOutcome:
        return await asyncio.to_thread(self._run_graph_blocking, value)

    def _run_graph_blocking(self, value: TemporalActivityInput) -> ActivityOutcome:
        tenant_id, _ = self._authorized(value)
        existing_result = self._store.activity_artifact(
            tenant_id=tenant_id,
            run_id=value.run_id,
            event_type="investigation.graph_completed",
        )
        if existing_result is not None:
            try:
                InvestigationResult.model_validate(existing_result["result"])
                result_ref = existing_result["result_ref"]
            except (KeyError, ValidationError) as exc:
                raise IntegrityFailure("graph result is malformed") from exc
            if not isinstance(result_ref, str):
                raise IntegrityFailure("graph result reference is malformed")
            return ActivityOutcome(
                outcome="graph_complete",
                result_ref=result_ref,
            )
        request = self._store.run_request(tenant_id=tenant_id, run_id=value.run_id)
        artifact = self._store.activity_artifact(
            tenant_id=tenant_id,
            run_id=value.run_id,
            event_type="investigation.evidence_collected",
        )
        if artifact is None:
            raise IntegrityFailure("evidence artifact is unavailable")
        evidence_payload = artifact.get("evidence")
        if not isinstance(evidence_payload, list):
            raise IntegrityFailure("evidence artifact is unavailable")
        try:
            evidence = tuple(Evidence.model_validate(item) for item in evidence_payload)
        except ValidationError as exc:
            raise IntegrityFailure("evidence artifact is malformed") from exc
        thread_ref = stable_id(
            "thread",
            tenant_id,
            request.incident_id,
            value.request_ref,
            length=32,
        )
        # Check for cancellation before starting the expensive graph execution.
        # This propagates cancel intent even if the run_graph activity is
        # cancelled before returning (e.g., concurrent cancel signal processed).
        preflight = self._store.get_run(tenant_id=tenant_id, run_id=value.run_id)
        if preflight is not None and preflight.status in (
            RunStatus.CANCEL_REQUESTED,
            RunStatus.CANCELLED,
        ):
            self._store.record_transition(
                tenant_id=tenant_id,
                run_id=value.run_id,
                event_type="investigation.graph_cancelled",
                operation_id=value.operation_id,
                actor_ref=value.actor_ref,
                request_ref=value.request_ref,
                attributes={"reason": "cancel_requested_before_graph"},
            )
            return ActivityOutcome(outcome="cancelled")
        result = self._orchestrator.run(
            tenant_id=tenant_id,
            request=request,
            request_id=value.request_ref,
            run_id=value.run_id,
            thread_ref=thread_ref,
            evidence=evidence,
        )
        result_ref = stable_id("result", value.run_id, length=32)
        self._store.record_transition(
            tenant_id=tenant_id,
            run_id=value.run_id,
            event_type="investigation.graph_completed",
            operation_id=value.operation_id,
            actor_ref=value.actor_ref,
            request_ref=value.request_ref,
            attributes={
                "result": result.model_dump(mode="json"),
                "result_ref": result_ref,
            },
        )
        return ActivityOutcome(
            outcome="graph_complete",
            result_ref=result_ref,
        )

    async def record_wait(self, value: TemporalActivityInput) -> ActivityOutcome:
        return await asyncio.to_thread(self._record_wait_blocking, value)

    def _record_wait_blocking(self, value: TemporalActivityInput) -> ActivityOutcome:
        tenant_id, _ = self._authorized(value)
        self._store.record_transition(
            tenant_id=tenant_id,
            run_id=value.run_id,
            event_type="investigation.waiting",
            operation_id=value.operation_id,
            actor_ref=value.actor_ref,
            request_ref=value.request_ref,
        )
        return ActivityOutcome(outcome="recorded")

    async def authorize_signal(self, value: TemporalActivityInput) -> ActivityOutcome:
        return await asyncio.to_thread(self._authorize_signal_blocking, value)

    def _authorize_signal_blocking(
        self, value: TemporalActivityInput
    ) -> ActivityOutcome:
        self._command_identity(
            value,
            expected_message_type="investigation.resume",
        )
        return ActivityOutcome(outcome="authorized")

    async def cancel(self, value: TemporalActivityInput) -> ActivityOutcome:
        return await asyncio.to_thread(self._cancel_blocking, value)

    def _cancel_blocking(self, value: TemporalActivityInput) -> ActivityOutcome:
        tenant_id, actor_ref = self._command_identity(
            value,
            expected_message_type="investigation.cancel",
        )
        current = self._store.get_run(
            tenant_id=tenant_id,
            run_id=value.run_id,
        )
        if current is None or current.status is not RunStatus.CANCEL_REQUESTED:
            raise IntegrityFailure("cancellation intent is not current")
        self._orchestrator.cancel_run(
            tenant_id=tenant_id,
            run_id=value.run_id,
        )
        self._store.record_transition(
            tenant_id=tenant_id,
            run_id=value.run_id,
            event_type="investigation.cancelled",
            operation_id=value.operation_id,
            actor_ref=actor_ref,
            request_ref=current.request_ref,
            attributes={"command_ref": value.command_ref},
        )
        return ActivityOutcome(outcome="recorded")

    def _command_identity(
        self,
        value: TemporalActivityInput,
        *,
        expected_message_type: str,
    ) -> tuple[str, str]:
        tenant_id = self._tenant_id(value)
        if value.command_ref is None:
            raise IntegrityFailure("signal activity omitted its command reference")
        record = self._store.delivery(
            tenant_id=tenant_id,
            direction="inbox",
            message_id=value.command_ref,
        )
        if (
            record is None
            or record.message_type != expected_message_type
            or record.payload.get("run_id") != value.run_id
            or not isinstance(record.payload.get("actor_ref"), str)
        ):
            raise IntegrityFailure("signal command is not authoritative")
        signal_identity = self._authority.identity(
            tenant_id=tenant_id,
            actor_ref=str(record.payload["actor_ref"]),
            request_ref=value.command_ref,
        )
        if signal_identity is None:
            raise PolicyDenied("signal principal is not current")
        self._require_policy(signal_identity)
        return tenant_id, str(record.payload["actor_ref"])

    async def complete(self, value: TemporalActivityInput) -> ActivityOutcome:
        return await asyncio.to_thread(self._complete_blocking, value)

    def _complete_blocking(self, value: TemporalActivityInput) -> ActivityOutcome:
        tenant_id, _ = self._authorized(value)
        artifact = self._store.activity_artifact(
            tenant_id=tenant_id,
            run_id=value.run_id,
            event_type="investigation.graph_completed",
        )
        if artifact is None:
            raise IntegrityFailure("graph result is unavailable")
        try:
            InvestigationResult.model_validate(artifact["result"])
        except (KeyError, ValidationError) as exc:
            raise IntegrityFailure("graph result is malformed") from exc
        result_ref = artifact.get("result_ref")
        if not isinstance(result_ref, str):
            raise IntegrityFailure("graph result reference is malformed")
        self._store.record_transition(
            tenant_id=tenant_id,
            run_id=value.run_id,
            event_type="investigation.completed",
            operation_id=value.operation_id,
            actor_ref=value.actor_ref,
            request_ref=value.request_ref,
            attributes={"result_ref": result_ref},
        )
        return ActivityOutcome(outcome="recorded", result_ref=result_ref)

    async def fail(self, value: TemporalActivityInput) -> ActivityOutcome:
        return await asyncio.to_thread(self._fail_blocking, value)

    def _fail_blocking(self, value: TemporalActivityInput) -> ActivityOutcome:
        tenant_id = self._tenant_id(value)
        current = self._store.get_run(tenant_id=tenant_id, run_id=value.run_id)
        if current is None:
            raise IntegrityFailure("failed workflow run is unavailable")
        if current.request_ref != value.request_ref:
            raise IntegrityFailure("failed workflow request reference is invalid")
        if current.status is RunStatus.CANCEL_REQUESTED:
            self._store.record_transition(
                tenant_id=tenant_id,
                run_id=value.run_id,
                event_type="investigation.cancelled",
                operation_id=f"{value.operation_id}:cancel-wins",
                actor_ref="system:temporal-worker",
                request_ref=current.request_ref,
            )
            return ActivityOutcome(outcome="recorded")
        if current.status in {
            RunStatus.FAILED,
            RunStatus.CANCELLED,
            RunStatus.COMPLETED,
            RunStatus.TIMED_OUT,
        }:
            return ActivityOutcome(outcome="duplicate")
        self._store.record_transition(
            tenant_id=tenant_id,
            run_id=value.run_id,
            event_type="investigation.failed",
            operation_id=value.operation_id,
            actor_ref="system:temporal-worker",
            request_ref=current.request_ref,
            failure_code=value.failure_code or "temporal_activity_failure",
        )
        return ActivityOutcome(outcome="recorded")

    async def time_out(self, value: TemporalActivityInput) -> ActivityOutcome:
        return await asyncio.to_thread(self._time_out_blocking, value)

    def _time_out_blocking(self, value: TemporalActivityInput) -> ActivityOutcome:
        tenant_id, _ = self._authorized(value)
        self._store.record_transition(
            tenant_id=tenant_id,
            run_id=value.run_id,
            event_type="investigation.timed_out",
            operation_id=value.operation_id,
            actor_ref=value.actor_ref,
            request_ref=value.request_ref,
            failure_code="signal_timeout",
        )
        return ActivityOutcome(outcome="recorded")

    def _authorized(self, value: TemporalActivityInput) -> tuple[str, IdentityContext]:
        tenant_id = self._tenant_id(value)
        identity = self._authority.identity(
            tenant_id=tenant_id,
            actor_ref=value.actor_ref,
            request_ref=value.request_ref,
        )
        if identity is None:
            raise PolicyDenied("activity principal is not current")
        self._require_policy(identity)
        return tenant_id, identity

    def _tenant_id(self, value: TemporalActivityInput) -> str:
        tenant_id = self._authority.tenant_id(tenant_ref=value.tenant_ref)
        if tenant_id is None:
            raise PolicyDenied("workflow tenant reference is not current")
        return tenant_id

    def _require_policy(self, identity: IdentityContext) -> None:
        decision = self._policy.authorize(
            identity,
            Action.INVESTIGATION_RUN,
            resource_tenant_id=identity.tenant_id,
            purpose="incident-response",
            risk=RiskLevel.MEDIUM,
        )
        if not decision.allowed:
            raise PolicyDenied(decision.reason)


class CallbackActivityOperations(ActivityOperations):
    """Small typed test adapter for workflow tests without application I/O."""

    def __init__(
        self,
        outcomes: Mapping[str, ActivityOutcome],
    ) -> None:
        self._outcomes = dict(outcomes)

    async def authorize(self, value: TemporalActivityInput) -> ActivityOutcome:
        return self._value("authorize", value)

    async def collect_evidence(self, value: TemporalActivityInput) -> ActivityOutcome:
        return self._value("collect_evidence", value)

    async def run_graph(self, value: TemporalActivityInput) -> ActivityOutcome:
        return self._value("run_graph", value)

    async def record_wait(self, value: TemporalActivityInput) -> ActivityOutcome:
        return self._value("record_wait", value)

    async def authorize_signal(self, value: TemporalActivityInput) -> ActivityOutcome:
        return self._value("authorize_signal", value)

    async def complete(self, value: TemporalActivityInput) -> ActivityOutcome:
        return self._value("complete", value)

    async def cancel(self, value: TemporalActivityInput) -> ActivityOutcome:
        return self._value("cancel", value)

    async def fail(self, value: TemporalActivityInput) -> ActivityOutcome:
        return self._value("fail", value)

    async def time_out(self, value: TemporalActivityInput) -> ActivityOutcome:
        return self._value("time_out", value)

    def _value(self, operation: str, value: TemporalActivityInput) -> ActivityOutcome:
        del value
        try:
            return self._outcomes[operation]
        except KeyError as exc:
            raise IntegrityFailure(
                f"test activity outcome is missing for {operation}"
            ) from exc
