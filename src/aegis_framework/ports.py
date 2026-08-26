"""Replaceable application contracts around framework and enterprise authority."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

from pydantic import Field

from aegis_framework.domain import (
    ApprovalGrant,
    ApprovalRequest,
    EffectReceipt,
    Evidence,
    IdentityContext,
    InvestigationRequest,
    InvestigationResult,
    RemediationProposal,
    RiskLevel,
    SpecialistFinding,
    SpecialistTask,
    StrictModel,
)

if TYPE_CHECKING:
    from aegis_framework.evals import EvalCase
    from aegis_framework.evaluation import (
        CaseResult,
        DatasetContract,
        EvaluationReport,
        ExecutionObservation,
    )
    from aegis_framework.remediation import (
        ActionIntent,
        ActionObservation,
        ActionReceipt,
    )
    from aegis_framework.sandbox import (
        BackendExecution,
        BackendObservation,
        SandboxExecutionRequest,
        SandboxResult,
    )


class Action(StrEnum):
    INVESTIGATION_RUN = "investigation:run"
    INVESTIGATION_READ = "investigation:read"
    TENANT_READ = "tenant:read"
    POLICY_READ = "policy:read"
    POLICY_WRITE = "policy:write"
    QUOTA_READ = "quota:read"
    QUOTA_WRITE = "quota:write"
    AUDIT_READ = "audit:read"
    MODEL_CATALOG_READ = "model:catalog:read"
    MODEL_USAGE_READ = "model:usage:read"
    MODEL_HEALTH_READ = "model:health:read"
    EVIDENCE_QUERY_READ = "evidence:query:read"
    EVIDENCE_CURSOR_READ = "evidence:cursor:read"
    ORCHESTRATION_ARTIFACT_READ = "orchestration:artifact:read"
    REMEDIATION_PROPOSE = "remediation:propose"
    REMEDIATION_READ = "remediation:read"
    APPROVAL_REQUEST = "approval:request"
    APPROVAL_DECIDE = "approval:decide"
    APPROVAL_REVOKE = "approval:revoke"
    EFFECT_EXECUTE = "effect:execute"
    EFFECT_READ = "effect:read"
    SANDBOX_EXECUTE = "sandbox:execute"
    SANDBOX_READ = "sandbox:read"
    SANDBOX_ARTIFACT_READ = "sandbox:artifact:read"
    MEMORY_WRITE = "memory:write"
    MEMORY_READ = "memory:read"
    MEMORY_RETRIEVE = "memory:retrieve"
    MEMORY_DELETE = "memory:delete"
    OPERATIONS_READ = "operations:read"
    SUPPORT_READ = "support:read"
    REPLAY_READ = "replay:read"
    PROJECTION_REBUILD = "projection:rebuild"


class PolicyDecision(StrictModel):
    allowed: bool
    policy_id: str
    policy_revision: int = Field(ge=0)
    purpose: str
    risk: RiskLevel
    reason: str


class BudgetDecision(StrictModel):
    allowed: bool
    reservation_id: str
    requested_units: int = Field(gt=0)
    remaining_units: int = Field(ge=0)
    reason: str


class RunClaimStatus(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"
    RETRY = "retry"
    IN_PROGRESS = "in_progress"


class RunClaim(StrictModel):
    status: RunClaimStatus
    attempt: int = Field(ge=1)
    result: InvestigationResult | None = None


class PolicyPort(Protocol):
    def authorize(
        self,
        identity: IdentityContext,
        action: Action,
        *,
        resource_tenant_id: str,
        purpose: str,
        risk: RiskLevel,
    ) -> PolicyDecision: ...


class BudgetPort(Protocol):
    def reserve(
        self,
        identity: IdentityContext,
        *,
        reservation_id: str,
        units: int,
    ) -> BudgetDecision: ...


class EvidencePort(Protocol):
    def collect(
        self,
        identity: IdentityContext,
        request: InvestigationRequest,
    ) -> Sequence[Evidence]: ...


class StructuredModelPort(Protocol):
    def analyze(self, task: SpecialistTask) -> object: ...


class OrchestratorPort(Protocol):
    def run(
        self,
        *,
        tenant_id: str,
        request: InvestigationRequest,
        request_id: str,
        run_id: str | None = None,
        thread_ref: str,
        evidence: Sequence[Evidence],
    ) -> InvestigationResult: ...

    def checkpoint_count(self, *, tenant_id: str, thread_ref: str) -> int: ...

    def cancel_run(self, *, tenant_id: str, run_id: str) -> None: ...


class ApprovalPort(Protocol):
    def open_request(
        self,
        identity: IdentityContext,
        proposal: RemediationProposal,
    ) -> ApprovalRequest: ...


class EffectPort(Protocol):
    def execute(
        self,
        identity: IdentityContext,
        proposal: RemediationProposal,
        approval: ApprovalGrant,
    ) -> EffectReceipt: ...


class ActionPort(Protocol):
    """Provider-neutral controlled action boundary."""

    def dry_run(self, intent: ActionIntent) -> ActionReceipt: ...

    def observe(self, intent: ActionIntent) -> ActionObservation: ...

    def execute(self, intent: ActionIntent) -> ActionReceipt: ...

    def compensate(self, intent: ActionIntent) -> ActionReceipt: ...


class SandboxBackend(Protocol):
    """Provider-neutral ephemeral compute boundary."""

    def ready(self) -> bool: ...

    def observe(self, request: SandboxExecutionRequest) -> BackendObservation: ...

    def provision(self, request: SandboxExecutionRequest) -> BackendExecution: ...

    def wait(
        self,
        request: SandboxExecutionRequest,
        execution: BackendExecution,
    ) -> SandboxResult: ...

    def cancel(
        self,
        request: SandboxExecutionRequest,
        execution: BackendExecution,
    ) -> None: ...

    def cleanup(
        self,
        request: SandboxExecutionRequest,
        execution: BackendExecution,
    ) -> None: ...


class AuditPort(Protocol):
    def append(
        self,
        *,
        identity: IdentityContext,
        event_type: str,
        attributes: Mapping[str, str | int | bool],
    ) -> None: ...


class IdempotencyPort(Protocol):
    def acquire(
        self,
        *,
        tenant_id: str,
        request_id: str,
        fingerprint: str,
    ) -> RunClaim: ...

    def complete(
        self,
        *,
        tenant_id: str,
        request_id: str,
        result: InvestigationResult,
    ) -> None: ...

    def fail(self, *, tenant_id: str, request_id: str, code: str) -> None: ...


class Observation(Protocol):
    def finish(
        self,
        *,
        status: str,
        attributes: Mapping[str, str | int | bool],
    ) -> None: ...


class ObservabilityPort(Protocol):
    def investigation(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]: ...

    def evidence_query(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]: ...


class GraphObservabilityPort(Protocol):
    def graph_node(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]: ...

    def model_call(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]: ...


class RemediationObservabilityPort(Protocol):
    def remediation(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]: ...


class SandboxObservabilityPort(Protocol):
    def sandbox(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]: ...


class MemoryObservabilityPort(Protocol):
    def memory(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]: ...


class ClockPort(Protocol):
    def now(self) -> datetime: ...


class FindingValidatorPort(Protocol):
    def validate(
        self, finding: SpecialistFinding, evidence: Sequence[Evidence]
    ) -> bool: ...


class EvaluationExecutorPort(Protocol):
    """Provider-neutral case execution boundary."""

    def execute(self, case: EvalCase) -> ExecutionObservation: ...


class EvaluationPublisherPort(Protocol):
    """Optional sanitized result publisher; never a CI authority."""

    def publish_evaluation_report(self, report: EvaluationReport) -> None: ...

    def publish_case_result(self, result: CaseResult) -> None: ...

    def publish_dataset_manifest(self, dataset: DatasetContract) -> None: ...
