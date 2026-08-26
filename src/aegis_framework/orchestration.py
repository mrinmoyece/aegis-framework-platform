"""Neutral governed-orchestration artifacts and application-ledger contracts."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from enum import StrEnum
from hashlib import sha256
from threading import Lock
from typing import Annotated, Literal, Protocol

from pydantic import Field, JsonValue, model_validator

from aegis_framework.domain import (
    Citation,
    CriticDecision,
    Hypothesis,
    Identifier,
    InvestigationStatus,
    RemediationProposal,
    Sha256Digest,
    StrictModel,
    stable_id,
)
from aegis_framework.errors import IntegrityFailure, OrchestrationFailure

GRAPH_VERSION = "6.0.0"
ARTIFACT_SCHEMA_VERSION = 1
MAX_SPECIALIST_FANOUT = 4
MAX_CRITIC_ITERATIONS = 1
MAX_ARTIFACTS = 64


class AgentRole(StrEnum):
    COORDINATOR = "coordinator"
    TELEMETRY_SPECIALIST = "telemetry_specialist"
    CHANGE_SPECIALIST = "change_specialist"
    RUNTIME_SPECIALIST = "runtime_specialist"
    KNOWLEDGE_SPECIALIST = "knowledge_specialist"
    CRITIC = "critic"
    REMEDIATION_PLANNER = "remediation_planner"
    VERIFICATION_AGENT = "verification_agent"


SPECIALIST_ROLES = (
    AgentRole.TELEMETRY_SPECIALIST,
    AgentRole.CHANGE_SPECIALIST,
    AgentRole.RUNTIME_SPECIALIST,
    AgentRole.KNOWLEDGE_SPECIALIST,
)


class ArtifactKind(StrEnum):
    INVESTIGATION_PLAN = "investigation_plan"
    INVESTIGATION_TASK = "investigation_task"
    EVIDENCE_ASSESSMENT = "evidence_assessment"
    HYPOTHESIS = "hypothesis"
    CRITIQUE = "critique"
    CONTRADICTION = "contradiction"
    CONTEXT_REFERENCES = "context_references"
    REMEDIATION_PROPOSAL = "remediation_proposal"
    VERIFICATION_PLAN = "verification_plan"
    COORDINATOR_DECISION = "coordinator_decision"
    FINAL_ASSESSMENT = "final_assessment"


class CalibrationBand(StrEnum):
    UNCALIBRATED = "uncalibrated"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class OrchestrationTerminalState(StrEnum):
    COMPLETE = "complete"
    ABSTAINED = "abstained"
    ESCALATED = "escalated"
    FAILED = "failed"
    CANCELLED = "cancelled"


class InvestigationPlanPayload(StrictModel):
    kind: Literal[ArtifactKind.INVESTIGATION_PLAN] = ArtifactKind.INVESTIGATION_PLAN
    objective: Annotated[str, Field(min_length=1, max_length=512)]
    task_ids: Annotated[
        tuple[Identifier, ...],
        Field(min_length=MAX_SPECIALIST_FANOUT, max_length=MAX_SPECIALIST_FANOUT),
    ]
    graph_version: Literal["6.0.0"] = "6.0.0"
    maximum_fanout: Literal[4] = 4
    maximum_critic_iterations: Literal[1] = 1


class InvestigationTaskPayload(StrictModel):
    kind: Literal[ArtifactKind.INVESTIGATION_TASK] = ArtifactKind.INVESTIGATION_TASK
    task_id: Identifier
    assigned_role: AgentRole
    objective: Annotated[str, Field(min_length=1, max_length=512)]
    allowed_evidence_kinds: Annotated[
        tuple[Identifier, ...], Field(min_length=1, max_length=3)
    ]
    predecessor_task_ids: Annotated[tuple[Identifier, ...], Field(max_length=4)] = ()


class EvidenceAssessmentPayload(StrictModel):
    kind: Literal[ArtifactKind.EVIDENCE_ASSESSMENT] = ArtifactKind.EVIDENCE_ASSESSMENT
    task_id: Identifier
    finding_id: Identifier
    statement: Annotated[str, Field(min_length=1, max_length=1_000)]
    cause_code: Identifier | None
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    calibration: CalibrationBand
    citations: Annotated[tuple[Citation, ...], Field(max_length=16)]
    abstained: bool
    reason: Annotated[str | None, Field(max_length=256)] = None

    @model_validator(mode="after")
    def bind_abstention(self) -> EvidenceAssessmentPayload:
        if self.abstained and (
            self.cause_code is not None or self.citations or self.confidence != 0.0
        ):
            raise ValueError("abstaining assessment cannot make supported claims")
        if not self.abstained and (self.cause_code is None or not self.citations):
            raise ValueError("non-abstaining assessment requires cause and citations")
        return self


class HypothesisPayload(StrictModel):
    kind: Literal[ArtifactKind.HYPOTHESIS] = ArtifactKind.HYPOTHESIS
    hypothesis: Hypothesis
    alternative_cause_codes: Annotated[tuple[Identifier, ...], Field(max_length=9)] = ()
    calibration: CalibrationBand


class CritiquePayload(StrictModel):
    kind: Literal[ArtifactKind.CRITIQUE] = ArtifactKind.CRITIQUE
    decision: CriticDecision
    reasons: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=16)]
    checked_citations: Annotated[int, Field(ge=0, le=256)]
    rejected_claim_ids: Annotated[tuple[Identifier, ...], Field(max_length=64)] = ()


class ContradictionPayload(StrictModel):
    kind: Literal[ArtifactKind.CONTRADICTION] = ArtifactKind.CONTRADICTION
    contradiction_ids: Annotated[
        tuple[Identifier, ...], Field(min_length=1, max_length=64)
    ]
    reason: Identifier


class ContextReferencesPayload(StrictModel):
    kind: Literal[ArtifactKind.CONTEXT_REFERENCES] = ArtifactKind.CONTEXT_REFERENCES
    timeline_event_ids: Annotated[tuple[Identifier, ...], Field(max_length=1_000)]
    conflict_ids: Annotated[tuple[Identifier, ...], Field(max_length=1_000)]
    causal_claims_supported: Literal[False] = False


class RemediationProposalPayload(StrictModel):
    kind: Literal[ArtifactKind.REMEDIATION_PROPOSAL] = ArtifactKind.REMEDIATION_PROPOSAL
    proposal: RemediationProposal
    production_effect_performed: Literal[False] = False


class VerificationPlanPayload(StrictModel):
    kind: Literal[ArtifactKind.VERIFICATION_PLAN] = ArtifactKind.VERIFICATION_PLAN
    proposal_id: Identifier
    steps: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=256)], ...],
        Field(min_length=1, max_length=8),
    ]
    required_evidence_ids: Annotated[
        tuple[Identifier, ...], Field(min_length=1, max_length=32)
    ]
    production_verification_performed: Literal[False] = False


class CoordinatorDecisionPayload(StrictModel):
    kind: Literal[ArtifactKind.COORDINATOR_DECISION] = ArtifactKind.COORDINATOR_DECISION
    decision: OrchestrationTerminalState
    reason_codes: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=16)]
    selected_hypothesis_id: Identifier | None = None
    proposal_id: Identifier | None = None


class FinalAssessmentPayload(StrictModel):
    kind: Literal[ArtifactKind.FINAL_ASSESSMENT] = ArtifactKind.FINAL_ASSESSMENT
    status: InvestigationStatus
    summary: Annotated[str, Field(min_length=1, max_length=1_000)]
    hypothesis_ids: Annotated[tuple[Identifier, ...], Field(max_length=10)]
    proposal_id: Identifier | None = None
    requires_human_escalation: bool
    production_effect_verified: Literal[False] = False


type ArtifactPayload = Annotated[
    InvestigationPlanPayload
    | InvestigationTaskPayload
    | EvidenceAssessmentPayload
    | HypothesisPayload
    | CritiquePayload
    | ContradictionPayload
    | ContextReferencesPayload
    | RemediationProposalPayload
    | VerificationPlanPayload
    | CoordinatorDecisionPayload
    | FinalAssessmentPayload,
    Field(discriminator="kind"),
]


class ArtifactProvenance(StrictModel):
    artifact_id: Identifier
    artifact_digest: Sha256Digest


class GovernanceArtifact(StrictModel):
    artifact_id: Identifier
    schema_version: Literal[1] = 1
    tenant_id: Identifier
    incident_id: Identifier
    run_id: Identifier
    task_id: Identifier | None = None
    ordinal: Annotated[int, Field(ge=1, le=1_000)]
    producer_role: AgentRole
    payload: ArtifactPayload
    provenance: Annotated[tuple[ArtifactProvenance, ...], Field(max_length=16)] = ()
    canonical_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_envelope(self) -> GovernanceArtifact:
        expected = artifact_digest(
            tenant_id=self.tenant_id,
            incident_id=self.incident_id,
            run_id=self.run_id,
            task_id=self.task_id,
            ordinal=self.ordinal,
            producer_role=self.producer_role,
            payload=self.payload,
            provenance=self.provenance,
        )
        if self.canonical_digest != expected:
            raise ValueError("artifact canonical digest mismatch")
        if self.payload.kind not in _ROLE_WRITES[self.producer_role]:
            raise ValueError("role is not permitted to produce this artifact kind")
        # Validate provenance chain: plan has no predecessors; everything else must.
        if self.payload.kind is ArtifactKind.INVESTIGATION_PLAN:
            if self.provenance:
                raise ValueError("investigation plan cannot have artifact predecessors")
        else:
            if not self.provenance:
                raise ValueError("artifact transition requires provenance")
        if isinstance(self.payload, InvestigationTaskPayload):
            if self.payload.assigned_role not in SPECIALIST_ROLES:
                raise ValueError("task can target only a fixed specialist role")
            if self.task_id != self.payload.task_id:
                raise ValueError("task envelope linkage is inconsistent")
        return self

    @classmethod
    def issue(
        cls,
        *,
        tenant_id: str,
        incident_id: str,
        run_id: str,
        task_id: str | None,
        ordinal: int,
        producer_role: AgentRole,
        payload: ArtifactPayload,
        sources: Sequence[GovernanceArtifact] = (),
    ) -> GovernanceArtifact:
        provenance = tuple(
            ArtifactProvenance(
                artifact_id=source.artifact_id,
                artifact_digest=source.canonical_digest,
            )
            for source in sorted(sources, key=lambda item: item.artifact_id)
        )
        _validate_transition(payload.kind, sources)
        digest = artifact_digest(
            tenant_id=tenant_id,
            incident_id=incident_id,
            run_id=run_id,
            task_id=task_id,
            ordinal=ordinal,
            producer_role=producer_role,
            payload=payload,
            provenance=provenance,
        )
        return cls(
            artifact_id=stable_id(
                "artifact",
                run_id,
                payload.kind.value,
                producer_role.value,
                task_id or "run",
                digest,
                length=40,
            ),
            tenant_id=tenant_id,
            incident_id=incident_id,
            run_id=run_id,
            task_id=task_id,
            ordinal=ordinal,
            producer_role=producer_role,
            payload=payload,
            provenance=provenance,
            canonical_digest=digest,
        )


class ArtifactSummary(StrictModel):
    artifact_id: Identifier
    schema_version: int
    ordinal: int
    kind: ArtifactKind
    producer_role: AgentRole
    task_id: Identifier | None


class ArtifactPage(StrictModel):
    items: tuple[ArtifactSummary, ...]
    next_ordinal: int | None


class TaskDispatchStatus(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"
    CACHED = "cached"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    CANCELLED = "cancelled"


class TaskDispatchClaim(StrictModel):
    status: TaskDispatchStatus
    fence_token: Identifier
    cached_result: dict[str, JsonValue] | None = None


class OrchestrationRunProjection(StrictModel):
    tenant_id: Identifier
    incident_id: Identifier
    run_id: Identifier
    thread_ref: Identifier
    graph_version: Identifier
    input_digest: Sha256Digest
    fence_token: Identifier
    cancelled: bool = False
    artifact_count: Annotated[int, Field(ge=0, le=MAX_ARTIFACTS)] = 0
    decision: OrchestrationTerminalState | None = None


class _TaskLedgerRecord(StrictModel):
    role: AgentRole
    input_digest: Sha256Digest
    fence_token: Identifier
    attempt: Annotated[int, Field(ge=1, le=16)]
    status: TaskDispatchStatus
    result: dict[str, JsonValue] | None = None


class OrchestrationLedgerPort(Protocol):
    def begin_run(
        self,
        *,
        tenant_id: str,
        incident_id: str,
        run_id: str,
        thread_ref: str,
        graph_version: str,
        input_digest: str,
    ) -> OrchestrationRunProjection: ...

    def claim_task(
        self,
        *,
        tenant_id: str,
        run_id: str,
        task_id: str,
        role: AgentRole,
        input_digest: str,
    ) -> TaskDispatchClaim: ...

    def complete_task(
        self,
        *,
        tenant_id: str,
        run_id: str,
        task_id: str,
        fence_token: str,
        result: Mapping[str, JsonValue],
    ) -> None: ...

    def append_artifacts(
        self,
        *,
        tenant_id: str,
        run_id: str,
        fence_token: str,
        artifacts: Sequence[GovernanceArtifact],
    ) -> None: ...

    def artifacts(
        self, *, tenant_id: str, run_id: str
    ) -> tuple[GovernanceArtifact, ...]: ...

    def artifact_page(
        self,
        *,
        tenant_id: str,
        run_id: str,
        after_ordinal: int,
        limit: int,
    ) -> ArtifactPage: ...

    def projection(
        self, *, tenant_id: str, run_id: str
    ) -> OrchestrationRunProjection | None: ...

    def cancel(self, *, tenant_id: str, run_id: str) -> None: ...


class OrchestrationArtifactReadPort(Protocol):
    def artifact_page(
        self,
        *,
        tenant_id: str,
        run_id: str,
        after_ordinal: int,
        limit: int,
    ) -> ArtifactPage: ...


class InMemoryOrchestrationLedger:
    """Deterministic application-ledger reference; never framework checkpoint truth."""

    def __init__(self) -> None:
        self._runs: dict[tuple[str, str], OrchestrationRunProjection] = {}
        self._tasks: dict[tuple[str, str, str], _TaskLedgerRecord] = {}
        self._artifacts: dict[tuple[str, str, str], GovernanceArtifact] = {}
        self._lock = Lock()

    def begin_run(
        self,
        *,
        tenant_id: str,
        incident_id: str,
        run_id: str,
        thread_ref: str,
        graph_version: str,
        input_digest: str,
    ) -> OrchestrationRunProjection:
        key = (tenant_id, run_id)
        fence = stable_id(
            "fence", tenant_id, run_id, graph_version, input_digest, length=40
        )
        proposed = OrchestrationRunProjection(
            tenant_id=tenant_id,
            incident_id=incident_id,
            run_id=run_id,
            thread_ref=thread_ref,
            graph_version=graph_version,
            input_digest=input_digest,
            fence_token=fence,
        )
        with self._lock:
            existing = self._runs.get(key)
            if existing is None:
                self._runs[key] = proposed
                return proposed
            if (
                existing.incident_id != incident_id
                or existing.thread_ref != thread_ref
                or existing.graph_version != graph_version
                or existing.input_digest != input_digest
            ):
                raise OrchestrationFailure("orchestration run binding changed")
            return existing

    def claim_task(
        self,
        *,
        tenant_id: str,
        run_id: str,
        task_id: str,
        role: AgentRole,
        input_digest: str,
    ) -> TaskDispatchClaim:
        key = (tenant_id, run_id, task_id)
        with self._lock:
            run = self._required_run(tenant_id, run_id)
            if run.cancelled:
                return TaskDispatchClaim(
                    status=TaskDispatchStatus.CANCELLED,
                    fence_token=task_fence(
                        tenant_id=tenant_id,
                        run_id=run_id,
                        task_id=task_id,
                        role=role,
                        input_digest=input_digest,
                        attempt=1,
                    ),
                )
            existing = self._tasks.get(key)
            if existing is None:
                fence = task_fence(
                    tenant_id=tenant_id,
                    run_id=run_id,
                    task_id=task_id,
                    role=role,
                    input_digest=input_digest,
                    attempt=1,
                )
                self._tasks[key] = _TaskLedgerRecord(
                    role=role,
                    input_digest=input_digest,
                    fence_token=fence,
                    attempt=1,
                    status=TaskDispatchStatus.STARTED,
                )
                return TaskDispatchClaim(
                    status=TaskDispatchStatus.STARTED,
                    fence_token=fence,
                )
            if existing.role is not role or existing.input_digest != input_digest:
                raise IntegrityFailure("task dispatch binding changed")
            if existing.status is TaskDispatchStatus.COMPLETED:
                if existing.result is None:
                    raise IntegrityFailure("completed task result is unavailable")
                return TaskDispatchClaim(
                    status=TaskDispatchStatus.CACHED,
                    fence_token=existing.fence_token,
                    cached_result=existing.result,
                )
            if existing.status is TaskDispatchStatus.RECONCILIATION_REQUIRED:
                return TaskDispatchClaim(
                    status=TaskDispatchStatus.RECONCILIATION_REQUIRED,
                    fence_token=existing.fence_token,
                )
            attempt = existing.attempt + 1
            fence = task_fence(
                tenant_id=tenant_id,
                run_id=run_id,
                task_id=task_id,
                role=role,
                input_digest=input_digest,
                attempt=attempt,
            )
            self._tasks[key] = existing.model_copy(
                update={
                    "attempt": attempt,
                    "fence_token": fence,
                    "status": TaskDispatchStatus.RECONCILIATION_REQUIRED,
                }
            )
            return TaskDispatchClaim(
                status=TaskDispatchStatus.RECONCILIATION_REQUIRED,
                fence_token=fence,
            )

    def complete_task(
        self,
        *,
        tenant_id: str,
        run_id: str,
        task_id: str,
        fence_token: str,
        result: Mapping[str, JsonValue],
    ) -> None:
        key = (tenant_id, run_id, task_id)
        canonical = json.loads(_canonical_json(dict(result)))
        if not isinstance(canonical, dict):
            raise IntegrityFailure("task result must be an object")
        with self._lock:
            run = self._required_run(tenant_id, run_id)
            if run.cancelled:
                raise IntegrityFailure("cancelled run rejected stale task result")
            existing = self._tasks.get(key)
            if (
                existing is None
                or existing.fence_token != fence_token
                or existing.status is not TaskDispatchStatus.STARTED
            ):
                raise IntegrityFailure("task result fence is stale")
            self._tasks[key] = existing.model_copy(
                update={
                    "status": TaskDispatchStatus.COMPLETED,
                    "result": canonical,
                }
            )

    def append_artifacts(
        self,
        *,
        tenant_id: str,
        run_id: str,
        fence_token: str,
        artifacts: Sequence[GovernanceArtifact],
    ) -> None:
        if len(artifacts) > MAX_ARTIFACTS:
            raise IntegrityFailure("artifact append exceeds run bound")
        with self._lock:
            run = self._required_run(tenant_id, run_id)
            if run.cancelled or run.fence_token != fence_token:
                raise IntegrityFailure("artifact fence is stale")
            proposed = {
                key: value
                for key, value in self._artifacts.items()
                if key[0] == tenant_id and key[1] == run_id
            }
            for artifact in artifacts:
                if artifact.tenant_id != tenant_id or artifact.run_id != run_id:
                    raise IntegrityFailure("artifact tenant/run binding mismatch")
                key = (tenant_id, run_id, artifact.artifact_id)
                existing = self._artifacts.get(key)
                if existing is not None and existing != artifact:
                    raise IntegrityFailure("immutable artifact changed")
                proposed[key] = artifact
            current = tuple(
                sorted(
                    proposed.values(),
                    key=lambda item: (item.ordinal, item.artifact_id),
                )
            )
            if len(current) > MAX_ARTIFACTS:
                raise IntegrityFailure("artifact run bound exceeded")
            ordinals = tuple(item.ordinal for item in current)
            if len(ordinals) != len(set(ordinals)):
                raise IntegrityFailure("artifact ordinal was reused")
            self._artifacts.update(proposed)
            decision = next(
                (
                    item.payload.decision
                    for item in reversed(current)
                    if isinstance(item.payload, CoordinatorDecisionPayload)
                ),
                run.decision,
            )
            self._runs[(tenant_id, run_id)] = run.model_copy(
                update={"artifact_count": len(current), "decision": decision}
            )

    def artifacts(
        self, *, tenant_id: str, run_id: str
    ) -> tuple[GovernanceArtifact, ...]:
        with self._lock:
            self._required_run(tenant_id, run_id)
            return self._run_artifacts(tenant_id, run_id)

    def artifact_page(
        self,
        *,
        tenant_id: str,
        run_id: str,
        after_ordinal: int,
        limit: int,
    ) -> ArtifactPage:
        if after_ordinal < 0 or limit < 1 or limit > 100:
            raise ValueError("artifact page bounds are invalid")
        with self._lock:
            self._required_run(tenant_id, run_id)
            selected = [
                item
                for item in self._run_artifacts(tenant_id, run_id)
                if item.ordinal > after_ordinal
            ][: limit + 1]
        page = selected[:limit]
        next_ordinal = page[-1].ordinal if len(selected) > limit and page else None
        return ArtifactPage(
            items=tuple(
                ArtifactSummary(
                    artifact_id=item.artifact_id,
                    schema_version=item.schema_version,
                    ordinal=item.ordinal,
                    kind=item.payload.kind,
                    producer_role=item.producer_role,
                    task_id=item.task_id,
                )
                for item in page
            ),
            next_ordinal=next_ordinal,
        )

    def projection(
        self, *, tenant_id: str, run_id: str
    ) -> OrchestrationRunProjection | None:
        with self._lock:
            return self._runs.get((tenant_id, run_id))

    def cancel(self, *, tenant_id: str, run_id: str) -> None:
        with self._lock:
            current = self._required_run(tenant_id, run_id)
            self._runs[(tenant_id, run_id)] = current.model_copy(
                update={"cancelled": True}
            )

    def rebuild_projection(
        self, *, tenant_id: str, run_id: str
    ) -> OrchestrationRunProjection:
        with self._lock:
            current = self._required_run(tenant_id, run_id)
            artifacts = self._run_artifacts(tenant_id, run_id)
            decision = next(
                (
                    item.payload.decision
                    for item in reversed(artifacts)
                    if isinstance(item.payload, CoordinatorDecisionPayload)
                ),
                None,
            )
            rebuilt = current.model_copy(
                update={"artifact_count": len(artifacts), "decision": decision}
            )
            self._runs[(tenant_id, run_id)] = rebuilt
            return rebuilt

    def _required_run(self, tenant_id: str, run_id: str) -> OrchestrationRunProjection:
        try:
            return self._runs[(tenant_id, run_id)]
        except KeyError as exc:
            raise IntegrityFailure("orchestration run is unavailable") from exc

    def _run_artifacts(
        self, tenant_id: str, run_id: str
    ) -> tuple[GovernanceArtifact, ...]:
        return tuple(
            sorted(
                (
                    artifact
                    for (
                        stored_tenant,
                        stored_run,
                        _,
                    ), artifact in self._artifacts.items()
                    if stored_tenant == tenant_id and stored_run == run_id
                ),
                key=lambda item: (item.ordinal, item.artifact_id),
            )
        )


_ROLE_WRITES: Mapping[AgentRole, frozenset[ArtifactKind]] = {
    AgentRole.COORDINATOR: frozenset(
        {
            ArtifactKind.INVESTIGATION_PLAN,
            ArtifactKind.INVESTIGATION_TASK,
            ArtifactKind.CONTEXT_REFERENCES,
            ArtifactKind.COORDINATOR_DECISION,
            ArtifactKind.FINAL_ASSESSMENT,
        }
    ),
    AgentRole.TELEMETRY_SPECIALIST: frozenset({ArtifactKind.EVIDENCE_ASSESSMENT}),
    AgentRole.CHANGE_SPECIALIST: frozenset({ArtifactKind.EVIDENCE_ASSESSMENT}),
    AgentRole.RUNTIME_SPECIALIST: frozenset({ArtifactKind.EVIDENCE_ASSESSMENT}),
    AgentRole.KNOWLEDGE_SPECIALIST: frozenset({ArtifactKind.EVIDENCE_ASSESSMENT}),
    AgentRole.CRITIC: frozenset(
        {ArtifactKind.CRITIQUE, ArtifactKind.CONTRADICTION, ArtifactKind.HYPOTHESIS}
    ),
    AgentRole.REMEDIATION_PLANNER: frozenset({ArtifactKind.REMEDIATION_PROPOSAL}),
    AgentRole.VERIFICATION_AGENT: frozenset({ArtifactKind.VERIFICATION_PLAN}),
}

_TRANSITIONS: Mapping[ArtifactKind, frozenset[ArtifactKind]] = {
    ArtifactKind.INVESTIGATION_PLAN: frozenset(
        {ArtifactKind.INVESTIGATION_TASK, ArtifactKind.CONTEXT_REFERENCES}
    ),
    ArtifactKind.INVESTIGATION_TASK: frozenset({ArtifactKind.EVIDENCE_ASSESSMENT}),
    ArtifactKind.EVIDENCE_ASSESSMENT: frozenset(
        {ArtifactKind.CRITIQUE, ArtifactKind.CONTRADICTION}
    ),
    ArtifactKind.CRITIQUE: frozenset(
        {
            ArtifactKind.HYPOTHESIS,
            ArtifactKind.COORDINATOR_DECISION,
        }
    ),
    ArtifactKind.CONTRADICTION: frozenset({ArtifactKind.COORDINATOR_DECISION}),
    ArtifactKind.HYPOTHESIS: frozenset({ArtifactKind.REMEDIATION_PROPOSAL}),
    ArtifactKind.REMEDIATION_PROPOSAL: frozenset({ArtifactKind.VERIFICATION_PLAN}),
    ArtifactKind.VERIFICATION_PLAN: frozenset({ArtifactKind.COORDINATOR_DECISION}),
    ArtifactKind.COORDINATOR_DECISION: frozenset({ArtifactKind.FINAL_ASSESSMENT}),
    ArtifactKind.CONTEXT_REFERENCES: frozenset(),
    ArtifactKind.FINAL_ASSESSMENT: frozenset(),
}


def artifact_digest(
    *,
    tenant_id: str,
    incident_id: str,
    run_id: str,
    task_id: str | None,
    ordinal: int,
    producer_role: AgentRole,
    payload: ArtifactPayload,
    provenance: Sequence[ArtifactProvenance],
) -> str:
    return sha256(
        _canonical_json(
            {
                "incident_id": incident_id,
                "ordinal": ordinal,
                "payload": payload.model_dump(mode="json"),
                "producer_role": producer_role.value,
                "provenance": [item.model_dump(mode="json") for item in provenance],
                "run_id": run_id,
                "schema_version": ARTIFACT_SCHEMA_VERSION,
                "task_id": task_id,
                "tenant_id": tenant_id,
            }
        ).encode()
    ).hexdigest()


def orchestration_input_digest(
    *,
    tenant_id: str,
    incident_id: str,
    run_id: str,
    evidence_digests: Sequence[str],
    alert_digest: str | None = None,
    evidence_ids: Sequence[str] = (),
    evidence_locators: Sequence[str] = (),
) -> str:
    return sha256(
        _canonical_json(
            {
                "alert_digest": alert_digest,
                "evidence_digests": sorted(evidence_digests),
                "evidence_ids": sorted(evidence_ids),
                "evidence_locators": sorted(evidence_locators),
                "graph_version": GRAPH_VERSION,
                "incident_id": incident_id,
                "run_id": run_id,
                "tenant_id": tenant_id,
            }
        ).encode()
    ).hexdigest()


def task_fence(
    *,
    tenant_id: str,
    run_id: str,
    task_id: str,
    role: AgentRole,
    input_digest: str,
    attempt: int,
) -> str:
    return stable_id(
        "task-fence",
        tenant_id,
        run_id,
        task_id,
        role.value,
        input_digest,
        str(attempt),
        length=40,
    )


def _validate_transition(
    target: ArtifactKind, sources: Sequence[GovernanceArtifact]
) -> None:
    if target is ArtifactKind.INVESTIGATION_PLAN:
        if sources:
            raise ValueError("investigation plan cannot have artifact predecessors")
        return
    if not sources:
        raise ValueError("artifact transition requires provenance")
    invalid = tuple(
        source.payload.kind
        for source in sources
        if target not in _TRANSITIONS[source.payload.kind]
    )
    if invalid:
        raise ValueError("artifact transition is not permitted")


def _canonical_json(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)
