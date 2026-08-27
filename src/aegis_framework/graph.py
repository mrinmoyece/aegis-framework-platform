"""Governed LangGraph adapter for bounded specialist orchestration."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from datetime import datetime
from threading import Lock
from typing import Any, Literal, cast

from langchain_core.runnables import RunnableConfig, RunnableLambda
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from pydantic import JsonValue, ValidationError

from aegis_framework.checkpointing import strict_checkpoint_serializer
from aegis_framework.correlation import correlate_evidence
from aegis_framework.domain import (
    Citation,
    CorrelationContext,
    CriticDecision,
    CriticVerdict,
    Evidence,
    EvidenceKind,
    Hypothesis,
    InvestigationRequest,
    InvestigationResult,
    InvestigationState,
    InvestigationStatus,
    ModelEvidence,
    NodeError,
    RemediationProposal,
    Specialist,
    SpecialistFinding,
    SpecialistTask,
    stable_id,
)
from aegis_framework.errors import (
    IntegrityFailure,
    ModelProviderError,
    OrchestrationFailure,
)
from aegis_framework.observability import NoopObservability
from aegis_framework.orchestration import (
    GRAPH_VERSION,
    AgentRole,
    ArtifactKind,
    ArtifactPage,
    CalibrationBand,
    ContextReferencesPayload,
    ContradictionPayload,
    CoordinatorDecisionPayload,
    CritiquePayload,
    EvidenceAssessmentPayload,
    FinalAssessmentPayload,
    GovernanceArtifact,
    HypothesisPayload,
    InMemoryOrchestrationLedger,
    InvestigationPlanPayload,
    InvestigationTaskPayload,
    OrchestrationLedgerPort,
    OrchestrationTerminalState,
    RemediationProposalPayload,
    TaskDispatchStatus,
    VerificationPlanPayload,
    orchestration_input_digest,
)
from aegis_framework.ports import GraphObservabilityPort, StructuredModelPort
from aegis_framework.safety import citation_is_valid, prepare_model_evidence

_GRAPH_RECURSION_LIMIT = 12
_MINIMUM_CONFIDENCE = 0.70
_SPECIALIST_BINDINGS = (
    (
        Specialist.TELEMETRY,
        AgentRole.TELEMETRY_SPECIALIST,
        ("telemetry", "change"),
        10,
        20,
    ),
    (
        Specialist.CHANGE,
        AgentRole.CHANGE_SPECIALIST,
        ("change", "telemetry"),
        11,
        21,
    ),
    (
        Specialist.RUNTIME,
        AgentRole.RUNTIME_SPECIALIST,
        ("telemetry", "change"),
        12,
        22,
    ),
    (
        Specialist.KNOWLEDGE,
        AgentRole.KNOWLEDGE_SPECIALIST,
        ("runbook", "change"),
        13,
        23,
    ),
)
_ROLE_BY_SPECIALIST = {binding[0]: binding[1] for binding in _SPECIALIST_BINDINGS}
_TASK_ORDINAL_BY_SPECIALIST = {
    binding[0]: binding[3] for binding in _SPECIALIST_BINDINGS
}
_ASSESSMENT_ORDINAL_BY_SPECIALIST = {
    binding[0]: binding[4] for binding in _SPECIALIST_BINDINGS
}


class LangGraphInvestigator:
    """Use LangGraph mechanics while application ports retain every authority fact."""

    def __init__(
        self,
        model: StructuredModelPort,
        checkpointer: BaseCheckpointSaver[str] | None = None,
        ledger: OrchestrationLedgerPort | None = None,
        observability: GraphObservabilityPort | None = None,
    ) -> None:
        self._model = model
        self._ledger = ledger or InMemoryOrchestrationLedger()
        self._observability = observability or NoopObservability()
        self._thread_tenants: dict[str, str] = {}
        self._thread_lock = Lock()
        self._checkpointer = checkpointer or InMemorySaver(
            serde=strict_checkpoint_serializer()
        )
        self._graph = self._build_graph()

    def _build_graph(
        self,
    ) -> CompiledStateGraph[
        InvestigationState,
        None,
        InvestigationState,
        InvestigationState,
    ]:
        builder = StateGraph(InvestigationState)
        builder.add_node(
            "coordinator",
            RunnableLambda(self._observed_node("coordinator", self._coordinator)),
        )
        builder.add_node(
            "telemetry_specialist",
            RunnableLambda(
                self._observed_node("telemetry_specialist", self._telemetry_specialist)
            ),
        )
        builder.add_node(
            "change_specialist",
            RunnableLambda(
                self._observed_node("change_specialist", self._change_specialist)
            ),
        )
        builder.add_node(
            "runtime_specialist",
            RunnableLambda(
                self._observed_node("runtime_specialist", self._runtime_specialist)
            ),
        )
        builder.add_node(
            "knowledge_specialist",
            RunnableLambda(
                self._observed_node("knowledge_specialist", self._knowledge_specialist)
            ),
        )
        builder.add_node(
            "critic",
            RunnableLambda(self._observed_node("critic", self._critic)),
        )
        builder.add_node(
            "remediation_planner",
            RunnableLambda(
                self._observed_node("remediation_planner", self._remediation_planner)
            ),
        )
        builder.add_node(
            "verification_agent",
            RunnableLambda(
                self._observed_node("verification_agent", self._verification_agent)
            ),
        )
        builder.add_node(
            "coordinator_decision",
            RunnableLambda(
                self._observed_node("coordinator_decision", self._coordinator_decision)
            ),
        )
        builder.add_edge(START, "coordinator")
        for node in (
            "telemetry_specialist",
            "change_specialist",
            "runtime_specialist",
            "knowledge_specialist",
        ):
            builder.add_edge("coordinator", node)
        builder.add_edge(
            [
                "telemetry_specialist",
                "change_specialist",
                "runtime_specialist",
                "knowledge_specialist",
            ],
            "critic",
        )
        builder.add_conditional_edges(
            "critic",
            self._route_after_critic,
            {
                "plan": "remediation_planner",
                "decide": "coordinator_decision",
            },
        )
        builder.add_edge("remediation_planner", "verification_agent")
        builder.add_edge("verification_agent", "coordinator_decision")
        builder.add_edge("coordinator_decision", END)
        return builder.compile(checkpointer=self._checkpointer)

    def _observed_node(
        self,
        node: str,
        callback: Callable[[InvestigationState], dict[str, object]],
    ) -> Callable[[InvestigationState], dict[str, Any]]:
        def observed(state: InvestigationState) -> dict[str, Any]:
            with self._observability.graph_node(
                tenant_id=state["tenant_id"],
                attributes={"node": node},
            ) as observation:
                try:
                    result = callback(state)
                except Exception:
                    observation.finish(
                        status="failed",
                        attributes={"error_code": "graph_node_failure"},
                    )
                    raise
                observation.finish(
                    status="complete",
                    attributes={
                        "artifact_count": (
                            len(artifacts)
                            if isinstance(
                                (artifacts := result.get("artifacts")),
                                (list, tuple),
                            )
                            else 0
                        ),
                    },
                )
                return cast(dict[str, Any], result)

        return observed

    def _coordinator(self, state: InvestigationState) -> dict[str, object]:
        evidence = tuple(Evidence.model_validate(item) for item in state["evidence"])
        safe_evidence, injection_detected = prepare_model_evidence(evidence)
        reference_time = datetime.fromisoformat(state["correlation_reference"])
        correlation = correlate_evidence(evidence, reference_time=reference_time)
        task_ids = tuple(
            _task_id(state["run_id"], specialist)
            for specialist, *_ in _SPECIALIST_BINDINGS
        )
        plan = GovernanceArtifact.issue(
            tenant_id=state["tenant_id"],
            incident_id=state["incident_id"],
            run_id=state["run_id"],
            task_id=None,
            ordinal=1,
            producer_role=AgentRole.COORDINATOR,
            payload=InvestigationPlanPayload(
                objective=(
                    "Assess the checkout incident with fixed independent specialists, "
                    "critic review, remediation proposal only, and verification "
                    "planning."
                ),
                task_ids=task_ids,
            ),
        )
        tasks = tuple(
            GovernanceArtifact.issue(
                tenant_id=state["tenant_id"],
                incident_id=state["incident_id"],
                run_id=state["run_id"],
                task_id=_task_id(state["run_id"], specialist),
                ordinal=task_ordinal,
                producer_role=AgentRole.COORDINATOR,
                payload=InvestigationTaskPayload(
                    task_id=_task_id(state["run_id"], specialist),
                    assigned_role=role,
                    objective=(
                        f"Produce a cited {specialist.value} assessment or abstain."
                    ),
                    allowed_evidence_kinds=evidence_kinds,
                ),
                sources=(plan,),
            )
            for specialist, role, evidence_kinds, task_ordinal, _ in (
                _SPECIALIST_BINDINGS
            )
        )
        context = GovernanceArtifact.issue(
            tenant_id=state["tenant_id"],
            incident_id=state["incident_id"],
            run_id=state["run_id"],
            task_id=None,
            ordinal=14,
            producer_role=AgentRole.COORDINATOR,
            payload=ContextReferencesPayload(
                timeline_event_ids=tuple(
                    event.event_id for event in correlation.timeline
                ),
                conflict_ids=tuple(
                    conflict.conflict_id for conflict in correlation.conflicts
                ),
            ),
            sources=(plan,),
        )
        artifacts = (plan, *tasks, context)
        self._append_artifacts(state, artifacts)
        return {
            "safe_evidence": tuple(
                item.model_dump(mode="json") for item in safe_evidence
            ),
            "injection_detected": injection_detected,
            "correlation": correlation.model_dump(mode="json"),
            "artifacts": [item.model_dump(mode="json") for item in artifacts],
            "critic_iteration": 0,
        }

    def _telemetry_specialist(self, state: InvestigationState) -> dict[str, object]:
        return self._run_specialist(state, Specialist.TELEMETRY)

    def _change_specialist(self, state: InvestigationState) -> dict[str, object]:
        return self._run_specialist(state, Specialist.CHANGE)

    def _runtime_specialist(self, state: InvestigationState) -> dict[str, object]:
        return self._run_specialist(state, Specialist.RUNTIME)

    def _knowledge_specialist(self, state: InvestigationState) -> dict[str, object]:
        return self._run_specialist(state, Specialist.KNOWLEDGE)

    def _run_specialist(
        self,
        state: InvestigationState,
        specialist: Specialist,
    ) -> dict[str, object]:
        task_id = _task_id(state["run_id"], specialist)
        role = _ROLE_BY_SPECIALIST[specialist]
        claim = self._ledger.claim_task(
            tenant_id=state["tenant_id"],
            run_id=state["run_id"],
            task_id=task_id,
            role=role,
            input_digest=state["input_digest"],
        )
        if claim.status is TaskDispatchStatus.CANCELLED:
            return {
                "cancelled": True,
                "findings": [],
                "node_errors": [],
                "artifacts": [],
            }
        if claim.status is TaskDispatchStatus.CACHED:
            try:
                finding = SpecialistFinding.model_validate(claim.cached_result)
            except ValidationError:
                finding = _abstaining_finding(
                    state["incident_id"], specialist, "cached_task_result_invalid"
                )
        elif claim.status is TaskDispatchStatus.RECONCILIATION_REQUIRED:
            finding = _abstaining_finding(
                state["incident_id"], specialist, claim.status.value
            )
        else:
            finding = self._execute_specialist(state, specialist)

        task = _artifact(
            state,
            ArtifactKind.INVESTIGATION_TASK,
            task_id=task_id,
        )
        try:
            assessment = _assessment_artifact(
                state=state,
                task=task,
                task_id=task_id,
                specialist=specialist,
                role=role,
                finding=finding,
            )
        except ValidationError:
            finding = _abstaining_finding(
                state["incident_id"],
                specialist,
                "assessment_payload_invalid",
            )
            assessment = _assessment_artifact(
                state=state,
                task=task,
                task_id=task_id,
                specialist=specialist,
                role=role,
                finding=finding,
            )
        try:
            if claim.status is TaskDispatchStatus.STARTED:
                self._ledger.complete_task(
                    tenant_id=state["tenant_id"],
                    run_id=state["run_id"],
                    task_id=task_id,
                    fence_token=claim.fence_token,
                    result=cast(
                        dict[str, JsonValue],
                        finding.model_dump(mode="json"),
                    ),
                )
            self._append_artifacts(state, (assessment,))
        except IntegrityFailure:
            if self._is_cancelled(state):
                return {
                    "cancelled": True,
                    "findings": [],
                    "node_errors": [],
                    "artifacts": [],
                }
            raise
        errors = (
            []
            if not finding.abstained
            else [
                NodeError(
                    node=specialist.value,
                    code=finding.reason or "specialist_abstained",
                ).model_dump(mode="json")
            ]
        )
        return {
            "findings": [finding.model_dump(mode="json")],
            "node_errors": errors,
            "artifacts": [assessment.model_dump(mode="json")],
        }

    def _execute_specialist(
        self, state: InvestigationState, specialist: Specialist
    ) -> SpecialistFinding:
        task = SpecialistTask(
            tenant_id=state["tenant_id"],
            run_id=state["run_id"],
            incident_id=state["incident_id"],
            specialist=specialist,
            evidence=tuple(
                ModelEvidence.model_validate(item) for item in state["safe_evidence"]
            ),
            correlation=CorrelationContext.model_validate(state["correlation"]),
        )
        if specialist is Specialist.RUNTIME:
            return _runtime_finding(task)
        if specialist is Specialist.KNOWLEDGE:
            return _knowledge_finding(task)
        try:
            with self._observability.model_call(
                tenant_id=state["tenant_id"],
                attributes={"role": specialist.value},
            ) as observation:
                try:
                    raw = self._model.analyze(task)
                except ModelProviderError:
                    observation.finish(
                        status="failed",
                        attributes={"error_code": "model_provider_error"},
                    )
                    raise
                except Exception:
                    observation.finish(
                        status="failed",
                        attributes={"error_code": "model_adapter_exception"},
                    )
                    raise
                else:
                    observation.finish(status="complete", attributes={})
            finding = SpecialistFinding.model_validate(raw)
        except ValidationError:
            return _abstaining_finding(
                state["incident_id"], specialist, "model_output_invalid"
            )
        except ModelProviderError:
            return _abstaining_finding(
                state["incident_id"], specialist, "model_provider_error"
            )
        except Exception:
            return _abstaining_finding(
                state["incident_id"], specialist, "model_adapter_exception"
            )
        if finding.specialist is not specialist:
            return _abstaining_finding(
                state["incident_id"], specialist, "specialist_identity_mismatch"
            )
        return finding

    def _critic(self, state: InvestigationState) -> dict[str, object]:
        if state.get("cancelled", False):
            return {
                "hypotheses": (),
                "critic": CriticVerdict(
                    decision=CriticDecision.ABSTAINED,
                    reasons=("run_cancelled",),
                    checked_citations=0,
                ).model_dump(mode="json"),
                "proposal": None,
                "critic_iteration": 1,
            }
        findings = tuple(
            SpecialistFinding.model_validate(item) for item in state.get("findings", ())
        )
        evidence = tuple(Evidence.model_validate(item) for item in state["evidence"])
        correlation = CorrelationContext.model_validate(state["correlation"])
        critic, hypotheses = _evaluate_critic(
            findings=findings,
            evidence=evidence,
            correlation=correlation,
            injection_detected=state.get("injection_detected", False),
        )
        assessments = tuple(_artifacts(state, ArtifactKind.EVIDENCE_ASSESSMENT))
        critique = GovernanceArtifact.issue(
            tenant_id=state["tenant_id"],
            incident_id=state["incident_id"],
            run_id=state["run_id"],
            task_id=None,
            ordinal=30,
            producer_role=AgentRole.CRITIC,
            payload=CritiquePayload(
                decision=critic.decision,
                reasons=tuple(
                    stable_id("reason", reason, length=24) for reason in critic.reasons
                ),
                checked_citations=critic.checked_citations,
                rejected_claim_ids=tuple(critic.contradictions),
            ),
            sources=assessments,
        )
        emitted: list[GovernanceArtifact] = [critique]
        if critic.contradictions:
            contradiction = GovernanceArtifact.issue(
                tenant_id=state["tenant_id"],
                incident_id=state["incident_id"],
                run_id=state["run_id"],
                task_id=None,
                ordinal=31,
                producer_role=AgentRole.CRITIC,
                payload=ContradictionPayload(
                    contradiction_ids=tuple(critic.contradictions),
                    reason=stable_id(
                        "reason",
                        critic.reasons[0] if critic.reasons else "contradiction",
                    ),
                ),
                sources=assessments,
            )
            emitted.append(contradiction)
        if hypotheses:
            emitted.append(
                GovernanceArtifact.issue(
                    tenant_id=state["tenant_id"],
                    incident_id=state["incident_id"],
                    run_id=state["run_id"],
                    task_id=None,
                    ordinal=32,
                    producer_role=AgentRole.CRITIC,
                    payload=HypothesisPayload(
                        hypothesis=hypotheses[0],
                        alternative_cause_codes=tuple(
                            sorted(
                                {
                                    finding.cause_code
                                    for finding in findings
                                    if finding.cause_code is not None
                                    and finding.cause_code != hypotheses[0].cause_code
                                }
                            )
                        ),
                        calibration=_calibration(hypotheses[0].confidence),
                    ),
                    sources=(critique,),
                )
            )
        self._append_artifacts(state, emitted)
        return {
            "hypotheses": tuple(
                hypothesis.model_dump(mode="json") for hypothesis in hypotheses
            ),
            "critic": critic.model_dump(mode="json"),
            "proposal": None,
            "artifacts": [item.model_dump(mode="json") for item in emitted],
            "critic_iteration": 1,
        }

    @staticmethod
    def _route_after_critic(
        state: InvestigationState,
    ) -> Literal["plan", "decide"]:
        critic = CriticVerdict.model_validate(state["critic"])
        return (
            "plan"
            if critic.decision is CriticDecision.ACCEPTED
            and bool(state.get("hypotheses"))
            else "decide"
        )

    def _remediation_planner(self, state: InvestigationState) -> dict[str, object]:
        evidence = tuple(Evidence.model_validate(item) for item in state["evidence"])
        hypothesis = Hypothesis.model_validate(state["hypotheses"][0])
        proposal = _proposal_from_runbook(
            tenant_id=state["tenant_id"],
            incident_id=state["incident_id"],
            evidence=evidence,
            hypothesis=hypothesis,
        )
        if proposal is None:
            return {"proposal": None}
        hypothesis_artifact = _artifact(state, ArtifactKind.HYPOTHESIS)
        artifact = GovernanceArtifact.issue(
            tenant_id=state["tenant_id"],
            incident_id=state["incident_id"],
            run_id=state["run_id"],
            task_id=None,
            ordinal=40,
            producer_role=AgentRole.REMEDIATION_PLANNER,
            payload=RemediationProposalPayload(proposal=proposal),
            sources=(hypothesis_artifact,),
        )
        self._append_artifacts(state, (artifact,))
        return {
            "proposal": proposal.model_dump(mode="json"),
            "artifacts": [artifact.model_dump(mode="json")],
        }

    def _verification_agent(self, state: InvestigationState) -> dict[str, object]:
        if state.get("proposal") is None:
            return {}
        proposal = RemediationProposal.model_validate(state["proposal"])
        evidence = tuple(Evidence.model_validate(item) for item in state["evidence"])
        proposal_artifact = _artifact(state, ArtifactKind.REMEDIATION_PROPOSAL)
        artifact = GovernanceArtifact.issue(
            tenant_id=state["tenant_id"],
            incident_id=state["incident_id"],
            run_id=state["run_id"],
            task_id=None,
            ordinal=50,
            producer_role=AgentRole.VERIFICATION_AGENT,
            payload=VerificationPlanPayload(
                proposal_id=proposal.proposal_id,
                steps=(
                    "After separately approved execution, compare checkout error rate "
                    "with the cited baseline.",
                    "Confirm the deployment version and incident window from fresh "
                    "authorized evidence.",
                    "Record verification through a future effect ledger, never this "
                    "graph.",
                ),
                required_evidence_ids=tuple(
                    sorted(
                        {
                            citation.evidence_id
                            for hypothesis in (
                                Hypothesis.model_validate(item)
                                for item in state["hypotheses"]
                            )
                            for citation in hypothesis.citations
                            if any(
                                source.evidence_id == citation.evidence_id
                                for source in evidence
                            )
                        }
                    )
                ),
            ),
            sources=(proposal_artifact,),
        )
        self._append_artifacts(state, (artifact,))
        return {"artifacts": [artifact.model_dump(mode="json")]}

    def _coordinator_decision(self, state: InvestigationState) -> dict[str, object]:
        critic = CriticVerdict.model_validate(state["critic"])
        if state.get("cancelled", False):
            return {
                "terminal_state": OrchestrationTerminalState.CANCELLED.value,
                "critic": critic.model_dump(mode="json"),
            }
        hypotheses = tuple(
            Hypothesis.model_validate(item) for item in state.get("hypotheses", ())
        )
        proposal = (
            RemediationProposal.model_validate(state["proposal"])
            if state.get("proposal") is not None
            else None
        )
        if critic.decision is CriticDecision.ACCEPTED and proposal is None:
            critic = critic.model_copy(
                update={"reasons": ("corroborated_but_no_valid_action",)}
            )
        verification = tuple(_artifacts(state, ArtifactKind.VERIFICATION_PLAN))
        reasons: tuple[str, ...]
        if (
            critic.decision is CriticDecision.ACCEPTED
            and proposal is not None
            and verification
            and hypotheses
        ):
            terminal = OrchestrationTerminalState.COMPLETE
            status = InvestigationStatus.COMPLETE
            reasons = ("corroborated_and_cited",)
            source = verification
            summary = (
                "Cited specialist assessments support one remediation proposal and a "
                "future verification plan; no approval or production effect occurred."
            )
            escalate = False
        else:
            terminal = (
                OrchestrationTerminalState.ESCALATED
                if critic.decision is CriticDecision.REJECTED
                else OrchestrationTerminalState.ABSTAINED
            )
            status = InvestigationStatus.ABSTAINED
            reasons = critic.reasons or ("no_authorized_proposal",)
            source = tuple(_artifacts(state, ArtifactKind.CONTRADICTION)) or tuple(
                _artifacts(state, ArtifactKind.CRITIQUE)
            )
            summary = (
                "The governed investigation abstained or escalated because evidence, "
                "citations, confidence, or critic gates did not support a proposal."
            )
            escalate = terminal is OrchestrationTerminalState.ESCALATED
        decision = GovernanceArtifact.issue(
            tenant_id=state["tenant_id"],
            incident_id=state["incident_id"],
            run_id=state["run_id"],
            task_id=None,
            ordinal=60,
            producer_role=AgentRole.COORDINATOR,
            payload=CoordinatorDecisionPayload(
                decision=terminal,
                reason_codes=tuple(
                    stable_id("reason", reason, length=24) for reason in reasons
                ),
                selected_hypothesis_id=(
                    hypotheses[0].hypothesis_id if hypotheses else None
                ),
                proposal_id=proposal.proposal_id if proposal is not None else None,
            ),
            sources=source,
        )
        final = GovernanceArtifact.issue(
            tenant_id=state["tenant_id"],
            incident_id=state["incident_id"],
            run_id=state["run_id"],
            task_id=None,
            ordinal=61,
            producer_role=AgentRole.COORDINATOR,
            payload=FinalAssessmentPayload(
                status=status,
                summary=summary,
                hypothesis_ids=tuple(
                    hypothesis.hypothesis_id for hypothesis in hypotheses
                ),
                proposal_id=proposal.proposal_id if proposal is not None else None,
                requires_human_escalation=escalate,
            ),
            sources=(decision,),
        )
        self._append_artifacts(state, (decision, final))
        return {
            "terminal_state": terminal.value,
            "critic": critic.model_dump(mode="json"),
            "artifacts": [
                decision.model_dump(mode="json"),
                final.model_dump(mode="json"),
            ],
        }

    def run(
        self,
        *,
        tenant_id: str,
        request: InvestigationRequest,
        request_id: str,
        run_id: str | None = None,
        thread_ref: str,
        evidence: Sequence[Evidence],
    ) -> InvestigationResult:
        bound_run_id = run_id or request_id
        with self._thread_lock:
            owner = self._thread_tenants.setdefault(thread_ref, tenant_id)
            if owner != tenant_id:
                raise OrchestrationFailure("checkpoint thread tenant mismatch")
        input_digest = orchestration_input_digest(
            tenant_id=tenant_id,
            incident_id=request.incident_id,
            run_id=bound_run_id,
            evidence_digests=tuple(item.content_hash for item in evidence),
        )
        projection = self._ledger.begin_run(
            tenant_id=tenant_id,
            incident_id=request.incident_id,
            run_id=bound_run_id,
            thread_ref=thread_ref,
            graph_version=GRAPH_VERSION,
            input_digest=input_digest,
        )
        config: RunnableConfig = {
            "configurable": {"thread_id": thread_ref},
            "recursion_limit": _GRAPH_RECURSION_LIMIT,
        }
        initial: InvestigationState = {
            "tenant_id": tenant_id,
            "incident_id": request.incident_id,
            "run_id": bound_run_id,
            "request_id": request_id,
            "thread_ref": thread_ref,
            "graph_version": GRAPH_VERSION,
            "input_digest": input_digest,
            "fence_token": projection.fence_token,
            "correlation_reference": request.alert.observed_at.isoformat(),
            "evidence": tuple(
                item.model_dump(mode="json")
                for item in sorted(evidence, key=lambda item: item.evidence_id)
            ),
            "findings": [],
            "node_errors": [],
            "artifacts": [],
            "injection_detected": False,
            "hypotheses": (),
            "proposal": None,
            "critic_iteration": 0,
            "cancelled": False,
        }
        try:
            snapshot = self._graph.get_state(config)
            existing = cast(InvestigationState, snapshot.values)
            if existing:
                _validate_checkpoint_binding(
                    existing,
                    tenant_id=tenant_id,
                    run_id=bound_run_id,
                    request_id=request_id,
                    graph_version=GRAPH_VERSION,
                    input_digest=input_digest,
                )
                if "terminal_state" in existing:
                    return self._result(
                        existing,
                        request=request,
                        request_id=request_id,
                        run_id=bound_run_id,
                        thread_ref=thread_ref,
                        replayed=True,
                    )
                raw_state = cast(
                    InvestigationState,
                    self._graph.invoke(None, config),
                )
            else:
                raw_state = cast(
                    InvestigationState,
                    self._graph.invoke(initial, config),
                )
        except OrchestrationFailure:
            raise
        except (KeyError, TypeError, ValidationError, ValueError) as exc:
            raise OrchestrationFailure(
                "LangGraph checkpoint or state is invalid"
            ) from exc
        except Exception as exc:
            current_projection = self._ledger.projection(
                tenant_id=tenant_id,
                run_id=bound_run_id,
            )
            if current_projection is not None and current_projection.cancelled:
                return self._cancelled_result(
                    tenant_id=tenant_id,
                    request=request,
                    request_id=request_id,
                    run_id=bound_run_id,
                    thread_ref=thread_ref,
                )
            raise OrchestrationFailure("LangGraph invocation failed") from exc
        return self._result(
            raw_state,
            request=request,
            request_id=request_id,
            run_id=bound_run_id,
            thread_ref=thread_ref,
            replayed=False,
        )

    def _result(
        self,
        state: InvestigationState,
        *,
        request: InvestigationRequest,
        request_id: str,
        run_id: str,
        thread_ref: str,
        replayed: bool,
    ) -> InvestigationResult:
        try:
            critic = CriticVerdict.model_validate(state["critic"])
            hypotheses = tuple(
                Hypothesis.model_validate(item) for item in state["hypotheses"]
            )
            proposal = (
                RemediationProposal.model_validate(state["proposal"])
                if state.get("proposal") is not None
                else None
            )
            terminal = OrchestrationTerminalState(state["terminal_state"])
            artifacts = self._ledger.artifacts(
                tenant_id=state["tenant_id"],
                run_id=run_id,
            )
        except (KeyError, TypeError, ValidationError, ValueError) as exc:
            raise OrchestrationFailure("LangGraph returned invalid state") from exc
        status = (
            InvestigationStatus.COMPLETE
            if terminal is OrchestrationTerminalState.COMPLETE
            else (
                InvestigationStatus.CANCELLED
                if terminal is OrchestrationTerminalState.CANCELLED
                else InvestigationStatus.ABSTAINED
            )
        )
        return InvestigationResult(
            status=status,
            tenant_id=state["tenant_id"],
            incident_id=request.incident_id,
            run_id=run_id,
            request_id=request_id,
            thread_ref=thread_ref,
            hypotheses=hypotheses,
            critic=critic,
            proposal=proposal,
            artifacts=tuple(item.model_dump(mode="json") for item in artifacts),
            replayed=replayed,
        )

    def _cancelled_result(
        self,
        *,
        tenant_id: str,
        request: InvestigationRequest,
        request_id: str,
        run_id: str,
        thread_ref: str,
    ) -> InvestigationResult:
        artifacts = self._ledger.artifacts(tenant_id=tenant_id, run_id=run_id)
        return InvestigationResult(
            status=InvestigationStatus.CANCELLED,
            tenant_id=tenant_id,
            incident_id=request.incident_id,
            run_id=run_id,
            request_id=request_id,
            thread_ref=thread_ref,
            hypotheses=(),
            critic=CriticVerdict(
                decision=CriticDecision.ABSTAINED,
                reasons=("run_cancelled",),
                checked_citations=0,
            ),
            proposal=None,
            artifacts=tuple(item.model_dump(mode="json") for item in artifacts),
        )

    def checkpoint_count(self, *, tenant_id: str, thread_ref: str) -> int:
        with self._thread_lock:
            owner = self._thread_tenants.get(thread_ref)
        if owner is not None and owner != tenant_id:
            raise OrchestrationFailure("checkpoint thread tenant mismatch")
        config: RunnableConfig = {"configurable": {"thread_id": thread_ref}}
        try:
            history = cast(Iterator[object], self._graph.get_state_history(config))
            return sum(1 for _ in history)
        except Exception as exc:
            raise OrchestrationFailure("LangGraph checkpoint read failed") from exc

    def artifact_page(
        self,
        *,
        tenant_id: str,
        run_id: str,
        after_ordinal: int,
        limit: int,
    ) -> ArtifactPage:
        return self._ledger.artifact_page(
            tenant_id=tenant_id,
            run_id=run_id,
            after_ordinal=after_ordinal,
            limit=limit,
        )

    def cancel_run(self, *, tenant_id: str, run_id: str) -> None:
        if self._ledger.projection(tenant_id=tenant_id, run_id=run_id) is not None:
            self._ledger.cancel(tenant_id=tenant_id, run_id=run_id)

    @property
    def ledger(self) -> OrchestrationLedgerPort:
        return self._ledger

    def _append_artifacts(
        self,
        state: InvestigationState,
        artifacts: Sequence[GovernanceArtifact],
    ) -> None:
        self._ledger.append_artifacts(
            tenant_id=state["tenant_id"],
            run_id=state["run_id"],
            fence_token=state["fence_token"],
            artifacts=artifacts,
        )

    def _is_cancelled(self, state: InvestigationState) -> bool:
        projection = self._ledger.projection(
            tenant_id=state["tenant_id"],
            run_id=state["run_id"],
        )
        return projection is not None and projection.cancelled


def _evaluate_critic(
    *,
    findings: Sequence[SpecialistFinding],
    evidence: Sequence[Evidence],
    correlation: CorrelationContext,
    injection_detected: bool,
) -> tuple[CriticVerdict, tuple[Hypothesis, ...]]:
    checked = sum(len(finding.citations) for finding in findings)
    invalid = tuple(
        sorted(
            {
                citation.evidence_id
                for finding in findings
                for citation in finding.citations
                if not citation_is_valid(citation, evidence)
            }
        )
    )
    if invalid:
        return (
            CriticVerdict(
                decision=CriticDecision.REJECTED,
                reasons=("citation_validation_failed",),
                checked_citations=checked,
                contradictions=invalid,
            ),
            (),
        )
    if correlation.conflicts:
        return (
            CriticVerdict(
                decision=CriticDecision.ABSTAINED,
                reasons=("deterministic_evidence_conflict",),
                checked_citations=checked,
                contradictions=tuple(
                    conflict.conflict_id for conflict in correlation.conflicts
                ),
            ),
            (),
        )
    required = {EvidenceKind.TELEMETRY, EvidenceKind.CHANGE}
    if required.intersection(correlation.missing_sources):
        return (
            CriticVerdict(
                decision=CriticDecision.ABSTAINED,
                reasons=(
                    "insufficient_corroboration",
                    "required_evidence_source_missing",
                ),
                checked_citations=checked,
            ),
            (),
        )
    if required.intersection(correlation.stale_sources):
        return (
            CriticVerdict(
                decision=CriticDecision.ABSTAINED,
                reasons=("required_evidence_stale",),
                checked_citations=checked,
            ),
            (),
        )
    if injection_detected:
        return (
            CriticVerdict(
                decision=CriticDecision.ABSTAINED,
                reasons=("untrusted_instruction_detected",),
                checked_citations=checked,
                injection_contained=True,
            ),
            (),
        )
    core_abstentions = tuple(
        finding
        for finding in findings
        if finding.specialist in {Specialist.TELEMETRY, Specialist.CHANGE}
        and finding.abstained
    )
    if core_abstentions:
        return (
            CriticVerdict(
                decision=CriticDecision.ABSTAINED,
                reasons=tuple(
                    sorted(
                        {
                            finding.reason or "specialist_abstained"
                            for finding in core_abstentions
                        }
                        | {"insufficient_corroboration"}
                    )
                ),
                checked_citations=checked,
            ),
            (),
        )
    usable = tuple(
        finding
        for finding in findings
        if not finding.abstained and finding.confidence >= _MINIMUM_CONFIDENCE
    )
    if len(usable) < 2:
        reasons = tuple(
            sorted(
                {
                    finding.reason or "specialist_abstained"
                    for finding in findings
                    if finding.abstained
                }
                | {"insufficient_corroboration"}
            )
        )
        return (
            CriticVerdict(
                decision=CriticDecision.ABSTAINED,
                reasons=reasons,
                checked_citations=checked,
            ),
            (),
        )
    cause_codes = tuple(
        sorted(
            {finding.cause_code for finding in usable if finding.cause_code is not None}
        )
    )
    if len(cause_codes) != 1:
        return (
            CriticVerdict(
                decision=CriticDecision.ABSTAINED,
                reasons=("specialist_contradiction",),
                checked_citations=checked,
                contradictions=cause_codes,
            ),
            (),
        )
    cause_code = cause_codes[0]
    citations = _unique_citations(usable)
    hypothesis = Hypothesis(
        hypothesis_id=stable_id("hypothesis", evidence[0].tenant_id, cause_code),
        rank=1,
        statement=(
            "A recent checkout-api deployment is the leading supported explanation "
            "for the elevated checkout failure rate."
        ),
        cause_code=cause_code,
        confidence=round(min(finding.confidence for finding in usable), 2),
        citations=citations,
    )
    return (
        CriticVerdict(
            decision=CriticDecision.ACCEPTED,
            reasons=("corroborated_and_cited",),
            checked_citations=checked,
        ),
        (hypothesis,),
    )


def _assessment_artifact(
    *,
    state: InvestigationState,
    task: GovernanceArtifact,
    task_id: str,
    specialist: Specialist,
    role: AgentRole,
    finding: SpecialistFinding,
) -> GovernanceArtifact:
    return GovernanceArtifact.issue(
        tenant_id=state["tenant_id"],
        incident_id=state["incident_id"],
        run_id=state["run_id"],
        task_id=task_id,
        ordinal=_ASSESSMENT_ORDINAL_BY_SPECIALIST[specialist],
        producer_role=role,
        payload=EvidenceAssessmentPayload(
            task_id=task_id,
            finding_id=finding.finding_id,
            statement=finding.statement,
            cause_code=finding.cause_code,
            confidence=finding.confidence,
            calibration=_calibration(finding.confidence),
            citations=finding.citations,
            abstained=finding.abstained,
            reason=finding.reason,
        ),
        sources=(task,),
    )


def _runtime_finding(task: SpecialistTask) -> SpecialistFinding:
    telemetry = next(
        (item for item in task.evidence if item.kind is EvidenceKind.TELEMETRY),
        None,
    )
    change = next(
        (item for item in task.evidence if item.kind is EvidenceKind.CHANGE),
        None,
    )
    if telemetry is None or change is None:
        return _abstaining_finding(
            task.incident_id, task.specialist, "runtime_evidence_missing"
        )
    value = telemetry.facts.get("value")
    threshold = telemetry.facts.get("threshold")
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not isinstance(threshold, (int, float))
        or isinstance(threshold, bool)
        or value <= threshold
        or change.facts.get("status") != "deployed"
    ):
        return _abstaining_finding(
            task.incident_id, task.specialist, "runtime_correlation_not_supported"
        )
    return SpecialistFinding(
        finding_id=stable_id(
            "finding", task.incident_id, task.specialist.value, "post_deploy_regression"
        ),
        specialist=task.specialist,
        statement=(
            "Runtime telemetry and deployment state independently support a "
            "post-deployment regression."
        ),
        cause_code="post_deploy_regression",
        confidence=0.84,
        citations=(_citation(telemetry), _citation(change)),
    )


def _knowledge_finding(task: SpecialistTask) -> SpecialistFinding:
    runbook = next(
        (item for item in task.evidence if item.kind is EvidenceKind.RUNBOOK),
        None,
    )
    change = next(
        (item for item in task.evidence if item.kind is EvidenceKind.CHANGE),
        None,
    )
    if (
        runbook is None
        or change is None
        or runbook.facts.get("action") != "rollback_candidate"
        or change.facts.get("status") != "deployed"
    ):
        return _abstaining_finding(
            task.incident_id, task.specialist, "knowledge_support_missing"
        )
    return SpecialistFinding(
        finding_id=stable_id(
            "finding", task.incident_id, task.specialist.value, "post_deploy_regression"
        ),
        specialist=task.specialist,
        statement=(
            "The trusted runbook contains a proposal-only rollback candidate for the "
            "observed deployment condition."
        ),
        cause_code="post_deploy_regression",
        confidence=0.78,
        citations=(_citation(runbook), _citation(change)),
    )


def _abstaining_finding(
    incident_id: str, specialist: Specialist, reason: str
) -> SpecialistFinding:
    return SpecialistFinding(
        finding_id=stable_id("finding", incident_id, specialist.value, reason),
        specialist=specialist,
        statement=f"{specialist.value} specialist abstained: {reason}.",
        cause_code=None,
        confidence=0.0,
        citations=(),
        abstained=True,
        reason=reason,
    )


def _citation(item: ModelEvidence) -> Citation:
    return Citation(
        evidence_id=item.evidence_id,
        locator=item.locator,
        content_hash=item.content_hash,
        provenance_digest=item.provenance_digest,
        source_id=item.source_id,
        query_id=item.query_id,
        page_number=item.page_number,
    )


def _unique_citations(
    findings: Sequence[SpecialistFinding],
) -> tuple[Citation, ...]:
    citations = {
        citation.evidence_id: citation
        for finding in findings
        for citation in finding.citations
    }
    return tuple(citations[key] for key in sorted(citations))


def _proposal_from_runbook(
    *,
    tenant_id: str,
    incident_id: str,
    evidence: Sequence[Evidence],
    hypothesis: Hypothesis,
) -> RemediationProposal | None:
    runbook = next(
        (item for item in evidence if item.kind is EvidenceKind.RUNBOOK),
        None,
    )
    change = next(
        (item for item in evidence if item.kind is EvidenceKind.CHANGE),
        None,
    )
    if (
        runbook is None
        or change is None
        or runbook.facts.get("action") != "rollback_candidate"
    ):
        return None
    target = (
        f"{change.facts.get('service', 'checkout-api')}:"
        f"{change.facts.get('version', 'unknown')}"
    )
    try:
        return RemediationProposal(
            proposal_id=stable_id("proposal", tenant_id, incident_id, target),
            action="rollback_candidate",
            target=target,
            rationale=(
                f"Hypothesis {hypothesis.hypothesis_id} is corroborated and cited."
            ),
            risk="medium",
        )
    except ValidationError:
        return None


def _task_id(run_id: str, specialist: Specialist) -> str:
    return stable_id("task", run_id, specialist.value, length=32)


def _calibration(confidence: float) -> CalibrationBand:
    if confidence <= 0.0:
        return CalibrationBand.UNCALIBRATED
    if confidence < 0.70:
        return CalibrationBand.LOW
    if confidence < 0.85:
        return CalibrationBand.MEDIUM
    return CalibrationBand.HIGH


def _artifacts(
    state: InvestigationState,
    kind: ArtifactKind,
) -> list[GovernanceArtifact]:
    selected: list[GovernanceArtifact] = []
    for item in state.get("artifacts", ()):
        payload = item.get("payload")
        if isinstance(payload, dict) and payload.get("kind") == kind.value:
            selected.append(GovernanceArtifact.model_validate(item))
    return selected


def _artifact(
    state: InvestigationState,
    kind: ArtifactKind,
    *,
    task_id: str | None = None,
) -> GovernanceArtifact:
    matches = [
        item
        for item in _artifacts(state, kind)
        if task_id is None or item.task_id == task_id
    ]
    if len(matches) != 1:
        raise OrchestrationFailure("required artifact transition source is unavailable")
    return matches[0]


def _validate_checkpoint_binding(
    state: InvestigationState,
    *,
    tenant_id: str,
    run_id: str,
    request_id: str,
    graph_version: str,
    input_digest: str,
) -> None:
    if (
        state.get("tenant_id") != tenant_id
        or state.get("run_id") != run_id
        or state.get("request_id") != request_id
        or state.get("graph_version") != graph_version
        or state.get("input_digest") != input_digest
    ):
        raise OrchestrationFailure("checkpoint graph version or run binding mismatch")
