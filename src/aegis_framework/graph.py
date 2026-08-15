"""LangGraph adapter for the bounded deterministic investigation graph."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from threading import Lock
from typing import cast

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from pydantic import ValidationError

from aegis_framework.checkpointing import strict_checkpoint_serializer
from aegis_framework.domain import (
    Citation,
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
from aegis_framework.errors import ModelProviderError, OrchestrationFailure
from aegis_framework.ports import StructuredModelPort
from aegis_framework.safety import citation_is_valid, prepare_model_evidence


class LangGraphInvestigator:
    """Owns graph mechanics, not policy, approval, tenancy, audit, or effects."""

    def __init__(
        self,
        model: StructuredModelPort,
        checkpointer: BaseCheckpointSaver[str] | None = None,
    ) -> None:
        self._model = model
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
        builder.add_node("coordinator", self._coordinator)
        builder.add_node("telemetry_specialist", self._telemetry_specialist)
        builder.add_node("change_specialist", self._change_specialist)
        builder.add_node("critic", self._critic)
        builder.add_edge(START, "coordinator")
        builder.add_edge("coordinator", "telemetry_specialist")
        builder.add_edge("coordinator", "change_specialist")
        builder.add_edge(["telemetry_specialist", "change_specialist"], "critic")
        builder.add_edge("critic", END)
        return builder.compile(checkpointer=self._checkpointer)

    @staticmethod
    def _coordinator(state: InvestigationState) -> dict[str, object]:
        evidence = tuple(Evidence.model_validate(item) for item in state["evidence"])
        safe_evidence, injection_detected = prepare_model_evidence(evidence)
        return {
            "safe_evidence": tuple(
                item.model_dump(mode="json") for item in safe_evidence
            ),
            "injection_detected": injection_detected,
        }

    def _telemetry_specialist(self, state: InvestigationState) -> dict[str, object]:
        return self._run_specialist(state, Specialist.TELEMETRY)

    def _change_specialist(self, state: InvestigationState) -> dict[str, object]:
        return self._run_specialist(state, Specialist.CHANGE)

    def _run_specialist(
        self,
        state: InvestigationState,
        specialist: Specialist,
    ) -> dict[str, object]:
        task = SpecialistTask(
            incident_id=state["incident_id"],
            specialist=specialist,
            evidence=tuple(
                ModelEvidence.model_validate(item) for item in state["safe_evidence"]
            ),
        )
        try:
            raw_finding = self._model.analyze(task)
            finding = SpecialistFinding.model_validate(raw_finding)
        except ValidationError:
            return _specialist_failure(
                state["incident_id"], specialist, "model_output_invalid"
            )
        except ModelProviderError:
            return _specialist_failure(
                state["incident_id"], specialist, "model_provider_error"
            )
        if finding.specialist is not specialist:
            return _specialist_failure(
                state["incident_id"], specialist, "specialist_identity_mismatch"
            )
        return {
            "findings": [finding.model_dump(mode="json")],
            "node_errors": [],
        }

    @staticmethod
    def _critic(state: InvestigationState) -> dict[str, object]:
        findings = tuple(
            SpecialistFinding.model_validate(item) for item in state.get("findings", ())
        )
        evidence = tuple(Evidence.model_validate(item) for item in state["evidence"])
        node_errors = tuple(
            NodeError.model_validate(item) for item in state.get("node_errors", ())
        )
        checked_citations = sum(len(finding.citations) for finding in findings)

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
            return {
                "hypotheses": (),
                "critic": CriticVerdict(
                    decision=CriticDecision.REJECTED,
                    reasons=("citation_validation_failed",),
                    checked_citations=checked_citations,
                    contradictions=invalid,
                ).model_dump(mode="json"),
                "proposal": None,
            }

        if state.get("injection_detected", False):
            return {
                "hypotheses": (),
                "critic": CriticVerdict(
                    decision=CriticDecision.ABSTAINED,
                    reasons=("untrusted_instruction_detected",),
                    checked_citations=checked_citations,
                    injection_contained=True,
                ).model_dump(mode="json"),
                "proposal": None,
            }

        usable = tuple(finding for finding in findings if not finding.abstained)
        if node_errors or len(usable) < 2:
            reasons = tuple(
                sorted(
                    {error.code for error in node_errors}
                    | {
                        finding.reason or "specialist_abstained"
                        for finding in findings
                        if finding.abstained
                    }
                    | ({"insufficient_corroboration"} if len(usable) < 2 else set())
                )
            )
            return {
                "hypotheses": (),
                "critic": CriticVerdict(
                    decision=CriticDecision.ABSTAINED,
                    reasons=reasons,
                    checked_citations=checked_citations,
                ).model_dump(mode="json"),
                "proposal": None,
            }

        missing_cause = any(finding.cause_code is None for finding in usable)
        cause_codes = tuple(
            sorted(
                {
                    finding.cause_code
                    for finding in usable
                    if finding.cause_code is not None
                }
            )
        )
        if len(cause_codes) != 1 or missing_cause:
            return {
                "hypotheses": (),
                "critic": CriticVerdict(
                    decision=CriticDecision.ABSTAINED,
                    reasons=("specialist_contradiction",),
                    checked_citations=checked_citations,
                    contradictions=cause_codes,
                ).model_dump(mode="json"),
                "proposal": None,
            }

        cause_code = cause_codes[0]
        citations = _unique_citations(usable)
        hypothesis = Hypothesis(
            hypothesis_id=stable_id("hypothesis", state["incident_id"], cause_code),
            rank=1,
            statement=(
                "A recent checkout-api deployment is the leading explanation for "
                "the elevated checkout failure rate."
            ),
            cause_code=cause_code,
            confidence=round(min(finding.confidence for finding in usable), 2),
            citations=citations,
        )
        proposal = _proposal_from_runbook(
            tenant_id=state["tenant_id"],
            incident_id=state["incident_id"],
            evidence=evidence,
            hypothesis=hypothesis,
        )
        reasons = (
            ("corroborated_and_cited",)
            if proposal is not None
            else ("corroborated_but_no_valid_action",)
        )
        return {
            "hypotheses": (hypothesis.model_dump(mode="json"),),
            "critic": CriticVerdict(
                decision=CriticDecision.ACCEPTED,
                reasons=reasons,
                checked_citations=checked_citations,
            ).model_dump(mode="json"),
            "proposal": (
                proposal.model_dump(mode="json") if proposal is not None else None
            ),
        }

    def run(
        self,
        *,
        tenant_id: str,
        request: InvestigationRequest,
        request_id: str,
        thread_ref: str,
        evidence: Sequence[Evidence],
    ) -> InvestigationResult:
        with self._thread_lock:
            owner = self._thread_tenants.setdefault(thread_ref, tenant_id)
            if owner != tenant_id:
                raise OrchestrationFailure("checkpoint thread tenant mismatch")
        config: RunnableConfig = {
            "configurable": {"thread_id": thread_ref},
            "recursion_limit": 8,
        }
        initial: InvestigationState = {
            "tenant_id": tenant_id,
            "incident_id": request.incident_id,
            "request_id": request_id,
            "thread_ref": thread_ref,
            "evidence": tuple(
                item.model_dump(mode="json")
                for item in sorted(evidence, key=lambda item: item.evidence_id)
            ),
            "findings": [],
            "node_errors": [],
            "injection_detected": False,
            "hypotheses": (),
            "proposal": None,
        }
        try:
            raw_state = self._graph.invoke(initial, config)
        except Exception as exc:
            raise OrchestrationFailure("LangGraph invocation failed") from exc

        try:
            critic = CriticVerdict.model_validate(raw_state["critic"])
            hypotheses = tuple(
                Hypothesis.model_validate(item) for item in raw_state["hypotheses"]
            )
            proposal = (
                RemediationProposal.model_validate(raw_state["proposal"])
                if raw_state.get("proposal") is not None
                else None
            )
        except (KeyError, TypeError, ValidationError) as exc:
            raise OrchestrationFailure("LangGraph returned invalid state") from exc

        status = (
            InvestigationStatus.COMPLETE
            if critic.decision is CriticDecision.ACCEPTED and proposal is not None
            else InvestigationStatus.ABSTAINED
        )
        return InvestigationResult(
            status=status,
            tenant_id=tenant_id,
            incident_id=request.incident_id,
            request_id=request_id,
            thread_ref=thread_ref,
            hypotheses=hypotheses,
            critic=critic,
            proposal=proposal,
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


def _specialist_failure(
    incident_id: str,
    specialist: Specialist,
    code: str,
) -> dict[str, object]:
    finding = SpecialistFinding(
        finding_id=stable_id("finding", incident_id, specialist.value, code),
        specialist=specialist,
        statement=f"{specialist.value} specialist abstained: {code}.",
        cause_code=None,
        confidence=0.0,
        citations=(),
        abstained=True,
        reason=code,
    )
    return {
        "findings": [finding.model_dump(mode="json")],
        "node_errors": [
            NodeError(node=specialist.value, code=code).model_dump(mode="json")
        ],
    }


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
    # Require the change record to carry explicit, non-empty service and version
    # rather than inventing a rollback target from defaults.
    service = change.facts.get("service")
    version = change.facts.get("version")
    if not isinstance(service, str) or not service.strip():
        return None
    if not isinstance(version, str) or not version.strip():
        return None
    # Bind the proposal to the runbook's declared scope: the service must match
    # the change record and the runbook condition must agree with the corroborated
    # hypothesis cause.
    runbook_service = runbook.facts.get("service")
    runbook_condition = runbook.facts.get("condition")
    if runbook_service != service:
        return None
    if runbook_condition != hypothesis.cause_code:
        return None
    target = f"{service}:{version}"
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
