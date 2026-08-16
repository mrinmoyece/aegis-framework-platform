from __future__ import annotations

from collections.abc import Sequence

import pytest

from aegis_framework.domain import (
    CriticDecision,
    Evidence,
    InvestigationStatus,
    SpecialistFinding,
    SpecialistTask,
)
from aegis_framework.errors import OrchestrationFailure
from aegis_framework.fixtures import (
    DemoScenario,
    build_demo_bundle,
    demo_identity,
    demo_request,
)
from aegis_framework.graph import LangGraphInvestigator
from aegis_framework.model import DeterministicStructuredModel


@pytest.mark.parametrize(
    ("scenario", "status", "decision", "reason"),
    [
        (
            DemoScenario.SUCCESS,
            InvestigationStatus.COMPLETE,
            CriticDecision.ACCEPTED,
            "corroborated_and_cited",
        ),
        (
            DemoScenario.CONTRADICTION,
            InvestigationStatus.ABSTAINED,
            CriticDecision.ABSTAINED,
            "specialist_contradiction",
        ),
        (
            DemoScenario.PROMPT_INJECTION,
            InvestigationStatus.ABSTAINED,
            CriticDecision.ABSTAINED,
            "untrusted_instruction_detected",
        ),
        (
            DemoScenario.MALFORMED_MODEL,
            InvestigationStatus.ABSTAINED,
            CriticDecision.ABSTAINED,
            "model_output_invalid",
        ),
        (
            DemoScenario.MODEL_ERROR,
            InvestigationStatus.ABSTAINED,
            CriticDecision.ABSTAINED,
            "model_provider_error",
        ),
        (
            DemoScenario.NO_EVIDENCE,
            InvestigationStatus.ABSTAINED,
            CriticDecision.ABSTAINED,
            "insufficient_corroboration",
        ),
    ],
)
def test_graph_routes_safely(
    scenario: DemoScenario,
    status: InvestigationStatus,
    decision: CriticDecision,
    reason: str,
) -> None:
    bundle = build_demo_bundle(scenario)
    result = bundle.service.investigate(
        demo_identity(request_id=f"route-{scenario.value}"),
        demo_request(),
    )
    assert result.status is status
    assert result.critic.decision is decision
    assert reason in result.critic.reasons


def test_success_is_cited_deterministic_and_checkpointed() -> None:
    bundle = build_demo_bundle()
    identity = demo_identity(request_id="checkpoint-determinism")
    result = bundle.service.investigate(identity, demo_request())
    initial_checkpoints = bundle.orchestrator.checkpoint_count(
        tenant_id=result.tenant_id,
        thread_ref=result.thread_ref,
    )
    replayed = bundle.service.investigate(identity, demo_request())
    assert initial_checkpoints == 8
    assert (
        bundle.orchestrator.checkpoint_count(
            tenant_id=result.tenant_id,
            thread_ref=result.thread_ref,
        )
        == initial_checkpoints
    )
    assert replayed.replayed is True
    assert replayed.hypotheses == result.hypotheses
    assert tuple(
        citation.evidence_id for citation in result.hypotheses[0].citations
    ) == tuple(
        sorted(citation.evidence_id for citation in result.hypotheses[0].citations)
    )


class _TamperingModel:
    def __init__(self) -> None:
        self._delegate = DeterministicStructuredModel()

    def analyze(self, task: SpecialistTask) -> object:
        finding = SpecialistFinding.model_validate(self._delegate.analyze(task))
        if finding.citations:
            bad = finding.citations[0].model_copy(update={"content_hash": "f" * 64})
            finding = finding.model_copy(
                update={"citations": (bad, *finding.citations[1:])}
            )
        return finding.model_dump(mode="python")


class _WrongSpecialistModel:
    def __init__(self) -> None:
        self._delegate = DeterministicStructuredModel()

    def analyze(self, task: SpecialistTask) -> object:
        finding = SpecialistFinding.model_validate(self._delegate.analyze(task))
        other = "change" if finding.specialist.value == "telemetry" else "telemetry"
        return {**finding.model_dump(mode="python"), "specialist": other}


class _UnexpectedFailureModel:
    def analyze(self, task: SpecialistTask) -> object:
        del task
        raise RuntimeError("unexpected provider defect")


class _UncitedModel:
    def __init__(self) -> None:
        self._delegate = DeterministicStructuredModel()

    def analyze(self, task: SpecialistTask) -> object:
        output = self._delegate.analyze(task)
        if not isinstance(output, dict):
            raise AssertionError("deterministic model returned a non-mapping")
        return {**output, "citations": ()}


def _run_direct(
    graph: LangGraphInvestigator,
    evidence: Sequence[Evidence],
    *,
    thread_ref: str,
) -> object:
    request = demo_request()
    return graph.run(
        tenant_id="tenant-acme",
        request=request,
        request_id="direct-request",
        thread_ref=thread_ref,
        evidence=evidence,
    )


def test_critic_rejects_invalid_citations() -> None:
    source = build_demo_bundle()
    evidence = source.service._evidence.collect(demo_identity(), demo_request())
    result = _run_direct(
        LangGraphInvestigator(_TamperingModel()),
        evidence,
        thread_ref="thread:tampered",
    )
    assert result.status is InvestigationStatus.ABSTAINED
    assert result.critic.decision is CriticDecision.REJECTED
    assert result.critic.reasons == ("citation_validation_failed",)


def test_specialist_identity_mismatch_abstains() -> None:
    source = build_demo_bundle()
    evidence = source.service._evidence.collect(demo_identity(), demo_request())
    result = _run_direct(
        LangGraphInvestigator(_WrongSpecialistModel()),
        evidence,
        thread_ref="thread:wrong-specialist",
    )
    assert result.status is InvestigationStatus.ABSTAINED
    assert "specialist_identity_mismatch" in result.critic.reasons


def test_uncited_model_output_abstains() -> None:
    source = build_demo_bundle()
    evidence = source.service._evidence.collect(demo_identity(), demo_request())
    result = _run_direct(
        LangGraphInvestigator(_UncitedModel()),
        evidence,
        thread_ref="thread:uncited",
    )
    assert result.status is InvestigationStatus.ABSTAINED
    assert result.critic.reasons == (
        "insufficient_corroboration",
        "model_output_invalid",
    )


def test_unexpected_adapter_error_is_explicit() -> None:
    source = build_demo_bundle()
    evidence = source.service._evidence.collect(demo_identity(), demo_request())
    result = _run_direct(
        LangGraphInvestigator(_UnexpectedFailureModel()),
        evidence,
        thread_ref="thread:unexpected",
    )
    assert result.status is InvestigationStatus.ABSTAINED
    assert "model_adapter_exception" in result.critic.reasons


def test_missing_runbook_never_produces_action() -> None:
    source = build_demo_bundle()
    evidence = tuple(
        item
        for item in source.service._evidence.collect(demo_identity(), demo_request())
        if item.kind.value != "runbook"
    )
    result = _run_direct(
        LangGraphInvestigator(DeterministicStructuredModel()),
        evidence,
        thread_ref="thread:no-runbook",
    )
    assert result.status is InvestigationStatus.ABSTAINED
    assert result.critic.decision is CriticDecision.ACCEPTED
    assert result.proposal is None
    assert result.critic.reasons == ("corroborated_but_no_valid_action",)


def test_invalid_evidence_target_safely_omits_proposal() -> None:
    source = build_demo_bundle()
    evidence = tuple(
        item.model_copy(
            update={
                "facts": {
                    **item.facts,
                    "version": "2026.08.15.1 (hotfix candidate)",
                }
            }
        )
        if item.kind.value == "change"
        else item
        for item in source.service._evidence.collect(demo_identity(), demo_request())
    )
    result = _run_direct(
        LangGraphInvestigator(DeterministicStructuredModel()),
        evidence,
        thread_ref="thread:invalid-target",
    )
    assert result.status is InvestigationStatus.ABSTAINED
    assert result.proposal is None
    assert result.critic.reasons == ("corroborated_but_no_valid_action",)


def test_checkpoint_owner_cannot_be_rebound_across_tenants() -> None:
    source = build_demo_bundle()
    graph = LangGraphInvestigator(DeterministicStructuredModel())
    evidence = source.service._evidence.collect(demo_identity(), demo_request())
    _run_direct(graph, evidence, thread_ref="thread:tenant-owned")
    with pytest.raises(OrchestrationFailure, match="tenant mismatch"):
        graph.run(
            tenant_id="tenant-beta",
            request=demo_request(),
            request_id="direct-cross-tenant",
            thread_ref="thread:tenant-owned",
            evidence=evidence,
        )
    with pytest.raises(OrchestrationFailure, match="tenant mismatch"):
        graph.checkpoint_count(
            tenant_id="tenant-beta",
            thread_ref="thread:tenant-owned",
        )
