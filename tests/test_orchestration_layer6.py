from __future__ import annotations

from collections.abc import Sequence

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from aegis_framework.api import AppMode, create_app
from aegis_framework.domain import Evidence, SpecialistTask
from aegis_framework.errors import IntegrityFailure, OrchestrationFailure
from aegis_framework.fixtures import (
    build_demo_bundle,
    demo_identity,
    demo_request,
)
from aegis_framework.graph import LangGraphInvestigator
from aegis_framework.model import DeterministicStructuredModel
from aegis_framework.orchestration import (
    GRAPH_VERSION,
    AgentRole,
    ArtifactKind,
    EvidenceAssessmentPayload,
    GovernanceArtifact,
    InMemoryOrchestrationLedger,
    TaskDispatchClaim,
    TaskDispatchStatus,
)


def _evidence() -> tuple[Evidence, ...]:
    bundle = build_demo_bundle()
    return tuple(bundle.service._evidence.collect(demo_identity(), demo_request()))


def _run(
    investigator: LangGraphInvestigator,
    *,
    evidence: Sequence[Evidence],
    run_id: str = "run:layer6",
    thread_ref: str = "thread:layer6",
) -> TaskDispatchClaim:
    return investigator.run(
        tenant_id="tenant-acme",
        request=demo_request(),
        request_id="request-layer6",
        run_id=run_id,
        thread_ref=thread_ref,
        evidence=evidence,
    )


def test_complete_run_emits_typed_bounded_artifact_chain() -> None:
    result = _run(
        LangGraphInvestigator(DeterministicStructuredModel()),
        evidence=_evidence(),
    )
    artifacts = tuple(
        GovernanceArtifact.model_validate(item) for item in result.artifacts
    )
    assert len(artifacts) == 16
    assert tuple(item.ordinal for item in artifacts) == tuple(
        sorted(item.ordinal for item in artifacts)
    )
    assert {item.schema_version for item in artifacts} == {1}
    assert {item.tenant_id for item in artifacts} == {"tenant-acme"}
    assert {item.run_id for item in artifacts} == {"run:layer6"}
    assert {item.payload.kind for item in artifacts} == {
        ArtifactKind.INVESTIGATION_PLAN,
        ArtifactKind.INVESTIGATION_TASK,
        ArtifactKind.EVIDENCE_ASSESSMENT,
        ArtifactKind.CONTEXT_REFERENCES,
        ArtifactKind.CRITIQUE,
        ArtifactKind.HYPOTHESIS,
        ArtifactKind.REMEDIATION_PROPOSAL,
        ArtifactKind.VERIFICATION_PLAN,
        ArtifactKind.COORDINATOR_DECISION,
        ArtifactKind.FINAL_ASSESSMENT,
    }
    assert (
        len(
            [
                item
                for item in artifacts
                if item.payload.kind is ArtifactKind.INVESTIGATION_TASK
            ]
        )
        == 4
    )
    assert (
        len(
            [
                item
                for item in artifacts
                if item.payload.kind is ArtifactKind.EVIDENCE_ASSESSMENT
            ]
        )
        == 4
    )


def test_fan_in_and_artifacts_are_deterministic_for_reversed_evidence() -> None:
    evidence = _evidence()
    first = _run(
        LangGraphInvestigator(DeterministicStructuredModel()),
        evidence=evidence,
        run_id="run:deterministic",
        thread_ref="thread:deterministic-a",
    )
    second = _run(
        LangGraphInvestigator(DeterministicStructuredModel()),
        evidence=tuple(reversed(evidence)),
        run_id="run:deterministic",
        thread_ref="thread:deterministic-b",
    )
    assert first.hypotheses == second.hypotheses
    assert first.artifacts == second.artifacts


def test_fixed_roles_and_artifact_transitions_deny_by_default() -> None:
    result = _run(
        LangGraphInvestigator(DeterministicStructuredModel()),
        evidence=_evidence(),
        run_id="run:roles",
        thread_ref="thread:roles",
    )
    artifacts = tuple(
        GovernanceArtifact.model_validate(item) for item in result.artifacts
    )
    task = next(
        item
        for item in artifacts
        if item.payload.kind is ArtifactKind.INVESTIGATION_TASK
    )
    assessment = next(
        item.payload
        for item in artifacts
        if item.payload.kind is ArtifactKind.EVIDENCE_ASSESSMENT
    )
    assert isinstance(assessment, EvidenceAssessmentPayload)
    with pytest.raises(ValidationError, match="not permitted"):
        GovernanceArtifact.issue(
            tenant_id=task.tenant_id,
            incident_id=task.incident_id,
            run_id=task.run_id,
            task_id=task.task_id,
            ordinal=999,
            producer_role=AgentRole.COORDINATOR,
            payload=assessment,
            sources=(task,),
        )
    with pytest.raises(ValueError, match="not a valid AgentRole"):
        AgentRole("self_created_role")
    with pytest.raises(ValueError, match="requires provenance"):
        GovernanceArtifact.issue(
            tenant_id=task.tenant_id,
            incident_id=task.incident_id,
            run_id=task.run_id,
            task_id=task.task_id,
            ordinal=998,
            producer_role=AgentRole.TELEMETRY_SPECIALIST,
            payload=assessment,
            sources=(),
        )
    tampered = task.model_dump(mode="json")
    tampered["canonical_digest"] = "f" * 64
    with pytest.raises(ValidationError, match="digest mismatch"):
        GovernanceArtifact.model_validate(tampered)


def test_dispatch_intent_duplicate_and_stale_result_are_explicit() -> None:
    ledger = InMemoryOrchestrationLedger()
    projection = ledger.begin_run(
        tenant_id="tenant-acme",
        incident_id="incident-1",
        run_id="run:dispatch",
        thread_ref="thread:dispatch",
        graph_version=GRAPH_VERSION,
        input_digest="a" * 64,
    )
    first = ledger.claim_task(
        tenant_id="tenant-acme",
        run_id="run:dispatch",
        task_id="task:dispatch",
        role=AgentRole.TELEMETRY_SPECIALIST,
        input_digest="a" * 64,
    )
    duplicate_pending = ledger.claim_task(
        tenant_id="tenant-acme",
        run_id="run:dispatch",
        task_id="task:dispatch",
        role=AgentRole.TELEMETRY_SPECIALIST,
        input_digest="a" * 64,
    )
    assert first.status is TaskDispatchStatus.STARTED
    assert duplicate_pending.status is TaskDispatchStatus.RECONCILIATION_REQUIRED
    assert duplicate_pending.fence_token != first.fence_token
    with pytest.raises(IntegrityFailure, match="fence is stale"):
        ledger.complete_task(
            tenant_id="tenant-acme",
            run_id="run:dispatch",
            task_id="task:dispatch",
            fence_token=first.fence_token,
            result={"finding_id": "stale-finding"},
        )
    started = ledger.claim_task(
        tenant_id="tenant-acme",
        run_id="run:dispatch",
        task_id="task:completed",
        role=AgentRole.CHANGE_SPECIALIST,
        input_digest="a" * 64,
    )
    ledger.complete_task(
        tenant_id="tenant-acme",
        run_id="run:dispatch",
        task_id="task:completed",
        fence_token=started.fence_token,
        result={"finding_id": "finding-1"},
    )
    cached = ledger.claim_task(
        tenant_id="tenant-acme",
        run_id="run:dispatch",
        task_id="task:completed",
        role=AgentRole.CHANGE_SPECIALIST,
        input_digest="a" * 64,
    )
    assert cached.status is TaskDispatchStatus.CACHED
    assert cached.cached_result == {"finding_id": "finding-1"}
    with pytest.raises(OrchestrationFailure, match="binding changed"):
        ledger.begin_run(
            tenant_id="tenant-acme",
            incident_id="incident-2",
            run_id="run:dispatch",
            thread_ref="thread:dispatch",
            graph_version=GRAPH_VERSION,
            input_digest="a" * 64,
        )
    with pytest.raises(ValueError, match="page bounds"):
        ledger.artifact_page(
            tenant_id="tenant-acme",
            run_id="run:dispatch",
            after_ordinal=-1,
            limit=1,
        )
    ledger.cancel(tenant_id="tenant-acme", run_id="run:dispatch")
    with pytest.raises(IntegrityFailure, match="cancelled"):
        ledger.complete_task(
            tenant_id="tenant-acme",
            run_id="run:dispatch",
            task_id="task:dispatch",
            fence_token=projection.fence_token,
            result={"finding_id": "changed"},
        )


def test_checkpoint_graph_version_and_input_binding_fail_closed() -> None:
    investigator = LangGraphInvestigator(DeterministicStructuredModel())
    evidence = _evidence()
    _run(
        investigator,
        evidence=evidence,
        run_id="run:version",
        thread_ref="thread:version",
    )
    investigator._graph.update_state(
        {"configurable": {"thread_id": "thread:version"}},
        {"graph_version": "5.0.0"},
    )
    with pytest.raises(OrchestrationFailure, match="graph version"):
        _run(
            investigator,
            evidence=evidence,
            run_id="run:version",
            thread_ref="thread:version",
        )


def test_oversized_model_fields_abstain_without_poisoning_replay() -> None:
    class _OversizedReasonModel:
        def analyze(self, task: SpecialistTask) -> object:
            return {
                "finding_id": f"finding:{task.specialist.value}",
                "specialist": task.specialist.value,
                "statement": "Bounded invalid abstention.",
                "cause_code": None,
                "confidence": 0.0,
                "citations": (),
                "abstained": True,
                "reason": "x" * 300,
            }

    investigator = LangGraphInvestigator(_OversizedReasonModel())
    first = _run(
        investigator,
        evidence=_evidence(),
        run_id="run:oversized",
        thread_ref="thread:oversized",
    )
    replayed = _run(
        investigator,
        evidence=_evidence(),
        run_id="run:oversized",
        thread_ref="thread:oversized",
    )
    assert first.status.value == "abstained"
    assert "model_output_invalid" in first.critic.reasons
    assert replayed.replayed is True
    assert replayed.artifacts == first.artifacts


def test_projection_rebuild_and_redacted_cursor_api_are_tenant_bound() -> None:
    app = create_app(mode=AppMode.DEMO)
    client = TestClient(app)
    headers = {
        "Authorization": "Bearer demo-responder-token",
        "X-Request-ID": "artifact-api-run",
    }
    payload = {
        "incident_id": "checkout-20260815-001",
        "alert": {
            "signal": "checkout_failure_rate",
            "service": "checkout-api",
            "region": "eu-west-1",
            "observed_at": "2026-08-15T00:00:00Z",
            "failure_rate": 0.42,
            "threshold": 0.05,
        },
    }
    created = client.post("/v1/investigations", headers=headers, json=payload)
    assert created.status_code == 200
    run_id = created.json()["run_id"]
    first = client.get(
        f"/v1/orchestrations/{run_id}/artifacts?limit=2",
        headers={
            "Authorization": "Bearer demo-viewer-token",
            "X-Request-ID": "artifact-api-read-1",
        },
    )
    assert first.status_code == 200
    assert len(first.json()["items"]) == 2
    assert first.json()["next_cursor"]
    assert "tenant_id" not in first.text
    second = client.get(
        f"/v1/orchestrations/{run_id}/artifacts"
        f"?limit=100&cursor={first.json()['next_cursor']}",
        headers={
            "Authorization": "Bearer demo-viewer-token",
            "X-Request-ID": "artifact-api-read-2",
        },
    )
    assert second.status_code == 200
    assert len(second.json()["items"]) == 14
    denied = client.get(
        f"/v1/orchestrations/{run_id}/artifacts",
        headers={
            "Authorization": "Bearer demo-beta-token",
            "X-Request-ID": "artifact-api-cross-tenant",
        },
    )
    assert denied.status_code == 404


def test_in_memory_projection_rebuild_is_deterministic() -> None:
    ledger = InMemoryOrchestrationLedger()
    investigator = LangGraphInvestigator(
        DeterministicStructuredModel(),
        ledger=ledger,
    )
    result = _run(
        investigator,
        evidence=_evidence(),
        run_id="run:rebuild",
        thread_ref="thread:rebuild",
    )
    before = ledger.projection(tenant_id="tenant-acme", run_id=result.run_id)
    rebuilt = ledger.rebuild_projection(
        tenant_id="tenant-acme",
        run_id=result.run_id,
    )
    assert rebuilt == before
    assert rebuilt.artifact_count == 16


def test_mid_run_cancellation_returns_cancelled_terminal_without_artifacts() -> None:
    class _CancelOnDispatchLedger(InMemoryOrchestrationLedger):
        def __init__(self) -> None:
            super().__init__()
            self._cancelled_once = False

        def claim_task(
            self,
            *,
            tenant_id: str,
            run_id: str,
            task_id: str,
            role: AgentRole,
            input_digest: str,
        ) -> object:
            if not self._cancelled_once:
                self._cancelled_once = True
                self.cancel(tenant_id=tenant_id, run_id=run_id)
            return super().claim_task(
                tenant_id=tenant_id,
                run_id=run_id,
                task_id=task_id,
                role=role,
                input_digest=input_digest,
            )

    ledger = _CancelOnDispatchLedger()
    result = _run(
        LangGraphInvestigator(
            DeterministicStructuredModel(),
            ledger=ledger,
        ),
        evidence=_evidence(),
        run_id="run:mid-cancel",
        thread_ref="thread:mid-cancel",
    )
    assert result.status.value == "cancelled"
    assert result.critic.reasons == ("run_cancelled",)
    assert len(result.artifacts) == 6


def test_cancel_port_and_exception_fallback_return_explicit_terminal() -> None:
    ledger = InMemoryOrchestrationLedger()
    investigator = LangGraphInvestigator(
        DeterministicStructuredModel(),
        ledger=ledger,
    )
    projection = ledger.begin_run(
        tenant_id="tenant-acme",
        incident_id=demo_request().incident_id,
        run_id="run:cancel-fallback",
        thread_ref="thread:cancel-fallback",
        graph_version=GRAPH_VERSION,
        input_digest="b" * 64,
    )
    investigator.cancel_run(
        tenant_id="tenant-acme",
        run_id="run:cancel-fallback",
    )
    assert investigator.ledger is ledger
    assert investigator._is_cancelled(
        {
            "tenant_id": "tenant-acme",
            "run_id": "run:cancel-fallback",
        }
    )
    result = investigator._cancelled_result(
        tenant_id="tenant-acme",
        request=demo_request(),
        request_id="cancel-fallback",
        run_id=projection.run_id,
        thread_ref=projection.thread_ref,
    )
    assert result.status.value == "cancelled"
    assert result.critic.reasons == ("run_cancelled",)
    investigator.cancel_run(
        tenant_id="tenant-acme",
        run_id="run:missing",
    )
    assert not investigator._is_cancelled(
        {
            "tenant_id": "tenant-acme",
            "run_id": "run:missing",
        }
    )
    with pytest.raises(OrchestrationFailure, match="invalid state"):
        investigator._result(
            {
                "tenant_id": "tenant-acme",
                "critic": {},
            },
            request=demo_request(),
            request_id="invalid-state",
            run_id="run:invalid-state",
            thread_ref="thread:invalid-state",
            replayed=False,
        )


def test_checkpoint_history_failure_is_typed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    investigator = LangGraphInvestigator(DeterministicStructuredModel())

    def fail(_config: object) -> object:
        raise RuntimeError("checkpoint unavailable")

    monkeypatch.setattr(investigator._graph, "get_state_history", fail)
    with pytest.raises(OrchestrationFailure, match="checkpoint read failed"):
        investigator.checkpoint_count(
            tenant_id="tenant-acme",
            thread_ref="thread:history-failure",
        )
