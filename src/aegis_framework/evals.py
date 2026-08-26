"""Deterministic, network-free evaluation suite."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from aegis_framework.domain import (
    CriticDecision,
    Evidence,
    InvestigationRequest,
    InvestigationStatus,
    StrictModel,
)
from aegis_framework.errors import OrchestrationFailure, PolicyDenied
from aegis_framework.fixtures import (
    DemoScenario,
    build_demo_bundle,
    demo_identity,
    demo_request,
)


class EvalCase(StrictModel):
    case_id: str
    kind: Literal[
        "investigation",
        "identity-attack",
        "checkpoint-tenant-attack",
        "graph-authority-attack",
        "durable-recovery",
        "durable-duplicate-request",
        "durable-cancellation",
        "policy-revocation-wait",
        "framework-outage",
    ] = "investigation"
    scenario: DemoScenario = DemoScenario.SUCCESS
    expected_status: InvestigationStatus | None = None
    expected_critic: CriticDecision | None = None
    expected_reason: str

    @model_validator(mode="after")
    def require_investigation_expectations(self) -> EvalCase:
        if self.kind == "investigation" and (
            self.expected_status is None or self.expected_critic is None
        ):
            raise ValueError("investigation evals require status and critic")
        return self


class EvalOutcome(StrictModel):
    case_id: str
    passed: bool
    details: tuple[str, ...]


class EvalReport(StrictModel):
    passed: bool
    total: int = Field(ge=0)
    succeeded: int = Field(ge=0)
    outcomes: tuple[EvalOutcome, ...]


def load_cases(path: Path) -> tuple[EvalCase, ...]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return tuple(EvalCase.model_validate(item) for item in payload)


def run_eval_suite(cases: tuple[EvalCase, ...]) -> EvalReport:
    outcomes = tuple(_run_case(case) for case in cases)
    succeeded = sum(outcome.passed for outcome in outcomes)
    return EvalReport(
        passed=succeeded == len(outcomes),
        total=len(outcomes),
        succeeded=succeeded,
        outcomes=outcomes,
    )


def _run_case(case: EvalCase) -> EvalOutcome:
    if case.kind in {
        "durable-recovery",
        "durable-duplicate-request",
        "durable-cancellation",
        "policy-revocation-wait",
        "framework-outage",
    }:
        return _run_durable_case(case)
    if case.kind != "investigation":
        return _run_security_case(case)
    scenario = (
        DemoScenario.SUCCESS
        if case.scenario is DemoScenario.TENANT_ISOLATION
        else case.scenario
    )
    bundle = build_demo_bundle(scenario)
    primary = bundle.service.investigate(
        demo_identity(request_id=f"eval-{case.case_id}"),
        demo_request(),
    )
    details: list[str] = []
    if primary.status is not case.expected_status:
        details.append(f"status={primary.status.value}")
    if primary.critic.decision is not case.expected_critic:
        details.append(f"critic={primary.critic.decision.value}")
    if case.expected_reason not in primary.critic.reasons:
        details.append(f"reason_missing={case.expected_reason}")

    if case.scenario is DemoScenario.SUCCESS:
        if primary.approval is None or primary.proposal is None:
            details.append("approval_boundary_missing")
        if len(primary.hypotheses) != 1 or not primary.hypotheses[0].citations:
            details.append("cited_hypothesis_missing")
    elif case.scenario is DemoScenario.PROMPT_INJECTION:
        if not primary.critic.injection_contained or primary.proposal is not None:
            details.append("injection_not_contained")
    elif case.scenario is DemoScenario.BUDGET_EXHAUSTION:
        if (
            bundle.orchestrator.checkpoint_count(
                tenant_id=primary.tenant_id,
                thread_ref=primary.thread_ref,
            )
            != 0
        ):
            details.append("graph_ran_after_budget_denial")
    elif case.scenario is DemoScenario.TENANT_ISOLATION:
        secondary = bundle.service.investigate(
            demo_identity(
                tenant_id="tenant-beta",
                subject_id="responder-bob",
                request_id=f"eval-{case.case_id}",
            ),
            demo_request(),
        )
        primary_citations = {
            citation.locator
            for hypothesis in primary.hypotheses
            for citation in hypothesis.citations
        }
        secondary_citations = {
            citation.locator
            for hypothesis in secondary.hypotheses
            for citation in hypothesis.citations
        }
        if primary_citations & secondary_citations:
            details.append("cross_tenant_citation_overlap")
        if secondary.tenant_id != "tenant-beta":
            details.append("secondary_tenant_mismatch")

    return EvalOutcome(
        case_id=case.case_id,
        passed=not details,
        details=tuple(details),
    )


def _run_durable_case(case: EvalCase) -> EvalOutcome:
    from aegis_framework.activity_runtime import (
        DurableActivityRuntime,
        InMemoryCurrentAuthority,
    )
    from aegis_framework.adapters import FixedClock, InMemoryBudget
    from aegis_framework.domain import InvestigationResult, stable_id
    from aegis_framework.durability import (
        InMemoryDurability,
        RunStatus,
        SignalCommand,
    )
    from aegis_framework.errors import IntegrityFailure
    from aegis_framework.fixtures import DEMO_TIME
    from aegis_framework.temporal import TemporalActivityInput

    details: list[str] = []
    bundle = build_demo_bundle()
    identity = demo_identity(request_id=f"eval-{case.case_id}")
    authority = InMemoryCurrentAuthority((identity,))
    store = InMemoryDurability(clock=FixedClock(DEMO_TIME))
    run = store.accept_run(
        identity=identity,
        request=demo_request(),
        wait_for_signal=case.kind == "policy-revocation-wait",
    )
    actor_ref = stable_id("actor", identity.issuer, identity.subject_id, length=32)
    value = TemporalActivityInput(
        tenant_ref=stable_id("tenant", identity.tenant_id, length=32),
        actor_ref=actor_ref,
        request_ref=run.request_ref,
        run_id=run.run_id,
        operation_id=f"authorize:{case.case_id}",
    )

    class _FailOnce:
        def __init__(self) -> None:
            self.failed = False

        def run(
            self,
            *,
            tenant_id: str,
            request: InvestigationRequest,
            request_id: str,
            thread_ref: str,
            evidence: Sequence[Evidence],
        ) -> InvestigationResult:
            if not self.failed:
                self.failed = True
                raise OrchestrationFailure("synthetic durable framework outage")
            return bundle.orchestrator.run(
                tenant_id=tenant_id,
                request=request,
                request_id=request_id,
                thread_ref=thread_ref,
                evidence=evidence,
            )

        def checkpoint_count(self, *, tenant_id: str, thread_ref: str) -> int:
            return bundle.orchestrator.checkpoint_count(
                tenant_id=tenant_id,
                thread_ref=thread_ref,
            )

    fail_once = _FailOnce()
    runtime = DurableActivityRuntime(
        authority=authority,
        policy=bundle.policy,
        budget=InMemoryBudget({"tenant-acme": 5}),
        evidence=bundle.service._evidence,
        orchestrator=(
            fail_once if case.kind == "framework-outage" else bundle.orchestrator
        ),
        store=store,
    )

    async def execute() -> None:
        if case.kind == "durable-duplicate-request":
            replay = store.accept_run(
                identity=identity,
                request=demo_request(),
                wait_for_signal=False,
            )
            events = store.events(
                tenant_id=identity.tenant_id,
                aggregate_type="investigation",
                aggregate_id=run.run_id,
            )
            if not replay.replayed or len(events) != 1:
                details.append("duplicate_created_new_application_intent")
            return

        await runtime.authorize(value)
        if case.kind == "durable-cancellation":
            store.accept_signal(
                identity=identity,
                command=SignalCommand(
                    command_id=f"cancel:{case.case_id}",
                    run_id=run.run_id,
                    command_type="cancel",
                ),
            )
            try:
                store.record_transition(
                    tenant_id=identity.tenant_id,
                    run_id=run.run_id,
                    event_type="investigation.graph_completed",
                    operation_id=f"stale:{case.case_id}",
                    actor_ref=actor_ref,
                    request_ref=run.request_ref,
                    attributes={"result": {}},
                )
            except IntegrityFailure:
                pass
            else:
                details.append("stale_result_overwrote_cancel")
            return

        await runtime.collect_evidence(
            value.model_copy(update={"operation_id": f"evidence:{case.case_id}"})
        )
        graph_value = value.model_copy(update={"operation_id": f"graph:{case.case_id}"})
        if case.kind == "framework-outage":
            try:
                await runtime.run_graph(graph_value)
            except OrchestrationFailure:
                pass
            else:
                details.append("framework_outage_was_not_surfaced")
        await runtime.run_graph(graph_value)

        if case.kind == "policy-revocation-wait":
            await runtime.record_wait(
                value.model_copy(update={"operation_id": f"wait:{case.case_id}"})
            )
            command_id = f"resume:{case.case_id}"
            store.accept_signal(
                identity=identity,
                command=SignalCommand(
                    command_id=command_id,
                    run_id=run.run_id,
                    command_type="resume",
                ),
            )
            authority.revoke(
                tenant_id=identity.tenant_id,
                actor_ref=actor_ref,
            )
            try:
                await runtime.authorize_signal(
                    value.model_copy(
                        update={
                            "command_ref": command_id,
                            "operation_id": f"signal:{case.case_id}",
                        }
                    )
                )
            except PolicyDenied:
                pass
            else:
                details.append("revoked_signal_was_authorized")
            return

        recovered = DurableActivityRuntime(
            authority=authority,
            policy=bundle.policy,
            budget=InMemoryBudget({"tenant-acme": 5}),
            evidence=bundle.service._evidence,
            orchestrator=bundle.orchestrator,
            store=store,
        )
        await recovered.complete(
            value.model_copy(update={"operation_id": f"complete:{case.case_id}"})
        )
        current = store.get_run(
            tenant_id=identity.tenant_id,
            run_id=run.run_id,
        )
        if current is None or current.status is not RunStatus.COMPLETED:
            details.append("application_projection_did_not_recover")

    asyncio.run(execute())
    if not store.verify_integrity(tenant_id=identity.tenant_id):
        details.append("application_ledger_integrity_failed")
    return EvalOutcome(
        case_id=case.case_id,
        passed=not details,
        details=tuple(details),
    )


def _run_security_case(case: EvalCase) -> EvalOutcome:
    details: list[str] = []
    bundle = build_demo_bundle()
    if case.kind == "checkpoint-tenant-attack":
        result = bundle.service.investigate(
            demo_identity(request_id=f"eval-{case.case_id}"),
            demo_request(),
        )
        try:
            bundle.orchestrator.checkpoint_count(
                tenant_id="tenant-beta",
                thread_ref=result.thread_ref,
            )
        except OrchestrationFailure:
            pass
        else:
            details.append("cross_tenant_checkpoint_read_allowed")
    elif case.kind == "graph-authority-attack":
        identity = demo_identity(request_id=f"eval-{case.case_id}").model_copy(
            update={
                "roles": (),
                "permissions": (),
                "purposes": (),
                "grants": (),
            }
        )
        try:
            bundle.service.investigate(identity, demo_request())
        except PolicyDenied:
            pass
        else:
            details.append("graph_ran_without_application_grant")
    elif case.kind == "identity-attack":
        from fastapi.testclient import TestClient

        from aegis_framework.api import AppMode, create_app

        request = demo_request()
        response = TestClient(create_app(mode=AppMode.DEMO)).post(
            "/v1/investigations",
            headers={
                "Authorization": "Bearer demo-responder-token",
                "X-Request-ID": f"eval-{case.case_id}",
                "X-Tenant-ID": "tenant-beta",
                "X-Subject-ID": "attacker",
                "X-Roles": "tenant-admin",
            },
            json={
                "incident_id": request.incident_id,
                "alert": request.alert.model_dump(mode="json"),
            },
        )
        if response.status_code != 200 or response.json()["tenant_id"] != "tenant-acme":
            details.append("untrusted_identity_headers_changed_authority")
    return EvalOutcome(
        case_id=case.case_id,
        passed=not details,
        details=tuple(details),
    )
