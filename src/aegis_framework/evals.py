"""Deterministic, network-free evaluation suite."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from aegis_framework.domain import CriticDecision, InvestigationStatus, StrictModel
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
