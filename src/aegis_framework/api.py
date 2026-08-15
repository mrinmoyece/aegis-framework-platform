"""FastAPI delivery adapter for the deterministic investigation slice."""

from __future__ import annotations

from threading import Lock
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, status
from pydantic import ValidationError

from aegis_framework.domain import (
    CheckoutAlert,
    Identifier,
    IdentityContext,
    InvestigationRequest,
    InvestigationResult,
    StrictModel,
    stable_id,
)
from aegis_framework.errors import (
    AegisFrameworkError,
    IdempotencyConflict,
    InvestigationInProgress,
    PolicyDenied,
)
from aegis_framework.fixtures import DemoBundle, DemoScenario, build_demo_bundle


class ApiInvestigationRequest(StrictModel):
    scenario: DemoScenario = DemoScenario.SUCCESS
    incident_id: Identifier
    alert: CheckoutAlert


class HealthResponse(StrictModel):
    status: str
    network_models_enabled: bool
    effects_enabled: bool


def create_app(*, budget_units: int = 10_000) -> FastAPI:
    if budget_units < 5:
        raise ValueError("API demo budget must permit at least one investigation")
    bundles: dict[DemoScenario, DemoBundle] = {}
    bundle_lock = Lock()
    app = FastAPI(
        title="Aegis Framework Platform",
        version="0.1.0",
        description="Deterministic Layer 1 checkout investigation API.",
    )
    app.state.demo_bundles = bundles
    app.state.demo_budget_units = budget_units

    def bundle_for(scenario: DemoScenario) -> DemoBundle:
        existing = bundles.get(scenario)
        if existing is not None:
            return existing
        with bundle_lock:
            existing = bundles.get(scenario)
            if existing is not None:
                return existing
            created = build_demo_bundle(
                scenario,
                use_otel=True,
                budget_units=budget_units,
            )
            bundles[scenario] = created
            return created

    @app.get("/healthz", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(
            status="ok",
            network_models_enabled=False,
            effects_enabled=False,
        )

    @app.post(
        "/v1/investigations",
        response_model=InvestigationResult,
        status_code=status.HTTP_200_OK,
    )
    def investigate(
        payload: ApiInvestigationRequest,
        x_tenant_id: Annotated[str, Header(alias="X-Tenant-ID")],
        x_subject_id: Annotated[str, Header(alias="X-Subject-ID")],
        x_roles: Annotated[str, Header(alias="X-Roles")],
        x_request_id: Annotated[str, Header(alias="X-Request-ID")],
        x_trace_id: Annotated[str | None, Header(alias="X-Trace-ID")] = None,
    ) -> InvestigationResult:
        try:
            identity = IdentityContext(
                tenant_id=x_tenant_id,
                subject_id=x_subject_id,
                roles=tuple(
                    role.strip() for role in x_roles.split(",") if role.strip()
                ),
                request_id=x_request_id,
                trace_id=x_trace_id or stable_id("trace", x_tenant_id, x_request_id),
            )
            request = InvestigationRequest(
                incident_id=payload.incident_id,
                alert=payload.alert,
            )
        except ValidationError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="identity headers are invalid",
            ) from exc
        try:
            return bundle_for(payload.scenario).service.investigate(identity, request)
        except PolicyDenied as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="investigation is not authorized",
            ) from exc
        except (IdempotencyConflict, InvestigationInProgress) as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        except AegisFrameworkError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="investigation failed safely",
            ) from exc

    return app


app = create_app()
