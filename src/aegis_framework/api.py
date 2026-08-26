"""Authenticated FastAPI delivery with explicit demo and production modes."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from threading import Lock
from typing import Annotated, Literal, NoReturn

from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Path,
    Query,
    status,
)
from pydantic import Field, TypeAdapter, ValidationError
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from aegis_framework.access import (
    AuditEventView,
    AuthenticatorPort,
    GovernancePort,
    PolicyRecord,
    QuotaRecord,
    TenantRecord,
)
from aegis_framework.domain import (
    CheckoutAlert,
    Identifier,
    IdentityContext,
    InvestigationRequest,
    InvestigationResult,
    RiskLevel,
    StrictModel,
    stable_id,
)
from aegis_framework.durability import (
    CursorCodec,
    DurableInvestigationService,
    InMemoryDurability,
    RunView,
    SignalCommand,
    TimelinePage,
)
from aegis_framework.errors import (
    AegisFrameworkError,
    ApprovalExpired,
    AuthenticationFailed,
    ConcurrencyConflict,
    IdempotencyConflict,
    IdentityUnavailable,
    IntegrityFailure,
    InvestigationInProgress,
    PayloadRejected,
    PolicyDenied,
    RepositoryUnavailable,
)
from aegis_framework.evidence import EvidenceCursorView, EvidenceQueryView
from aegis_framework.evidence_runtime import EvidenceStatusPort
from aegis_framework.fixtures import DemoBundle, DemoScenario, build_demo_bundle
from aegis_framework.identity import UnavailableAuthenticator
from aegis_framework.model_gateway import (
    CredentialReference,
    DataClassification,
    InMemoryModelControlStore,
    ModelCapability,
    ModelCatalogEntry,
    ModelControlStore,
    ModelPrice,
    ModelProvider,
    ModelRoute,
    ModelUsageView,
    ProviderHealthView,
    TenantModelPolicy,
)
from aegis_framework.orchestration import (
    ArtifactSummary,
    OrchestrationArtifactReadPort,
)
from aegis_framework.ports import Action, PolicyDecision, PolicyPort
from aegis_framework.references import TenantReferenceCodec
from aegis_framework.remediation import (
    ApprovalDisposition,
    ApprovalService,
    ApprovalView,
)
from aegis_framework.service import InvestigationService

_IDENTIFIER_ADAPTER = TypeAdapter(Identifier)


class AppMode(StrEnum):
    PRODUCTION = "production"
    DEMO = "demo"
    TEST = "test"


class ApiInvestigationRequest(StrictModel):
    incident_id: Identifier
    alert: CheckoutAlert


class ApiDurableInvestigationRequest(StrictModel):
    incident_id: Identifier
    alert: CheckoutAlert
    wait_for_signal: bool = False


class ApiSignalRequest(StrictModel):
    command_id: Identifier


class DurableRunResponse(StrictModel):
    run_id: Identifier
    incident_id: Identifier
    request_ref: Identifier
    workflow_id: Identifier
    status: str
    version: int = Field(ge=1)
    last_cursor: int = Field(ge=1)
    created_at: str
    updated_at: str
    failure_code: Identifier | None = None
    replayed: bool = False


class HealthResponse(StrictModel):
    status: str
    identity_mode: AppMode
    network_connectors_enabled: bool
    network_models_enabled: bool
    effects_enabled: bool


class ReadinessResponse(StrictModel):
    status: str
    identity_ready: bool
    governance_ready: bool


class MeResponse(StrictModel):
    tenant_id: Identifier
    issuer: str
    subject_id: str
    principal_kind: str
    roles: tuple[Identifier, ...]
    permissions: tuple[Identifier, ...]
    purposes: tuple[Identifier, ...]
    grant_version: int = Field(ge=1)
    expires_at: str


class ModelCatalogView(StrictModel):
    provider: ModelProvider
    model: Identifier
    region: Identifier
    capabilities: tuple[str, ...]
    context_tokens: int
    maximum_output_tokens: int
    tokenizer: Identifier | None
    tokenizer_limitations: str
    usage_limitations: str
    pricing_version: Identifier


class OrchestrationArtifactPageView(StrictModel):
    items: tuple[ArtifactSummary, ...]
    next_cursor: str | None


class ApiApprovalDecisionRequest(StrictModel):
    command_id: Identifier
    disposition: Literal[ApprovalDisposition.GRANT, ApprovalDisposition.DENY]
    rationale: str = Field(min_length=1, max_length=2_000)
    expected_version: int = Field(ge=1)
    plan_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    approval_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class ApiApprovalRevocationRequest(StrictModel):
    command_id: Identifier
    rationale: str = Field(min_length=12, max_length=2_000)
    expected_version: int = Field(ge=1)


class ApprovalApiView(StrictModel):
    approval_ref: Identifier
    plan_ref: Identifier
    status: str
    version: int = Field(ge=1)
    grants: int = Field(ge=0)
    quorum: int = Field(ge=1)
    decision_count: int = Field(ge=0)
    expires_at: str
    plan_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    approval_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class BodySizeLimitMiddleware:
    """Reject request bodies over the bound even without Content-Length."""

    def __init__(self, app: ASGIApp, *, maximum_bytes: int) -> None:
        self._app = app
        self._maximum_bytes = maximum_bytes

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return
        headers = {
            key.lower(): value
            for key, value in scope.get("headers", ())
            if isinstance(key, bytes) and isinstance(value, bytes)
        }
        raw_length = headers.get(b"content-length")
        try:
            content_length = int(raw_length) if raw_length is not None else None
        except ValueError:
            await _send_error(send, status.HTTP_400_BAD_REQUEST, "invalid request")
            return
        if content_length is not None and (
            content_length < 0 or content_length > self._maximum_bytes
        ):
            await _send_error(
                send,
                status.HTTP_413_CONTENT_TOO_LARGE,
                "request body is too large",
            )
            return

        messages: list[Message] = []
        observed = 0
        while True:
            message = await receive()
            messages.append(message)
            if message.get("type") == "http.request":
                body = message.get("body", b"")
                if isinstance(body, bytes):
                    observed += len(body)
                if observed > self._maximum_bytes:
                    await _send_error(
                        send,
                        status.HTTP_413_CONTENT_TOO_LARGE,
                        "request body is too large",
                    )
                    return
                if not message.get("more_body", False):
                    break
            elif message.get("type") == "http.disconnect":
                break
        iterator = iter(messages)

        async def replay() -> Message:
            return next(iterator, {"type": "http.request", "body": b""})

        await self._app(scope, replay, send)


@dataclass(frozen=True)
class ApiRuntime:
    authenticator: AuthenticatorPort
    governance: GovernancePort
    policy: PolicyPort
    service_for: Callable[[DemoScenario], InvestigationService]
    durable: DurableInvestigationService | None = None
    model_control: ModelControlStore | None = None
    evidence_control: EvidenceStatusPort | None = None
    orchestration_control: OrchestrationArtifactReadPort | None = None
    orchestration_cursor_codec: CursorCodec | None = None
    approvals: ApprovalService | None = None

    def ready(self) -> bool:
        return self.authenticator.ready() and self.governance.ready()


class _UnavailableGovernance:
    def ready(self) -> bool:
        return False

    def get_tenant(self, *, tenant_id: str) -> TenantRecord | None:
        del tenant_id
        return None

    def current_policy(self, *, tenant_id: str) -> PolicyRecord | None:
        del tenant_id
        return None

    def get_quota(self, *, tenant_id: str, quota_key: str) -> QuotaRecord | None:
        del tenant_id, quota_key
        return None

    def list_audit(
        self, *, identity: IdentityContext, limit: int
    ) -> tuple[AuditEventView, ...]:
        del identity, limit
        raise IdentityUnavailable("production governance is not configured")


class _UnavailablePolicy:
    def authorize(
        self,
        identity: IdentityContext,
        action: Action,
        *,
        resource_tenant_id: str,
        purpose: str,
        risk: RiskLevel,
    ) -> PolicyDecision:
        del identity, action, resource_tenant_id, purpose, risk
        raise IdentityUnavailable("production policy is not configured")


def create_app(
    *,
    mode: AppMode,
    budget_units: int = 10_000,
    runtime: ApiRuntime | None = None,
    maximum_body_bytes: int = 65_536,
) -> FastAPI:
    if maximum_body_bytes < 1_024 or maximum_body_bytes > 1_048_576:
        raise ValueError("API body bound is outside the permitted range")
    if runtime is not None and mode is AppMode.DEMO:
        raise ValueError("an injected runtime must use test or production mode")
    selected_runtime = runtime or (
        _build_demo_runtime(budget_units=budget_units)
        if mode is AppMode.DEMO
        else _production_runtime_from_environment()
    )

    app = FastAPI(
        title="Aegis Framework Platform",
        version="0.7.0",
        description="Authenticated Layer 7 approval and controlled-effect API.",
    )
    app.add_middleware(BodySizeLimitMiddleware, maximum_bytes=maximum_body_bytes)
    app.state.mode = mode
    app.state.runtime = selected_runtime

    def authenticated(
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
        x_request_id: Annotated[str | None, Header(alias="X-Request-ID")] = None,
        x_trace_id: Annotated[str | None, Header(alias="X-Trace-ID")] = None,
    ) -> IdentityContext:
        if x_request_id is None:
            _unauthorized()
        try:
            _IDENTIFIER_ADAPTER.validate_python(x_request_id)
            if x_trace_id is not None:
                _IDENTIFIER_ADAPTER.validate_python(x_trace_id)
        except ValidationError:
            _unauthorized()
        token = _bearer_token(authorization)
        trace_id = x_trace_id or stable_id("trace", x_request_id)
        try:
            return selected_runtime.authenticator.authenticate(
                bearer_token=token,
                request_id=x_request_id,
                trace_id=trace_id,
            )
        except AuthenticationFailed as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="authentication failed",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        except IdentityUnavailable as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="identity service is unavailable",
            ) from exc
        except RepositoryUnavailable as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="identity service is unavailable",
            ) from exc

    @app.get("/healthz", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(
            status="ok",
            identity_mode=mode,
            network_connectors_enabled=False,
            network_models_enabled=False,
            effects_enabled=False,
        )

    @app.get("/readyz", response_model=ReadinessResponse)
    def readiness() -> ReadinessResponse:
        identity_ready = selected_runtime.authenticator.ready()
        governance_ready = selected_runtime.governance.ready()
        if not selected_runtime.ready():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "status": "not_ready",
                    "identity_ready": identity_ready,
                    "governance_ready": governance_ready,
                },
            )
        return ReadinessResponse(
            status="ready",
            identity_ready=identity_ready,
            governance_ready=governance_ready,
        )

    @app.get("/v1/me", response_model=MeResponse)
    def me(identity: IdentityContext = Depends(authenticated)) -> MeResponse:
        return MeResponse(
            tenant_id=identity.tenant_id,
            issuer=identity.issuer,
            subject_id=identity.subject_id,
            principal_kind=identity.principal_kind.value,
            roles=identity.roles,
            permissions=identity.permissions,
            purposes=identity.purposes,
            grant_version=identity.grant_version,
            expires_at=identity.expires_at.isoformat(),
        )

    @app.get("/v1/tenants/{tenant_id}", response_model=TenantRecord)
    def tenant(
        tenant_id: Annotated[Identifier, Path()],
        identity: IdentityContext = Depends(authenticated),
    ) -> TenantRecord:
        _authorize_resource(
            selected_runtime,
            identity,
            Action.TENANT_READ,
            resource_tenant_id=tenant_id,
        )
        record = selected_runtime.governance.get_tenant(tenant_id=tenant_id)
        if record is None:
            _not_found()
        return record

    @app.get("/v1/policies/current", response_model=PolicyRecord)
    def policy(
        identity: IdentityContext = Depends(authenticated),
    ) -> PolicyRecord:
        _authorize_resource(
            selected_runtime,
            identity,
            Action.POLICY_READ,
            resource_tenant_id=identity.tenant_id,
        )
        record = selected_runtime.governance.current_policy(
            tenant_id=identity.tenant_id
        )
        if record is None:
            _not_found()
        return record

    @app.get("/v1/quotas/investigations", response_model=QuotaRecord)
    def quota(
        identity: IdentityContext = Depends(authenticated),
    ) -> QuotaRecord:
        _authorize_resource(
            selected_runtime,
            identity,
            Action.QUOTA_READ,
            resource_tenant_id=identity.tenant_id,
        )
        record = selected_runtime.governance.get_quota(
            tenant_id=identity.tenant_id,
            quota_key="investigation-units",
        )
        if record is None:
            _not_found()
        return record

    @app.get("/v1/audit", response_model=tuple[AuditEventView, ...])
    def audit(
        identity: IdentityContext = Depends(authenticated),
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
    ) -> tuple[AuditEventView, ...]:
        _authorize_resource(
            selected_runtime,
            identity,
            Action.AUDIT_READ,
            resource_tenant_id=identity.tenant_id,
        )
        return tuple(
            selected_runtime.governance.list_audit(identity=identity, limit=limit)
        )

    @app.get("/v1/models/catalog", response_model=tuple[ModelCatalogView, ...])
    def model_catalog(
        identity: IdentityContext = Depends(authenticated),
    ) -> tuple[ModelCatalogView, ...]:
        control = _require_model_control(selected_runtime)
        _authorize_resource(
            selected_runtime,
            identity,
            Action.MODEL_CATALOG_READ,
            resource_tenant_id=identity.tenant_id,
        )
        return tuple(
            _catalog_view(entry)
            for entry in control.catalog(tenant_id=identity.tenant_id)
        )

    @app.get(
        "/v1/models/usage/{run_id}",
        response_model=ModelUsageView,
    )
    def model_usage(
        run_id: Annotated[str, Path(min_length=1, max_length=128)],
        identity: IdentityContext = Depends(authenticated),
    ) -> ModelUsageView:
        control = _require_model_control(selected_runtime)
        _authorize_resource(
            selected_runtime,
            identity,
            Action.MODEL_USAGE_READ,
            resource_tenant_id=identity.tenant_id,
        )
        return control.usage(tenant_id=identity.tenant_id, run_id=run_id)

    @app.get(
        "/v1/models/health",
        response_model=tuple[ProviderHealthView, ...],
    )
    def model_health(
        identity: IdentityContext = Depends(authenticated),
    ) -> tuple[ProviderHealthView, ...]:
        control = _require_model_control(selected_runtime)
        _authorize_resource(
            selected_runtime,
            identity,
            Action.MODEL_HEALTH_READ,
            resource_tenant_id=identity.tenant_id,
        )
        return tuple(control.health(tenant_id=identity.tenant_id))

    @app.get(
        "/v1/evidence/queries/{query_id}",
        response_model=EvidenceQueryView,
    )
    def evidence_query_status(
        query_id: Annotated[str, Path(min_length=1, max_length=128)],
        identity: IdentityContext = Depends(authenticated),
    ) -> EvidenceQueryView:
        control = _require_evidence_control(selected_runtime)
        _authorize_resource(
            selected_runtime,
            identity,
            Action.EVIDENCE_QUERY_READ,
            resource_tenant_id=identity.tenant_id,
        )
        result = control.status(
            tenant_id=identity.tenant_id,
            query_id=query_id,
        )
        if result is None:
            _not_found()
        return result

    @app.get(
        "/v1/evidence/queries/{query_id}/cursor",
        response_model=EvidenceCursorView,
    )
    def evidence_cursor_status(
        query_id: Annotated[str, Path(min_length=1, max_length=128)],
        identity: IdentityContext = Depends(authenticated),
    ) -> EvidenceCursorView:
        control = _require_evidence_control(selected_runtime)
        _authorize_resource(
            selected_runtime,
            identity,
            Action.EVIDENCE_CURSOR_READ,
            resource_tenant_id=identity.tenant_id,
        )
        result = control.cursor_status(
            tenant_id=identity.tenant_id,
            query_id=query_id,
        )
        if result is None:
            _not_found()
        return result

    @app.get(
        "/v1/orchestrations/{run_id}/artifacts",
        response_model=OrchestrationArtifactPageView,
    )
    def orchestration_artifacts(
        run_id: Annotated[str, Path(min_length=1, max_length=128)],
        identity: IdentityContext = Depends(authenticated),
        cursor: Annotated[str | None, Query(max_length=1_024)] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
    ) -> OrchestrationArtifactPageView:
        control = selected_runtime.orchestration_control
        codec = selected_runtime.orchestration_cursor_codec
        if control is None or codec is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="orchestration artifact store is unavailable",
            )
        _authorize_resource(
            selected_runtime,
            identity,
            Action.ORCHESTRATION_ARTIFACT_READ,
            resource_tenant_id=identity.tenant_id,
        )
        try:
            after_ordinal = (
                codec.decode(
                    cursor,
                    tenant_id=identity.tenant_id,
                    run_id=run_id,
                )
                if cursor is not None
                else 0
            )
            page = control.artifact_page(
                tenant_id=identity.tenant_id,
                run_id=run_id,
                after_ordinal=after_ordinal,
                limit=limit,
            )
        except (IntegrityFailure, ValueError):
            _not_found()
        return OrchestrationArtifactPageView(
            items=page.items,
            next_cursor=(
                codec.encode(
                    tenant_id=identity.tenant_id,
                    run_id=run_id,
                    cursor=page.next_ordinal,
                )
                if page.next_ordinal is not None
                else None
            ),
        )

    @app.get(
        "/v1/approvals/{approval_id}",
        response_model=ApprovalApiView,
    )
    def approval_status(
        approval_id: Annotated[str, Path(min_length=1, max_length=128)],
        identity: IdentityContext = Depends(authenticated),
    ) -> ApprovalApiView:
        approvals = _require_approvals(selected_runtime)
        try:
            view = approvals.get(identity, approval_id=approval_id)
        except PolicyDenied:
            _not_found()
        if view is None:
            _not_found()
        return _approval_view(view)

    @app.post(
        "/v1/approvals/{approval_id}/decisions",
        response_model=ApprovalApiView,
    )
    def decide_approval(
        approval_id: Annotated[str, Path(min_length=1, max_length=128)],
        payload: ApiApprovalDecisionRequest,
        identity: IdentityContext = Depends(authenticated),
    ) -> ApprovalApiView:
        approvals = _require_approvals(selected_runtime)
        try:
            view = approvals.decide(
                identity,
                approval_id=approval_id,
                disposition=payload.disposition,
                rationale=payload.rationale,
                expected_version=payload.expected_version,
                command_id=payload.command_id,
                plan_digest=payload.plan_digest,
                approval_digest=payload.approval_digest,
            )
        except PolicyDenied:
            _not_found()
        except ApprovalExpired as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="approval is no longer current",
            ) from exc
        except (ConcurrencyConflict, IdempotencyConflict) as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="approval decision conflicts with current state",
            ) from exc
        except IntegrityFailure as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="approval is already terminal",
            ) from exc
        return _approval_view(view)

    @app.post(
        "/v1/approvals/{approval_id}/revocations",
        response_model=ApprovalApiView,
    )
    def revoke_approval(
        approval_id: Annotated[str, Path(min_length=1, max_length=128)],
        payload: ApiApprovalRevocationRequest,
        identity: IdentityContext = Depends(authenticated),
    ) -> ApprovalApiView:
        approvals = _require_approvals(selected_runtime)
        try:
            approvals.revoke(
                identity,
                approval_id=approval_id,
                expected_version=payload.expected_version,
                command_id=payload.command_id,
                rationale=payload.rationale,
            )
            view = approvals.get(identity, approval_id=approval_id)
        except PolicyDenied:
            _not_found()
        except (ConcurrencyConflict, IdempotencyConflict) as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="approval revocation conflicts with current state",
            ) from exc
        except IntegrityFailure as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="approval is already terminal",
            ) from exc
        if view is None:
            _not_found()
        return _approval_view(view)

    @app.post(
        "/v1/investigations",
        response_model=InvestigationResult,
        status_code=status.HTTP_200_OK,
    )
    def investigate(
        payload: ApiInvestigationRequest,
        identity: IdentityContext = Depends(authenticated),
    ) -> InvestigationResult:
        request = InvestigationRequest(
            incident_id=payload.incident_id,
            alert=payload.alert,
        )
        try:
            return selected_runtime.service_for(DemoScenario.SUCCESS).investigate(
                identity, request
            )
        except PolicyDenied as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="investigation is not authorized",
            ) from exc
        except (IdempotencyConflict, InvestigationInProgress) as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="investigation request conflicts with current state",
            ) from exc
        except AegisFrameworkError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="investigation failed safely",
            ) from exc

    @app.post(
        "/v1/durable-investigations",
        response_model=DurableRunResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    def submit_durable_investigation(
        payload: ApiDurableInvestigationRequest,
        identity: IdentityContext = Depends(authenticated),
    ) -> DurableRunResponse:
        durable = _require_durable(selected_runtime)
        request = InvestigationRequest(
            incident_id=payload.incident_id,
            alert=payload.alert,
        )
        try:
            result = durable.submit(
                identity,
                request,
                wait_for_signal=payload.wait_for_signal,
            )
        except PolicyDenied as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="investigation is not authorized",
            ) from exc
        except (ConcurrencyConflict, IdempotencyConflict) as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="investigation request conflicts with current state",
            ) from exc
        except AegisFrameworkError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="durable investigation failed safely",
            ) from exc
        return _durable_response(result)

    @app.get(
        "/v1/durable-investigations/{run_id}",
        response_model=DurableRunResponse,
    )
    def durable_investigation(
        run_id: Annotated[str, Path(min_length=1, max_length=128)],
        identity: IdentityContext = Depends(authenticated),
    ) -> DurableRunResponse:
        durable = _require_durable(selected_runtime)
        try:
            result = durable.get(identity, run_id=run_id)
        except PolicyDenied:
            _not_found()
        except AegisFrameworkError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="durable investigation failed safely",
            ) from exc
        if result is None:
            _not_found()
        return _durable_response(result)

    @app.get(
        "/v1/durable-investigations/{run_id}/timeline",
        response_model=TimelinePage,
    )
    def durable_timeline(
        run_id: Annotated[str, Path(min_length=1, max_length=128)],
        cursor: Annotated[str | None, Query(max_length=1_024)] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        identity: IdentityContext = Depends(authenticated),
    ) -> TimelinePage:
        durable = _require_durable(selected_runtime)
        try:
            if durable.get(identity, run_id=run_id) is None:
                _not_found()
            return durable.timeline(
                identity,
                run_id=run_id,
                cursor=cursor,
                limit=limit,
            )
        except PolicyDenied:
            _not_found()
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="timeline cursor is invalid",
            ) from exc
        except AegisFrameworkError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="durable investigation failed safely",
            ) from exc

    @app.post(
        "/v1/durable-investigations/{run_id}/signals/{command_type}",
        response_model=DurableRunResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    def durable_signal(
        run_id: Annotated[str, Path(min_length=1, max_length=128)],
        command_type: Annotated[str, Path(pattern=r"^(resume|cancel)$")],
        payload: ApiSignalRequest,
        identity: IdentityContext = Depends(authenticated),
    ) -> DurableRunResponse:
        durable = _require_durable(selected_runtime)
        try:
            result = durable.signal(
                identity,
                command=SignalCommand(
                    command_id=payload.command_id,
                    run_id=run_id,
                    command_type=command_type,
                ),
            )
        except PolicyDenied:
            _not_found()
        except (ConcurrencyConflict, IdempotencyConflict) as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="signal conflicts with current state",
            ) from exc
        except PayloadRejected as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="signal exceeds the permitted bound",
            ) from exc
        except AegisFrameworkError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="durable signal failed safely",
            ) from exc
        return _durable_response(result)

    return app


def _build_demo_runtime(*, budget_units: int) -> ApiRuntime:
    if budget_units < 5:
        raise ValueError("API demo budget must permit at least one investigation")
    bundles: dict[DemoScenario, DemoBundle] = {}
    bundle_lock = Lock()

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

    primary = bundle_for(DemoScenario.SUCCESS)
    from aegis_framework.adapters import FixedClock
    from aegis_framework.durability import CursorCodec, DurableInvestigationService
    from aegis_framework.fixtures import DEMO_TIME

    durable_store = InMemoryDurability(clock=FixedClock(DEMO_TIME))
    from aegis_framework.evidence_runtime import (
        CursorVault,
        InMemoryEvidenceControlStore,
    )

    evidence_control = InMemoryEvidenceControlStore(
        cursor_vault=CursorVault(b"aegis-demo-evidence-cursor-key-1"),
        clock=FixedClock(DEMO_TIME).now,
    )
    model_control = _demo_model_control()
    from aegis_framework.remediation_demo import build_remediation_api_demo

    remediation_demo = build_remediation_api_demo()
    return ApiRuntime(
        authenticator=primary.authenticator,
        governance=primary.governance,
        policy=primary.policy,
        # Use the primary bundle's service for all API requests so budget
        # and idempotency state are shared at the app boundary — scenario
        # selection is server-side configuration, not caller-selectable.
        service_for=lambda _scenario: primary.service,
        durable=DurableInvestigationService(
            policy=primary.policy,
            store=durable_store,
            cursor_codec=CursorCodec(b"aegis-demo-cursor-key-is-test-only-0001"),
        ),
        model_control=model_control,
        evidence_control=evidence_control,
        orchestration_control=primary.orchestrator,
        orchestration_cursor_codec=CursorCodec(
            b"aegis-demo-artifact-cursor-test-only-01"
        ),
        approvals=remediation_demo.approvals,
    )


def _unavailable_runtime() -> ApiRuntime:
    def unavailable_service(scenario: DemoScenario) -> InvestigationService:
        del scenario
        raise IdentityUnavailable("production services are not configured")

    return ApiRuntime(
        authenticator=UnavailableAuthenticator(),
        governance=_UnavailableGovernance(),
        policy=_UnavailablePolicy(),
        service_for=unavailable_service,
    )


def _production_runtime_from_environment() -> ApiRuntime:
    required = {
        "dsn": os.getenv("AEGIS_POSTGRES_DSN"),
        "issuer": os.getenv("AEGIS_OIDC_ISSUER"),
        "audience": os.getenv("AEGIS_OIDC_AUDIENCE"),
        "jwks_uri": os.getenv("AEGIS_OIDC_JWKS_URI"),
        "cursor_key": os.getenv("AEGIS_CURSOR_SIGNING_KEY"),
        "reference_key": os.getenv("AEGIS_REFERENCE_ENCRYPTION_KEY"),
    }
    if any(value is None or not value for value in required.values()):
        return _unavailable_runtime()

    from aegis_framework.adapters import SystemClock
    from aegis_framework.authorization import EnterprisePolicy
    from aegis_framework.durable_postgres import PostgresDurability
    from aegis_framework.identity import (
        HttpJwksFetcher,
        IssuerConfiguration,
        JwtAuthenticator,
    )
    from aegis_framework.model_postgres import PostgresModelControlStore
    from aegis_framework.orchestration_postgres import PostgresOrchestrationLedger
    from aegis_framework.postgres import PostgresRepository, open_runtime_pool

    clock = SystemClock()
    try:
        configuration = IssuerConfiguration(
            issuer=str(required["issuer"]),
            audiences=(str(required["audience"]),),
            jwks_uri=str(required["jwks_uri"]),
            algorithms=tuple(
                algorithm.strip()
                for algorithm in os.getenv("AEGIS_OIDC_ALGORITHMS", "RS256").split(",")
                if algorithm.strip()
            ),
        )
        pool = open_runtime_pool(dsn=str(required["dsn"]))
        orchestration_pool = open_runtime_pool(dsn=str(required["dsn"]))
        repository = PostgresRepository(pool=pool, clock=clock)
        cursor_codec = CursorCodec(str(required["cursor_key"]).encode())
        tenant_references = TenantReferenceCodec(
            str(required["reference_key"]).encode()
        )
        authenticator = JwtAuthenticator(
            configurations=(configuration,),
            identities=repository,
            fetcher=HttpJwksFetcher(
                allow_loopback_http=(
                    os.getenv("AEGIS_OIDC_ALLOW_LOOPBACK_HTTP", "false").lower()
                    == "true"
                )
            ),
            clock=clock,
        )
    except (RepositoryUnavailable, ValidationError, ValueError):
        return _unavailable_runtime()

    def unavailable_investigation(scenario: DemoScenario) -> InvestigationService:
        del scenario
        raise IdentityUnavailable(
            "production evidence and model adapters are not configured in Layer 3"
        )

    policy = EnterprisePolicy(policies=repository, clock=clock)
    return ApiRuntime(
        authenticator=authenticator,
        governance=repository,
        policy=policy,
        service_for=unavailable_investigation,
        durable=DurableInvestigationService(
            policy=policy,
            store=PostgresDurability(
                pool=pool,
                clock=clock,
                tenant_references=tenant_references,
            ),
            cursor_codec=cursor_codec,
        ),
        model_control=PostgresModelControlStore(pool=pool),
        orchestration_control=PostgresOrchestrationLedger(
            pool=orchestration_pool,
            clock=clock,
        ),
        orchestration_cursor_codec=cursor_codec,
    )


def _demo_model_control() -> InMemoryModelControlStore:
    entries = tuple(
        ModelCatalogEntry(
            tenant_id=tenant_id,
            provider=ModelProvider.FAKE,
            model="deterministic-v1",
            region="local",
            capabilities=frozenset({ModelCapability.JSON_SCHEMA}),
            context_tokens=32_768,
            maximum_output_tokens=4_096,
            tokenizer=None,
            tokenizer_limitations="Portable conservative byte estimate only.",
            usage_limitations=(
                "Deterministic fake usage is synthetic, never provider billing."
            ),
            price=ModelPrice(
                version="fake-2026-08-15",
                currency="USD",
                input_microunits_per_million_tokens=1_000,
                output_microunits_per_million_tokens=2_000,
            ),
            credential=CredentialReference(
                reference=f"secret:fake-model-{tenant_id}",
                version=1,
            ),
        )
        for tenant_id in ("tenant-acme", "tenant-beta")
    )
    policies = tuple(
        TenantModelPolicy(
            tenant_id=entry.tenant_id,
            policy_id=f"model-policy-{entry.tenant_id}",
            revision=1,
            allowed_providers=frozenset({ModelProvider.FAKE}),
            allowed_models=frozenset({entry.model}),
            allowed_regions=frozenset({entry.region}),
            allowed_data_classifications=frozenset({DataClassification.INTERNAL}),
            allowed_purposes=frozenset({"incident-response"}),
            required_capabilities=frozenset({ModelCapability.JSON_SCHEMA}),
            risk_ceiling=RiskLevel.MEDIUM,
            routes=(
                ModelRoute(
                    provider=entry.provider,
                    model=entry.model,
                    region=entry.region,
                    priority=1,
                ),
            ),
            maximum_input_tokens=16_384,
            maximum_output_tokens=4_096,
            maximum_cost_microunits=10_000,
            maximum_calls_per_run=8,
        )
        for entry in entries
    )
    return InMemoryModelControlStore(
        policies=policies,
        catalog=entries,
        tenant_cost_limits={
            "tenant-acme": 1_000_000,
            "tenant-beta": 1_000_000,
        },
    )


def _catalog_view(entry: ModelCatalogEntry) -> ModelCatalogView:
    return ModelCatalogView(
        provider=entry.provider,
        model=entry.model,
        region=entry.region,
        capabilities=tuple(sorted(item.value for item in entry.capabilities)),
        context_tokens=entry.context_tokens,
        maximum_output_tokens=entry.maximum_output_tokens,
        tokenizer=entry.tokenizer,
        tokenizer_limitations=entry.tokenizer_limitations,
        usage_limitations=entry.usage_limitations,
        pricing_version=entry.price.version,
    )


def _require_model_control(runtime: ApiRuntime) -> ModelControlStore:
    if runtime.model_control is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="model operations are unavailable",
        )
    return runtime.model_control


def _require_evidence_control(runtime: ApiRuntime) -> EvidenceStatusPort:
    if runtime.evidence_control is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="evidence control is not configured",
        )
    return runtime.evidence_control


def _require_approvals(runtime: ApiRuntime) -> ApprovalService:
    if runtime.approvals is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="approval service is unavailable",
        )
    return runtime.approvals


def _approval_view(value: ApprovalView) -> ApprovalApiView:
    return ApprovalApiView(
        approval_ref=value.approval.approval_id,
        plan_ref=value.approval.plan_id,
        status=value.status.value,
        version=value.version,
        grants=value.grants,
        quorum=value.approval.requirement.quorum,
        decision_count=len(value.decisions),
        expires_at=value.approval.expires_at.isoformat(),
        plan_digest=value.approval.plan_digest,
        approval_digest=value.approval.canonical_digest,
    )


def _authorize_resource(
    runtime: ApiRuntime,
    identity: IdentityContext,
    action: Action,
    *,
    resource_tenant_id: str,
) -> None:
    try:
        decision = runtime.policy.authorize(
            identity,
            action,
            resource_tenant_id=resource_tenant_id,
            purpose="incident-response",
            risk=RiskLevel.LOW,
        )
    except (IdentityUnavailable, RepositoryUnavailable) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="authorization service is unavailable",
        ) from exc
    except AegisFrameworkError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="authorization failed safely",
        ) from exc
    if not decision.allowed:
        _not_found()


def _bearer_token(authorization: str | None) -> str:
    if authorization is None or len(authorization) > 16_400:
        _unauthorized()
    scheme, separator, token = authorization.partition(" ")
    if separator != " " or scheme.lower() != "bearer" or not token:
        _unauthorized()
    return token


def _unauthorized() -> NoReturn:
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _not_found() -> NoReturn:
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")


async def _send_error(send: Send, status_code: int, detail: str) -> None:
    body = json_bytes({"detail": detail})
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def json_bytes(value: Mapping[str, object]) -> bytes:
    import json

    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def _require_durable(runtime: ApiRuntime) -> DurableInvestigationService:
    if runtime.durable is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="durable investigation service is unavailable",
        )
    return runtime.durable


def _durable_response(value: RunView) -> DurableRunResponse:
    return DurableRunResponse(
        run_id=value.run_id,
        incident_id=value.incident_id,
        request_ref=value.request_ref,
        workflow_id=value.workflow_id,
        status=value.status.value,
        version=value.version,
        last_cursor=value.last_cursor,
        created_at=value.created_at.isoformat(),
        updated_at=value.updated_at.isoformat(),
        failure_code=value.failure_code,
        replayed=value.replayed,
    )


app = create_app(mode=AppMode(os.getenv("AEGIS_MODE", AppMode.PRODUCTION.value)))
