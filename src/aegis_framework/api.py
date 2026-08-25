"""Authenticated FastAPI delivery with explicit demo and production modes."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from threading import Lock
from typing import Annotated, NoReturn

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
from aegis_framework.errors import (
    AegisFrameworkError,
    AuthenticationFailed,
    IdempotencyConflict,
    IdentityUnavailable,
    InvestigationInProgress,
    PolicyDenied,
    RepositoryUnavailable,
)
from aegis_framework.fixtures import DemoBundle, DemoScenario, build_demo_bundle
from aegis_framework.identity import UnavailableAuthenticator
from aegis_framework.ports import Action, PolicyDecision, PolicyPort
from aegis_framework.service import InvestigationService

_IDENTIFIER_ADAPTER = TypeAdapter(Identifier)


class AppMode(StrEnum):
    PRODUCTION = "production"
    DEMO = "demo"
    TEST = "test"


class ApiInvestigationRequest(StrictModel):
    incident_id: Identifier
    alert: CheckoutAlert


class HealthResponse(StrictModel):
    status: str
    identity_mode: AppMode
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
        version="0.2.0",
        description="Authenticated Layer 2 checkout investigation API.",
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
    return ApiRuntime(
        authenticator=primary.authenticator,
        governance=primary.governance,
        policy=primary.policy,
        # Use the primary bundle's service for all API requests so budget
        # and idempotency state are shared at the app boundary — scenario
        # selection is server-side configuration, not caller-selectable.
        service_for=lambda _scenario: primary.service,
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
    }
    if any(value is None or not value for value in required.values()):
        return _unavailable_runtime()

    from aegis_framework.adapters import SystemClock
    from aegis_framework.authorization import EnterprisePolicy
    from aegis_framework.identity import (
        HttpJwksFetcher,
        IssuerConfiguration,
        JwtAuthenticator,
    )
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
        repository = PostgresRepository(pool=pool, clock=clock)
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
            "production evidence and model adapters are not configured in Layer 2"
        )

    return ApiRuntime(
        authenticator=authenticator,
        governance=repository,
        policy=EnterprisePolicy(policies=repository, clock=clock),
        service_for=unavailable_investigation,
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


app = create_app(mode=AppMode(os.getenv("AEGIS_MODE", AppMode.PRODUCTION.value)))
