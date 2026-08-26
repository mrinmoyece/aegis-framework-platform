"""Same-origin operator BFF with a fail-closed production session boundary."""

from __future__ import annotations

import hmac
import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from threading import Lock
from typing import Annotated, Literal
from urllib.parse import urlencode

from fastapi import APIRouter, Cookie, FastAPI, Header, HTTPException, Request, Response
from pydantic import AwareDatetime, Field
from starlette.responses import FileResponse, JSONResponse
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from aegis_framework.domain import Identifier, StrictModel

_SESSION_COOKIE = "__Host-aegis-session"
_SESSION_LIFETIME = timedelta(minutes=30)
_HANDSHAKE_LIFETIME = timedelta(minutes=5)
_MAX_SESSIONS = 128
_MAX_HANDSHAKES = 32  # cap pending login-start requests from unauthenticated callers
_DIGEST = "a" * 64
# Fixed expiry for the demo approval: set once when the module first loads so
# the same-origin BFF does not reset the countdown on every 10-second poll.
_DEMO_APPROVAL_EXPIRES_AT: datetime = datetime.now(UTC) + timedelta(minutes=12)


class OperatorUser(StrictModel):
    actor_ref: Identifier
    display_name: str = Field(min_length=1, max_length=120)
    principal_kind: Literal["human"]
    roles: tuple[Identifier, ...] = Field(max_length=16)
    permissions: tuple[Identifier, ...] = Field(max_length=64)
    grant_version: int = Field(ge=1)


class OperatorSessionView(StrictModel):
    authenticated: Literal[True] = True
    tenant_id: Identifier
    available_tenants: tuple[Identifier, ...] = Field(max_length=16)
    user: OperatorUser
    expires_at: AwareDatetime
    server_time: AwareDatetime
    csrf_token: str = Field(min_length=32, max_length=128)
    session_generation: Identifier
    session_mode: Literal["deterministic-demo", "oidc"]


class AuthorizationStart(StrictModel):
    authorization_url: str = Field(pattern=r"^/operator/session/callback\?")
    state: str = Field(min_length=32, max_length=128)
    nonce: str = Field(min_length=32, max_length=128)
    code_challenge: str = Field(min_length=43, max_length=128)
    code_challenge_method: Literal["S256"] = "S256"
    # Demo-only: the server-generated verifier is returned so the client can
    # complete the PKCE exchange without a separate out-of-band flow.
    code_verifier: str = Field(min_length=43, max_length=128)
    expires_at: AwareDatetime


class AuthorizationCallback(StrictModel):
    code: str = Field(min_length=1, max_length=256)
    state: str = Field(min_length=32, max_length=128)
    # PKCE code_verifier (RFC 7636 §4.1): 43-128 unreserved chars from the client.
    code_verifier: str = Field(min_length=43, max_length=128)


class TenantSwitchRequest(StrictModel):
    tenant_id: Identifier


class HealthItem(StrictModel):
    component: Identifier
    status: Literal["healthy", "degraded", "unavailable"]
    objective_percent: float = Field(gt=0, le=100)
    budget_status: Literal["within", "at-risk", "exhausted"]
    runbook: str = Field(pattern=r"^docs/runbooks/[a-z0-9-]+\.md$")


class IncidentItem(StrictModel):
    incident_id: Identifier
    title: str = Field(min_length=1, max_length=200)
    severity: Literal["sev1", "sev2", "sev3"]
    status: Literal["investigating", "mitigating", "resolved"]
    updated_at: AwareDatetime
    stale_after: AwareDatetime


class TimelineItem(StrictModel):
    event_id: Identifier
    occurred_at: AwareDatetime
    event_type: Identifier
    summary: str = Field(min_length=1, max_length=300)
    evidence_ids: tuple[Identifier, ...] = Field(max_length=16)


class EvidenceItem(StrictModel):
    evidence_id: Identifier
    source_kind: Identifier
    locator_label: str = Field(min_length=1, max_length=120)
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    disposition: Literal["accepted", "redacted", "quarantined"]
    summary: str = Field(min_length=1, max_length=300)


class GraphNodeItem(StrictModel):
    role: Identifier
    status: Literal["complete", "abstained", "rejected"]
    artifact_kind: Identifier
    citations: int = Field(ge=0, le=100)


class HypothesisItem(StrictModel):
    hypothesis_id: Identifier
    statement: str = Field(min_length=1, max_length=300)
    confidence: float = Field(ge=0, le=1)
    critic: Literal["accepted", "abstained", "rejected"]
    evidence_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=16)


class ModelUsageItem(StrictModel):
    provider: Identifier
    model: Identifier
    calls: int = Field(ge=0, le=10_000)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    cost_microunits: int = Field(ge=0)
    ambiguous_cost_microunits: int = Field(ge=0)


class ApprovalItem(StrictModel):
    approval_id: Identifier
    status: Literal["pending", "approved", "denied", "expired", "revoked"]
    risk: Literal["low", "medium", "high"]
    grants: int = Field(ge=0, le=16)
    quorum: int = Field(ge=1, le=16)
    plan_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    approval_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    expires_at: AwareDatetime
    created_by_actor_ref: Identifier
    can_decide: bool
    denial_reason: str | None = Field(default=None, max_length=200)


class EffectItem(StrictModel):
    effect_id: Identifier
    status: Literal[
        "not-started",
        "executing",
        "ambiguous",
        "reconciled",
        "verified",
        "rollback-required",
    ]
    target: str = Field(min_length=1, max_length=200)
    receipt_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    verification: Literal["not-run", "failed", "passed", "ambiguous"]
    rollback: Literal["not-required", "available", "running", "failed"]


class SandboxItem(StrictModel):
    execution_id: Identifier
    status: Literal["complete", "failed", "quarantined"]
    artifact_count: int = Field(ge=0, le=100)
    quarantined_count: int = Field(ge=0, le=100)
    cleanup_complete: bool


class MemoryItem(StrictModel):
    memory_id: Identifier
    tier: Literal["working", "episodic", "semantic"]
    provenance: str = Field(min_length=1, max_length=200)
    status: Literal["indexed", "held", "tombstoned"]
    retention_expires_at: AwareDatetime
    legal_hold: bool


class EvaluationItem(StrictModel):
    suite_id: Identifier
    passed: bool
    regressions: int = Field(ge=0, le=10_000)
    cases: int = Field(ge=0, le=100_000)
    baseline_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class AuditItem(StrictModel):
    event_id: Identifier
    event_type: Identifier
    actor_ref: Identifier
    recorded_at: AwareDatetime
    record_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class ReplayItem(StrictModel):
    report_id: Identifier
    integrity: Literal["verified", "failed"]
    projection_matches: bool
    truncated: bool
    report_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class ProtocolPeerItem(StrictModel):
    peer_id: Identifier
    protocol: Literal["mcp", "a2a"]
    owner_ref: Identifier
    environment: Literal["development", "test", "staging", "production"]
    trust_tier: Literal["internal", "partner", "restricted"]
    status: Literal[
        "pending-review",
        "active",
        "quarantined",
        "revoked",
        "expired",
        "emergency-disabled",
    ]
    revision: int = Field(ge=1)
    card_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    schema_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    certificate_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    key_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    capabilities: tuple[Identifier, ...] = Field(max_length=32)
    transports: tuple[Identifier, ...] = Field(max_length=4)
    classifications: tuple[
        Literal["public", "internal", "confidential", "restricted"], ...
    ] = Field(max_length=4)
    risks: tuple[Literal["low", "medium", "high"], ...] = Field(max_length=3)
    review_after: AwareDatetime
    expires_at: AwareDatetime
    production_ready: bool
    can_administer: bool


class OperatorSnapshot(StrictModel):
    schema_version: Literal[1] = 1
    tenant_id: Identifier
    session_generation: Identifier
    generated_at: AwareDatetime
    stale_after: AwareDatetime
    synthetic: bool
    health: tuple[HealthItem, ...] = Field(max_length=32)
    incidents: tuple[IncidentItem, ...] = Field(max_length=100)
    timeline: tuple[TimelineItem, ...] = Field(max_length=200)
    evidence: tuple[EvidenceItem, ...] = Field(max_length=200)
    graph: tuple[GraphNodeItem, ...] = Field(max_length=32)
    hypotheses: tuple[HypothesisItem, ...] = Field(max_length=32)
    model_usage: tuple[ModelUsageItem, ...] = Field(max_length=32)
    approvals: tuple[ApprovalItem, ...] = Field(max_length=100)
    effects: tuple[EffectItem, ...] = Field(max_length=100)
    sandboxes: tuple[SandboxItem, ...] = Field(max_length=100)
    memories: tuple[MemoryItem, ...] = Field(max_length=100)
    evaluations: tuple[EvaluationItem, ...] = Field(max_length=100)
    audit: tuple[AuditItem, ...] = Field(max_length=200)
    replay: tuple[ReplayItem, ...] = Field(max_length=100)
    protocol_peers: tuple[ProtocolPeerItem, ...] = Field(max_length=100)


class ApprovalDecisionRequest(StrictModel):
    command_id: Identifier
    disposition: Literal["grant", "deny"]
    rationale: str = Field(min_length=12, max_length=2_000)
    expected_status: Literal["pending"]
    plan_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    approval_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    typed_confirmation: str = Field(min_length=1, max_length=128)


class MutationReceipt(StrictModel):
    command_id: Identifier
    outcome: Literal["denied", "accepted", "conflict", "ambiguous"]
    message: str = Field(min_length=1, max_length=300)
    server_time: AwareDatetime


class ProtocolTrustMutationRequest(StrictModel):
    command_id: Identifier
    action: Literal["review", "quarantine", "revoke", "emergency-disable"]
    expected_revision: int = Field(ge=1)
    expected_card_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    expected_schema_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    expected_certificate_digest: str | None = Field(
        default=None, pattern=r"^[a-f0-9]{64}$"
    )
    expected_key_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    rationale: str = Field(min_length=12, max_length=2_000)
    typed_confirmation: str = Field(min_length=1, max_length=160)


@dataclass(frozen=True)
class _Handshake:
    verifier_digest: str
    code_challenge: str  # S256 challenge to validate the PKCE code_verifier on exchange
    nonce: str
    origin_digest: str
    expires_at: datetime


@dataclass(frozen=True)
class _Session:
    token_digest: str
    csrf_digest: str
    csrf_token: str
    generation: str
    origin_digest: str
    tenant_id: str
    expires_at: datetime


class InMemoryOperatorSessions:
    """Bounded deterministic session adapter; never production-ready."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._handshakes: dict[str, _Handshake] = {}
        self._sessions: dict[str, _Session] = {}

    def begin(self, *, now: datetime, origin: str) -> AuthorizationStart:
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        challenge = _b64_digest(verifier)
        with self._lock:
            self._prune(now)
            if len(self._handshakes) >= _MAX_HANDSHAKES:
                raise ValueError("handshake capacity exceeded; try again shortly")
            self._handshakes[_digest(state)] = _Handshake(
                verifier_digest=_digest(verifier),
                code_challenge=challenge,
                nonce=nonce,
                origin_digest=_digest(origin),
                expires_at=now + _HANDSHAKE_LIFETIME,
            )
        callback = "/operator/session/callback?" + urlencode(
            {"code": "deterministic-demo-code", "state": state}
        )
        return AuthorizationStart(
            authorization_url=callback,
            state=state,
            nonce=nonce,
            code_challenge=challenge,
            code_verifier=verifier,
            expires_at=now + _HANDSHAKE_LIFETIME,
        )

    def exchange(
        self, *, state: str, code: str, code_verifier: str, origin: str, now: datetime
    ) -> tuple[str, _Session]:
        with self._lock:
            self._prune(now)
            handshake = self._handshakes.pop(_digest(state), None)
            if (
                handshake is None
                or handshake.expires_at <= now
                or not hmac.compare_digest(_digest(origin), handshake.origin_digest)
                or not hmac.compare_digest(code, "deterministic-demo-code")
                # PKCE S256: SHA-256(code_verifier) base64url-encoded == challenge.
                or not hmac.compare_digest(
                    _b64_digest(code_verifier), handshake.code_challenge
                )
            ):
                raise ValueError("authorization response is invalid")
            token = secrets.token_urlsafe(48)
            csrf = secrets.token_urlsafe(32)
            record = _Session(
                token_digest=_digest(token),
                csrf_digest=_digest(csrf),
                csrf_token=csrf,
                generation=f"session-{secrets.token_hex(16)}",
                origin_digest=handshake.origin_digest,
                tenant_id="tenant-acme",
                expires_at=now + _SESSION_LIFETIME,
            )
            self._sessions[record.token_digest] = record
            self._limit()
            return token, record

    def get(self, token: str | None, *, now: datetime) -> _Session | None:
        if token is None:
            return None
        with self._lock:
            self._prune(now)
            return self._sessions.get(_digest(token))

    def rotate_tenant(
        self, token: str, *, tenant_id: str, now: datetime
    ) -> tuple[str, _Session]:
        if tenant_id not in {"tenant-acme", "tenant-beta"}:
            raise LookupError("tenant is unavailable")
        with self._lock:
            self._prune(now)
            existing = self._sessions.pop(_digest(token), None)
            if existing is None:
                raise ValueError("session is unavailable")
            rotated_token = secrets.token_urlsafe(48)
            csrf = secrets.token_urlsafe(32)
            record = _Session(
                token_digest=_digest(rotated_token),
                csrf_digest=_digest(csrf),
                csrf_token=csrf,
                generation=f"session-{secrets.token_hex(16)}",
                origin_digest=existing.origin_digest,
                tenant_id=tenant_id,
                expires_at=now + _SESSION_LIFETIME,
            )
            self._sessions[record.token_digest] = record
            return rotated_token, record

    def delete(self, token: str | None) -> None:
        if token is None:
            return
        with self._lock:
            self._sessions.pop(_digest(token), None)

    def _prune(self, now: datetime) -> None:
        self._handshakes = {
            key: value
            for key, value in self._handshakes.items()
            if value.expires_at > now
        }
        self._sessions = {
            key: value
            for key, value in self._sessions.items()
            if value.expires_at > now
        }

    def _limit(self) -> None:
        while len(self._sessions) > _MAX_SESSIONS:
            oldest = min(self._sessions, key=lambda key: self._sessions[key].expires_at)
            del self._sessions[oldest]


class OperatorSecurityHeadersMiddleware:
    """Set browser isolation headers without logging request or response data."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        # Exclude FastAPI's built-in API docs paths — they use CDN assets and inline
        # bootstrap scripts that are incompatible with the strict 'self'/nonce CSP.
        path = str(scope.get("path", ""))
        if path in {"/docs", "/redoc", "/openapi.json"}:
            await self._app(scope, receive, send)
            return
        nonce = secrets.token_urlsafe(18)

        async def secured_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", ()))
                policy = (
                    "default-src 'self'; "
                    f"script-src 'self' 'nonce-{nonce}'; "
                    "style-src 'self'; img-src 'self' data:; font-src 'self'; "
                    "connect-src 'self'; object-src 'none'; base-uri 'none'; "
                    "form-action 'self'; frame-ancestors 'none'; "
                    "upgrade-insecure-requests"
                )
                cache_control = (
                    b"public, max-age=31536000, immutable"
                    if str(scope.get("path", "")).startswith("/assets/")
                    else b"no-store, max-age=0"
                )
                additions: Mapping[bytes, bytes] = {
                    b"content-security-policy": policy.encode(),
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": b"DENY",
                    b"referrer-policy": b"no-referrer",
                    b"permissions-policy": (
                        b"camera=(), microphone=(), geolocation=(), payment=(), usb=()"
                    ),
                    b"strict-transport-security": (
                        b"max-age=63072000; includeSubDomains; preload"
                    ),
                    b"cache-control": cache_control,
                    b"pragma": b"no-cache",
                    b"x-csp-nonce": nonce.encode(),
                }
                existing = {key.lower() for key, _ in headers}
                headers.extend(
                    (key, value)
                    for key, value in additions.items()
                    if key not in existing
                )
                message["headers"] = headers
            await send(message)

        await self._app(scope, receive, secured_send)


def install_operator_routes(app: FastAPI, *, production: bool) -> None:
    """Install the BFF; production stays unavailable without live adapters."""

    sessions = InMemoryOperatorSessions()
    peer_states: dict[str, tuple[str, int]] = {
        "partner-investigator": ("active", 3),
        "quarantined-mcp": ("quarantined", 7),
    }
    peer_lock = Lock()
    router = APIRouter(
        prefix="/operator",
        tags=["operator-bff"],
        default_response_class=JSONResponse,
    )

    def available() -> None:
        if production:
            raise HTTPException(
                status_code=503,
                detail=(
                    "operator OIDC exchange and durable session store "
                    "are not configured"
                ),
            )

    def current_session(
        token: str | None = Cookie(default=None, alias=_SESSION_COOKIE),
    ) -> _Session:
        available()
        record = sessions.get(token, now=_now())
        if record is None:
            raise HTTPException(
                status_code=401, detail="operator session is unavailable"
            )
        return record

    def require_mutation(
        request: Request,
        record: _Session,
        csrf_token: str | None,
    ) -> None:
        origin = request.headers.get("origin")
        if origin is None or not hmac.compare_digest(
            _digest(origin), record.origin_digest
        ):
            raise HTTPException(
                status_code=403, detail="request origin is not permitted"
            )
        if csrf_token is None or not hmac.compare_digest(
            _digest(csrf_token), record.csrf_digest
        ):
            raise HTTPException(status_code=403, detail="CSRF validation failed")

    def request_origin(request: Request) -> str:
        origin = request.headers.get("origin")
        if origin is not None:
            return origin
        return f"{request.url.scheme}://{request.url.netloc}"

    @router.get("/readyz")
    def operator_ready() -> dict[str, object]:
        if production:
            raise HTTPException(
                status_code=503,
                detail={
                    "status": "not_ready",
                    "oidc_exchange": False,
                    "durable_session_store": False,
                },
            )
        return {
            "status": "demo_ready",
            "oidc_exchange": False,
            "durable_session_store": False,
        }

    @router.post("/session/authorization", response_model=AuthorizationStart)
    def begin_authorization(request: Request) -> AuthorizationStart:
        available()
        return sessions.begin(now=_now(), origin=request_origin(request))

    @router.post("/session/callback", response_model=OperatorSessionView)
    def authorization_callback(
        payload: AuthorizationCallback, request: Request, response: Response
    ) -> OperatorSessionView:
        available()
        now = _now()
        try:
            token, record = sessions.exchange(
                state=payload.state,
                code=payload.code,
                code_verifier=payload.code_verifier,
                origin=request_origin(request),
                now=now,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=401, detail="authorization response is invalid"
            ) from exc
        _set_session_cookie(
            response,
            token,
            max_age=int(_SESSION_LIFETIME.total_seconds()),
        )
        return _session_view(record, now=now)

    @router.get("/session", response_model=OperatorSessionView)
    def session_status(
        token: str | None = Cookie(default=None, alias=_SESSION_COOKIE),
    ) -> OperatorSessionView:
        record = current_session(token)
        return _session_view(record, now=_now())

    @router.post("/session/tenant", response_model=OperatorSessionView)
    def switch_tenant(
        payload: TenantSwitchRequest,
        request: Request,
        response: Response,
        x_csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
        token: str | None = Cookie(default=None, alias=_SESSION_COOKIE),
    ) -> OperatorSessionView:
        record = current_session(token)
        require_mutation(request, record, x_csrf_token)
        if token is None:
            raise HTTPException(
                status_code=401, detail="operator session is unavailable"
            )
        try:
            rotated_token, rotated = sessions.rotate_tenant(
                token, tenant_id=payload.tenant_id, now=_now()
            )
        except LookupError as exc:
            raise HTTPException(
                status_code=404, detail="tenant is unavailable"
            ) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=409, detail="operator session changed during tenant switch"
            ) from exc
        _set_session_cookie(
            response,
            rotated_token,
            max_age=int(_SESSION_LIFETIME.total_seconds()),
        )
        return _session_view(rotated, now=_now())

    @router.post("/session/logout", status_code=204)
    def logout(
        request: Request,
        response: Response,
        x_csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
        token: str | None = Cookie(default=None, alias=_SESSION_COOKIE),
    ) -> Response:
        record = current_session(token)
        require_mutation(request, record, x_csrf_token)
        sessions.delete(token)
        response.delete_cookie(
            _SESSION_COOKIE,
            path="/",
            secure=True,
            httponly=True,
            samesite="strict",
        )
        response.status_code = 204
        return response

    @router.get("/api/snapshot", response_model=OperatorSnapshot)
    def snapshot(
        token: str | None = Cookie(default=None, alias=_SESSION_COOKIE),
    ) -> OperatorSnapshot:
        record = current_session(token)
        return _snapshot(
            record.tenant_id,
            session_generation=record.generation,
            now=_now(),
            peer_states=peer_states,
        )

    @router.post(
        "/api/approvals/{approval_id}/decisions",
        response_model=MutationReceipt,
    )
    def decide_approval(
        approval_id: Annotated[str, Field(min_length=1, max_length=128)],
        payload: ApprovalDecisionRequest,
        request: Request,
        x_csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
        x_idempotency_key: Annotated[
            str | None, Header(alias="Idempotency-Key")
        ] = None,
        token: str | None = Cookie(default=None, alias=_SESSION_COOKIE),
    ) -> MutationReceipt:
        record = current_session(token)
        require_mutation(request, record, x_csrf_token)
        # If the client provides an Idempotency-Key header it MUST match the
        # command_id in the request body so both retry mechanisms are consistent.
        if x_idempotency_key is not None and not hmac.compare_digest(
            x_idempotency_key, payload.command_id
        ):
            raise HTTPException(
                status_code=422,
                detail="Idempotency-Key header does not match command_id",
            )
        if approval_id != "approval-checkout-001":
            raise HTTPException(status_code=404, detail="approval is unavailable")
        if record.tenant_id != "tenant-acme":
            raise HTTPException(status_code=404, detail="approval is unavailable")
        if payload.plan_digest != _DIGEST or payload.approval_digest != _DIGEST:
            raise HTTPException(status_code=409, detail="approval scope is stale")
        if payload.typed_confirmation != "APPROVE CHECKOUT-API":
            raise HTTPException(status_code=422, detail="typed confirmation is invalid")
        return MutationReceipt(
            command_id=payload.command_id,
            outcome="denied",
            message=(
                "The deterministic responder has no approval:decide grant; "
                "server authority denied the mutation."
            ),
            server_time=_now(),
        )

    @router.post(
        "/api/protocol-peers/{peer_id}/trust",
        response_model=MutationReceipt,
    )
    def mutate_protocol_trust(
        peer_id: Annotated[str, Field(min_length=1, max_length=128)],
        payload: ProtocolTrustMutationRequest,
        request: Request,
        x_csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
        token: str | None = Cookie(default=None, alias=_SESSION_COOKIE),
    ) -> MutationReceipt:
        record = current_session(token)
        require_mutation(request, record, x_csrf_token)
        if record.tenant_id != "tenant-acme":
            raise HTTPException(status_code=404, detail="protocol peer is unavailable")
        peers = {
            item.peer_id: item
            for item in _demo_protocol_peers(now=_now(), peer_states=peer_states)
        }
        peer = peers.get(peer_id)
        if peer is None:
            raise HTTPException(status_code=404, detail="protocol peer is unavailable")
        if (
            payload.expected_revision != peer.revision
            or payload.expected_card_digest != peer.card_digest
            or payload.expected_schema_digest != peer.schema_digest
            or payload.expected_certificate_digest != peer.certificate_digest
            or payload.expected_key_digest != peer.key_digest
        ):
            raise HTTPException(status_code=409, detail="protocol trust is stale")
        confirmations = {
            "review": f"TRUST {peer_id}",
            "quarantine": f"QUARANTINE {peer_id}",
            "revoke": f"REVOKE {peer_id}",
            "emergency-disable": f"DISABLE {peer_id}",
        }
        if payload.typed_confirmation != confirmations[payload.action]:
            raise HTTPException(status_code=422, detail="typed confirmation is invalid")
        target = {
            "review": "active",
            "quarantine": "quarantined",
            "revoke": "revoked",
            "emergency-disable": "emergency-disabled",
        }[payload.action]
        if peer.status in {"revoked", "emergency-disabled"}:
            raise HTTPException(status_code=409, detail="protocol trust is terminal")
        if payload.action == "review" and peer.status != "pending-review":
            raise HTTPException(
                status_code=409,
                detail="only pending protocol trust can be activated",
            )
        with peer_lock:
            current = peer_states.get(peer_id)
            if current != (peer.status, peer.revision):
                raise HTTPException(status_code=409, detail="protocol trust changed")
            peer_states[peer_id] = (target, peer.revision + 1)
        return MutationReceipt(
            command_id=payload.command_id,
            outcome="accepted",
            message=(
                f"Protocol peer trust changed to {target}; in-flight work must "
                "reauthorize and reconcile under the new registry revision."
            ),
            server_time=_now(),
        )

    app.include_router(router)


def install_operator_ui(app: FastAPI, *, directory: Path | None = None) -> None:
    """Serve the reviewed build when present; APIs remain separately routed."""

    root = directory or Path(
        os.getenv("AEGIS_OPERATOR_UI_DIR", Path.cwd() / "ui" / "dist")
    )
    index = root / "index.html"
    assets = root / "assets"
    if not index.is_file() or not assets.is_dir():
        return
    app.mount("/assets", StaticFiles(directory=assets), name="operator-assets")
    workspace_routes = {
        "",
        "approvals",
        "audit",
        "effects",
        "evaluations",
        "investigation",
        "memory",
        "models",
        "replay",
        "sandboxes",
        "protocol-peers",
    }

    @app.get("/{workspace_path:path}", include_in_schema=False)
    def operator_workspace(workspace_path: str) -> FileResponse:
        if workspace_path not in workspace_routes:
            raise HTTPException(status_code=404, detail="resource is unavailable")
        return FileResponse(index, media_type="text/html")


def _set_session_cookie(response: Response, token: str, *, max_age: int) -> None:
    response.set_cookie(
        _SESSION_COOKIE,
        token,
        max_age=max_age,
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )


def _session_view(record: _Session, *, now: datetime) -> OperatorSessionView:
    return OperatorSessionView(
        tenant_id=record.tenant_id,
        available_tenants=("tenant-acme", "tenant-beta"),
        user=OperatorUser(
            actor_ref="actor-demo-responder",
            display_name="Demo incident responder",
            principal_kind="human",
            roles=("incident-responder",),
            permissions=(
                "audit:read",
                "investigation:read",
                "interoperability:read",
                "interoperability:trust:admin",
                "model:usage:read",
                "operations:read",
                "orchestration:artifact:read",
                "remediation:read",
                "replay:read",
                "sandbox:read",
            ),
            grant_version=7,
        ),
        expires_at=record.expires_at,
        server_time=now,
        csrf_token=record.csrf_token,
        session_generation=record.generation,
        session_mode="deterministic-demo",
    )


def _snapshot(
    tenant_id: str,
    *,
    session_generation: str,
    now: datetime,
    peer_states: Mapping[str, tuple[str, int]] | None = None,
) -> OperatorSnapshot:
    stale_after = now + timedelta(seconds=30)
    if tenant_id != "tenant-acme":
        return OperatorSnapshot(
            tenant_id=tenant_id,
            session_generation=session_generation,
            generated_at=now,
            stale_after=stale_after,
            synthetic=True,
            health=(),
            incidents=(),
            timeline=(),
            evidence=(),
            graph=(),
            hypotheses=(),
            model_usage=(),
            approvals=(),
            effects=(),
            sandboxes=(),
            memories=(),
            evaluations=(),
            audit=(),
            replay=(),
            protocol_peers=(),
        )
    return OperatorSnapshot(
        tenant_id=tenant_id,
        session_generation=session_generation,
        generated_at=now,
        stale_after=stale_after,
        synthetic=True,
        health=(
            HealthItem(
                component="api",
                status="healthy",
                objective_percent=99.9,
                budget_status="within",
                runbook="docs/runbooks/api-availability.md",
            ),
            HealthItem(
                component="effects",
                status="degraded",
                objective_percent=100,
                budget_status="at-risk",
                runbook="docs/runbooks/safety-violation.md",
            ),
        ),
        incidents=(
            IncidentItem(
                incident_id="checkout-2026-08-17",
                title="Checkout failure rate above regional SLO",
                severity="sev1",
                status="investigating",
                updated_at=now - timedelta(minutes=2),
                stale_after=stale_after,
            ),
        ),
        timeline=(
            TimelineItem(
                event_id="evt-alert",
                occurred_at=now - timedelta(minutes=14),
                event_type="alert.received",
                summary="Failure rate reached 18% in eu-west.",
                evidence_ids=("evidence-telemetry-001",),
            ),
            TimelineItem(
                event_id="evt-change",
                occurred_at=now - timedelta(minutes=11),
                event_type="change.correlated",
                summary="Deployment checkout-api-2026.08.17.4 preceded the alert.",
                evidence_ids=("evidence-change-001",),
            ),
        ),
        evidence=(
            EvidenceItem(
                evidence_id="evidence-telemetry-001",
                source_kind="telemetry",
                locator_label="redacted telemetry query",
                content_hash=_DIGEST,
                disposition="accepted",
                summary="Bounded failure-rate facts; raw evidence is not returned.",
            ),
            EvidenceItem(
                evidence_id="evidence-change-001",
                source_kind="change",
                locator_label="redacted deployment record",
                content_hash="b" * 64,
                disposition="accepted",
                summary=(
                    "<script>alert('untrusted')</script> is rendered as evidence text."
                ),
            ),
        ),
        graph=tuple(
            GraphNodeItem(
                role=role,
                status="complete",
                artifact_kind=f"{role}-finding",
                citations=2,
            )
            for role in ("telemetry", "change", "runtime", "knowledge", "critic")
        ),
        hypotheses=(
            HypothesisItem(
                hypothesis_id="hypothesis-rollout",
                statement=(
                    "The checkout deployment is temporally correlated with failures."
                ),
                confidence=0.86,
                critic="accepted",
                evidence_ids=("evidence-telemetry-001", "evidence-change-001"),
            ),
        ),
        model_usage=(
            ModelUsageItem(
                provider="fake",
                model="deterministic-specialist",
                calls=5,
                input_tokens=4_100,
                output_tokens=920,
                cost_microunits=0,
                ambiguous_cost_microunits=0,
            ),
        ),
        approvals=(
            ApprovalItem(
                approval_id="approval-checkout-001",
                status="pending",
                risk="high",
                grants=0,
                quorum=2,
                plan_digest=_DIGEST,
                approval_digest=_DIGEST,
                expires_at=_DEMO_APPROVAL_EXPIRES_AT,
                created_by_actor_ref="actor-remediation-planner",
                can_decide=False,
                denial_reason="Current grants do not include approval:decide.",
            ),
        ),
        effects=(
            EffectItem(
                effect_id="effect-rollout-restart",
                status="not-started",
                target="checkout-api / eu-west / exact deployment UID",
                verification="not-run",
                rollback="available",
            ),
            EffectItem(
                effect_id="effect-prior-ambiguous",
                status="ambiguous",
                target="synthetic prior operation requiring observation",
                verification="ambiguous",
                rollback="not-required",
            ),
        ),
        sandboxes=(
            SandboxItem(
                execution_id="sandbox-checkout-001",
                status="quarantined",
                artifact_count=2,
                quarantined_count=1,
                cleanup_complete=True,
            ),
        ),
        memories=(
            MemoryItem(
                memory_id="memory-checkout-runbook",
                tier="semantic",
                provenance="accepted cited runbook evidence",
                status="held",
                retention_expires_at=now + timedelta(days=30),
                legal_hold=True,
            ),
        ),
        evaluations=(
            EvaluationItem(
                suite_id="aegis-enterprise-v1",
                passed=True,
                regressions=0,
                cases=50,
                baseline_digest="c" * 64,
            ),
        ),
        audit=(
            AuditItem(
                event_id="audit-operator-read",
                event_type="operator.snapshot.read",
                actor_ref="actor-demo-responder",
                recorded_at=now,
                record_hash="d" * 64,
            ),
        ),
        replay=(
            ReplayItem(
                report_id="replay-checkout-001",
                integrity="verified",
                projection_matches=True,
                truncated=False,
                report_digest="e" * 64,
            ),
        ),
        protocol_peers=_demo_protocol_peers(
            now=now,
            peer_states=peer_states or {},
        ),
    )


def _demo_protocol_peers(
    *,
    now: datetime,
    peer_states: Mapping[str, tuple[str, int]],
) -> tuple[ProtocolPeerItem, ...]:
    partner_status, partner_revision = peer_states.get(
        "partner-investigator", ("active", 3)
    )
    mcp_status, mcp_revision = peer_states.get("quarantined-mcp", ("quarantined", 7))
    return (
        ProtocolPeerItem(
            peer_id="partner-investigator",
            protocol="a2a",
            owner_ref="team-incident-response",
            environment="staging",
            trust_tier="partner",
            status=partner_status,
            revision=partner_revision,
            card_digest="f" * 64,
            schema_digest="1" * 64,
            certificate_digest="2" * 64,
            key_digest="3" * 64,
            capabilities=(
                "investigate-incident",
                "read-investigation-artifact",
                "read-investigation-status",
                "submit-remediation-proposal",
            ),
            transports=("json-rpc-http", "grpc"),
            classifications=("internal",),
            risks=("low", "medium", "high"),
            review_after=now + timedelta(days=7),
            expires_at=now + timedelta(days=30),
            production_ready=False,
            can_administer=True,
        ),
        ProtocolPeerItem(
            peer_id="quarantined-mcp",
            protocol="mcp",
            owner_ref="team-platform",
            environment="test",
            trust_tier="restricted",
            status=mcp_status,
            revision=mcp_revision,
            schema_digest="4" * 64,
            certificate_digest="5" * 64,
            key_digest="6" * 64,
            capabilities=("mcp-aegis-status-read",),
            transports=("streamable-http",),
            classifications=("public", "internal"),
            risks=("low",),
            review_after=now + timedelta(days=1),
            expires_at=now + timedelta(days=14),
            production_ready=False,
            can_administer=True,
        ),
    )


def _now() -> datetime:
    return datetime.now(UTC)


def _digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _b64_digest(value: str) -> str:
    import base64

    encoded = base64.urlsafe_b64encode(sha256(value.encode()).digest())
    return encoded.rstrip(b"=").decode()
