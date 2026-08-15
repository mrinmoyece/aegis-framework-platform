"""OIDC access-token verification with bounded JWKS rotation and current grants."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Annotated, Literal
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

import jwt
from jwt import InvalidTokenError, PyJWK
from jwt.exceptions import InvalidKeyError
from pydantic import Field, field_validator

from aegis_framework.access import (
    AuthenticatorPort,
    GrantStatus,
    IdentityRepositoryPort,
    JwksFetcherPort,
    PrincipalStatus,
    TenantStatus,
)
from aegis_framework.authorization import RoleCatalog
from aegis_framework.domain import (
    GrantBinding,
    IdentityContext,
    Issuer,
    StrictModel,
)
from aegis_framework.errors import AuthenticationFailed, IdentityUnavailable
from aegis_framework.ports import ClockPort

_ALLOWED_TOKEN_TYPES = frozenset({"JWT", "at+jwt"})
_MAX_BEARER_LENGTH = 16_384


class IssuerConfiguration(StrictModel):
    issuer: Issuer
    audiences: tuple[Annotated[str, Field(min_length=1, max_length=200)], ...]
    jwks_uri: Annotated[str, Field(min_length=8, max_length=512)]
    algorithms: tuple[Literal["RS256", "PS256", "ES256"], ...] = ("RS256",)
    tenant_claim: str = Field(default="aegis_tenant", min_length=1, max_length=64)
    grant_version_claim: str = Field(
        default="aegis_grant_version", min_length=1, max_length=64
    )
    clock_skew_seconds: int = Field(default=30, ge=0, le=120)
    maximum_token_lifetime_seconds: int = Field(default=3_600, ge=60, le=86_400)
    jwks_ttl_seconds: int = Field(default=300, ge=30, le=3_600)
    jwks_refresh_cooldown_seconds: int = Field(default=5, ge=1, le=60)
    maximum_jwks_keys: int = Field(default=16, ge=1, le=32)

    @field_validator("audiences", "algorithms")
    @classmethod
    def require_unique_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(set(value)))
        if not normalized:
            raise ValueError("at least one value is required")
        return normalized


class HttpJwksFetcher:
    """Small HTTPS-only adapter; issuer and URI are configured, never token-derived."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 2.0,
        maximum_response_bytes: int = 131_072,
        allow_loopback_http: bool = False,
    ) -> None:
        if timeout_seconds <= 0 or maximum_response_bytes < 1_024:
            raise ValueError("JWKS HTTP bounds are invalid")
        self._timeout_seconds = timeout_seconds
        self._maximum_response_bytes = maximum_response_bytes
        self._allow_loopback_http = allow_loopback_http
        self._opener = build_opener(_RejectRedirectHandler())

    def fetch(self, *, issuer: str, jwks_uri: str) -> Mapping[str, object]:
        del issuer
        parsed = urlsplit(jwks_uri)
        loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
        if parsed.scheme != "https" and not (
            self._allow_loopback_http and parsed.scheme == "http" and loopback
        ):
            raise IdentityUnavailable("JWKS URI must use HTTPS")
        if parsed.username or parsed.password or not parsed.hostname or parsed.fragment:
            raise IdentityUnavailable("JWKS URI is not acceptable")

        request = Request(  # noqa: S310 - URI is validated and administrator-configured.
            jwks_uri,
            headers={"Accept": "application/json", "User-Agent": "aegis-framework/0.2"},
            method="GET",
        )
        try:
            with self._opener.open(
                request,
                timeout=self._timeout_seconds,
            ) as response:
                if response.geturl() != jwks_uri:
                    raise IdentityUnavailable("JWKS redirects are not permitted")
                payload = response.read(self._maximum_response_bytes + 1)
        except IdentityUnavailable:
            raise
        except (OSError, TimeoutError) as exc:
            raise IdentityUnavailable("JWKS endpoint is unavailable") from exc
        if len(payload) > self._maximum_response_bytes:
            raise IdentityUnavailable("JWKS response exceeds the configured bound")
        try:
            document = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IdentityUnavailable("JWKS response is not valid JSON") from exc
        if not isinstance(document, dict):
            raise IdentityUnavailable("JWKS response must be an object")
        return document


class _RejectRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: object,
        file_pointer: object,
        code: int,
        message: str,
        headers: object,
        new_url: str,
    ) -> None:
        del request, file_pointer, code, message, headers, new_url
        return None


@dataclass(frozen=True)
class _CacheState:
    keys: Mapping[str, Mapping[str, object]]
    expires_at: datetime
    refreshed_at: datetime


class BoundedJwksCache:
    """Bounded fail-closed cache that refreshes once for an unfamiliar key ID."""

    def __init__(
        self,
        *,
        configuration: IssuerConfiguration,
        fetcher: JwksFetcherPort,
        clock: ClockPort,
    ) -> None:
        self._configuration = configuration
        self._fetcher = fetcher
        self._clock = clock
        self._state: _CacheState | None = None
        self._lock = Lock()

    def verification_key(self, *, key_id: str, algorithm: str) -> PyJWK:
        if not key_id or len(key_id) > 128:
            raise AuthenticationFailed("token key ID is invalid")
        with self._lock:
            now = self._clock.now()
            state = self._state
            if state is None or state.expires_at <= now:
                state = self._refresh(now)
            candidate = state.keys.get(key_id)
            if candidate is None and (
                now - state.refreshed_at
                >= timedelta(seconds=self._configuration.jwks_refresh_cooldown_seconds)
            ):
                state = self._refresh(now)
                candidate = state.keys.get(key_id)
            if candidate is None:
                raise AuthenticationFailed("token signing key is unknown")
            return self._parse_key(candidate, algorithm)

    def _refresh(self, now: datetime) -> _CacheState:
        try:
            document = self._fetcher.fetch(
                issuer=self._configuration.issuer,
                jwks_uri=self._configuration.jwks_uri,
            )
        except IdentityUnavailable:
            raise
        except Exception as exc:
            raise IdentityUnavailable("JWKS fetcher failed") from exc
        raw_keys = document.get("keys")
        if not isinstance(raw_keys, list) or not raw_keys:
            raise IdentityUnavailable("JWKS must contain keys")
        if len(raw_keys) > self._configuration.maximum_jwks_keys:
            raise IdentityUnavailable("JWKS contains too many keys")

        parsed: dict[str, Mapping[str, object]] = {}
        for raw_key in raw_keys:
            if not isinstance(raw_key, dict):
                raise IdentityUnavailable("JWKS key must be an object")
            key_id = raw_key.get("kid")
            if not isinstance(key_id, str) or not key_id or len(key_id) > 128:
                raise IdentityUnavailable("JWKS key ID is invalid")
            if key_id in parsed:
                raise IdentityUnavailable("JWKS key IDs must be unique")
            parsed[key_id] = raw_key
        state = _CacheState(
            keys=parsed,
            refreshed_at=now,
            expires_at=now + timedelta(seconds=self._configuration.jwks_ttl_seconds),
        )
        self._state = state
        return state

    def _parse_key(self, candidate: Mapping[str, object], algorithm: str) -> PyJWK:
        declared_algorithm = candidate.get("alg")
        if declared_algorithm is not None and declared_algorithm != algorithm:
            raise AuthenticationFailed("token algorithm does not match its key")
        if candidate.get("use") not in {None, "sig"}:
            raise AuthenticationFailed("token key is not a signing key")
        key_operations = candidate.get("key_ops")
        if key_operations is not None and (
            not isinstance(key_operations, list) or "verify" not in key_operations
        ):
            raise AuthenticationFailed("token key cannot verify signatures")
        try:
            return PyJWK.from_dict(dict(candidate), algorithm=algorithm)
        except (InvalidKeyError, InvalidTokenError, ValueError, TypeError) as exc:
            raise AuthenticationFailed("token signing key is invalid") from exc


class JwtAuthenticator:
    """Validate JWTs, then resolve tenant and grants from application storage."""

    def __init__(
        self,
        *,
        configurations: tuple[IssuerConfiguration, ...],
        identities: IdentityRepositoryPort,
        fetcher: JwksFetcherPort,
        clock: ClockPort,
    ) -> None:
        if not configurations:
            raise ValueError("at least one trusted issuer is required")
        self._configurations = {
            configuration.issuer: configuration for configuration in configurations
        }
        if len(self._configurations) != len(configurations):
            raise ValueError("trusted issuer values must be unique")
        self._identities = identities
        self._clock = clock
        self._caches = {
            issuer: BoundedJwksCache(
                configuration=configuration,
                fetcher=fetcher,
                clock=clock,
            )
            for issuer, configuration in self._configurations.items()
        }

    def ready(self) -> bool:
        return True

    def authenticate(
        self,
        *,
        bearer_token: str,
        request_id: str,
        trace_id: str,
    ) -> IdentityContext:
        if (
            not bearer_token
            or len(bearer_token) > _MAX_BEARER_LENGTH
            or any(character.isspace() for character in bearer_token)
        ):
            raise AuthenticationFailed("bearer token is invalid")
        try:
            header = jwt.get_unverified_header(bearer_token)
            unverified = jwt.decode(
                bearer_token,
                options={
                    "verify_signature": False,
                    "verify_aud": False,
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_iss": False,
                    "verify_nbf": False,
                },
            )
        except InvalidTokenError as exc:
            raise AuthenticationFailed("bearer token is malformed") from exc
        issuer = unverified.get("iss")
        configuration = (
            self._configurations.get(issuer) if isinstance(issuer, str) else None
        )
        if configuration is None:
            raise AuthenticationFailed("token issuer is not trusted")

        algorithm = header.get("alg")
        key_id = header.get("kid")
        token_type = header.get("typ")
        if (
            not isinstance(algorithm, str)
            or algorithm not in configuration.algorithms
            or not isinstance(key_id, str)
            or header.get("crit") is not None
            or (token_type is not None and token_type not in _ALLOWED_TOKEN_TYPES)
        ):
            raise AuthenticationFailed("token header is not permitted")
        key = self._caches[configuration.issuer].verification_key(
            key_id=key_id,
            algorithm=algorithm,
        )
        try:
            claims = jwt.decode(
                bearer_token,
                key,
                algorithms=[algorithm],
                audience=list(configuration.audiences),
                issuer=configuration.issuer,
                options={
                    "require": ["aud", "exp", "iat", "iss", "sub"],
                    "verify_aud": True,
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_iss": True,
                    "verify_nbf": False,
                    "verify_signature": True,
                },
            )
        except InvalidTokenError as exc:
            raise AuthenticationFailed("bearer token validation failed") from exc
        issued_at, expires_at = self._validate_times(claims, configuration)

        subject_id = claims.get("sub")
        tenant_id = claims.get(configuration.tenant_claim)
        grant_version = claims.get(configuration.grant_version_claim)
        if (
            not isinstance(subject_id, str)
            or not isinstance(tenant_id, str)
            or not isinstance(grant_version, int)
            or isinstance(grant_version, bool)
            or grant_version < 1
        ):
            raise AuthenticationFailed("required authority claims are invalid")

        principal = self._identities.resolve_principal(
            tenant_id=tenant_id,
            issuer=configuration.issuer,
            subject_id=subject_id,
        )
        if (
            principal is None
            or principal.status is not PrincipalStatus.ACTIVE
            or principal.tenant_id != tenant_id
            or principal.grant_version != grant_version
        ):
            raise AuthenticationFailed("principal or grants are not current")
        tenant = self._identities.get_tenant(tenant_id=principal.tenant_id)
        if tenant is None or tenant.status is not TenantStatus.ACTIVE:
            raise AuthenticationFailed("tenant is not active")

        now = self._clock.now()
        grants = tuple(
            sorted(
                self._identities.active_grants(
                    tenant_id=principal.tenant_id,
                    issuer=principal.issuer,
                    subject_id=principal.subject_id,
                    now=now,
                ),
                key=lambda grant: (grant.purpose, grant.role, grant.grant_id),
            )
        )
        if not grants:
            raise AuthenticationFailed("principal has no current grant")
        bindings: list[GrantBinding] = []
        for grant in grants:
            if grant.status is not GrantStatus.ACTIVE or grant.expires_at <= now:
                raise AuthenticationFailed("identity repository returned stale grant")
            permissions = RoleCatalog.permissions_for(grant.role)
            if not permissions:
                raise AuthenticationFailed("grant refers to an unknown role")
            bindings.append(
                GrantBinding(
                    role=grant.role,
                    purpose=grant.purpose,
                    permissions=permissions,
                    risk_ceiling=grant.risk_ceiling,
                    expires_at=grant.expires_at,
                )
            )
        effective_expiry = min(expires_at, *(grant.expires_at for grant in grants))
        roles = tuple(sorted({binding.role for binding in bindings}))
        permissions = tuple(
            sorted(
                {
                    permission
                    for binding in bindings
                    for permission in binding.permissions
                }
            )
        )
        purposes = tuple(sorted({binding.purpose for binding in bindings}))
        return IdentityContext(
            tenant_id=principal.tenant_id,
            issuer=principal.issuer,
            subject_id=principal.subject_id,
            principal_kind=principal.principal_kind,
            roles=roles,
            permissions=permissions,
            purposes=purposes,
            grants=tuple(bindings),
            grant_version=principal.grant_version,
            authenticated_at=issued_at,
            expires_at=effective_expiry,
            request_id=request_id,
            trace_id=trace_id,
        )

    def _validate_times(
        self,
        claims: Mapping[str, object],
        configuration: IssuerConfiguration,
    ) -> tuple[datetime, datetime]:
        issued_at = _numeric_date(claims.get("iat"), "iat")
        expires_at = _numeric_date(claims.get("exp"), "exp")
        not_before_raw = claims.get("nbf")
        not_before = (
            _numeric_date(not_before_raw, "nbf") if not_before_raw is not None else None
        )
        now = self._clock.now()
        skew = timedelta(seconds=configuration.clock_skew_seconds)
        if issued_at > now + skew:
            raise AuthenticationFailed("token was issued in the future")
        if expires_at <= now - skew:
            raise AuthenticationFailed("token has expired")
        if expires_at <= issued_at:
            raise AuthenticationFailed("token expiry must follow issuance")
        if expires_at - issued_at > timedelta(
            seconds=configuration.maximum_token_lifetime_seconds
        ):
            raise AuthenticationFailed("token lifetime exceeds policy")
        if not_before is not None and (
            not_before > now + skew or not_before >= expires_at
        ):
            raise AuthenticationFailed("token is not currently valid")
        return issued_at, expires_at


class StaticAuthenticator:
    """Explicit demo/test-only authenticator with no production environment path."""

    def __init__(self, identities: Mapping[str, IdentityContext]) -> None:
        if not identities:
            raise ValueError("static identities cannot be empty")
        self._identities = dict(identities)

    def ready(self) -> bool:
        return True

    def authenticate(
        self,
        *,
        bearer_token: str,
        request_id: str,
        trace_id: str,
    ) -> IdentityContext:
        identity = self._identities.get(bearer_token)
        if identity is None:
            raise AuthenticationFailed("demo bearer token is invalid")
        return identity.model_copy(
            update={"request_id": request_id, "trace_id": trace_id}
        )


class UnavailableAuthenticator:
    def ready(self) -> bool:
        return False

    def authenticate(
        self,
        *,
        bearer_token: str,
        request_id: str,
        trace_id: str,
    ) -> IdentityContext:
        del bearer_token, request_id, trace_id
        raise IdentityUnavailable("production identity is not configured")


def _numeric_date(value: object, claim: str) -> datetime:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise AuthenticationFailed(f"token {claim} claim must be a NumericDate")
    try:
        return datetime.fromtimestamp(value, tz=UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise AuthenticationFailed(f"token {claim} claim is invalid") from exc


def require_authenticator(value: AuthenticatorPort) -> AuthenticatorPort:
    """Keep the port import exercised at the factory boundary for strict typing."""

    return value
