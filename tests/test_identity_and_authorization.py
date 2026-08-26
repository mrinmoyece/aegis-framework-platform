from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from pydantic import ValidationError

from aegis_framework.access import (
    GrantRecord,
    GrantStatus,
    PolicyRecord,
    PrincipalKind,
    PrincipalRecord,
    PrincipalStatus,
    SecretReference,
    TenantRecord,
    TenantStatus,
)
from aegis_framework.adapters import (
    FixedClock,
    HashChainAudit,
    InMemoryGovernance,
    InMemoryIdentityRepository,
)
from aegis_framework.authorization import EnterprisePolicy
from aegis_framework.domain import IdentityContext, RiskLevel
from aegis_framework.errors import (
    AuthenticationFailed,
    ConcurrencyConflict,
    IdentityUnavailable,
)
from aegis_framework.fixtures import DEMO_TIME, demo_identity
from aegis_framework.identity import (
    BoundedJwksCache,
    HttpJwksFetcher,
    IssuerConfiguration,
    JwtAuthenticator,
    StaticAuthenticator,
    _numeric_date,
    require_authenticator,
)
from aegis_framework.ports import Action

_ISSUER = "https://id.example.test/realms/aegis"
_AUDIENCE = "aegis-api"


class _MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


class _Fetcher:
    def __init__(self, document: Mapping[str, object]) -> None:
        self.document = document
        self.calls = 0

    def fetch(self, *, issuer: str, jwks_uri: str) -> Mapping[str, object]:
        assert issuer == _ISSUER
        assert jwks_uri == f"{_ISSUER}/protocol/openid-connect/certs"
        self.calls += 1
        return self.document


def _key(key_id: str) -> tuple[object, dict[str, object]]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    public_jwk.update({"kid": key_id, "alg": "RS256", "use": "sig"})
    return private, public_jwk


def _repository(
    *,
    grant_version: int = 3,
    principal_kind: PrincipalKind = PrincipalKind.HUMAN,
    grant_status: GrantStatus = GrantStatus.ACTIVE,
    tenant_status: TenantStatus = TenantStatus.ACTIVE,
    role: str = "incident-responder",
    purpose: str = "incident-response",
) -> InMemoryIdentityRepository:
    tenant = TenantRecord(
        tenant_id="tenant-acme",
        display_name="Acme",
        status=tenant_status,
        version=1,
    )
    principal = PrincipalRecord(
        tenant_id=tenant.tenant_id,
        issuer=_ISSUER,
        subject_id="subject-alice",
        principal_kind=principal_kind,
        status=PrincipalStatus.ACTIVE,
        grant_version=grant_version,
        version=1,
    )
    grant = GrantRecord(
        grant_id="grant-primary",
        tenant_id=tenant.tenant_id,
        issuer=principal.issuer,
        subject_id=principal.subject_id,
        role=role,
        purpose=purpose,
        risk_ceiling=RiskLevel.MEDIUM,
        status=grant_status,
        expires_at=DEMO_TIME + timedelta(hours=2),
        version=1,
    )
    return InMemoryIdentityRepository(
        tenants=(tenant,),
        principals=(principal,),
        grants=(grant,),
    )


def _configuration(**updates: object) -> IssuerConfiguration:
    return IssuerConfiguration(
        issuer=_ISSUER,
        audiences=(_AUDIENCE,),
        jwks_uri=f"{_ISSUER}/protocol/openid-connect/certs",
        **updates,
    )


def _claims(**updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "iss": _ISSUER,
        "sub": "subject-alice",
        "aud": _AUDIENCE,
        "iat": DEMO_TIME.timestamp(),
        "nbf": DEMO_TIME.timestamp(),
        "exp": (DEMO_TIME + timedelta(minutes=30)).timestamp(),
        "aegis_tenant": "tenant-acme",
        "aegis_grant_version": 3,
        "roles": ["forged-super-admin"],
    }
    for key, value in updates.items():
        if value is None:
            payload.pop(key, None)
        else:
            payload[key] = value
    return payload


def _authenticator(
    *,
    private: object,
    jwk: Mapping[str, object],
    repository: InMemoryIdentityRepository | None = None,
    clock: _MutableClock | None = None,
    fetcher: _Fetcher | None = None,
    configuration: IssuerConfiguration | None = None,
) -> tuple[JwtAuthenticator, _Fetcher, _MutableClock]:
    del private
    selected_clock = clock or _MutableClock(DEMO_TIME)
    selected_fetcher = fetcher or _Fetcher({"keys": [dict(jwk)]})
    authenticator = JwtAuthenticator(
        configurations=(configuration or _configuration(),),
        identities=repository or _repository(),
        fetcher=selected_fetcher,
        clock=selected_clock,
    )
    return authenticator, selected_fetcher, selected_clock


def _token(
    private: object,
    *,
    key_id: str = "key-1",
    algorithm: str = "RS256",
    claims: Mapping[str, object] | None = None,
    include_kid: bool = True,
) -> str:
    headers = {"kid": key_id} if include_kid else {}
    return jwt.encode(
        dict(claims or _claims()),
        private,
        algorithm=algorithm,
        headers=headers,
    )


def test_jwt_resolves_authority_from_current_application_grants() -> None:
    private, jwk = _key("key-1")
    authenticator, fetcher, _ = _authenticator(private=private, jwk=jwk)
    identity = authenticator.authenticate(
        bearer_token=_token(private),
        request_id="request-jwt",
        trace_id="trace-jwt",
    )
    assert identity.tenant_id == "tenant-acme"
    assert identity.subject_id == "subject-alice"
    assert identity.roles == ("incident-responder",)
    assert "forged-super-admin" not in identity.roles
    assert Action.INVESTIGATION_RUN.value in identity.permissions
    assert identity.grant_version == 3
    assert fetcher.calls == 1


def test_workload_principal_is_authoritative_repository_data() -> None:
    private, jwk = _key("key-1")
    authenticator, _, _ = _authenticator(
        private=private,
        jwk=jwk,
        repository=_repository(
            principal_kind=PrincipalKind.WORKLOAD,
            role="workload-investigator",
        ),
    )
    identity = authenticator.authenticate(
        bearer_token=_token(private),
        request_id="request-workload",
        trace_id="trace-workload",
    )
    assert identity.principal_kind is PrincipalKind.WORKLOAD
    assert identity.roles == ("workload-investigator",)


@pytest.mark.parametrize(
    "claim_updates",
    [
        {"iss": "https://attacker.invalid"},
        {"aud": "other-api"},
        {"exp": (DEMO_TIME - timedelta(minutes=1)).timestamp()},
        {"iat": (DEMO_TIME + timedelta(minutes=5)).timestamp()},
        {"nbf": (DEMO_TIME + timedelta(minutes=5)).timestamp()},
        {"exp": (DEMO_TIME + timedelta(hours=2)).timestamp()},
        {"sub": None},
        {"nbf": None},
        {"aegis_tenant": None},
        {"aegis_grant_version": None},
    ],
)
def test_jwt_claim_attacks_fail_closed(claim_updates: dict[str, object]) -> None:
    private, jwk = _key("key-1")
    authenticator, _, _ = _authenticator(private=private, jwk=jwk)
    with pytest.raises(AuthenticationFailed):
        authenticator.authenticate(
            bearer_token=_token(private, claims=_claims(**claim_updates)),
            request_id="request-attack",
            trace_id="trace-attack",
        )


def test_algorithm_kid_and_size_attacks_fail_before_authority() -> None:
    private, jwk = _key("key-1")
    authenticator, _, _ = _authenticator(private=private, jwk=jwk)
    wrong_algorithm = _token(
        b"attacker-secret-with-at-least-32-bytes",
        algorithm="HS256",
        claims=_claims(),
    )
    for token in (
        wrong_algorithm,
        _token(private, include_kid=False),
        "x" * 16_385,
    ):
        with pytest.raises(AuthenticationFailed):
            authenticator.authenticate(
                bearer_token=token,
                request_id="request-header-attack",
                trace_id="trace-header-attack",
            )


def test_jwks_rotation_is_bounded_and_unknown_kids_do_not_refresh_storm() -> None:
    first_private, first_jwk = _key("key-1")
    second_private, second_jwk = _key("key-2")
    clock = _MutableClock(DEMO_TIME)
    fetcher = _Fetcher({"keys": [first_jwk]})
    authenticator, _, _ = _authenticator(
        private=first_private,
        jwk=first_jwk,
        clock=clock,
        fetcher=fetcher,
    )
    authenticator.authenticate(
        bearer_token=_token(first_private),
        request_id="request-first-key",
        trace_id="trace-first-key",
    )
    with pytest.raises(AuthenticationFailed):
        authenticator.authenticate(
            bearer_token=_token(second_private, key_id="key-2"),
            request_id="request-unknown-key",
            trace_id="trace-unknown-key",
        )
    assert fetcher.calls == 1

    fetcher.document = {"keys": [first_jwk, second_jwk]}
    clock.value += timedelta(seconds=6)
    rotated = authenticator.authenticate(
        bearer_token=_token(second_private, key_id="key-2"),
        request_id="request-rotated-key",
        trace_id="trace-rotated-key",
    )
    assert rotated.subject_id == "subject-alice"
    assert fetcher.calls == 2


def test_invalid_or_oversized_jwks_fails_closed() -> None:
    private, jwk = _key("key-1")
    duplicate = _Fetcher({"keys": [jwk, jwk]})
    authenticator, _, _ = _authenticator(
        private=private,
        jwk=jwk,
        fetcher=duplicate,
    )
    with pytest.raises(IdentityUnavailable):
        authenticator.authenticate(
            bearer_token=_token(private),
            request_id="request-duplicate-jwk",
            trace_id="trace-duplicate-jwk",
        )

    second_private, second_jwk = _key("key-2")
    bounded = _Fetcher({"keys": [jwk, second_jwk]})
    authenticator, _, _ = _authenticator(
        private=second_private,
        jwk=second_jwk,
        fetcher=bounded,
        configuration=_configuration(maximum_jwks_keys=1),
    )
    with pytest.raises(IdentityUnavailable):
        authenticator.authenticate(
            bearer_token=_token(second_private, key_id="key-2"),
            request_id="request-large-jwks",
            trace_id="trace-large-jwks",
        )


class _HttpResponse:
    def __init__(self, *, url: str, payload: bytes) -> None:
        self._url = url
        self._payload = payload

    def __enter__(self) -> _HttpResponse:
        return self

    def __exit__(self, *args: object) -> None:
        del args

    def geturl(self) -> str:
        return self._url

    def read(self, size: int) -> bytes:
        return self._payload[:size]


class _HttpOpener:
    def __init__(self, response: _HttpResponse | OSError) -> None:
        self.response = response

    def open(self, request: object, timeout: float) -> _HttpResponse:
        del request, timeout
        if isinstance(self.response, OSError):
            raise self.response
        return self.response


def test_http_jwks_fetcher_enforces_transport_and_response_bounds() -> None:
    with pytest.raises(ValueError, match="bounds"):
        HttpJwksFetcher(timeout_seconds=0)
    fetcher = HttpJwksFetcher(maximum_response_bytes=1_024)
    with pytest.raises(IdentityUnavailable, match="HTTPS"):
        fetcher.fetch(issuer=_ISSUER, jwks_uri="http://id.example.test/keys")
    with pytest.raises(IdentityUnavailable, match="acceptable"):
        fetcher.fetch(issuer=_ISSUER, jwks_uri="https://user@id.example.test/keys")

    uri = "https://id.example.test/keys"
    fetcher._opener = _HttpOpener(_HttpResponse(url=uri, payload=b'{"keys":[]}'))
    assert fetcher.fetch(issuer=_ISSUER, jwks_uri=uri) == {"keys": []}

    fetcher._opener = _HttpOpener(
        _HttpResponse(
            url="https://redirect.example.test/keys",
            payload=b"{}",
        )
    )
    with pytest.raises(IdentityUnavailable, match="redirect"):
        fetcher.fetch(issuer=_ISSUER, jwks_uri=uri)

    fetcher._opener = _HttpOpener(_HttpResponse(url=uri, payload=b"x" * 1_025))
    with pytest.raises(IdentityUnavailable, match="exceeds"):
        fetcher.fetch(issuer=_ISSUER, jwks_uri=uri)

    fetcher._opener = _HttpOpener(_HttpResponse(url=uri, payload=b"not-json"))
    with pytest.raises(IdentityUnavailable, match="valid JSON"):
        fetcher.fetch(issuer=_ISSUER, jwks_uri=uri)

    fetcher._opener = _HttpOpener(_HttpResponse(url=uri, payload=b"[]"))
    with pytest.raises(IdentityUnavailable, match="object"):
        fetcher.fetch(issuer=_ISSUER, jwks_uri=uri)

    fetcher._opener = _HttpOpener(OSError("offline"))
    with pytest.raises(IdentityUnavailable, match="unavailable"):
        fetcher.fetch(issuer=_ISSUER, jwks_uri=uri)


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({}, "contain keys"),
        ({"keys": ["not-an-object"]}, "must be an object"),
        ({"keys": [{"kid": ""}]}, "ID is invalid"),
    ],
)
def test_jwks_cache_rejects_malformed_documents(
    document: Mapping[str, object],
    message: str,
) -> None:
    cache = BoundedJwksCache(
        configuration=_configuration(),
        fetcher=_Fetcher(document),
        clock=_MutableClock(DEMO_TIME),
    )
    with pytest.raises(IdentityUnavailable, match=message):
        cache.verification_key(key_id="key-1", algorithm="RS256")


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"alg": "PS256"}, "algorithm"),
        ({"use": "enc"}, "not a signing"),
        ({"key_ops": ["sign"]}, "cannot verify"),
        ({"kty": "invalid"}, "key is invalid"),
    ],
)
def test_jwks_cache_rejects_keys_with_invalid_verification_semantics(
    updates: dict[str, object],
    message: str,
) -> None:
    _, jwk = _key("key-1")
    candidate = {**jwk, **updates}
    cache = BoundedJwksCache(
        configuration=_configuration(),
        fetcher=_Fetcher({"keys": [candidate]}),
        clock=_MutableClock(DEMO_TIME),
    )
    with pytest.raises(AuthenticationFailed, match=message):
        cache.verification_key(key_id="key-1", algorithm="RS256")


def test_identity_configuration_and_numeric_date_edges_fail_closed() -> None:
    private, jwk = _key("key-1")
    with pytest.raises(ValueError, match="trusted issuer"):
        JwtAuthenticator(
            configurations=(),
            identities=_repository(),
            fetcher=_Fetcher({"keys": [jwk]}),
            clock=_MutableClock(DEMO_TIME),
        )
    with pytest.raises(ValidationError):
        _configuration(algorithms=("PS256",))
    configuration = _configuration()
    with pytest.raises(ValueError, match="unique"):
        JwtAuthenticator(
            configurations=(configuration, configuration),
            identities=_repository(),
            fetcher=_Fetcher({"keys": [jwk]}),
            clock=_MutableClock(DEMO_TIME),
        )
    authenticator, _, _ = _authenticator(private=private, jwk=jwk)
    with pytest.raises(AuthenticationFailed, match="bearer token"):
        authenticator.authenticate(
            bearer_token="contains whitespace",
            request_id="request-space",
            trace_id="trace-space",
        )
    with pytest.raises(AuthenticationFailed, match="follow issuance"):
        authenticator.authenticate(
            bearer_token=_token(
                private,
                claims=_claims(
                    iat=DEMO_TIME.timestamp(),
                    exp=DEMO_TIME.timestamp(),
                ),
            ),
            request_id="request-time-order",
            trace_id="trace-time-order",
        )
    with pytest.raises(AuthenticationFailed, match="NumericDate"):
        _numeric_date(True, "iat")
    with pytest.raises(AuthenticationFailed, match="invalid"):
        _numeric_date(float("inf"), "exp")
    with pytest.raises(ValueError, match="cannot be empty"):
        StaticAuthenticator({})
    assert require_authenticator(authenticator) is authenticator


@pytest.mark.parametrize(
    ("repository", "claims"),
    [
        (_repository(grant_version=4), _claims()),
        (_repository(grant_status=GrantStatus.REVOKED), _claims()),
        (_repository(tenant_status=TenantStatus.SUSPENDED), _claims()),
        (_repository(), _claims(aegis_tenant="tenant-beta")),
    ],
)
def test_stale_revoked_and_cross_tenant_grants_fail_closed(
    repository: InMemoryIdentityRepository,
    claims: Mapping[str, object],
) -> None:
    private, jwk = _key("key-1")
    authenticator, _, _ = _authenticator(
        private=private,
        jwk=jwk,
        repository=repository,
    )
    with pytest.raises(AuthenticationFailed):
        authenticator.authenticate(
            bearer_token=_token(private, claims=claims),
            request_id="request-stale",
            trace_id="trace-stale",
        )


def _governance() -> InMemoryGovernance:
    identity = demo_identity()
    tenant = TenantRecord(
        tenant_id=identity.tenant_id,
        display_name="Acme",
        status=TenantStatus.ACTIVE,
        version=1,
    )
    policy = PolicyRecord(
        policy_id="policy-acme",
        tenant_id=identity.tenant_id,
        revision=2,
        allowed_actions=tuple(action.value for action in Action),
        allowed_purposes=("incident-response",),
        max_risk=RiskLevel.MEDIUM,
        version=1,
    )
    return InMemoryGovernance(
        tenants=(tenant,),
        policies=(policy,),
        quotas=(),
        audit=HashChainAudit(FixedClock(DEMO_TIME)),
    )


@pytest.mark.parametrize(
    ("action", "tenant_id", "purpose", "risk", "allowed"),
    [
        (
            Action.INVESTIGATION_RUN,
            "tenant-acme",
            "incident-response",
            RiskLevel.MEDIUM,
            True,
        ),
        (
            Action.INVESTIGATION_RUN,
            "tenant-beta",
            "incident-response",
            RiskLevel.MEDIUM,
            False,
        ),
        (
            Action.INVESTIGATION_RUN,
            "tenant-acme",
            "billing",
            RiskLevel.MEDIUM,
            False,
        ),
        (
            Action.INVESTIGATION_RUN,
            "tenant-acme",
            "incident-response",
            RiskLevel.HIGH,
            False,
        ),
        (
            Action.AUDIT_READ,
            "tenant-acme",
            "incident-response",
            RiskLevel.LOW,
            False,
        ),
    ],
)
def test_policy_binds_tenant_purpose_risk_and_permission(
    action: Action,
    tenant_id: str,
    purpose: str,
    risk: RiskLevel,
    allowed: bool,
) -> None:
    policy = EnterprisePolicy(
        policies=_governance(),
        clock=FixedClock(DEMO_TIME),
    )
    decision = policy.authorize(
        demo_identity(),
        action,
        resource_tenant_id=tenant_id,
        purpose=purpose,
        risk=risk,
    )
    assert decision.allowed is allowed


def test_identity_authority_projection_is_immutable_and_consistent() -> None:
    identity = demo_identity()
    with pytest.raises(ValidationError, match="roles must match"):
        IdentityContext.model_validate(
            {
                **identity.model_dump(),
                "roles": ("tenant-admin",),
            }
        )
    with pytest.raises(ValidationError):
        identity.roles += ("tenant-admin",)


def test_optimistic_policy_update_and_secret_reference_boundary() -> None:
    governance = _governance()
    policy = governance.current_policy(tenant_id="tenant-acme")
    assert policy is not None
    updated = governance.replace_policy(
        policy=policy.model_copy(update={"revision": 3}),
        expected_version=1,
    )
    assert updated.version == 2
    with pytest.raises(ConcurrencyConflict):
        governance.replace_policy(policy=policy, expected_version=1)

    reference = SecretReference(
        tenant_id="tenant-acme",
        name="model-api",
        provider="vault",
        reference="vault://tenant-acme/model-api",
        version=1,
    )
    assert "secret_value" not in reference.model_dump()


def test_audit_chain_is_per_tenant_redacted_and_frozen() -> None:
    audit = HashChainAudit(FixedClock(DEMO_TIME))
    first = demo_identity(tenant_id="tenant-acme", subject_id="alice")
    second = demo_identity(tenant_id="tenant-beta", subject_id="bob")
    audit.append(
        identity=first,
        event_type="identity.authenticated",
        attributes={
            "request_ref": "request:safe",
            "prompt": "must-not-persist",
        },
    )
    audit.append(
        identity=second,
        event_type="identity.authenticated",
        attributes={"request_ref": "request:other"},
    )
    acme = audit.records_for("tenant-acme")
    beta = audit.records_for("tenant-beta")
    assert acme[0].sequence == beta[0].sequence == 1
    assert acme[0].previous_hash == beta[0].previous_hash == "0" * 64
    assert "prompt" not in acme[0].attributes
    assert "alice" not in acme[0].actor_ref
    assert audit.verify()
    with pytest.raises(ValidationError):
        acme[0].attributes = {}
