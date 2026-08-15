from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import pytest

from aegis_framework.access import (
    GrantRecord,
    GrantStatus,
    PrincipalKind,
    PrincipalRecord,
    PrincipalStatus,
    TenantRecord,
    TenantStatus,
)
from aegis_framework.adapters import InMemoryIdentityRepository, SystemClock
from aegis_framework.domain import RiskLevel
from aegis_framework.identity import (
    HttpJwksFetcher,
    IssuerConfiguration,
    JwtAuthenticator,
)


def _required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        pytest.skip("local Keycloak integration environment is not configured")
    return value


@pytest.mark.keycloak
def test_local_keycloak_access_token_uses_the_same_strict_verifier() -> None:
    token = _required("AEGIS_TEST_KEYCLOAK_TOKEN")
    issuer = _required("AEGIS_TEST_KEYCLOAK_ISSUER")
    jwks_uri = _required("AEGIS_TEST_KEYCLOAK_JWKS_URI")
    audience = _required("AEGIS_TEST_KEYCLOAK_AUDIENCE")
    subject = _required("AEGIS_TEST_KEYCLOAK_SUBJECT")
    tenant_id = _required("AEGIS_TEST_KEYCLOAK_TENANT")
    grant_version = int(_required("AEGIS_TEST_KEYCLOAK_GRANT_VERSION"))
    for url in (issuer, jwks_uri):
        assert urlsplit(url).hostname in {"127.0.0.1", "::1", "localhost"}

    now = datetime.now(UTC)
    repository = InMemoryIdentityRepository(
        tenants=(
            TenantRecord(
                tenant_id=tenant_id,
                display_name="Local Keycloak tenant",
                status=TenantStatus.ACTIVE,
                version=1,
            ),
        ),
        principals=(
            PrincipalRecord(
                tenant_id=tenant_id,
                issuer=issuer,
                subject_id=subject,
                principal_kind=PrincipalKind.HUMAN,
                status=PrincipalStatus.ACTIVE,
                grant_version=grant_version,
                version=1,
            ),
        ),
        grants=(
            GrantRecord(
                grant_id="keycloak-local-grant",
                tenant_id=tenant_id,
                issuer=issuer,
                subject_id=subject,
                role="incident-responder",
                purpose="incident-response",
                risk_ceiling=RiskLevel.MEDIUM,
                status=GrantStatus.ACTIVE,
                expires_at=now + timedelta(hours=1),
                version=1,
            ),
        ),
    )
    authenticator = JwtAuthenticator(
        configurations=(
            IssuerConfiguration(
                issuer=issuer,
                audiences=(audience,),
                jwks_uri=jwks_uri,
            ),
        ),
        identities=repository,
        fetcher=HttpJwksFetcher(allow_loopback_http=True),
        clock=SystemClock(),
    )
    identity = authenticator.authenticate(
        bearer_token=token,
        request_id="keycloak-local",
        trace_id="keycloak-local-trace",
    )
    assert identity.tenant_id == tenant_id
    assert identity.subject_id == subject
    assert identity.roles == ("incident-responder",)
