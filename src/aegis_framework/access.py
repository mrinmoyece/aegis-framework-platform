"""Provider-neutral identity, tenancy, policy, quota, secret, and audit contracts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from pydantic import AwareDatetime, Field, field_validator, model_validator

from aegis_framework.domain import (
    Identifier,
    IdentityContext,
    Issuer,
    PrincipalKind,
    RiskLevel,
    StrictModel,
    SubjectIdentifier,
)


class TenantStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"


class PrincipalStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


class GrantStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"


class TenantRecord(StrictModel):
    tenant_id: Identifier
    display_name: str = Field(min_length=1, max_length=200)
    status: TenantStatus
    version: int = Field(ge=1)


class PrincipalRecord(StrictModel):
    tenant_id: Identifier
    issuer: Issuer
    subject_id: SubjectIdentifier
    principal_kind: PrincipalKind
    status: PrincipalStatus
    grant_version: int = Field(ge=1)
    version: int = Field(ge=1)


class GrantRecord(StrictModel):
    grant_id: Identifier
    tenant_id: Identifier
    issuer: Issuer
    subject_id: SubjectIdentifier
    role: Identifier
    purpose: Identifier
    risk_ceiling: RiskLevel
    status: GrantStatus
    expires_at: AwareDatetime
    version: int = Field(ge=1)


class PolicyRecord(StrictModel):
    policy_id: Identifier
    tenant_id: Identifier
    revision: int = Field(ge=1)
    allowed_actions: tuple[Identifier, ...]
    allowed_purposes: tuple[Identifier, ...]
    max_risk: RiskLevel
    version: int = Field(ge=1)

    @field_validator("allowed_actions", "allowed_purposes")
    @classmethod
    def normalize_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(value)))


class QuotaRecord(StrictModel):
    tenant_id: Identifier
    quota_key: Identifier
    limit_units: int = Field(ge=0)
    used_units: int = Field(ge=0)
    period_start: AwareDatetime
    period_end: AwareDatetime
    version: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_period_and_usage(self) -> QuotaRecord:
        if self.period_end <= self.period_start:
            raise ValueError("quota period end must follow its start")
        if self.used_units > self.limit_units:
            raise ValueError("quota usage cannot exceed its limit")
        return self


class SecretReference(StrictModel):
    tenant_id: Identifier
    name: Identifier
    provider: Identifier
    reference: str = Field(
        min_length=3,
        max_length=512,
        pattern=r"^[a-z][a-z0-9+.-]*://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$",
    )
    version: int = Field(ge=1)


class AuditEventView(StrictModel):
    event_id: Identifier
    sequence: int = Field(ge=1)
    event_type: Identifier
    actor_ref: Identifier
    principal_kind: PrincipalKind
    recorded_at: AwareDatetime
    attributes: dict[str, str | int | bool]
    previous_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    record_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class IdentityRepositoryPort(Protocol):
    def resolve_principal(
        self, *, tenant_id: str, issuer: str, subject_id: str
    ) -> PrincipalRecord | None: ...

    def active_grants(
        self,
        *,
        tenant_id: str,
        issuer: str,
        subject_id: str,
        now: datetime,
    ) -> Sequence[GrantRecord]: ...

    def get_tenant(self, *, tenant_id: str) -> TenantRecord | None: ...


class PolicyRepositoryPort(Protocol):
    def current_policy(self, *, tenant_id: str) -> PolicyRecord | None: ...


class GovernancePort(PolicyRepositoryPort, Protocol):
    def get_tenant(self, *, tenant_id: str) -> TenantRecord | None: ...

    def get_quota(self, *, tenant_id: str, quota_key: str) -> QuotaRecord | None: ...

    def list_audit(
        self, *, identity: IdentityContext, limit: int
    ) -> Sequence[AuditEventView]: ...

    def ready(self) -> bool: ...


class AuthenticatorPort(Protocol):
    def authenticate(
        self,
        *,
        bearer_token: str,
        request_id: str,
        trace_id: str,
    ) -> IdentityContext: ...

    def ready(self) -> bool: ...


class JwksFetcherPort(Protocol):
    def fetch(self, *, issuer: str, jwks_uri: str) -> Mapping[str, object]: ...
