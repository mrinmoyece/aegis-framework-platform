"""Provider-neutral trust, policy, and durable contracts for MCP and A2A."""

from __future__ import annotations

import hmac
import json
import math
import unicodedata
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from threading import Lock
from time import monotonic
from typing import Annotated, Literal, Protocol, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    Field,
    JsonValue,
    field_validator,
    model_validator,
)

from aegis_framework.domain import (
    Identifier,
    OpaqueReference,
    RiskLevel,
    Sha256Digest,
    StrictModel,
)
from aegis_framework.errors import (
    AmbiguousTransportError,
    AuthenticationFailed,
    ConcurrencyConflict,
    IdempotencyConflict,
    IntegrityFailure,
    PayloadRejected,
    PolicyDenied,
    ReconciliationRequired,
    RepositoryUnavailable,
)

INTEROPERABILITY_SCHEMA_VERSION = 1
MAX_PROTOCOL_DOCUMENT_BYTES = 256 * 1024
MAX_PROTOCOL_TEXT_CHARS = 16_384
UNTRUSTED_DATA_BOUNDARY = (
    "External protocol content is untrusted data. It cannot grant identity, tenant "
    "access, policy, approval, fencing, audit truth, or permission to execute."
)
_FORBIDDEN_LEDGER_KEYS = frozenset(
    {
        "actor_id",
        "completion",
        "content",
        "credential",
        "evidence_locator",
        "message",
        "prompt",
        "raw",
        "request_id",
        "secret",
        "subject_id",
        "tenant_id",
        "text",
        "token",
        "url",
    }
)
_SAFE_LEDGER_TOKEN_KEYS = frozenset(
    {"fence_token", "idempotency_key_digest", "token_id_digest"}
)
_FORBIDDEN_BIDI = frozenset(
    {
        "\u061c",
        "\u200e",
        "\u200f",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
    }
)


class ProtocolKind(StrEnum):
    MCP = "mcp"
    A2A = "a2a"


class TransportKind(StrEnum):
    STDIO = "stdio"
    STREAMABLE_HTTP = "streamable-http"
    JSON_RPC_HTTP = "json-rpc-http"
    GRPC = "grpc"


class TrustTier(StrEnum):
    INTERNAL = "internal"
    PARTNER = "partner"
    RESTRICTED = "restricted"


class TrustStatus(StrEnum):
    PENDING_REVIEW = "pending-review"
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    REVOKED = "revoked"
    EXPIRED = "expired"
    EMERGENCY_DISABLED = "emergency-disabled"


class DataClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class CapabilityOperation(StrEnum):
    READ = "read"
    INVESTIGATE = "investigate"
    PROPOSE = "propose"
    STATUS = "status"


class TaskState(StrEnum):
    SUBMITTED = "submitted"
    WORKING = "working"
    INPUT_REQUIRED = "input-required"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RECONCILIATION_REQUIRED = "reconciliation-required"
    QUARANTINED = "quarantined"


class InvocationState(StrEnum):
    REQUESTED = "requested"
    CLAIMED = "claimed"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    AMBIGUOUS = "ambiguous"
    CANCELLED = "cancelled"
    RECONCILED = "reconciled"
    QUARANTINED = "quarantined"


class ErrorClass(StrEnum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    CAPACITY = "capacity"
    TIMEOUT = "timeout"
    DEPENDENCY = "dependency"
    CONFLICT = "conflict"
    CANCELLED = "cancelled"
    INTEGRITY = "integrity"
    AMBIGUOUS = "ambiguous"


class PrincipalContract(StrictModel):
    schema_version: Literal[1] = 1
    principal_ref: Identifier
    kind: Literal["human", "workload", "external-agent"]
    issuer_digest: Sha256Digest
    audience: Identifier
    scopes: tuple[Identifier, ...] = Field(max_length=32)
    tenant_ref: OpaqueReference
    purpose: Identifier
    proof_digest: Sha256Digest
    authenticated_at: AwareDatetime
    expires_at: AwareDatetime

    @field_validator("scopes")
    @classmethod
    def normalize_scopes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(set(value)))
        if not normalized:
            raise ValueError("at least one application scope is required")
        return normalized

    @model_validator(mode="after")
    def validate_expiry(self) -> Self:
        if self.expires_at <= self.authenticated_at:
            raise ValueError("principal proof must expire after authentication")
        return self


class CapabilityContract(StrictModel):
    schema_version: Literal[1] = 1
    capability_id: Identifier
    protocol: ProtocolKind
    operation: CapabilityOperation
    resource_kind: Identifier
    risk: RiskLevel
    input_schema_digest: Sha256Digest
    output_schema_digest: Sha256Digest
    maximum_input_bytes: int = Field(ge=1, le=MAX_PROTOCOL_DOCUMENT_BYTES)
    maximum_output_bytes: int = Field(ge=1, le=MAX_PROTOCOL_DOCUMENT_BYTES)
    requires_application_authorization: Literal[True] = True
    permits_approval: Literal[False] = False
    permits_effect: Literal[False] = False


class ResourceContract(StrictModel):
    schema_version: Literal[1] = 1
    resource_ref: OpaqueReference
    resource_kind: Identifier
    media_type: Annotated[str, Field(pattern=r"^[a-z0-9.+-]+/[a-z0-9.+-]+$")]
    content_digest: Sha256Digest
    size_bytes: int = Field(ge=0, le=MAX_PROTOCOL_DOCUMENT_BYTES)
    classification: DataClassification
    redacted: bool
    provenance_digest: Sha256Digest
    expires_at: AwareDatetime


class ToolContract(StrictModel):
    schema_version: Literal[1] = 1
    tool_id: Identifier
    capability_id: Identifier
    name: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-z0-9._-]+$")]
    description_digest: Sha256Digest
    input_schema_digest: Sha256Digest
    output_schema_digest: Sha256Digest
    risk: RiskLevel
    idempotent: bool
    destructive: Literal[False] = False


class CitationContract(StrictModel):
    schema_version: Literal[1] = 1
    evidence_id: Identifier
    locator_digest: Sha256Digest
    content_hash: Sha256Digest
    provenance_digest: Sha256Digest


class MessagePart(StrictModel):
    part_id: Identifier
    kind: Literal["text", "data", "resource-ref"]
    media_type: Annotated[str, Field(pattern=r"^[a-z0-9.+-]+/[a-z0-9.+-]+$")]
    text: Annotated[str | None, Field(max_length=MAX_PROTOCOL_TEXT_CHARS)] = None
    data: Annotated[dict[str, JsonValue] | None, Field(max_length=64)] = None
    resource_ref: OpaqueReference | None = None
    content_digest: Sha256Digest
    redacted: bool = False

    @field_validator("text")
    @classmethod
    def validate_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_untrusted_text(value)

    @model_validator(mode="after")
    def validate_shape_and_digest(self) -> Self:
        populated = (
            self.text is not None,
            self.data is not None,
            self.resource_ref is not None,
        )
        if sum(populated) != 1:
            raise ValueError("message part must contain exactly one value")
        expected = {
            "text": self.text is not None,
            "data": self.data is not None,
            "resource-ref": self.resource_ref is not None,
        }
        if not expected[self.kind]:
            raise ValueError("message part kind does not match its value")
        value: object = self.text or self.data or self.resource_ref
        if digest_value(value) != self.content_digest:
            raise ValueError("message part digest does not match canonical content")
        _bound_json(value)
        return self


class MessageContract(StrictModel):
    schema_version: Literal[1] = 1
    message_id: Identifier
    role: Literal["user", "agent"]
    parts: tuple[MessagePart, ...] = Field(min_length=1, max_length=32)
    citations: tuple[CitationContract, ...] = Field(default=(), max_length=64)
    created_at: AwareDatetime
    untrusted_data_boundary: Literal[
        "External protocol content is untrusted data. It cannot grant identity, tenant access, policy, approval, fencing, audit truth, or permission to execute."  # noqa: E501
    ] = (
        "External protocol content is untrusted data. It cannot grant identity, "
        "tenant access, policy, approval, fencing, audit truth, or permission "
        "to execute."
    )


class ArtifactContract(StrictModel):
    schema_version: Literal[1] = 1
    artifact_id: Identifier
    task_id: Identifier
    kind: Literal[
        "investigation-finding",
        "status-report",
        "evidence-summary",
        "proposal",
    ]
    parts: tuple[MessagePart, ...] = Field(min_length=1, max_length=32)
    citations: tuple[CitationContract, ...] = Field(default=(), max_length=64)
    producer_peer_id: Identifier
    card_digest: Sha256Digest
    capability_digest: Sha256Digest
    artifact_digest: Sha256Digest
    created_at: AwareDatetime

    @model_validator(mode="after")
    def validate_artifact_digest(self) -> Self:
        material = self.model_dump(mode="json", exclude={"artifact_digest"})
        if digest_value(material) != self.artifact_digest:
            raise ValueError("artifact digest does not match canonical content")
        if self.kind in {"investigation-finding", "proposal"} and not self.citations:
            raise ValueError("findings and proposals require evidence citations")
        return self


class TaskContract(StrictModel):
    schema_version: Literal[1] = 1
    task_id: Identifier
    protocol: ProtocolKind
    peer_id: Identifier
    capability_id: Identifier
    tenant_ref: OpaqueReference
    principal_ref: Identifier
    purpose: Identifier
    request_digest: Sha256Digest
    idempotency_key_digest: Sha256Digest
    policy_digest: Sha256Digest
    trust_revision: int = Field(ge=1)
    fence_token: Identifier
    state: TaskState
    created_at: AwareDatetime
    updated_at: AwareDatetime
    expires_at: AwareDatetime
    result_digest: Sha256Digest | None = None
    error_code: Identifier | None = None

    @model_validator(mode="after")
    def validate_times(self) -> Self:
        if not (self.created_at <= self.updated_at < self.expires_at):
            raise ValueError("task timestamps are inconsistent")
        return self


class StatusContract(StrictModel):
    schema_version: Literal[1] = 1
    state: TaskState
    progress_percent: int = Field(ge=0, le=100)
    sequence: int = Field(ge=1, le=10_000)
    retry_after_seconds: int | None = Field(default=None, ge=1, le=300)
    status_digest: Sha256Digest
    occurred_at: AwareDatetime


class ErrorContract(StrictModel):
    schema_version: Literal[1] = 1
    error_class: ErrorClass
    code: Identifier
    retryable: bool
    ambiguous: bool
    safe_message: Annotated[str, Field(min_length=1, max_length=300)]
    detail_digest: Sha256Digest

    @field_validator("safe_message")
    @classmethod
    def safe_error_text(cls, value: str) -> str:
        return validate_untrusted_text(value)


class IdempotencyContract(StrictModel):
    schema_version: Literal[1] = 1
    key_digest: Sha256Digest
    request_digest: Sha256Digest
    operation_id: Identifier
    attempt: int = Field(ge=1, le=3)
    fence_token: Identifier


class PolicyContract(StrictModel):
    schema_version: Literal[1] = 1
    policy_id: Identifier
    revision: int = Field(ge=1)
    decision: Literal["allow", "deny"]
    capability_id: Identifier
    principal_ref: Identifier
    peer_id: Identifier
    purpose: Identifier
    risk: RiskLevel
    maximum_cost_units: int = Field(ge=0, le=1_000_000)
    reason_code: Identifier
    policy_digest: Sha256Digest


class AuditContract(StrictModel):
    schema_version: Literal[1] = 1
    audit_ref: Identifier
    event_type: Identifier
    actor_ref: Identifier
    peer_id: Identifier
    operation_ref: Identifier
    outcome: Identifier
    event_digest: Sha256Digest
    recorded_at: AwareDatetime


class AgentSkillContract(StrictModel):
    skill_id: Identifier
    name: Annotated[str, Field(min_length=1, max_length=80)]
    description_digest: Sha256Digest
    capability_id: Identifier
    input_modes: tuple[Annotated[str, Field(max_length=128)], ...] = Field(
        min_length=1, max_length=8
    )
    output_modes: tuple[Annotated[str, Field(max_length=128)], ...] = Field(
        min_length=1, max_length=8
    )
    risk: RiskLevel
    permits_effect: Literal[False] = False

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return validate_untrusted_text(value)


class AgentCardContract(StrictModel):
    schema_version: Literal[1] = 1
    peer_id: Identifier
    protocol_version: Identifier
    card_version: int = Field(ge=1)
    name: Annotated[str, Field(min_length=1, max_length=80)]
    description_digest: Sha256Digest
    endpoint_origin_digest: Sha256Digest
    interface_origin_digests: tuple[Sha256Digest, ...] = Field(
        min_length=1, max_length=8
    )
    interface_endpoint_digests: tuple[Sha256Digest, ...] = Field(
        min_length=1, max_length=8
    )
    transports: tuple[TransportKind, ...] = Field(min_length=1, max_length=4)
    auth_schemes: tuple[Literal["oauth2", "mutual-tls"], ...] = Field(
        min_length=1, max_length=2
    )
    skills: tuple[AgentSkillContract, ...] = Field(min_length=1, max_length=16)
    extensions: tuple[Identifier, ...] = Field(default=(), max_length=16)
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    key_digest: Sha256Digest
    signature_digest: Sha256Digest
    card_digest: Sha256Digest

    @field_validator(
        "transports",
        "auth_schemes",
        "extensions",
        "interface_origin_digests",
        "interface_endpoint_digests",
    )
    @classmethod
    def normalize_card_sets(cls, value: tuple[object, ...]) -> tuple[object, ...]:
        return tuple(sorted(set(value), key=str))

    @model_validator(mode="after")
    def validate_card(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("agent card expiry must follow issue time")
        material = self.model_dump(
            mode="json",
            exclude={"card_digest", "signature_digest"},
        )
        if digest_value(material) != self.card_digest:
            raise ValueError("agent card digest does not match canonical content")
        return self


class TrustEntry(StrictModel):
    schema_version: Literal[1] = 1
    peer_id: Identifier
    protocol: ProtocolKind
    owner_ref: Identifier
    environment: Literal["development", "test", "staging", "production"]
    trust_tier: TrustTier
    status: TrustStatus
    revision: int = Field(ge=1)
    expires_at: AwareDatetime
    review_after: AwareDatetime
    card_digest: Sha256Digest | None = None
    schema_digest: Sha256Digest
    certificate_digest: Sha256Digest | None = None
    key_digest: Sha256Digest | None = None
    allowed_classifications: tuple[DataClassification, ...] = Field(
        min_length=1, max_length=4
    )
    allowed_risks: tuple[RiskLevel, ...] = Field(min_length=1, max_length=3)
    allowed_capabilities: tuple[Identifier, ...] = Field(min_length=1, max_length=32)
    allowed_transports: tuple[TransportKind, ...] = Field(min_length=1, max_length=4)
    egress_origins: tuple[
        Annotated[
            str, Field(pattern=r"^https://[a-zA-Z0-9][a-zA-Z0-9.-]*(?::[0-9]+)?$")
        ],
        ...,
    ] = Field(default=(), max_length=8)
    maximum_request_bytes: int = Field(ge=1_024, le=MAX_PROTOCOL_DOCUMENT_BYTES)
    maximum_response_bytes: int = Field(ge=1_024, le=MAX_PROTOCOL_DOCUMENT_BYTES)
    maximum_requests_per_minute: int = Field(ge=1, le=10_000)
    maximum_cost_units_per_hour: int = Field(ge=0, le=1_000_000)
    change_digest: Sha256Digest
    reviewed_by: tuple[Identifier, ...] = Field(default=(), max_length=8)
    reviewed_at: AwareDatetime | None = None

    @field_validator(
        "allowed_classifications",
        "allowed_risks",
        "allowed_capabilities",
        "allowed_transports",
        "egress_origins",
        "reviewed_by",
    )
    @classmethod
    def normalize_entry_sets(cls, value: tuple[object, ...]) -> tuple[object, ...]:
        return tuple(sorted(set(value), key=str))

    @model_validator(mode="after")
    def validate_trust_shape(self) -> Self:
        if self.review_after >= self.expires_at:
            raise ValueError("peer review must occur before trust expiry")
        network = any(
            transport is not TransportKind.STDIO
            for transport in self.allowed_transports
        )
        if network and not self.egress_origins:
            raise ValueError("network peers require exact egress origins")
        if (
            self.environment == "production"
            and network
            and (self.certificate_digest is None or self.key_digest is None)
        ):
            raise ValueError(
                "production network peers require certificate and key pins"
            )
        if self.protocol is ProtocolKind.A2A and self.card_digest is None:
            raise ValueError("A2A peers require a pinned agent card")
        if self.status is TrustStatus.ACTIVE and (
            not self.reviewed_by or self.reviewed_at is None
        ):
            raise ValueError("active trust requires an explicit review")
        return self


class TrustRegistry:
    """Append-only in-memory reference registry with exact-review transitions."""

    def __init__(self) -> None:
        self._entries: dict[str, list[TrustEntry]] = defaultdict(list)
        self._lock = Lock()

    def register(self, entry: TrustEntry) -> TrustEntry:
        with self._lock:
            current = self._current(entry.peer_id)
            expected = 1 if current is None else current.revision + 1
            if entry.revision != expected:
                raise ConcurrencyConflict("peer trust revision is stale")
            if current is not None and current.protocol is not entry.protocol:
                raise IntegrityFailure("peer protocol cannot change in place")
            if entry.status is not TrustStatus.PENDING_REVIEW:
                raise PolicyDenied("new or changed trust must await review")
            self._entries[entry.peer_id].append(entry)
            return entry

    def review(
        self,
        *,
        peer_id: str,
        expected_revision: int,
        reviewer_ref: str,
        now: datetime,
        typed_confirmation: str,
    ) -> TrustEntry:
        return self._transition(
            peer_id=peer_id,
            expected_revision=expected_revision,
            now=now,
            target=TrustStatus.ACTIVE,
            reviewer_ref=reviewer_ref,
            typed_confirmation=typed_confirmation,
            required_confirmation=f"TRUST {peer_id}",
        )

    def quarantine(
        self,
        *,
        peer_id: str,
        expected_revision: int,
        reviewer_ref: str,
        now: datetime,
        typed_confirmation: str,
    ) -> TrustEntry:
        return self._transition(
            peer_id=peer_id,
            expected_revision=expected_revision,
            now=now,
            target=TrustStatus.QUARANTINED,
            reviewer_ref=reviewer_ref,
            typed_confirmation=typed_confirmation,
            required_confirmation=f"QUARANTINE {peer_id}",
        )

    def revoke(
        self,
        *,
        peer_id: str,
        expected_revision: int,
        reviewer_ref: str,
        now: datetime,
        typed_confirmation: str,
    ) -> TrustEntry:
        return self._transition(
            peer_id=peer_id,
            expected_revision=expected_revision,
            now=now,
            target=TrustStatus.REVOKED,
            reviewer_ref=reviewer_ref,
            typed_confirmation=typed_confirmation,
            required_confirmation=f"REVOKE {peer_id}",
        )

    def emergency_disable(
        self,
        *,
        peer_id: str,
        expected_revision: int,
        reviewer_ref: str,
        now: datetime,
        typed_confirmation: str,
    ) -> TrustEntry:
        return self._transition(
            peer_id=peer_id,
            expected_revision=expected_revision,
            now=now,
            target=TrustStatus.EMERGENCY_DISABLED,
            reviewer_ref=reviewer_ref,
            typed_confirmation=typed_confirmation,
            required_confirmation=f"DISABLE {peer_id}",
        )

    def require_active(
        self,
        *,
        peer_id: str,
        protocol: ProtocolKind,
        capability_id: str,
        risk: RiskLevel,
        classification: DataClassification,
        now: datetime,
    ) -> TrustEntry:
        with self._lock:
            current = self._current(peer_id)
            if current is None or current.protocol is not protocol:
                raise PolicyDenied("peer is not registered for this protocol")
            if current.status is not TrustStatus.ACTIVE:
                raise PolicyDenied("peer trust is not active")
            if current.expires_at <= now or current.review_after <= now:
                raise PolicyDenied("peer trust review is expired")
            if capability_id not in current.allowed_capabilities:
                raise PolicyDenied("peer capability is not allowed")
            if risk not in current.allowed_risks:
                raise PolicyDenied("peer risk is not allowed")
            if classification not in current.allowed_classifications:
                raise PolicyDenied("peer classification is not allowed")
            return current

    def get(self, peer_id: str) -> TrustEntry | None:
        with self._lock:
            return self._current(peer_id)

    def history(self, peer_id: str) -> tuple[TrustEntry, ...]:
        with self._lock:
            return tuple(self._entries.get(peer_id, ()))

    def _transition(
        self,
        *,
        peer_id: str,
        expected_revision: int,
        now: datetime,
        target: TrustStatus,
        reviewer_ref: str,
        typed_confirmation: str,
        required_confirmation: str,
    ) -> TrustEntry:
        if typed_confirmation != required_confirmation:
            raise PayloadRejected("typed trust confirmation is invalid")
        with self._lock:
            current = self._current(peer_id)
            if current is None:
                raise PolicyDenied("peer is unavailable")
            if current.revision != expected_revision:
                raise ConcurrencyConflict("peer trust revision is stale")
            if target is TrustStatus.ACTIVE and current.status is not (
                TrustStatus.PENDING_REVIEW
            ):
                raise PolicyDenied("only pending trust can be activated")
            if target is not TrustStatus.ACTIVE and current.status in {
                TrustStatus.REVOKED,
                TrustStatus.EMERGENCY_DISABLED,
            }:
                raise PolicyDenied("terminal peer trust cannot transition")
            updated = current.model_copy(
                update={
                    "revision": current.revision + 1,
                    "status": target,
                    "reviewed_by": tuple(sorted({*current.reviewed_by, reviewer_ref})),
                    "reviewed_at": now,
                    "change_digest": digest_value(
                        {
                            "previous": current.change_digest,
                            "revision": current.revision + 1,
                            "reviewer_ref": reviewer_ref,
                            "status": target,
                        }
                    ),
                }
            )
            self._entries[peer_id].append(updated)
            return updated

    def _current(self, peer_id: str) -> TrustEntry | None:
        entries = self._entries.get(peer_id)
        return entries[-1] if entries else None


class WorkloadIdentityAssertion(StrictModel):
    schema_version: Literal[1] = 1
    principal_ref: Identifier
    issuer_digest: Sha256Digest
    audience: Identifier
    scopes: tuple[Identifier, ...] = Field(min_length=1, max_length=32)
    tenant_ref: OpaqueReference
    purpose: Identifier
    token_id_digest: Sha256Digest
    proof_digest: Sha256Digest
    confirmation_digest: Sha256Digest
    issued_at: AwareDatetime
    expires_at: AwareDatetime

    @field_validator("scopes")
    @classmethod
    def normalize_assertion_scopes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(value)))

    @model_validator(mode="after")
    def validate_lifetime(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("workload assertion expiry must follow issue time")
        return self


class ReplayCache(Protocol):
    distributed: bool

    def consume(self, token_id_digest: str, *, expires_at: datetime) -> bool: ...


class InMemoryReplayCache:
    """Bounded deterministic cache; deliberately not production-ready."""

    distributed = False

    def __init__(self, *, maximum_entries: int = 10_000) -> None:
        if maximum_entries < 1:
            raise ValueError("replay cache bound is invalid")
        self._maximum_entries = maximum_entries
        self._entries: dict[str, datetime] = {}
        self._lock = Lock()

    def consume(self, token_id_digest: str, *, expires_at: datetime) -> bool:
        with self._lock:
            if token_id_digest in self._entries:
                return False
            if len(self._entries) >= self._maximum_entries:
                oldest = min(self._entries, key=self._entries.__getitem__)
                del self._entries[oldest]
            self._entries[token_id_digest] = expires_at
            return True


class WorkloadIdentityPolicy(StrictModel):
    audience: Identifier
    allowed_issuer_digests: tuple[Sha256Digest, ...] = Field(
        min_length=1, max_length=16
    )
    required_scopes: tuple[Identifier, ...] = Field(min_length=1, max_length=16)
    allowed_purposes: tuple[Identifier, ...] = Field(min_length=1, max_length=16)
    maximum_lifetime_seconds: int = Field(ge=30, le=3_600)
    require_mutual_tls: bool = True
    allowed_principals: tuple[Identifier, ...] = Field(min_length=1, max_length=128)


class WorkloadIdentityValidator:
    """Validate verified OIDC/workload claims against application RBAC."""

    def __init__(
        self,
        *,
        policy: WorkloadIdentityPolicy,
        replay_cache: ReplayCache,
        mutual_tls_ready: Callable[[], bool],
        production: bool,
    ) -> None:
        self._policy = policy
        self._replay_cache = replay_cache
        self._mutual_tls_ready = mutual_tls_ready
        self._production = production

    def ready(self) -> bool:
        if not self._production:
            return True
        return (
            self._replay_cache.distributed
            and self._mutual_tls_ready()
            and self._policy.require_mutual_tls
        )

    def validate(
        self,
        assertion: WorkloadIdentityAssertion,
        *,
        expected_tenant_ref: str,
        expected_purpose: str,
        channel_binding_digest: str,
        now: datetime,
    ) -> PrincipalContract:
        if not self.ready():
            raise RepositoryUnavailable(
                "production workload identity requires distributed replay and mTLS"
            )
        if assertion.issuer_digest not in self._policy.allowed_issuer_digests:
            raise AuthenticationFailed("workload issuer is not trusted")
        if assertion.audience != self._policy.audience:
            raise AuthenticationFailed("workload audience is invalid")
        if assertion.principal_ref not in self._policy.allowed_principals:
            raise PolicyDenied("workload principal is not allowed")
        if assertion.tenant_ref != expected_tenant_ref:
            raise PolicyDenied("workload tenant binding is invalid")
        if (
            assertion.purpose != expected_purpose
            or assertion.purpose not in self._policy.allowed_purposes
        ):
            raise PolicyDenied("workload purpose is not allowed")
        if not set(self._policy.required_scopes).issubset(assertion.scopes):
            raise PolicyDenied("workload scopes are insufficient")
        if not hmac.compare_digest(
            assertion.confirmation_digest,
            channel_binding_digest,
        ):
            raise AuthenticationFailed("workload proof is not channel-bound")
        lifetime = (assertion.expires_at - assertion.issued_at).total_seconds()
        if assertion.issued_at > now or assertion.expires_at <= now:
            raise AuthenticationFailed("workload assertion is outside its validity")
        if lifetime > self._policy.maximum_lifetime_seconds:
            raise AuthenticationFailed("workload assertion lifetime is too long")
        if not self._replay_cache.consume(
            assertion.token_id_digest,
            expires_at=assertion.expires_at,
        ):
            raise AuthenticationFailed("workload assertion replay was detected")
        return PrincipalContract(
            principal_ref=assertion.principal_ref,
            kind="workload",
            issuer_digest=assertion.issuer_digest,
            audience=assertion.audience,
            scopes=assertion.scopes,
            tenant_ref=assertion.tenant_ref,
            purpose=assertion.purpose,
            proof_digest=assertion.proof_digest,
            authenticated_at=now,
            expires_at=assertion.expires_at,
        )


class InteroperabilityFactType(StrEnum):
    TRUST_REGISTERED = "interop.trust_registered"
    TRUST_REVIEWED = "interop.trust_reviewed"
    TRUST_QUARANTINED = "interop.trust_quarantined"
    TRUST_REVOKED = "interop.trust_revoked"
    INVOCATION_REQUESTED = "interop.invocation_requested"
    INVOCATION_CLAIMED = "interop.invocation_claimed"
    INVOCATION_SUCCEEDED = "interop.invocation_succeeded"
    INVOCATION_FAILED = "interop.invocation_failed"
    INVOCATION_AMBIGUOUS = "interop.invocation_ambiguous"
    INVOCATION_RECONCILED = "interop.invocation_reconciled"
    TASK_CANCEL_REQUESTED = "interop.task_cancel_requested"
    TASK_CANCELLED = "interop.task_cancelled"
    ARTIFACT_ACCEPTED = "interop.artifact_accepted"
    ARTIFACT_QUARANTINED = "interop.artifact_quarantined"
    PROPOSAL_SUBMITTED = "interop.proposal_submitted"


class InteroperabilityFact(StrictModel):
    schema_version: Literal[1] = 1
    fact_id: Identifier
    operation_id: Identifier
    sequence: int = Field(ge=1, le=128)
    fact_type: InteroperabilityFactType
    command_ref: Identifier
    actor_ref: Identifier
    peer_id: Identifier
    payload: dict[str, JsonValue] = Field(max_length=32)
    previous_digest: Sha256Digest
    fact_digest: Sha256Digest
    recorded_at: AwareDatetime

    @model_validator(mode="after")
    def validate_fact(self) -> Self:
        reject_raw_ledger_payload(self.payload)
        material = self.model_dump(mode="json", exclude={"fact_digest"})
        if digest_value(material) != self.fact_digest:
            raise ValueError("interoperability fact digest is invalid")
        return self


class InvocationProjection(StrictModel):
    operation_id: Identifier
    tenant_ref: OpaqueReference
    peer_id: Identifier
    protocol: ProtocolKind
    capability_id: Identifier
    risk: RiskLevel
    state: InvocationState
    version: int = Field(ge=1)
    request_digest: Sha256Digest
    trust_digest: Sha256Digest
    policy_digest: Sha256Digest
    trust_revision: int = Field(ge=1)
    fence_token: Identifier
    cursor_digest: Sha256Digest | None = None
    result_digest: Sha256Digest | None = None
    error_code: Identifier | None = None
    ambiguous: bool = False
    cancellation_requested: bool = False
    updated_at: AwareDatetime


class InteroperabilityLedger:
    """Digest-only application ledger; framework histories receive references."""

    def __init__(self) -> None:
        self._facts: dict[str, list[InteroperabilityFact]] = defaultdict(list)
        self._commands: dict[str, tuple[str, str]] = {}
        self._projections: dict[str, InvocationProjection] = {}
        self._lock = Lock()

    def append(
        self,
        *,
        operation_id: str,
        fact_type: InteroperabilityFactType,
        command_ref: str,
        actor_ref: str,
        peer_id: str,
        payload: Mapping[str, JsonValue],
        recorded_at: datetime,
        projection: InvocationProjection | None = None,
    ) -> InteroperabilityFact:
        reject_raw_ledger_payload(payload)
        payload_digest = digest_value(dict(payload))
        with self._lock:
            existing_command = self._commands.get(command_ref)
            if existing_command is not None:
                if existing_command != (operation_id, payload_digest):
                    raise IdempotencyConflict(
                        "interoperability command conflicts with an existing fact"
                    )
                if projection is not None:
                    current = self._projections.get(operation_id)
                    if current is None or projection.version != current.version + 1:
                        raise ConcurrencyConflict(
                            "duplicate interoperability claim is stale"
                        )
                return next(
                    fact
                    for fact in self._facts[operation_id]
                    if fact.command_ref == command_ref
                )
            facts = self._facts[operation_id]
            previous = facts[-1].fact_digest if facts else "0" * 64
            sequence = len(facts) + 1
            material: dict[str, object] = {
                "actor_ref": actor_ref,
                "command_ref": command_ref,
                "fact_id": f"interop-fact-{operation_id}-{sequence}",
                "fact_type": fact_type.value,
                "operation_id": operation_id,
                "payload": dict(payload),
                "peer_id": peer_id,
                "previous_digest": previous,
                "recorded_at": recorded_at,
                "schema_version": 1,
                "sequence": sequence,
            }
            fact = InteroperabilityFact(
                **material,
                fact_digest=digest_value(material),
            )
            if projection is not None:
                current = self._projections.get(operation_id)
                expected = 1 if current is None else current.version + 1
                if projection.version != expected:
                    raise ConcurrencyConflict(
                        "interoperability projection version is stale"
                    )
                self._projections[operation_id] = projection
            facts.append(fact)
            self._commands[command_ref] = (operation_id, payload_digest)
            return fact

    def facts(self, operation_id: str) -> tuple[InteroperabilityFact, ...]:
        with self._lock:
            return tuple(self._facts.get(operation_id, ()))

    def projection(self, operation_id: str) -> InvocationProjection | None:
        with self._lock:
            return self._projections.get(operation_id)

    def verify(self, operation_id: str) -> bool:
        previous = "0" * 64
        for expected_sequence, fact in enumerate(self.facts(operation_id), start=1):
            if fact.sequence != expected_sequence or fact.previous_digest != previous:
                return False
            if (
                digest_value(fact.model_dump(mode="json", exclude={"fact_digest"}))
                != fact.fact_digest
            ):
                return False
            previous = fact.fact_digest
        return True


class InvocationQuota:
    """Reference single-process quota; PostgreSQL owns distributed enforcement."""

    def __init__(
        self,
        *,
        request_limit: int,
        cost_limit: int,
    ) -> None:
        if request_limit < 1 or cost_limit < 0:
            raise ValueError("invocation quota is invalid")
        self._request_limit = request_limit
        self._cost_limit = cost_limit
        self._usage: dict[str, tuple[int, int]] = {}
        self._reservations: dict[str, tuple[str, int]] = {}
        self._lock = Lock()

    def reserve(
        self,
        *,
        tenant_ref: str,
        reservation_id: str,
        cost_units: int,
    ) -> None:
        if cost_units < 0:
            raise ValueError("cost reservation cannot be negative")
        with self._lock:
            existing = self._reservations.get(reservation_id)
            if existing is not None:
                if existing != (tenant_ref, cost_units):
                    raise IdempotencyConflict("quota reservation conflicts")
                return
            requests, cost = self._usage.get(tenant_ref, (0, 0))
            if (
                requests + 1 > self._request_limit
                or cost + cost_units > self._cost_limit
            ):
                raise PolicyDenied("interoperability quota is exhausted")
            self._usage[tenant_ref] = (requests + 1, cost + cost_units)
            self._reservations[reservation_id] = (tenant_ref, cost_units)

    def usage(self, tenant_ref: str) -> tuple[int, int]:
        with self._lock:
            return self._usage.get(tenant_ref, (0, 0))


class CircuitBreaker:
    def __init__(
        self,
        *,
        failure_threshold: int = 3,
        cooldown_seconds: float = 30.0,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if failure_threshold < 1 or failure_threshold > 20:
            raise ValueError("circuit threshold is invalid")
        if cooldown_seconds <= 0 or cooldown_seconds > 3_600:
            raise ValueError("circuit cooldown is invalid")
        self._failure_threshold = failure_threshold
        self._cooldown_seconds = cooldown_seconds
        self._clock = clock
        self._failures: dict[str, int] = defaultdict(int)
        self._opened_at: dict[str, float] = {}
        self._lock = Lock()

    def allow(self, peer_id: str) -> bool:
        with self._lock:
            if self._failures[peer_id] < self._failure_threshold:
                return True
            opened_at = self._opened_at.get(peer_id)
            if (
                opened_at is not None
                and self._clock() - opened_at >= self._cooldown_seconds
            ):
                self._failures[peer_id] = self._failure_threshold - 1
                self._opened_at.pop(peer_id, None)
                return True
            return False

    def record(self, peer_id: str, *, success: bool) -> None:
        with self._lock:
            if success:
                self._failures[peer_id] = 0
                self._opened_at.pop(peer_id, None)
            else:
                self._failures[peer_id] += 1
                if self._failures[peer_id] >= self._failure_threshold:
                    self._opened_at.setdefault(peer_id, self._clock())


class ProtocolPolicyPort(Protocol):
    def authorize(
        self,
        *,
        principal: PrincipalContract,
        peer: TrustEntry,
        capability: CapabilityContract,
        request_digest: str,
    ) -> PolicyContract: ...


class ProtocolTransportPort(Protocol):
    def invoke(
        self,
        *,
        peer: TrustEntry,
        task: TaskContract,
        message: MessageContract,
        timeout_seconds: float,
        cancelled: Callable[[], bool],
    ) -> tuple[StatusContract, tuple[ArtifactContract, ...]]: ...

    def reconcile(
        self,
        *,
        peer: TrustEntry,
        task: TaskContract,
        timeout_seconds: float,
    ) -> tuple[StatusContract, tuple[ArtifactContract, ...]]: ...

    def cancel(
        self,
        *,
        peer: TrustEntry,
        task: TaskContract,
        timeout_seconds: float,
    ) -> StatusContract: ...


class InvocationResult(StrictModel):
    task: TaskContract
    status: StatusContract
    artifacts: tuple[ArtifactContract, ...] = Field(max_length=64)
    replayed: bool = False


class ExternalInvocationGateway:
    """Application-owned durable controls around an untrusted protocol adapter."""

    def __init__(
        self,
        *,
        registry: TrustRegistry,
        policy: ProtocolPolicyPort,
        ledger: InteroperabilityLedger,
        quota: InvocationQuota,
        circuit: CircuitBreaker,
        transport: ProtocolTransportPort,
        now: Callable[[], datetime],
    ) -> None:
        self._registry = registry
        self._policy = policy
        self._ledger = ledger
        self._quota = quota
        self._circuit = circuit
        self._transport = transport
        self._now = now

    def invoke(
        self,
        *,
        principal: PrincipalContract,
        capability: CapabilityContract,
        peer_id: str,
        message: MessageContract,
        operation_id: str,
        command_ref: str,
        idempotency_key: str,
        tenant_ref: str,
        classification: DataClassification,
        cost_units: int,
        timeout_seconds: float,
        cancelled: Callable[[], bool],
    ) -> InvocationResult:
        if principal.tenant_ref != tenant_ref:
            raise PolicyDenied("principal tenant reference does not match invocation")
        if timeout_seconds <= 0 or timeout_seconds > 120:
            raise PayloadRejected("protocol timeout is outside the bound")
        if not self._circuit.allow(peer_id):
            raise RepositoryUnavailable("peer circuit is open")
        now = self._now()
        request_digest = digest_value(message.model_dump(mode="json"))
        existing = self._ledger.projection(operation_id)
        if existing is not None:
            if existing.tenant_ref != principal.tenant_ref:
                raise PolicyDenied("invocation tenant binding is invalid")
            if existing.request_digest != request_digest:
                raise IdempotencyConflict("operation ID has a different request")
            if existing.state is InvocationState.AMBIGUOUS:
                raise ReconciliationRequired(
                    "ambiguous invocation requires reconciliation"
                )
            status = StatusContract(
                state=_task_state(existing.state),
                progress_percent=100
                if existing.state is InvocationState.SUCCEEDED
                else 0,
                sequence=existing.version,
                status_digest=digest_value(existing.model_dump(mode="json")),
                occurred_at=existing.updated_at,
            )
            return InvocationResult(
                task=self._task_from_projection(
                    existing,
                    principal=principal,
                    idempotency_key=idempotency_key,
                    now=now,
                ),
                status=status,
                artifacts=(),
                replayed=True,
            )
        peer = self._registry.require_active(
            peer_id=peer_id,
            protocol=capability.protocol,
            capability_id=capability.capability_id,
            risk=capability.risk,
            classification=classification,
            now=now,
        )
        policy = self._policy.authorize(
            principal=principal,
            peer=peer,
            capability=capability,
            request_digest=request_digest,
        )
        if policy.decision != "allow":
            raise PolicyDenied("application protocol policy denied the invocation")
        reservation_id = f"interop-reservation-{operation_id}"
        self._quota.reserve(
            tenant_ref=tenant_ref,
            reservation_id=reservation_id,
            cost_units=cost_units,
        )
        fence_token = f"interop-fence-{operation_id}-1"
        trust_digest = digest_value(peer.model_dump(mode="json"))
        task = TaskContract(
            task_id=f"interop-task-{operation_id}",
            protocol=capability.protocol,
            peer_id=peer_id,
            capability_id=capability.capability_id,
            tenant_ref=tenant_ref,
            principal_ref=principal.principal_ref,
            purpose=principal.purpose,
            request_digest=request_digest,
            idempotency_key_digest=digest_value(idempotency_key),
            policy_digest=policy.policy_digest,
            trust_revision=peer.revision,
            fence_token=fence_token,
            state=TaskState.SUBMITTED,
            created_at=now,
            updated_at=now,
            expires_at=principal.expires_at,
        )
        requested = InvocationProjection(
            operation_id=operation_id,
            tenant_ref=tenant_ref,
            peer_id=peer_id,
            protocol=capability.protocol,
            capability_id=capability.capability_id,
            risk=capability.risk,
            state=InvocationState.REQUESTED,
            version=1,
            request_digest=request_digest,
            trust_digest=trust_digest,
            policy_digest=policy.policy_digest,
            trust_revision=peer.revision,
            fence_token=fence_token,
            updated_at=now,
        )
        self._ledger.append(
            operation_id=operation_id,
            fact_type=InteroperabilityFactType.INVOCATION_REQUESTED,
            command_ref=command_ref,
            actor_ref=principal.principal_ref,
            peer_id=peer_id,
            payload={
                "capability_id": capability.capability_id,
                "cost_units": cost_units,
                "idempotency_key_digest": task.idempotency_key_digest,
                "policy_digest": policy.policy_digest,
                "request_digest": request_digest,
                "reservation_ref": reservation_id,
                "trust_digest": trust_digest,
            },
            recorded_at=now,
            projection=requested,
        )
        if cancelled():
            return self.cancel(
                principal=principal,
                operation_id=operation_id,
                command_ref=f"{command_ref}-cancel",
                timeout_seconds=timeout_seconds,
            )
        claimed_at = self._now()
        claimed = requested.model_copy(
            update={
                "state": InvocationState.CLAIMED,
                "version": 2,
                "updated_at": claimed_at,
            }
        )
        self._ledger.append(
            operation_id=operation_id,
            fact_type=InteroperabilityFactType.INVOCATION_CLAIMED,
            command_ref=f"{command_ref}-claim",
            actor_ref=principal.principal_ref,
            peer_id=peer_id,
            payload={
                "fence_token": fence_token,
                "request_digest": request_digest,
                "trust_revision": peer.revision,
            },
            recorded_at=claimed_at,
            projection=claimed,
        )
        try:
            status, artifacts = self._transport.invoke(
                peer=peer,
                task=task,
                message=message,
                timeout_seconds=timeout_seconds,
                cancelled=cancelled,
            )
            self._validate_result(
                peer=peer,
                capability=capability,
                task=task,
                status=status,
                artifacts=artifacts,
            )
        except (AmbiguousTransportError, TimeoutError, ConnectionError) as exc:
            self._circuit.record(peer_id, success=False)
            ambiguous_at = self._now()
            ambiguous = claimed.model_copy(
                update={
                    "state": InvocationState.AMBIGUOUS,
                    "version": 3,
                    "ambiguous": True,
                    "error_code": "transport-ambiguous",
                    "updated_at": ambiguous_at,
                }
            )
            self._ledger.append(
                operation_id=operation_id,
                fact_type=InteroperabilityFactType.INVOCATION_AMBIGUOUS,
                command_ref=f"{command_ref}-ambiguous",
                actor_ref=principal.principal_ref,
                peer_id=peer_id,
                payload={
                    "error_code": "transport-ambiguous",
                    "fence_token": fence_token,
                    "request_digest": request_digest,
                },
                recorded_at=ambiguous_at,
                projection=ambiguous,
            )
            raise ReconciliationRequired(
                "protocol outcome is ambiguous; observe before retry"
            ) from exc
        except Exception:
            self._circuit.record(peer_id, success=False)
            failed_at = self._now()
            failed = claimed.model_copy(
                update={
                    "state": InvocationState.FAILED,
                    "version": 3,
                    "error_code": "peer-result-rejected",
                    "updated_at": failed_at,
                }
            )
            self._ledger.append(
                operation_id=operation_id,
                fact_type=InteroperabilityFactType.INVOCATION_FAILED,
                command_ref=f"{command_ref}-failed",
                actor_ref=principal.principal_ref,
                peer_id=peer_id,
                payload={
                    "error_code": "peer-result-rejected",
                    "request_digest": request_digest,
                },
                recorded_at=failed_at,
                projection=failed,
            )
            raise
        self._circuit.record(peer_id, success=True)
        result_digest = digest_value(
            {
                "artifacts": [
                    artifact.model_dump(mode="json") for artifact in artifacts
                ],
                "status": status.model_dump(mode="json"),
            }
        )
        completed_at = self._now()
        completed = claimed.model_copy(
            update={
                "state": InvocationState.SUCCEEDED,
                "version": 3,
                "result_digest": result_digest,
                "updated_at": completed_at,
            }
        )
        self._ledger.append(
            operation_id=operation_id,
            fact_type=InteroperabilityFactType.INVOCATION_SUCCEEDED,
            command_ref=f"{command_ref}-succeeded",
            actor_ref=principal.principal_ref,
            peer_id=peer_id,
            payload={
                "artifact_count": len(artifacts),
                "result_digest": result_digest,
                "status_digest": status.status_digest,
            },
            recorded_at=completed_at,
            projection=completed,
        )
        return InvocationResult(
            task=task.model_copy(
                update={
                    "state": TaskState.COMPLETED,
                    "updated_at": completed_at,
                    "result_digest": result_digest,
                }
            ),
            status=status,
            artifacts=artifacts,
        )

    def reconcile(
        self,
        *,
        principal: PrincipalContract,
        operation_id: str,
        command_ref: str,
        classification: DataClassification,
        timeout_seconds: float,
    ) -> InvocationResult:
        current = self._ledger.projection(operation_id)
        if current is None or current.state is not InvocationState.AMBIGUOUS:
            raise PolicyDenied("only ambiguous invocations can be reconciled")
        if current.tenant_ref != principal.tenant_ref:
            raise PolicyDenied("invocation tenant binding is invalid")
        now = self._now()
        peer = self._registry.require_active(
            peer_id=current.peer_id,
            protocol=current.protocol,
            capability_id=current.capability_id,
            risk=current.risk,
            classification=classification,
            now=now,
        )
        if digest_value(peer.model_dump(mode="json")) != current.trust_digest:
            raise PolicyDenied("peer trust changed before reconciliation")
        task = self._task_from_projection(
            current,
            principal=principal,
            idempotency_key=operation_id,
            now=now,
        )
        status, artifacts = self._transport.reconcile(
            peer=peer,
            task=task,
            timeout_seconds=timeout_seconds,
        )
        if status.state not in {TaskState.COMPLETED, TaskState.FAILED}:
            raise ReconciliationRequired("peer reconciliation remains inconclusive")
        result_digest = digest_value(
            {
                "artifacts": [
                    artifact.model_dump(mode="json") for artifact in artifacts
                ],
                "status": status.model_dump(mode="json"),
            }
        )
        reconciled = current.model_copy(
            update={
                "state": InvocationState.RECONCILED,
                "version": current.version + 1,
                "ambiguous": False,
                "result_digest": result_digest,
                "updated_at": now,
            }
        )
        self._ledger.append(
            operation_id=operation_id,
            fact_type=InteroperabilityFactType.INVOCATION_RECONCILED,
            command_ref=command_ref,
            actor_ref=principal.principal_ref,
            peer_id=current.peer_id,
            payload={
                "artifact_count": len(artifacts),
                "result_digest": result_digest,
                "status_digest": status.status_digest,
            },
            recorded_at=now,
            projection=reconciled,
        )
        return InvocationResult(
            task=task.model_copy(
                update={
                    "state": status.state,
                    "updated_at": now,
                    "result_digest": result_digest,
                }
            ),
            status=status,
            artifacts=artifacts,
        )

    def cancel(
        self,
        *,
        principal: PrincipalContract,
        operation_id: str,
        command_ref: str,
        timeout_seconds: float,
    ) -> InvocationResult:
        current = self._ledger.projection(operation_id)
        if current is None:
            raise PolicyDenied("invocation is unavailable")
        if current.tenant_ref != principal.tenant_ref:
            raise PolicyDenied("invocation tenant binding is invalid")
        if current.state in {
            InvocationState.SUCCEEDED,
            InvocationState.FAILED,
            InvocationState.CANCELLED,
            InvocationState.RECONCILED,
            InvocationState.QUARANTINED,
        }:
            raise PolicyDenied("terminal invocation cannot be cancelled")
        now = self._now()
        peer = self._registry.get(current.peer_id)
        if peer is None:
            raise PolicyDenied("peer is unavailable")
        requested = current.model_copy(
            update={
                "version": current.version + 1,
                "cancellation_requested": True,
                "updated_at": now,
            }
        )
        self._ledger.append(
            operation_id=operation_id,
            fact_type=InteroperabilityFactType.TASK_CANCEL_REQUESTED,
            command_ref=command_ref,
            actor_ref=principal.principal_ref,
            peer_id=current.peer_id,
            payload={
                "fence_token": current.fence_token,
                "request_digest": current.request_digest,
            },
            recorded_at=now,
            projection=requested,
        )
        task = self._task_from_projection(
            requested,
            principal=principal,
            idempotency_key=operation_id,
            now=now,
        )
        status = self._transport.cancel(
            peer=peer,
            task=task,
            timeout_seconds=timeout_seconds,
        )
        if status.state is not TaskState.CANCELLED:
            raise ReconciliationRequired("peer cancellation is not confirmed")
        cancelled_at = self._now()
        cancelled_projection = requested.model_copy(
            update={
                "state": InvocationState.CANCELLED,
                "version": requested.version + 1,
                "updated_at": cancelled_at,
            }
        )
        self._ledger.append(
            operation_id=operation_id,
            fact_type=InteroperabilityFactType.TASK_CANCELLED,
            command_ref=f"{command_ref}-confirmed",
            actor_ref=principal.principal_ref,
            peer_id=current.peer_id,
            payload={"status_digest": status.status_digest},
            recorded_at=cancelled_at,
            projection=cancelled_projection,
        )
        return InvocationResult(
            task=task.model_copy(
                update={"state": TaskState.CANCELLED, "updated_at": cancelled_at}
            ),
            status=status,
            artifacts=(),
        )

    def _task_from_projection(
        self,
        projection: InvocationProjection,
        *,
        principal: PrincipalContract,
        idempotency_key: str,
        now: datetime,
    ) -> TaskContract:
        return TaskContract(
            task_id=f"interop-task-{projection.operation_id}",
            protocol=projection.protocol,
            peer_id=projection.peer_id,
            capability_id=projection.capability_id,
            tenant_ref=projection.tenant_ref,
            principal_ref=principal.principal_ref,
            purpose=principal.purpose,
            request_digest=projection.request_digest,
            idempotency_key_digest=digest_value(idempotency_key),
            policy_digest=projection.policy_digest,
            trust_revision=projection.trust_revision,
            fence_token=projection.fence_token,
            state=_task_state(projection.state),
            created_at=now,
            updated_at=now,
            expires_at=principal.expires_at,
            result_digest=projection.result_digest,
            error_code=projection.error_code,
        )

    def _validate_result(
        self,
        *,
        peer: TrustEntry,
        capability: CapabilityContract,
        task: TaskContract,
        status: StatusContract,
        artifacts: Sequence[ArtifactContract],
    ) -> None:
        if status.state is not TaskState.COMPLETED:
            raise PayloadRejected("peer did not return a completed task")
        if len(artifacts) > 64:
            raise PayloadRejected("peer returned too many artifacts")
        total = 0
        for artifact in artifacts:
            if (
                artifact.task_id != task.task_id
                or artifact.producer_peer_id != peer.peer_id
            ):
                raise PayloadRejected("peer artifact provenance is invalid")
            if (
                artifact.card_digest != peer.card_digest
                and peer.protocol is ProtocolKind.A2A
            ):
                raise PayloadRejected("peer artifact card pin is invalid")
            if artifact.capability_digest != digest_value(
                capability.model_dump(mode="json")
            ):
                raise PayloadRejected("peer artifact capability pin is invalid")
            total += len(canonical_json(artifact.model_dump(mode="json")))
        if total > peer.maximum_response_bytes:
            raise PayloadRejected("peer artifacts exceed the response bound")


def validate_untrusted_text(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    if normalized != value:
        raise ValueError("protocol text must already use NFC normalization")
    if any(character in _FORBIDDEN_BIDI for character in value):
        raise ValueError("protocol text contains bidirectional control characters")
    for character in value:
        category = unicodedata.category(character)
        if category == "Cc" and character not in {"\n", "\r", "\t"}:
            raise ValueError("protocol text contains a control character")
    if len(value) > MAX_PROTOCOL_TEXT_CHARS:
        raise ValueError("protocol text exceeds its bound")
    return value


def canonical_json(value: object) -> bytes:
    normalized = _normalize_json(value)
    _bound_json(normalized)
    return json.dumps(
        normalized,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def digest_value(value: object) -> str:
    return sha256(canonical_json(value)).hexdigest()


def reject_raw_ledger_payload(payload: Mapping[str, object]) -> None:
    for key, value in payload.items():
        normalized = key.lower()
        if normalized in _FORBIDDEN_LEDGER_KEYS or (
            any(
                token in normalized
                for token in (
                    "credential",
                    "evidence_locator",
                    "prompt",
                    "secret",
                    "token",
                )
            )
            and normalized not in _SAFE_LEDGER_TOKEN_KEYS
        ):
            raise IntegrityFailure(
                "raw protocol content is forbidden in the application ledger"
            )
        _bound_json(value)


def _bound_json(value: object, *, depth: int = 0) -> None:
    if depth > 12:
        raise PayloadRejected("protocol JSON exceeds the nesting bound")
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, str):
        validate_untrusted_text(value)
        return
    if isinstance(value, list | tuple):
        if len(value) > 256:
            raise PayloadRejected("protocol JSON array exceeds the item bound")
        for item in value:
            _bound_json(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > 128:
            raise PayloadRejected("protocol JSON object exceeds the member bound")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 128:
                raise PayloadRejected("protocol JSON key is invalid")
            validate_untrusted_text(key)
            _bound_json(item, depth=depth + 1)
        return
    raise PayloadRejected("protocol document contains an unsupported value")


def _normalize_json(value: object, *, depth: int = 0) -> object:
    if depth > 12:
        raise PayloadRejected("protocol JSON exceeds the nesting bound")
    if isinstance(value, BaseModel):
        return _normalize_json(value.model_dump(mode="json"), depth=depth + 1)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise PayloadRejected("protocol datetime must be timezone-aware")
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise PayloadRejected("protocol JSON contains a non-finite number")
        return value
    if isinstance(value, list | tuple):
        return [_normalize_json(item, depth=depth + 1) for item in value]
    if isinstance(value, dict):
        return {
            key: _normalize_json(item, depth=depth + 1) for key, item in value.items()
        }
    raise PayloadRejected("protocol document contains an unsupported value")


def _task_state(state: InvocationState) -> TaskState:
    return {
        InvocationState.REQUESTED: TaskState.SUBMITTED,
        InvocationState.CLAIMED: TaskState.WORKING,
        InvocationState.SUCCEEDED: TaskState.COMPLETED,
        InvocationState.FAILED: TaskState.FAILED,
        InvocationState.AMBIGUOUS: TaskState.RECONCILIATION_REQUIRED,
        InvocationState.CANCELLED: TaskState.CANCELLED,
        InvocationState.RECONCILED: TaskState.COMPLETED,
        InvocationState.QUARANTINED: TaskState.QUARANTINED,
    }[state]
