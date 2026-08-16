"""Provider-neutral domain models and graph state."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from hashlib import sha256
from typing import Annotated, Literal, TypedDict

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_validator,
    model_validator,
)

Identifier = Annotated[
    str, Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9._:-]+$")
]
OpaqueReference = Annotated[
    str, Field(min_length=1, max_length=512, pattern=r"^[a-zA-Z0-9._:-]+$")
]
Issuer = Annotated[
    str,
    Field(
        min_length=8,
        max_length=512,
        pattern=r"^https?://[a-zA-Z0-9][a-zA-Z0-9._:-]*(?:/[a-zA-Z0-9._~:/-]*)?$",
    ),
]
SubjectIdentifier = Annotated[
    str, Field(min_length=1, max_length=255, pattern=r"^[\x21-\x7e]+$")
]
Sha256Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
type FactValue = str | int | float | bool | None
type StateRecord = dict[str, JsonValue]
FactText = Annotated[str, Field(max_length=512)]
type BoundedFactValue = FactText | int | float | bool | None


class StrictModel(BaseModel):
    """Base model that rejects undeclared data at every trust boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class EvidenceKind(StrEnum):
    TELEMETRY = "telemetry"
    CHANGE = "change"
    RUNBOOK = "runbook"


class Specialist(StrEnum):
    TELEMETRY = "telemetry"
    CHANGE = "change"
    RUNTIME = "runtime"
    KNOWLEDGE = "knowledge"


class InvestigationStatus(StrEnum):
    COMPLETE = "complete"
    ABSTAINED = "abstained"
    DENIED = "denied"
    CANCELLED = "cancelled"


class CriticDecision(StrEnum):
    ACCEPTED = "accepted"
    ABSTAINED = "abstained"
    REJECTED = "rejected"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class PrincipalKind(StrEnum):
    HUMAN = "human"
    WORKLOAD = "workload"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class GrantBinding(StrictModel):
    role: Identifier
    purpose: Identifier
    permissions: tuple[Identifier, ...]
    risk_ceiling: RiskLevel
    expires_at: AwareDatetime

    @field_validator("permissions")
    @classmethod
    def normalize_permissions(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(value)))


class IdentityContext(StrictModel):
    tenant_id: Identifier
    issuer: Issuer
    subject_id: SubjectIdentifier
    principal_kind: PrincipalKind
    roles: tuple[Identifier, ...]
    permissions: tuple[Identifier, ...]
    purposes: tuple[Identifier, ...]
    grants: tuple[GrantBinding, ...]
    grant_version: Annotated[int, Field(ge=1)]
    authenticated_at: AwareDatetime
    expires_at: AwareDatetime
    request_id: Identifier
    trace_id: Identifier

    @field_validator("roles", "permissions", "purposes")
    @classmethod
    def normalize_authority(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(value)))

    @field_validator("grants")
    @classmethod
    def normalize_grants(
        cls, value: tuple[GrantBinding, ...]
    ) -> tuple[GrantBinding, ...]:
        return tuple(
            sorted(
                set(value),
                key=lambda grant: (
                    grant.purpose,
                    grant.role,
                    grant.risk_ceiling.value,
                    grant.expires_at,
                ),
            )
        )

    @model_validator(mode="after")
    def validate_authority_projection(self) -> IdentityContext:
        if self.expires_at <= self.authenticated_at:
            raise ValueError("identity expiry must follow authentication")
        expected_roles = tuple(sorted({grant.role for grant in self.grants}))
        expected_permissions = tuple(
            sorted(
                {
                    permission
                    for grant in self.grants
                    for permission in grant.permissions
                }
            )
        )
        expected_purposes = tuple(sorted({grant.purpose for grant in self.grants}))
        if self.roles != expected_roles:
            raise ValueError("identity roles must match immutable grant bindings")
        if self.permissions != expected_permissions:
            raise ValueError("identity permissions must match immutable grant bindings")
        if self.purposes != expected_purposes:
            raise ValueError("identity purposes must match immutable grant bindings")
        return self


class CheckoutAlert(StrictModel):
    signal: Literal["checkout_failure_rate"]
    service: Literal["checkout-api"]
    region: Identifier
    observed_at: AwareDatetime
    failure_rate: Annotated[float, Field(ge=0.0, le=1.0)]
    threshold: Annotated[float, Field(gt=0.0, le=1.0)]


class InvestigationRequest(StrictModel):
    incident_id: Identifier
    alert: CheckoutAlert


class Evidence(StrictModel):
    evidence_id: Identifier
    tenant_id: Identifier
    kind: EvidenceKind
    source: Identifier
    locator: Annotated[str, Field(min_length=1, max_length=512)]
    observed_at: AwareDatetime
    summary: Annotated[str, Field(min_length=1, max_length=512)]
    facts: Annotated[dict[str, BoundedFactValue], Field(min_length=1, max_length=32)]
    content_hash: Sha256Digest
    untrusted_text: Annotated[str | None, Field(max_length=65_536)] = None
    provenance_digest: Sha256Digest | None = None
    source_id: Identifier | None = None
    query_id: Identifier | None = None
    page_number: int | None = Field(default=None, ge=1, le=100)

    @model_validator(mode="after")
    def bind_extended_provenance(self) -> Evidence:
        values = (
            self.provenance_digest,
            self.source_id,
            self.query_id,
            self.page_number,
        )
        if any(value is not None for value in values) and any(
            value is None for value in values
        ):
            raise ValueError("extended evidence provenance must be complete")
        return self


class ModelEvidence(StrictModel):
    evidence_id: Identifier
    kind: EvidenceKind
    locator: Annotated[str, Field(min_length=1, max_length=512)]
    content_hash: Sha256Digest
    facts: Annotated[dict[str, BoundedFactValue], Field(min_length=1, max_length=32)]
    provenance_digest: Sha256Digest | None = None
    source_id: Identifier | None = None
    query_id: Identifier | None = None
    page_number: int | None = Field(default=None, ge=1, le=100)

    @model_validator(mode="after")
    def bind_extended_provenance(self) -> ModelEvidence:
        values = (
            self.provenance_digest,
            self.source_id,
            self.query_id,
            self.page_number,
        )
        if any(value is not None for value in values) and any(
            value is None for value in values
        ):
            raise ValueError("model evidence provenance must be complete")
        return self


class Citation(StrictModel):
    evidence_id: Identifier
    locator: Annotated[str, Field(min_length=1, max_length=512)]
    content_hash: Sha256Digest
    provenance_digest: Sha256Digest | None = None
    source_id: Identifier | None = None
    query_id: Identifier | None = None
    page_number: int | None = Field(default=None, ge=1, le=100)

    @model_validator(mode="after")
    def bind_extended_provenance(self) -> Citation:
        values = (
            self.provenance_digest,
            self.source_id,
            self.query_id,
            self.page_number,
        )
        if any(value is not None for value in values) and any(
            value is None for value in values
        ):
            raise ValueError("citation provenance must be complete")
        return self


class CorrelationStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    CONFLICTED = "conflicted"
    STALE = "stale"


class TimelineEvidenceEvent(StrictModel):
    event_id: Identifier
    occurred_at: AwareDatetime
    kind: EvidenceKind
    statement: Annotated[str, Field(min_length=1, max_length=512)]
    citations: Annotated[tuple[Citation, ...], Field(min_length=1, max_length=16)]


class EvidenceLink(StrictModel):
    link_id: Identifier
    relation: Literal["temporal_proximity", "shared_fact"]
    left_evidence_id: Identifier
    right_evidence_id: Identifier
    fact_key: Identifier | None = None
    distance_seconds: int | None = Field(default=None, ge=0, le=604_800)
    causal: Literal[False] = False


class EvidenceConflict(StrictModel):
    conflict_id: Identifier
    fact_key: Identifier
    values: Annotated[tuple[FactText, ...], Field(min_length=2, max_length=16)]
    citations: Annotated[tuple[Citation, ...], Field(min_length=2, max_length=32)]


class CorrelationContext(StrictModel):
    status: CorrelationStatus
    timeline: Annotated[tuple[TimelineEvidenceEvent, ...], Field(max_length=1_000)]
    links: Annotated[tuple[EvidenceLink, ...], Field(max_length=2_000)]
    conflicts: Annotated[tuple[EvidenceConflict, ...], Field(max_length=1_000)]
    missing_sources: Annotated[tuple[EvidenceKind, ...], Field(max_length=16)]
    stale_sources: Annotated[tuple[EvidenceKind, ...], Field(max_length=16)]
    causal_claims_supported: Literal[False] = False


class SpecialistTask(StrictModel):
    tenant_id: Identifier
    run_id: Identifier
    incident_id: Identifier
    specialist: Specialist
    evidence: tuple[ModelEvidence, ...]
    correlation: CorrelationContext | None = None


class SpecialistFinding(StrictModel):
    finding_id: Identifier
    specialist: Specialist
    statement: Annotated[str, Field(min_length=1, max_length=1_000)]
    cause_code: Identifier | None
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    citations: Annotated[tuple[Citation, ...], Field(max_length=16)]
    abstained: bool = False
    reason: Annotated[str | None, Field(max_length=256)] = None

    @field_validator("citations")
    @classmethod
    def normalize_citations(cls, value: tuple[Citation, ...]) -> tuple[Citation, ...]:
        return tuple(sorted(value, key=lambda citation: citation.evidence_id))

    @model_validator(mode="after")
    def require_cited_non_abstaining_finding(self) -> SpecialistFinding:
        if self.abstained:
            if self.cause_code is not None or self.citations or self.confidence != 0.0:
                raise ValueError(
                    "abstaining findings cannot claim evidence or confidence"
                )
            return self
        if self.cause_code is None or not self.citations:
            raise ValueError("non-abstaining findings require a cause and citation")
        return self


class Hypothesis(StrictModel):
    hypothesis_id: Identifier
    rank: Annotated[int, Field(ge=1, le=10)]
    statement: Annotated[str, Field(min_length=1, max_length=1_000)]
    cause_code: Identifier
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    citations: Annotated[tuple[Citation, ...], Field(min_length=1, max_length=64)]


class CriticVerdict(StrictModel):
    decision: CriticDecision
    reasons: Annotated[tuple[str, ...], Field(max_length=16)]
    checked_citations: Annotated[int, Field(ge=0)]
    contradictions: Annotated[tuple[str, ...], Field(max_length=64)] = ()
    injection_contained: bool = False


class RemediationProposal(StrictModel):
    proposal_id: Identifier
    action: Literal["rollback_candidate"]
    target: Identifier
    rationale: Annotated[str, Field(min_length=1, max_length=1_000)]
    risk: Literal["medium"]
    requires_approval: Literal[True] = True


class ApprovalRequest(StrictModel):
    approval_id: Identifier
    proposal_id: Identifier
    tenant_id: Identifier
    status: Literal[ApprovalStatus.PENDING] = ApprovalStatus.PENDING
    required_roles: tuple[Identifier, ...]
    created_at: AwareDatetime


class ApprovalGrant(StrictModel):
    approval_id: Identifier
    proposal_id: Identifier
    tenant_id: Identifier
    status: Literal[ApprovalStatus.APPROVED]
    approver_id: Identifier
    fencing_token: Identifier
    approved_at: AwareDatetime


class EffectReceipt(StrictModel):
    effect_id: Identifier
    proposal_id: Identifier
    status: Literal["executed", "verified"]
    fencing_token: Identifier
    recorded_at: AwareDatetime


class InvestigationResult(StrictModel):
    status: InvestigationStatus
    tenant_id: Identifier
    incident_id: Identifier
    run_id: Identifier
    request_id: Identifier
    thread_ref: Identifier
    hypotheses: tuple[Hypothesis, ...]
    critic: CriticVerdict
    proposal: RemediationProposal | None
    artifacts: Annotated[tuple[StateRecord, ...], Field(max_length=64)] = ()
    approval: ApprovalRequest | None = None
    replayed: bool = False
    framework: Literal["langgraph"] = "langgraph"
    graph_iterations: Literal[1] = 1
    graph_version: Literal["6.0.0"] = "6.0.0"


class NodeError(StrictModel):
    node: Identifier
    code: Identifier


def merge_findings(
    left: list[StateRecord], right: list[StateRecord]
) -> list[StateRecord]:
    """Merge parallel branch output without depending on scheduler order."""

    merged = {str(finding["finding_id"]): finding for finding in (*left, *right)}
    return sorted(
        merged.values(),
        key=lambda finding: (
            str(finding["specialist"]),
            str(finding["finding_id"]),
        ),
    )


def merge_node_errors(
    left: list[StateRecord], right: list[StateRecord]
) -> list[StateRecord]:
    merged = {
        (str(error["node"]), str(error["code"])): error for error in (*left, *right)
    }
    return sorted(
        merged.values(),
        key=lambda error: (str(error["node"]), str(error["code"])),
    )


def merge_artifacts(
    left: list[StateRecord], right: list[StateRecord]
) -> list[StateRecord]:
    merged: dict[str, StateRecord] = {}
    digests: dict[str, str] = {}
    for artifact in (*left, *right):
        artifact_id = str(artifact["artifact_id"])
        digest = str(artifact["canonical_digest"])
        existing = digests.get(artifact_id)
        if existing is not None and existing != digest:
            raise ValueError("artifact id was reused with a different digest")
        digests[artifact_id] = digest
        merged[artifact_id] = artifact
    return sorted(
        merged.values(),
        key=lambda artifact: (
            int(str(artifact["ordinal"])),
            str(artifact["artifact_id"]),
        ),
    )


def merge_cancelled(left: bool, right: bool) -> bool:
    return left or right


class InvestigationState(TypedDict, total=False):
    tenant_id: str
    incident_id: str
    run_id: str
    request_id: str
    thread_ref: str
    graph_version: str
    input_digest: str
    fence_token: str
    correlation_reference: str
    evidence: tuple[StateRecord, ...]
    safe_evidence: tuple[StateRecord, ...]
    correlation: StateRecord
    findings: Annotated[list[StateRecord], merge_findings]
    node_errors: Annotated[list[StateRecord], merge_node_errors]
    artifacts: Annotated[list[StateRecord], merge_artifacts]
    injection_detected: bool
    hypotheses: tuple[StateRecord, ...]
    critic: StateRecord
    proposal: StateRecord | None
    terminal_state: str
    critic_iteration: int
    cancelled: Annotated[bool, merge_cancelled]


def stable_id(prefix: str, *parts: str, length: int = 24) -> str:
    digest = sha256("\x00".join(parts).encode()).hexdigest()[:length]
    return f"{prefix}:{digest}"


def evidence_hash(
    *,
    tenant_id: str,
    kind: EvidenceKind,
    locator: str,
    observed_at: datetime,
    facts: Mapping[str, FactValue],
    summary: str,
    untrusted_text: str | None = None,
) -> str:
    # Use JSON for an unambiguous canonical serialisation that handles all
    # fact key/value types without delimiter-collision risk.
    canonical_facts = json.dumps(
        {key: facts[key] for key in sorted(facts)},
        separators=(",", ":"),
        ensure_ascii=False,
    )
    # Bind every field that influences safety decisions so that post-creation
    # mutations of summary or untrusted_text invalidate the content hash.
    material = "\x00".join(
        [
            tenant_id,
            kind.value,
            locator,
            observed_at.isoformat(),
            canonical_facts,
            summary,
            untrusted_text if untrusted_text is not None else "",
        ]
    )
    return sha256(material.encode()).hexdigest()
