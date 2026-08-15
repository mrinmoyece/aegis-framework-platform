"""Provider-neutral domain models and graph state."""

from __future__ import annotations

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


class InvestigationStatus(StrEnum):
    COMPLETE = "complete"
    ABSTAINED = "abstained"
    DENIED = "denied"


class CriticDecision(StrEnum):
    ACCEPTED = "accepted"
    ABSTAINED = "abstained"
    REJECTED = "rejected"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class IdentityContext(StrictModel):
    tenant_id: Identifier
    subject_id: Identifier
    roles: tuple[Identifier, ...]
    request_id: Identifier
    trace_id: Identifier

    @field_validator("roles")
    @classmethod
    def normalize_roles(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(value)))


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
    untrusted_text: Annotated[str | None, Field(max_length=2_000)] = None


class ModelEvidence(StrictModel):
    evidence_id: Identifier
    kind: EvidenceKind
    locator: Annotated[str, Field(min_length=1, max_length=512)]
    content_hash: Sha256Digest
    facts: Annotated[dict[str, BoundedFactValue], Field(min_length=1, max_length=32)]


class Citation(StrictModel):
    evidence_id: Identifier
    locator: Annotated[str, Field(min_length=1, max_length=512)]
    content_hash: Sha256Digest


class SpecialistTask(StrictModel):
    incident_id: Identifier
    specialist: Specialist
    evidence: tuple[ModelEvidence, ...]


class SpecialistFinding(StrictModel):
    finding_id: Identifier
    specialist: Specialist
    statement: Annotated[str, Field(min_length=1, max_length=1_000)]
    cause_code: Identifier | None
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    citations: tuple[Citation, ...]
    abstained: bool = False
    reason: Annotated[str | None, Field(max_length=500)] = None

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
    citations: Annotated[tuple[Citation, ...], Field(min_length=1)]


class CriticVerdict(StrictModel):
    decision: CriticDecision
    reasons: tuple[str, ...]
    checked_citations: Annotated[int, Field(ge=0)]
    contradictions: tuple[str, ...] = ()
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
    request_id: Identifier
    thread_ref: Identifier
    hypotheses: tuple[Hypothesis, ...]
    critic: CriticVerdict
    proposal: RemediationProposal | None
    approval: ApprovalRequest | None = None
    replayed: bool = False
    framework: Literal["langgraph"] = "langgraph"
    graph_iterations: Literal[1] = 1


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


class InvestigationState(TypedDict, total=False):
    tenant_id: str
    incident_id: str
    request_id: str
    thread_ref: str
    evidence: tuple[StateRecord, ...]
    safe_evidence: tuple[StateRecord, ...]
    findings: Annotated[list[StateRecord], merge_findings]
    node_errors: Annotated[list[StateRecord], merge_node_errors]
    injection_detected: bool
    hypotheses: tuple[StateRecord, ...]
    critic: StateRecord
    proposal: StateRecord | None


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
) -> str:
    canonical_facts = "|".join(f"{key}={facts[key]!r}" for key in sorted(facts))
    material = (
        f"{tenant_id}\x00{kind.value}\x00{locator}\x00"
        f"{observed_at.isoformat()}\x00{canonical_facts}"
    )
    return sha256(material.encode()).hexdigest()
