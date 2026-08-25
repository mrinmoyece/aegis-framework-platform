"""Immutable provider-neutral contracts for evidence collection and provenance."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from typing import Annotated

from pydantic import (
    AwareDatetime,
    Field,
    JsonValue,
    field_validator,
    model_validator,
)

from aegis_framework.domain import (
    Evidence,
    EvidenceKind,
    Identifier,
    Sha256Digest,
    StrictModel,
)

_MAX_QUERY_WINDOW = timedelta(days=7)
_MAX_RECORD_BYTES = 2 * 1024 * 1024


class EvidenceSourceKind(StrEnum):
    DYNATRACE = "dynatrace"
    GITHUB = "github"
    KUBERNETES = "kubernetes"
    RUNBOOK = "runbook"


class SourceTrust(StrEnum):
    EXTERNAL_UNTRUSTED = "external_untrusted"
    PLATFORM_CONTROL_PLANE = "platform_control_plane"
    OPERATOR_APPROVED = "operator_approved"


class DataClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class EvidenceDisposition(StrEnum):
    ACCEPTED = "accepted"
    REDACTED = "redacted"
    QUARANTINED = "quarantined"
    DUPLICATE = "duplicate"


class QueryStatus(StrEnum):
    REQUESTED = "requested"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    STALE = "stale"


class QuarantineReason(StrEnum):
    ACTIVE_CONTENT = "active_content"
    ARCHIVE_BOUNDS = "archive_bounds"
    CLASSIFICATION = "classification"
    CONTENT_TYPE = "content_type"
    MALFORMED = "malformed"
    PROMPT_INJECTION = "prompt_injection"
    SCANNER_REJECTED = "scanner_rejected"
    SECRET = "secret"  # nosec B105  # noqa: S105
    SIZE = "size"


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        default=_canonical_default,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _canonical_default(value: object) -> object:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, bytes):
        return value.hex()
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


def canonical_digest(
    value: StrictModel | Mapping[str, object] | Sequence[object],
) -> str:
    material: object
    if isinstance(value, StrictModel):
        material = value.model_dump(mode="json", exclude={"digest", "bundle_digest"})
    else:
        material = value
    return sha256(canonical_json(material).encode()).hexdigest()


class EvidenceBounds(StrictModel):
    maximum_pages: int = Field(default=20, ge=1, le=100)
    maximum_records: int = Field(default=1_000, ge=1, le=10_000)
    maximum_page_bytes: int = Field(default=2 * 1024 * 1024, ge=1_024, le=8_388_608)
    maximum_total_bytes: int = Field(default=16 * 1024 * 1024, ge=1_024, le=67_108_864)
    request_timeout_seconds: float = Field(default=20.0, ge=1.0, le=120.0)

    @model_validator(mode="after")
    def total_covers_page(self) -> EvidenceBounds:
        if self.maximum_total_bytes < self.maximum_page_bytes:
            raise ValueError("total evidence bytes must cover at least one page")
        return self


class EvidenceSource(StrictModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    tenant_id: Identifier
    source_id: Identifier
    kind: EvidenceSourceKind
    trust: SourceTrust
    classification: DataClassification
    region: Identifier
    credential_ref: Identifier | None = None
    credential_version: int | None = Field(default=None, ge=1)
    policy_revision: int = Field(ge=1)
    allowed_resources: Annotated[tuple[str, ...], Field(min_length=1, max_length=64)]
    enabled: bool = False

    @field_validator("allowed_resources")
    @classmethod
    def normalize_resources(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item or len(item) > 512 for item in value):
            raise ValueError("source resource allowlist is invalid")
        return tuple(sorted(set(value)))

    @model_validator(mode="after")
    def bind_credential_version(self) -> EvidenceSource:
        if (self.credential_ref is None) != (self.credential_version is None):
            raise ValueError("credential reference and version must be bound together")
        return self

    @property
    def digest(self) -> Sha256Digest:
        return canonical_digest(self)


class EvidenceTimeRange(StrictModel):
    start: AwareDatetime
    end: AwareDatetime

    @model_validator(mode="after")
    def validate_range(self) -> EvidenceTimeRange:
        if self.end <= self.start:
            raise ValueError("evidence query end must follow start")
        if self.end - self.start > _MAX_QUERY_WINDOW:
            raise ValueError("evidence query window exceeds seven days")
        return self


class EvidenceQuery(StrictModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    query_id: Identifier
    tenant_id: Identifier
    incident_id: Identifier
    run_id: Identifier
    source: EvidenceSource
    window: EvidenceTimeRange
    resource: Annotated[str, Field(min_length=1, max_length=512)]
    parameters: Annotated[dict[str, JsonValue], Field(max_length=32)] = Field(
        default_factory=dict
    )
    bounds: EvidenceBounds = Field(default_factory=EvidenceBounds)
    created_at: AwareDatetime

    @field_validator("parameters")
    @classmethod
    def bound_parameters(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        if len(canonical_json(value).encode()) > 16_384:
            raise ValueError("evidence query parameters exceed the bound")
        return dict(sorted(value.items()))

    @model_validator(mode="after")
    def bind_source(self) -> EvidenceQuery:
        if self.source.tenant_id != self.tenant_id:
            raise ValueError("evidence source tenant does not match query")
        if self.resource not in self.source.allowed_resources:
            raise ValueError("evidence resource is not allowlisted")
        return self

    @property
    def digest(self) -> Sha256Digest:
        return canonical_digest(self)


class EvidenceCursor(StrictModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    tenant_id: Identifier
    incident_id: Identifier
    query_id: Identifier
    source_id: Identifier
    page_number: int = Field(ge=1, le=100)
    cursor_ref: Identifier
    cursor_digest: Sha256Digest
    created_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def validate_expiry(self) -> EvidenceCursor:
        if self.expires_at <= self.created_at:
            raise ValueError("evidence cursor expiry must follow creation")
        return self

    @property
    def digest(self) -> Sha256Digest:
        return canonical_digest(self)


class ConnectorRecord(StrictModel):
    """Ephemeral adapter output. It must never be written to Temporal history."""

    record_id: Identifier
    locator: Annotated[str, Field(min_length=1, max_length=1_024)]
    observed_at: AwareDatetime
    content_type: Annotated[str, Field(min_length=3, max_length=128)]
    payload: Annotated[bytes, Field(min_length=1, max_length=_MAX_RECORD_BYTES)]
    source_version: Annotated[str | None, Field(max_length=128)] = None
    etag: Annotated[str | None, Field(max_length=256)] = None


class ConnectorPage(StrictModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    query_id: Identifier
    source_id: Identifier
    page_number: int = Field(ge=1, le=100)
    records: Annotated[tuple[ConnectorRecord, ...], Field(max_length=1_000)]
    next_cursor: Annotated[str | None, Field(max_length=4_096)] = None
    response_bytes: int = Field(ge=0, le=8_388_608)
    rate_limit_remaining: int | None = Field(default=None, ge=0)
    retrieved_at: AwareDatetime

    @model_validator(mode="after")
    def validate_response_size(self) -> ConnectorPage:
        actual = sum(len(record.payload) for record in self.records)
        if actual > self.response_bytes:
            raise ValueError("connector page byte count is inconsistent")
        return self


class ScannerFinding(StrictModel):
    scanner: Identifier
    rule_id: Identifier
    severity: Annotated[str, Field(pattern=r"^(info|warning|blocking)$")]
    count: int = Field(ge=1, le=10_000)


class EvidenceProvenance(StrictModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    tenant_id: Identifier
    incident_id: Identifier
    run_id: Identifier
    source_id: Identifier
    source_kind: EvidenceSourceKind
    source_trust: SourceTrust
    source_digest: Sha256Digest
    query_id: Identifier
    query_digest: Sha256Digest
    page_number: int = Field(ge=1, le=100)
    locator: Annotated[str, Field(min_length=1, max_length=1_024)]
    observed_at: AwareDatetime
    retrieved_at: AwareDatetime
    credential_version: int | None = Field(default=None, ge=1)
    policy_revision: int = Field(ge=1)
    classification: DataClassification
    retention_ref: Identifier
    raw_content_hash: Sha256Digest

    @property
    def digest(self) -> Sha256Digest:
        return canonical_digest(self)


class NormalizedEvidence(StrictModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    evidence_id: Identifier
    tenant_id: Identifier
    incident_id: Identifier
    kind: EvidenceSourceKind
    summary: Annotated[str, Field(min_length=1, max_length=512)]
    facts: Annotated[dict[str, JsonValue], Field(max_length=64)]
    canonical_text: Annotated[str, Field(max_length=65_536)]
    content_hash: Sha256Digest
    provenance: EvidenceProvenance
    disposition: EvidenceDisposition
    redaction_count: int = Field(default=0, ge=0, le=10_000)
    scanner_findings: Annotated[tuple[ScannerFinding, ...], Field(max_length=64)] = ()
    quarantine_reason: QuarantineReason | None = None
    duplicate_of: Identifier | None = None

    @field_validator("facts")
    @classmethod
    def normalize_facts(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        if len(canonical_json(value).encode()) > 16_384:
            raise ValueError("normalized evidence facts exceed the bound")
        return dict(sorted(value.items()))

    @model_validator(mode="after")
    def validate_disposition(self) -> NormalizedEvidence:
        if sha256(self.canonical_text.encode()).hexdigest() != self.content_hash:
            raise ValueError("normalized content hash does not match content")
        if self.provenance.tenant_id != self.tenant_id:
            raise ValueError("evidence provenance tenant mismatch")
        if self.provenance.incident_id != self.incident_id:
            raise ValueError("evidence provenance incident mismatch")
        if (self.disposition is EvidenceDisposition.QUARANTINED) != (
            self.quarantine_reason is not None
        ):
            raise ValueError("quarantine disposition requires exactly one reason")
        if (self.disposition is EvidenceDisposition.DUPLICATE) != (
            self.duplicate_of is not None
        ):
            raise ValueError("duplicate disposition requires exactly one target")
        return self

    @property
    def digest(self) -> Sha256Digest:
        return canonical_digest(self)


class EvidenceCitation(StrictModel):
    evidence_id: Identifier
    locator: Annotated[str, Field(min_length=1, max_length=1_024)]
    content_hash: Sha256Digest
    provenance_digest: Sha256Digest
    source_id: Identifier
    query_id: Identifier
    page_number: int = Field(ge=1, le=100)


class EvidenceBundle(StrictModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    bundle_id: Identifier
    tenant_id: Identifier
    incident_id: Identifier
    run_id: Identifier
    query_ids: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=64)]
    evidence: Annotated[tuple[NormalizedEvidence, ...], Field(max_length=10_000)]
    citations: Annotated[tuple[EvidenceCitation, ...], Field(max_length=10_000)]
    source_kinds: Annotated[tuple[EvidenceSourceKind, ...], Field(max_length=16)]
    created_at: AwareDatetime
    bundle_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_bundle(self) -> EvidenceBundle:
        ordered_evidence = tuple(
            sorted(self.evidence, key=lambda item: item.evidence_id)
        )
        ordered_citations = tuple(
            sorted(self.citations, key=lambda item: item.evidence_id)
        )
        if ordered_evidence != self.evidence or ordered_citations != self.citations:
            raise ValueError(
                "evidence bundle content must be deterministically ordered"
            )
        accepted = {
            item.evidence_id: item
            for item in self.evidence
            if item.disposition
            in {EvidenceDisposition.ACCEPTED, EvidenceDisposition.REDACTED}
        }
        cited_ids = {citation.evidence_id for citation in self.citations}
        if cited_ids != set(accepted.keys()):
            raise ValueError(
                "bundle citations must cover exactly all accepted evidence"
            )
        for citation in self.citations:
            item = accepted[citation.evidence_id]
            if item.tenant_id != self.tenant_id:
                raise ValueError("evidence tenant_id does not match bundle")
            if item.incident_id != self.incident_id:
                raise ValueError("evidence incident_id does not match bundle")
            if item.provenance.run_id != self.run_id:
                raise ValueError("evidence run_id does not match bundle")
            if item.provenance.query_id not in self.query_ids:
                raise ValueError("evidence query_id is not in bundle query_ids")
            if (
                citation.locator != item.provenance.locator
                or citation.content_hash != item.content_hash
                or citation.provenance_digest != item.provenance.digest
                or citation.source_id != item.provenance.source_id
                or citation.query_id != item.provenance.query_id
                or citation.page_number != item.provenance.page_number
            ):
                raise ValueError("bundle citation is not bound to accepted evidence")
        expected = canonical_digest(
            self.model_dump(mode="json", exclude={"bundle_digest"})
        )
        if self.bundle_digest != expected:
            raise ValueError("evidence bundle digest is invalid")
        return self


class EvidenceQueryView(StrictModel):
    query_id: Identifier
    incident_id: Identifier
    source_kind: EvidenceSourceKind
    status: QueryStatus
    page_count: int = Field(ge=0, le=100)
    record_count: int = Field(ge=0, le=10_000)
    accepted_count: int = Field(ge=0, le=10_000)
    quarantined_count: int = Field(ge=0, le=10_000)
    failure_code: Identifier | None = None
    cursor_available: bool = False
    reconciliation_required: bool = False
    updated_at: AwareDatetime


class EvidenceCursorView(StrictModel):
    query_id: Identifier
    source_kind: EvidenceSourceKind
    page_number: int = Field(ge=1, le=100)
    expires_at: AwareDatetime
    available: bool = True


def build_bundle(
    *,
    bundle_id: str,
    tenant_id: str,
    incident_id: str,
    run_id: str,
    query_ids: Sequence[str],
    evidence: Sequence[NormalizedEvidence],
    created_at: datetime,
) -> EvidenceBundle:
    ordered = tuple(sorted(evidence, key=lambda item: item.evidence_id))
    citations = tuple(
        EvidenceCitation(
            evidence_id=item.evidence_id,
            locator=item.provenance.locator,
            content_hash=item.content_hash,
            provenance_digest=item.provenance.digest,
            source_id=item.provenance.source_id,
            query_id=item.provenance.query_id,
            page_number=item.provenance.page_number,
        )
        for item in ordered
        if item.disposition
        in {EvidenceDisposition.ACCEPTED, EvidenceDisposition.REDACTED}
    )
    normalized_query_ids = tuple(sorted(set(query_ids)))
    source_kinds = tuple(
        sorted({item.kind for item in ordered}, key=lambda item: item.value)
    )
    draft = EvidenceBundle.model_construct(
        schema_version=1,
        bundle_id=bundle_id,
        tenant_id=tenant_id,
        incident_id=incident_id,
        run_id=run_id,
        query_ids=normalized_query_ids,
        evidence=ordered,
        citations=citations,
        source_kinds=source_kinds,
        created_at=created_at,
        bundle_digest="0" * 64,
    )
    return EvidenceBundle(
        schema_version=1,
        bundle_id=bundle_id,
        tenant_id=tenant_id,
        incident_id=incident_id,
        run_id=run_id,
        query_ids=normalized_query_ids,
        evidence=ordered,
        citations=citations,
        source_kinds=source_kinds,
        created_at=created_at,
        bundle_digest=canonical_digest(
            draft.model_dump(mode="json", exclude={"bundle_digest"})
        ),
    )


def to_graph_evidence(item: NormalizedEvidence) -> Evidence:
    """Project accepted normalized evidence into the existing bounded graph contract."""

    if item.disposition not in {
        EvidenceDisposition.ACCEPTED,
        EvidenceDisposition.REDACTED,
    }:
        raise ValueError("only accepted evidence can enter graph state")
    kind = {
        EvidenceSourceKind.DYNATRACE: EvidenceKind.TELEMETRY,
        EvidenceSourceKind.KUBERNETES: EvidenceKind.TELEMETRY,
        EvidenceSourceKind.GITHUB: EvidenceKind.CHANGE,
        EvidenceSourceKind.RUNBOOK: EvidenceKind.RUNBOOK,
    }[item.kind]
    facts = {
        key: value
        for key, value in item.facts.items()
        if isinstance(value, (str, int, float, bool, type(None)))
    }
    if not facts:
        raise ValueError("graph evidence requires allowlisted scalar facts")
    if len(item.provenance.locator) > 512:
        raise ValueError("graph evidence locator exceeds its boundary")
    return Evidence(
        evidence_id=item.evidence_id,
        tenant_id=item.tenant_id,
        kind=kind,
        source=item.provenance.source_id,
        locator=item.provenance.locator,
        observed_at=item.provenance.observed_at,
        summary=item.summary,
        facts=facts,
        content_hash=item.content_hash,
        untrusted_text=item.canonical_text,
        provenance_digest=item.provenance.digest,
        source_id=item.provenance.source_id,
        query_id=item.provenance.query_id,
        page_number=item.provenance.page_number,
    )
