"""Application-authoritative memory contracts, lifecycle, retrieval, and compaction."""

from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter, defaultdict, deque
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from threading import BoundedSemaphore, Lock
from typing import Annotated, Literal, Protocol

from pydantic import (
    AwareDatetime,
    Field,
    JsonValue,
    field_validator,
    model_validator,
)
from pydantic_core import to_jsonable_python

from aegis_framework.domain import (
    Identifier,
    Sha256Digest,
    StrictModel,
    stable_id,
)
from aegis_framework.errors import (
    ConcurrencyConflict,
    IdempotencyConflict,
    IntegrityFailure,
    PolicyDenied,
)
from aegis_framework.evidence import (
    DataClassification,
    EvidenceDisposition,
    NormalizedEvidence,
    SourceTrust,
)
from aegis_framework.evidence import (
    canonical_digest as evidence_canonical_digest,
)

_MAX_MEMORY_TEXT = 65_536
_MAX_FACT_BYTES = 16_384
_WORD = re.compile(r"[a-z0-9][a-z0-9._:-]{1,63}")
_INJECTION = re.compile(
    r"\b(?:ignore (?:all |any )?(?:prior|previous|system) instructions?|"
    r"system prompt|developer message|invoke (?:the )?tool|exfiltrat(?:e|ion))\b",
    re.I,
)
_SECRET = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"\bgh[opsu]_[A-Za-z0-9]{20,255}\b|"
    r"(?i:\b(?:api[_-]?key|password|secret|token)\s*[:=]\s*[^\s,;]{8,})"
)
_PII = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b|"
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)


def canonical_digest(value: object) -> Sha256Digest:
    """Hash nested strict models with the repository canonical JSON rules."""

    return evidence_canonical_digest(to_jsonable_python(value))


class MemoryTier(StrEnum):
    WORKING = "working"
    EPISODIC = "episodic"
    SEMANTIC = "semantic"


class MemoryStatus(StrEnum):
    CANDIDATE = "candidate"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    TOMBSTONED = "tombstoned"
    ERASED = "erased"


class MemoryFactType(StrEnum):
    CANDIDATE_PROPOSED = "memory.candidate_proposed"
    CANDIDATE_ACCEPTED = "memory.candidate_accepted"
    CANDIDATE_REJECTED = "memory.candidate_rejected"
    SCAN_REQUESTED = "memory.scan_requested"
    SCAN_COMPLETED = "memory.scan_completed"
    CHUNK_REQUESTED = "memory.chunk_requested"
    CHUNK_COMPLETED = "memory.chunk_completed"
    EMBED_REQUESTED = "memory.embed_requested"
    EMBED_COMPLETED = "memory.embed_completed"
    INDEX_REQUESTED = "memory.index_requested"
    INDEX_COMPLETED = "memory.index_completed"
    RETRIEVE_REQUESTED = "memory.retrieve_requested"
    RETRIEVE_COMPLETED = "memory.retrieve_completed"
    CONTEXT_BUILT = "memory.context_built"
    COMPACT_REQUESTED = "memory.compact_requested"
    COMPACT_COMPLETED = "memory.compact_completed"
    SUMMARY_ACCEPTED = "memory.summary_accepted"
    SUMMARY_REJECTED = "memory.summary_rejected"
    FEEDBACK_RECORDED = "memory.feedback_recorded"
    SUPERSEDED = "memory.superseded"
    TOMBSTONED = "memory.tombstoned"
    RETENTION_EXPIRED = "memory.retention_expired"
    LEGAL_HOLD_APPLIED = "memory.legal_hold_applied"
    LEGAL_HOLD_RELEASED = "memory.legal_hold_released"
    DELETE_REQUESTED = "memory.delete_requested"
    DERIVED_PURGED = "memory.derived_purged"
    CRYPTO_ERASED = "memory.crypto_erased"
    REBUILD_REQUESTED = "memory.rebuild_requested"
    REBUILD_COMPLETED = "memory.rebuild_completed"


class MemoryACL(StrictModel):
    roles: Annotated[tuple[Identifier, ...], Field(max_length=32)] = ()
    principals: Annotated[tuple[Identifier, ...], Field(max_length=64)] = ()

    @field_validator("roles", "principals")
    @classmethod
    def normalize_acl(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(value)))

    def permits(self, *, roles: Sequence[str], principal_ref: str) -> bool:
        return (not self.roles and not self.principals) or bool(
            set(self.roles).intersection(roles) or principal_ref in self.principals
        )


class ErasableBlobReference(StrictModel):
    tenant_id: Identifier
    blob_ref: Identifier
    key_ref: Identifier
    key_version: int = Field(ge=1)
    content_digest: Sha256Digest
    byte_count: int = Field(ge=0, le=64 * 1024 * 1024)


class MemoryCitation(StrictModel):
    evidence_id: Identifier
    source_id: Identifier
    locator: Annotated[str, Field(min_length=1, max_length=1_024)]
    content_hash: Sha256Digest
    provenance_digest: Sha256Digest


class MemoryProvenance(StrictModel):
    tenant_id: Identifier
    incident_id: Identifier
    run_id: Identifier
    source_id: Identifier
    source_type: Identifier
    source_digest: Sha256Digest
    evidence_id: Identifier
    locator: Annotated[str, Field(min_length=1, max_length=1_024)]
    content_hash: Sha256Digest
    provenance_digest: Sha256Digest
    observed_at: AwareDatetime
    ingested_at: AwareDatetime


class RetentionBinding(StrictModel):
    policy_ref: Identifier
    expires_at: AwareDatetime
    legal_hold_refs: Annotated[tuple[Identifier, ...], Field(max_length=16)] = ()

    @field_validator("legal_hold_refs")
    @classmethod
    def normalize_holds(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(value)))

    @property
    def held(self) -> bool:
        return bool(self.legal_hold_refs)


class MemoryRecord(StrictModel):
    schema_version: Literal[1] = 1
    memory_id: Identifier
    tenant_id: Identifier
    tier: MemoryTier
    status: MemoryStatus
    incident_id: Identifier
    run_id: Identifier
    source_type: Identifier
    provenance: MemoryProvenance
    citations: Annotated[tuple[MemoryCitation, ...], Field(min_length=1, max_length=64)]
    acl: MemoryACL
    classification: DataClassification
    trust: SourceTrust
    schema_name: Identifier
    schema_revision: int = Field(ge=1, le=1_000)
    chunker_version: Identifier
    embedder_model: Identifier
    embedder_version: Identifier
    embedding_dimensions: int = Field(ge=2, le=4_096)
    content_digest: Sha256Digest
    quality: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    retention: RetentionBinding
    blob: ErasableBlobReference
    supersedes: Annotated[tuple[Identifier, ...], Field(max_length=64)] = ()
    superseded_by: Identifier | None = None
    tombstone_reason: Identifier | None = None
    created_at: AwareDatetime
    accepted_at: AwareDatetime | None = None
    canonical_digest: Sha256Digest

    @field_validator("citations")
    @classmethod
    def order_citations(
        cls, value: tuple[MemoryCitation, ...]
    ) -> tuple[MemoryCitation, ...]:
        return tuple(
            sorted(
                set(value),
                key=lambda item: (
                    item.evidence_id,
                    item.source_id,
                    item.locator,
                    item.content_hash,
                ),
            )
        )

    @field_validator("supersedes")
    @classmethod
    def order_supersedes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(value)))

    @model_validator(mode="after")
    def validate_bindings(self) -> MemoryRecord:
        if (
            self.provenance.tenant_id != self.tenant_id
            or self.provenance.incident_id != self.incident_id
            or self.provenance.run_id != self.run_id
            or self.blob.tenant_id != self.tenant_id
            or self.blob.content_digest != self.content_digest
        ):
            raise ValueError("memory scope or content binding is inconsistent")
        citation = self.citations[0]
        if (
            citation.evidence_id != self.provenance.evidence_id
            or citation.source_id != self.provenance.source_id
            or citation.locator != self.provenance.locator
            or citation.content_hash != self.provenance.content_hash
            or citation.provenance_digest != self.provenance.provenance_digest
        ):
            raise ValueError("memory citation is not bound to provenance")
        if self.status in {MemoryStatus.ACCEPTED, MemoryStatus.ACTIVE}:
            if self.accepted_at is None:
                raise ValueError("accepted memory requires acceptance time")
        elif self.accepted_at is not None:
            raise ValueError("unaccepted memory cannot have acceptance time")
        if self.tier is MemoryTier.WORKING and self.run_id == "":
            raise ValueError("working memory requires a run binding")
        if self.canonical_digest != memory_digest(self):
            raise ValueError("memory record digest mismatch")
        return self


class MemoryAcceptance(StrictModel):
    decision_id: Identifier
    tenant_id: Identifier
    memory_id: Identifier
    disposition: Literal["accept", "reject"]
    reviewer_ref: Identifier
    reviewer_kind: Literal["human", "policy"]
    policy_id: Identifier
    policy_revision: int = Field(ge=1)
    policy_digest: Sha256Digest
    reason_code: Identifier
    decided_at: AwareDatetime

    @property
    def digest(self) -> Sha256Digest:
        return canonical_digest(self)


class MemoryChunk(StrictModel):
    chunk_id: Identifier
    memory_id: Identifier
    tenant_id: Identifier
    ordinal: int = Field(ge=0, le=10_000)
    text: Annotated[str, Field(min_length=1, max_length=_MAX_MEMORY_TEXT)]
    content_digest: Sha256Digest
    token_estimate: int = Field(ge=1, le=32_768)
    byte_count: int = Field(ge=1, le=262_144)
    citation: MemoryCitation
    chunker_version: Identifier

    @model_validator(mode="after")
    def validate_content(self) -> MemoryChunk:
        encoded = self.text.encode()
        if (
            sha256(encoded).hexdigest() != self.content_digest
            or len(encoded) != self.byte_count
            or token_estimate(self.text) != self.token_estimate
        ):
            raise ValueError("memory chunk content binding is invalid")
        return self


class EmbeddingSpec(StrictModel):
    provider: Identifier
    model: Identifier
    version: Identifier
    dimensions: int = Field(ge=2, le=4_096)
    normalized: Literal[True] = True
    timeout_seconds: float = Field(ge=0.1, le=120.0)
    maximum_attempts: int = Field(ge=1, le=3)
    maximum_batch_items: int = Field(ge=1, le=256)
    maximum_batch_tokens: int = Field(ge=1, le=1_000_000)

    @property
    def digest(self) -> Sha256Digest:
        return canonical_digest(self)


class EmbeddingRequest(StrictModel):
    operation_id: Identifier
    tenant_id: Identifier
    run_id: Identifier
    reservation_id: Identifier
    fence_token: Identifier
    spec: EmbeddingSpec
    chunks: Annotated[tuple[MemoryChunk, ...], Field(min_length=1, max_length=256)]
    request_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_request(self) -> EmbeddingRequest:
        if any(chunk.tenant_id != self.tenant_id for chunk in self.chunks):
            raise ValueError("embedding request contains cross-tenant chunks")
        if (
            len(self.chunks) > self.spec.maximum_batch_items
            or sum(chunk.token_estimate for chunk in self.chunks)
            > self.spec.maximum_batch_tokens
        ):
            raise ValueError("embedding request exceeds declared batch bounds")
        if self.request_digest != canonical_digest(
            self.model_dump(mode="json", exclude={"request_digest"})
        ):
            raise ValueError("embedding request digest mismatch")
        return self


class EmbeddingVector(StrictModel):
    chunk_id: Identifier
    content_digest: Sha256Digest
    values: Annotated[tuple[float, ...], Field(min_length=2, max_length=4_096)]

    @field_validator("values")
    @classmethod
    def finite_normalized(cls, value: tuple[float, ...]) -> tuple[float, ...]:
        if any(not math.isfinite(item) for item in value):
            raise ValueError("embedding vector contains a non-finite value")
        norm = math.sqrt(sum(item * item for item in value))
        if not math.isclose(norm, 1.0, rel_tol=1e-6, abs_tol=1e-6):
            raise ValueError("embedding vector is not unit normalized")
        return value


class EmbeddingResult(StrictModel):
    operation_id: Identifier
    request_digest: Sha256Digest
    spec_digest: Sha256Digest
    attempt: int = Field(ge=1, le=3)
    fence_token: Identifier
    vectors: Annotated[tuple[EmbeddingVector, ...], Field(min_length=1, max_length=256)]
    result_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_result(self) -> EmbeddingResult:
        if self.result_digest != canonical_digest(
            self.model_dump(mode="json", exclude={"result_digest"})
        ):
            raise ValueError("embedding result digest mismatch")
        return self


class EmbeddingPort(Protocol):
    def embed(self, request: EmbeddingRequest) -> EmbeddingResult: ...


class SummaryRequest(StrictModel):
    operation_id: Identifier
    tenant_id: Identifier
    run_id: Identifier
    source_chunks: Annotated[
        tuple[MemoryChunk, ...], Field(min_length=1, max_length=256)
    ]
    maximum_tokens: int = Field(ge=16, le=8_192)
    summarizer_model: Identifier
    summarizer_version: Identifier
    depth: int = Field(ge=1, le=4)
    fence_token: Identifier
    request_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_request(self) -> SummaryRequest:
        if any(chunk.tenant_id != self.tenant_id for chunk in self.source_chunks):
            raise ValueError("summary request contains cross-tenant chunks")
        if self.request_digest != canonical_digest(
            self.model_dump(mode="json", exclude={"request_digest"})
        ):
            raise ValueError("summary request digest mismatch")
        return self


class SummaryClaim(StrictModel):
    text: Annotated[str, Field(min_length=1, max_length=1_024)]
    citations: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=32)]


class SummaryResult(StrictModel):
    operation_id: Identifier
    request_digest: Sha256Digest
    summary: Annotated[str, Field(min_length=1, max_length=_MAX_MEMORY_TEXT)]
    claims: Annotated[tuple[SummaryClaim, ...], Field(min_length=1, max_length=128)]
    source_coverage: float = Field(ge=0.0, le=1.0)
    fallback_used: bool
    fence_token: Identifier
    result_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_result(self) -> SummaryResult:
        if self.result_digest != canonical_digest(
            self.model_dump(mode="json", exclude={"result_digest"})
        ):
            raise ValueError("summary result digest mismatch")
        return self


class SummarizationPort(Protocol):
    def summarize(self, request: SummaryRequest) -> SummaryResult: ...


class MemoryFact(StrictModel):
    schema_version: Literal[1] = 1
    tenant_id: Identifier
    memory_id: Identifier
    sequence: int = Field(ge=1)
    fact_id: Identifier
    fact_type: MemoryFactType
    command_id: Identifier
    actor_ref: Identifier
    recorded_at: AwareDatetime
    payload: dict[str, JsonValue] = Field(default_factory=dict, max_length=32)
    previous_digest: Sha256Digest
    fact_digest: Sha256Digest

    @field_validator("payload")
    @classmethod
    def bound_payload(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        ordered = dict(sorted(value.items()))
        if len(str(ordered).encode()) > _MAX_FACT_BYTES:
            raise ValueError("memory fact payload exceeds the immutable bound")
        sensitive = {"text", "query", "prompt", "completion", "tenant_id", "locator"}
        if sensitive.intersection(ordered):
            raise ValueError("memory fact payload contains prohibited sensitive fields")
        return ordered


class MemoryOperationFact(StrictModel):
    schema_version: Literal[1] = 1
    tenant_id: Identifier
    operation_id: Identifier
    run_id: Identifier
    incident_id: Identifier
    sequence: int = Field(ge=1, le=16)
    fact_type: MemoryFactType
    policy_digest: Sha256Digest
    query_digest: Sha256Digest | None = None
    result_digest: Sha256Digest | None = None
    fact_digest: Sha256Digest
    recorded_at: AwareDatetime

    @model_validator(mode="after")
    def validate_digest(self) -> MemoryOperationFact:
        if self.fact_digest != canonical_digest(
            self.model_dump(mode="json", exclude={"fact_digest"})
        ):
            raise ValueError("memory operation fact digest mismatch")
        return self


class MemoryOperationLedger(Protocol):
    def append_operation(self, fact: MemoryOperationFact) -> None: ...

    def operation_facts(
        self, *, tenant_id: str, operation_id: str
    ) -> tuple[MemoryOperationFact, ...]: ...


class InMemoryMemoryOperationLedger:
    def __init__(self) -> None:
        self._facts: dict[tuple[str, str], list[MemoryOperationFact]] = {}
        self._lock = Lock()

    def append_operation(self, fact: MemoryOperationFact) -> None:
        key = (fact.tenant_id, fact.operation_id)
        with self._lock:
            facts = self._facts.setdefault(key, [])
            if facts:
                if fact.sequence <= len(facts):
                    existing = facts[fact.sequence - 1]
                    if existing.fact_digest != fact.fact_digest:
                        raise IdempotencyConflict(
                            "memory operation fact replay changed"
                        )
                    return
                if fact.sequence != len(facts) + 1:
                    raise ConcurrencyConflict("memory operation sequence changed")
            elif fact.sequence != 1:
                raise ConcurrencyConflict("memory operation must begin at sequence one")
            facts.append(fact)

    def operation_facts(
        self, *, tenant_id: str, operation_id: str
    ) -> tuple[MemoryOperationFact, ...]:
        with self._lock:
            return tuple(self._facts.get((tenant_id, operation_id), ()))


class MemoryProjection(StrictModel):
    tenant_id: Identifier
    memory_id: Identifier
    tier: MemoryTier
    status: MemoryStatus
    version: int = Field(ge=1)
    record_digest: Sha256Digest
    last_fact_digest: Sha256Digest
    chunk_count: int = Field(ge=0, le=10_000)
    indexed: bool = False
    tombstoned: bool = False
    legal_hold_count: int = Field(ge=0, le=16)
    derived_purged: bool = False
    blob_erased: bool = False
    updated_at: AwareDatetime


class MemoryLedger(Protocol):
    def put_record(self, record: MemoryRecord) -> None: ...

    def record(self, *, tenant_id: str, memory_id: str) -> MemoryRecord | None: ...

    def append(
        self,
        *,
        tenant_id: str,
        memory_id: str,
        expected_version: int,
        fact_type: MemoryFactType,
        command_id: str,
        actor_ref: str,
        recorded_at: datetime,
        payload: Mapping[str, JsonValue],
    ) -> MemoryProjection: ...

    def projection(
        self, *, tenant_id: str, memory_id: str
    ) -> MemoryProjection | None: ...

    def facts(self, *, tenant_id: str, memory_id: str) -> tuple[MemoryFact, ...]: ...


class InMemoryMemoryLedger:
    """Deterministic reference ledger; production has no in-memory fallback."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], MemoryRecord] = {}
        self._facts: dict[tuple[str, str], list[MemoryFact]] = {}
        self._commands: dict[tuple[str, str], Sha256Digest] = {}
        self._projections: dict[tuple[str, str], MemoryProjection] = {}
        self._lock = Lock()

    def put_record(self, record: MemoryRecord) -> None:
        key = (record.tenant_id, record.memory_id)
        with self._lock:
            existing = self._records.get(key)
            if (
                existing is not None
                and existing.canonical_digest != record.canonical_digest
            ):
                raise IdempotencyConflict("memory record replay changed content")
            self._records.setdefault(key, record)

    def record(self, *, tenant_id: str, memory_id: str) -> MemoryRecord | None:
        with self._lock:
            return self._records.get((tenant_id, memory_id))

    def append(
        self,
        *,
        tenant_id: str,
        memory_id: str,
        expected_version: int,
        fact_type: MemoryFactType,
        command_id: str,
        actor_ref: str,
        recorded_at: datetime,
        payload: Mapping[str, JsonValue],
    ) -> MemoryProjection:
        key = (tenant_id, memory_id)
        fingerprint = canonical_digest(
            {
                "fact_type": fact_type.value,
                "memory_id": memory_id,
                "payload": dict(sorted(payload.items())),
            }
        )
        with self._lock:
            if key not in self._records:
                raise IntegrityFailure("memory record is missing")
            command_key = (tenant_id, command_id)
            existing_command = self._commands.get(command_key)
            if existing_command is not None:
                if existing_command != fingerprint:
                    raise IdempotencyConflict("memory command replay changed")
                return self._projections[key]
            current = self._projections.get(key)
            version = current.version if current is not None else 0
            if version != expected_version:
                raise ConcurrencyConflict("memory aggregate version changed")
            sequence = version + 1
            previous = current.last_fact_digest if current is not None else "0" * 64
            material: dict[str, object] = {
                "schema_version": 1,
                "tenant_id": tenant_id,
                "memory_id": memory_id,
                "sequence": sequence,
                "fact_id": stable_id(
                    "memory-fact",
                    tenant_id,
                    memory_id,
                    str(sequence),
                    command_id,
                    length=32,
                ),
                "fact_type": fact_type.value,
                "command_id": command_id,
                "actor_ref": actor_ref,
                "recorded_at": recorded_at,
                "payload": dict(sorted(payload.items())),
                "previous_digest": previous,
            }
            fact = MemoryFact(
                **material,
                fact_digest=canonical_digest(material),
            )
            projection = reduce_memory(current, fact, self._records[key])
            self._facts.setdefault(key, []).append(fact)
            self._commands[command_key] = fingerprint
            self._projections[key] = projection
            return projection

    def projection(self, *, tenant_id: str, memory_id: str) -> MemoryProjection | None:
        with self._lock:
            return self._projections.get((tenant_id, memory_id))

    def facts(self, *, tenant_id: str, memory_id: str) -> tuple[MemoryFact, ...]:
        with self._lock:
            return tuple(self._facts.get((tenant_id, memory_id), ()))

    def rebuild(self, *, tenant_id: str, memory_id: str) -> MemoryProjection:
        key = (tenant_id, memory_id)
        with self._lock:
            record = self._records.get(key)
            if record is None:
                raise IntegrityFailure("cannot rebuild unknown memory")
            projection: MemoryProjection | None = None
            for fact in self._facts.get(key, ()):
                projection = reduce_memory(projection, fact, record)
            if projection is None:
                raise IntegrityFailure("cannot rebuild memory without facts")
            self._projections[key] = projection
            return projection


def reduce_memory(
    current: MemoryProjection | None,
    fact: MemoryFact,
    record: MemoryRecord,
) -> MemoryProjection:
    expected_sequence = 1 if current is None else current.version + 1
    expected_previous = "0" * 64 if current is None else current.last_fact_digest
    if (
        fact.sequence != expected_sequence
        or fact.previous_digest != expected_previous
        or fact.tenant_id != record.tenant_id
        or fact.memory_id != record.memory_id
        or fact.fact_digest
        != canonical_digest(fact.model_dump(mode="json", exclude={"fact_digest"}))
    ):
        raise IntegrityFailure("memory fact chain is invalid")
    if current is None and fact.fact_type is not MemoryFactType.CANDIDATE_PROPOSED:
        raise IntegrityFailure("memory lifecycle must begin with a candidate")
    status = current.status if current is not None else MemoryStatus.CANDIDATE
    indexed = current.indexed if current is not None else False
    tombstoned = current.tombstoned if current is not None else False
    hold_count = current.legal_hold_count if current is not None else 0
    derived_purged = current.derived_purged if current is not None else False
    blob_erased = current.blob_erased if current is not None else False
    chunk_count = current.chunk_count if current is not None else 0
    if fact.fact_type is MemoryFactType.CANDIDATE_ACCEPTED:
        status = MemoryStatus.ACCEPTED
    elif fact.fact_type is MemoryFactType.CANDIDATE_REJECTED:
        status = MemoryStatus.REJECTED
    elif fact.fact_type is MemoryFactType.CHUNK_COMPLETED:
        chunk_count = _bounded_count(fact.payload.get("chunk_count"), maximum=10_000)
    elif fact.fact_type is MemoryFactType.INDEX_COMPLETED:
        if status not in {MemoryStatus.ACCEPTED, MemoryStatus.ACTIVE}:
            raise IntegrityFailure("unaccepted memory cannot be indexed")
        status = MemoryStatus.ACTIVE
        indexed = True
    elif fact.fact_type is MemoryFactType.SUPERSEDED:
        status = MemoryStatus.SUPERSEDED
    elif fact.fact_type in {
        MemoryFactType.TOMBSTONED,
        MemoryFactType.RETENTION_EXPIRED,
        MemoryFactType.DELETE_REQUESTED,
    }:
        tombstoned = True
        status = MemoryStatus.TOMBSTONED
    elif fact.fact_type is MemoryFactType.LEGAL_HOLD_APPLIED:
        hold_count = min(16, hold_count + 1)
    elif fact.fact_type is MemoryFactType.LEGAL_HOLD_RELEASED:
        hold_count = max(0, hold_count - 1)
    elif fact.fact_type is MemoryFactType.DERIVED_PURGED:
        if not tombstoned:
            raise IntegrityFailure("derived memory purge requires a tombstone")
        derived_purged = True
        indexed = False
    elif fact.fact_type is MemoryFactType.CRYPTO_ERASED:
        if not derived_purged or hold_count:
            raise IntegrityFailure("crypto erasure requires purge and no legal hold")
        blob_erased = True
        status = MemoryStatus.ERASED
    return MemoryProjection(
        tenant_id=fact.tenant_id,
        memory_id=fact.memory_id,
        tier=record.tier,
        status=status,
        version=fact.sequence,
        record_digest=record.canonical_digest,
        last_fact_digest=fact.fact_digest,
        chunk_count=chunk_count,
        indexed=indexed,
        tombstoned=tombstoned,
        legal_hold_count=hold_count,
        derived_purged=derived_purged,
        blob_erased=blob_erased,
        updated_at=fact.recorded_at,
    )


class DeterministicChunker:
    """Stable bounded splitter that keeps provenance with every chunk."""

    version = "aegis-boundary-chunker-v1"

    def __init__(
        self,
        *,
        maximum_tokens: int = 256,
        overlap_tokens: int = 32,
        maximum_chunks: int = 256,
    ) -> None:
        if (
            maximum_tokens < 16
            or maximum_tokens > 2_048
            or overlap_tokens < 0
            or overlap_tokens >= maximum_tokens
            or maximum_chunks < 1
            or maximum_chunks > 1_000
        ):
            raise ValueError("chunker bounds are invalid")
        self._maximum_tokens = maximum_tokens
        self._overlap_tokens = overlap_tokens
        self._maximum_chunks = maximum_chunks

    def split(
        self,
        *,
        tenant_id: str,
        memory_id: str,
        text: str,
        citation: MemoryCitation,
    ) -> tuple[MemoryChunk, ...]:
        normalized = canonical_text(text)
        words = normalized.split()
        if not words:
            raise ValueError("memory content is empty")
        step = self._maximum_tokens - self._overlap_tokens
        chunks: list[MemoryChunk] = []
        for ordinal, start in enumerate(range(0, len(words), step)):
            part = " ".join(words[start : start + self._maximum_tokens])
            if not part:
                break
            if ordinal >= self._maximum_chunks:
                raise ValueError("memory content exceeds the chunk count bound")
            digest = sha256(part.encode()).hexdigest()
            chunks.append(
                MemoryChunk(
                    chunk_id=stable_id(
                        "memory-chunk",
                        tenant_id,
                        memory_id,
                        str(ordinal),
                        digest,
                        length=32,
                    ),
                    memory_id=memory_id,
                    tenant_id=tenant_id,
                    ordinal=ordinal,
                    text=part,
                    content_digest=digest,
                    token_estimate=token_estimate(part),
                    byte_count=len(part.encode()),
                    citation=citation,
                    chunker_version=self.version,
                )
            )
            if start + self._maximum_tokens >= len(words):
                break
        return tuple(chunks)


class DeterministicEmbeddingAdapter:
    """Hermetic provider adapter used for tests/evals; it performs no I/O."""

    def __init__(self, *, dimensions: int = 64) -> None:
        if dimensions < 2 or dimensions > 4_096:
            raise ValueError("embedding dimensions are invalid")
        self._dimensions = dimensions

    def embed(self, request: EmbeddingRequest) -> EmbeddingResult:
        if (
            request.spec.provider != "fake"
            or request.spec.dimensions != self._dimensions
        ):
            raise PolicyDenied("deterministic adapter does not match embedding spec")
        vectors = tuple(
            EmbeddingVector(
                chunk_id=chunk.chunk_id,
                content_digest=chunk.content_digest,
                values=_deterministic_vector(chunk.text, self._dimensions),
            )
            for chunk in request.chunks
        )
        material = {
            "operation_id": request.operation_id,
            "request_digest": request.request_digest,
            "spec_digest": request.spec.digest,
            "attempt": 1,
            "fence_token": request.fence_token,
            "vectors": [vector.model_dump(mode="json") for vector in vectors],
        }
        return EmbeddingResult(**material, result_digest=canonical_digest(material))


class ControlledEmbeddingGateway:
    """Bounded admission wrapper; durable intent/result belongs to the caller ledger."""

    def __init__(
        self,
        *,
        adapter: EmbeddingPort,
        maximum_concurrency: int = 8,
        maximum_calls: int = 1_000,
        rate_limit_per_minute: int = 60,
        circuit_failure_threshold: int = 3,
        circuit_open_seconds: int = 30,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if maximum_concurrency < 1 or maximum_concurrency > 256:
            raise ValueError("embedding concurrency bound is invalid")
        if maximum_calls < 1 or maximum_calls > 1_000_000:
            raise ValueError("embedding call budget is invalid")
        if rate_limit_per_minute < 1 or rate_limit_per_minute > 100_000:
            raise ValueError("embedding rate bound is invalid")
        if (
            circuit_failure_threshold < 1
            or circuit_failure_threshold > 100
            or circuit_open_seconds < 1
            or circuit_open_seconds > 3_600
        ):
            raise ValueError("embedding circuit bounds are invalid")
        self._adapter = adapter
        self._semaphore = BoundedSemaphore(maximum_concurrency)
        self._remaining = maximum_calls
        self._rate_limit = rate_limit_per_minute
        self._circuit_threshold = circuit_failure_threshold
        self._circuit_duration = timedelta(seconds=circuit_open_seconds)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._rate_windows: defaultdict[str, deque[datetime]] = defaultdict(deque)
        self._circuit_failures: defaultdict[str, int] = defaultdict(int)
        self._circuit_opened: dict[str, datetime] = {}
        self._lock = Lock()

    def embed(self, request: EmbeddingRequest) -> EmbeddingResult:
        if not self._semaphore.acquire(blocking=False):
            raise PolicyDenied("embedding concurrency exhausted")
        try:
            admitted_at = self._clock()
            circuit_key = f"{request.tenant_id}\x00{request.spec.digest}"
            with self._lock:
                opened = self._circuit_opened.get(circuit_key)
                if opened is not None:
                    if admitted_at - opened < self._circuit_duration:
                        raise PolicyDenied("embedding circuit is open")
                    self._circuit_opened.pop(circuit_key)
                    self._circuit_failures[circuit_key] = 0
                window = self._rate_windows[request.tenant_id]
                cutoff = admitted_at - timedelta(minutes=1)
                while window and window[0] <= cutoff:
                    window.popleft()
                if len(window) >= self._rate_limit:
                    raise PolicyDenied("embedding rate limit exhausted")
                if self._remaining <= 0:
                    raise PolicyDenied("embedding budget exhausted")
                window.append(admitted_at)
                self._remaining -= 1
            try:
                result = self._adapter.embed(request)
            except (IntegrityFailure, PolicyDenied, ValueError):
                with self._lock:
                    self._circuit_failures[circuit_key] += 1
                    if self._circuit_failures[circuit_key] >= self._circuit_threshold:
                        self._circuit_opened[circuit_key] = self._clock()
                raise
            completed_at = self._clock()
            if (
                completed_at - admitted_at
            ).total_seconds() > request.spec.timeout_seconds:
                raise IntegrityFailure("embedding provider exceeded timeout")
            expected = {chunk.chunk_id: chunk for chunk in request.chunks}
            if (
                len(result.vectors) != len(expected)
                or result.fence_token != request.fence_token
                or result.request_digest != request.request_digest
            ):
                raise IntegrityFailure("embedding provider returned an invalid binding")
            for vector in result.vectors:
                chunk = expected.get(vector.chunk_id)
                if (
                    chunk is None
                    or vector.content_digest != chunk.content_digest
                    or len(vector.values) != request.spec.dimensions
                ):
                    raise IntegrityFailure(
                        "embedding provider returned invalid vectors"
                    )
            with self._lock:
                self._circuit_failures[circuit_key] = 0
                self._circuit_opened.pop(circuit_key, None)
            return result
        finally:
            self._semaphore.release()


class IndexedChunk(StrictModel):
    record: MemoryRecord
    chunk: MemoryChunk
    vector: EmbeddingVector
    indexed_at: AwareDatetime


class RetrievalPolicy(StrictModel):
    policy_id: Identifier
    revision: int = Field(ge=1)
    lexical_weight: float = Field(ge=0.0, le=1.0)
    vector_weight: float = Field(ge=0.0, le=1.0)
    recency_weight: float = Field(ge=0.0, le=1.0)
    quality_weight: float = Field(ge=0.0, le=1.0)
    mmr_lambda: float = Field(ge=0.0, le=1.0)
    maximum_candidates: int = Field(ge=1, le=1_000)
    top_k: int = Field(ge=1, le=100)
    maximum_tokens: int = Field(ge=16, le=32_768)
    maximum_bytes: int = Field(ge=256, le=262_144)
    cache_ttl_seconds: int = Field(ge=0, le=3_600)
    freshness_seconds: int = Field(ge=1, le=31_536_000)

    @model_validator(mode="after")
    def validate_weights(self) -> RetrievalPolicy:
        if not math.isclose(
            self.lexical_weight
            + self.vector_weight
            + self.recency_weight
            + self.quality_weight,
            1.0,
            abs_tol=1e-9,
        ):
            raise ValueError("retrieval score weights must sum to one")
        if self.top_k > self.maximum_candidates:
            raise ValueError("retrieval top_k exceeds candidate bound")
        return self

    @property
    def digest(self) -> Sha256Digest:
        return canonical_digest(self)


class RetrievalQuery(StrictModel):
    query_id: Identifier
    tenant_id: Identifier
    run_id: Identifier
    incident_id: Identifier
    principal_ref: Identifier
    roles: Annotated[tuple[Identifier, ...], Field(max_length=32)]
    allowed_classifications: Annotated[
        frozenset[DataClassification], Field(min_length=1, max_length=4)
    ]
    text: Annotated[str, Field(min_length=1, max_length=8_192)]
    query_digest: Sha256Digest
    requested_at: AwareDatetime
    as_of: AwareDatetime
    policy: RetrievalPolicy

    @model_validator(mode="after")
    def validate_query(self) -> RetrievalQuery:
        if self.query_digest != sha256(canonical_text(self.text).encode()).hexdigest():
            raise ValueError("retrieval query digest mismatch")
        return self


class RetrievalHit(StrictModel):
    memory_id: Identifier
    chunk_id: Identifier
    tier: MemoryTier
    text: Annotated[str, Field(min_length=1, max_length=_MAX_MEMORY_TEXT)]
    citation: MemoryCitation
    lexical_score: float = Field(ge=0.0, le=1.0)
    vector_score: float = Field(ge=0.0, le=1.0)
    recency_score: float = Field(ge=0.0, le=1.0)
    quality_score: float = Field(ge=0.0, le=1.0)
    combined_score: float = Field(ge=0.0, le=1.0)
    stale: bool
    contradiction_group: Identifier | None = None


class RetrievalResult(StrictModel):
    query_id: Identifier
    query_digest: Sha256Digest
    policy_digest: Sha256Digest
    hits: Annotated[tuple[RetrievalHit, ...], Field(max_length=100)]
    candidate_count: int = Field(ge=0, le=1_000)
    token_count: int = Field(ge=0, le=32_768)
    byte_count: int = Field(ge=0, le=262_144)
    insufficient_context: bool
    cache_hit: bool
    result_digest: Sha256Digest


class InMemoryHybridIndex:
    """Derived lexical/vector index and tenant-scoped bounded cache."""

    def __init__(self) -> None:
        self._items: dict[tuple[str, str], IndexedChunk] = {}
        self._cache: dict[
            tuple[str, str, str],
            tuple[datetime, RetrievalResult],
        ] = {}
        self._lock = Lock()

    def index(self, item: IndexedChunk) -> None:
        if (
            item.record.tenant_id != item.chunk.tenant_id
            or item.chunk.chunk_id != item.vector.chunk_id
            or item.chunk.content_digest != item.vector.content_digest
            or len(item.vector.values) != item.record.embedding_dimensions
            or item.record.status not in {MemoryStatus.ACCEPTED, MemoryStatus.ACTIVE}
        ):
            raise IntegrityFailure("index input binding is invalid")
        with self._lock:
            self._items[(item.record.tenant_id, item.chunk.chunk_id)] = item
            cache_keys = [key for key in self._cache if key[0] == item.record.tenant_id]
            for cache_key in cache_keys:
                self._cache.pop(cache_key)

    def retrieve(
        self,
        query: RetrievalQuery,
        query_vector: Sequence[float],
    ) -> RetrievalResult:
        if len(query_vector) < 2 or any(
            not math.isfinite(value) for value in query_vector
        ):
            raise ValueError("query vector is invalid")
        cache_key = (
            query.tenant_id,
            query.query_digest,
            canonical_digest(
                {
                    "policy": query.policy.digest,
                    "principal_ref": query.principal_ref,
                    "roles": query.roles,
                    "classifications": sorted(
                        item.value for item in query.allowed_classifications
                    ),
                    "as_of": query.as_of,
                }
            ),
        )
        with self._lock:
            cached = self._cache.get(cache_key)
            if cached is not None and query.requested_at < cached[0]:
                return cached[1].model_copy(update={"cache_hit": True})
            if cached is not None:
                self._cache.pop(cache_key)
            items = tuple(self._items.values())
        eligible = [
            item
            for item in items
            if _eligible(item, query) and len(item.vector.values) == len(query_vector)
        ]
        query_terms = Counter(_terms(query.text))
        scored = [
            _score(item, query, query_vector=query_vector, query_terms=query_terms)
            for item in eligible
        ]
        scored.sort(
            key=lambda pair: (
                -pair[1].combined_score,
                pair[0].record.memory_id,
                pair[0].chunk.ordinal,
                pair[0].chunk.chunk_id,
            )
        )
        candidates = scored[: query.policy.maximum_candidates]
        selected = _mmr(candidates, query.policy)
        hits: list[RetrievalHit] = []
        tokens = 0
        byte_count = 0
        seen_claims: dict[str, str] = {}
        for item, hit in selected:
            token_count = item.chunk.token_estimate
            chunk_bytes = item.chunk.byte_count
            if (
                len(hits) >= query.policy.top_k
                or tokens + token_count > query.policy.maximum_tokens
                or byte_count + chunk_bytes > query.policy.maximum_bytes
            ):
                continue
            claim_key = _claim_key(item.chunk.text)
            prior_digest = seen_claims.get(claim_key)
            contradiction = None
            if prior_digest is not None and prior_digest != item.chunk.content_digest:
                contradiction = stable_id(
                    "contradiction",
                    query.tenant_id,
                    claim_key,
                    length=24,
                )
                for index, existing in enumerate(hits):
                    if _claim_key(existing.text) == claim_key:
                        hits[index] = existing.model_copy(
                            update={"contradiction_group": contradiction}
                        )
            seen_claims[claim_key] = item.chunk.content_digest
            hits.append(hit.model_copy(update={"contradiction_group": contradiction}))
            tokens += token_count
            byte_count += chunk_bytes
        material = {
            "query_id": query.query_id,
            "query_digest": query.query_digest,
            "policy_digest": query.policy.digest,
            "hits": [hit.model_dump(mode="json") for hit in hits],
            "candidate_count": len(candidates),
            "token_count": tokens,
            "byte_count": byte_count,
            "insufficient_context": not hits,
            "cache_hit": False,
        }
        result = RetrievalResult(**material, result_digest=canonical_digest(material))
        if query.policy.cache_ttl_seconds > 0:
            with self._lock:
                self._cache[cache_key] = (
                    query.requested_at
                    + timedelta(seconds=query.policy.cache_ttl_seconds),
                    result,
                )
        return result

    def purge(self, *, tenant_id: str, memory_id: str) -> int:
        with self._lock:
            item_keys = [
                item_key
                for item_key, item in self._items.items()
                if item.record.tenant_id == tenant_id
                and item.record.memory_id == memory_id
            ]
            for item_key in item_keys:
                self._items.pop(item_key)
            cache_keys = [key for key in self._cache if key[0] == tenant_id]
            for cache_key in cache_keys:
                self._cache.pop(cache_key)
            return len(item_keys)

    def invalidate_tenant(self, tenant_id: str) -> None:
        with self._lock:
            cache_keys = [key for key in self._cache if key[0] == tenant_id]
            for cache_key in cache_keys:
                self._cache.pop(cache_key)


class MemoryStatusPort(Protocol):
    def projection(
        self, *, tenant_id: str, memory_id: str
    ) -> MemoryProjection | None: ...


class MemoryRetrievalPort(Protocol):
    def retrieve(self, query: RetrievalQuery) -> RetrievalResult: ...


class MemoryReadPort(MemoryStatusPort, MemoryRetrievalPort, Protocol):
    pass


class InMemoryMemoryControl:
    """Demo/test read adapter over application projections and a derived index."""

    def __init__(
        self,
        *,
        ledger: MemoryLedger,
        index: InMemoryHybridIndex,
        dimensions: int,
    ) -> None:
        self._ledger = ledger
        self._index = index
        self._dimensions = dimensions

    def projection(self, *, tenant_id: str, memory_id: str) -> MemoryProjection | None:
        return self._ledger.projection(tenant_id=tenant_id, memory_id=memory_id)

    def retrieve(self, query: RetrievalQuery) -> RetrievalResult:
        return self._index.retrieve(
            query,
            _deterministic_vector(query.text, self._dimensions),
        )


class MemoryRetrievalService:
    """Records digest-only retrieval/context facts around a derived search index."""

    def __init__(
        self,
        *,
        index: InMemoryHybridIndex,
        operations: MemoryOperationLedger,
        clock: Callable[[], datetime],
    ) -> None:
        self._index = index
        self._operations = operations
        self._clock = clock

    def retrieve(
        self,
        query: RetrievalQuery,
        query_vector: Sequence[float],
    ) -> RetrievalResult:
        operation_id = stable_id(
            "memory-retrieval",
            query.tenant_id,
            query.run_id,
            query.query_id,
            length=32,
        )
        self._append_operation(
            query,
            operation_id=operation_id,
            sequence=1,
            fact_type=MemoryFactType.RETRIEVE_REQUESTED,
        )
        result = self._index.retrieve(query, query_vector)
        self._append_operation(
            query,
            operation_id=operation_id,
            sequence=2,
            fact_type=MemoryFactType.RETRIEVE_COMPLETED,
            result_digest=result.result_digest,
        )
        return result

    def record_context(
        self,
        query: RetrievalQuery,
        context: MemoryContext,
    ) -> None:
        operation_id = stable_id(
            "memory-retrieval",
            query.tenant_id,
            query.run_id,
            query.query_id,
            length=32,
        )
        self._append_operation(
            query,
            operation_id=operation_id,
            sequence=3,
            fact_type=MemoryFactType.CONTEXT_BUILT,
            result_digest=context.context_digest,
        )

    def _append_operation(
        self,
        query: RetrievalQuery,
        *,
        operation_id: str,
        sequence: int,
        fact_type: MemoryFactType,
        result_digest: str | None = None,
    ) -> None:
        material = {
            "schema_version": 1,
            "tenant_id": query.tenant_id,
            "operation_id": operation_id,
            "run_id": query.run_id,
            "incident_id": query.incident_id,
            "sequence": sequence,
            "fact_type": fact_type,
            "policy_digest": query.policy.digest,
            "query_digest": query.query_digest,
            "result_digest": result_digest,
            "recorded_at": self._clock(),
        }
        self._operations.append_operation(
            MemoryOperationFact(
                **material,
                fact_digest=canonical_digest(material),
            )
        )


class ContextBudget(StrictModel):
    total_tokens: int = Field(ge=256, le=1_000_000)
    reserved_system_tokens: int = Field(ge=64, le=100_000)
    reserved_safety_tokens: int = Field(ge=64, le=100_000)
    working_tokens: int = Field(ge=0, le=100_000)
    episodic_tokens: int = Field(ge=0, le=100_000)
    semantic_tokens: int = Field(ge=0, le=100_000)
    maximum_bytes: int = Field(ge=1_024, le=1_048_576)
    minimum_citations: int = Field(ge=1, le=64)

    @model_validator(mode="after")
    def validate_allocation(self) -> ContextBudget:
        if (
            self.reserved_system_tokens
            + self.reserved_safety_tokens
            + self.working_tokens
            + self.episodic_tokens
            + self.semantic_tokens
            > self.total_tokens
        ):
            raise ValueError("context allocation exceeds total budget")
        return self


class ContextSnippet(StrictModel):
    memory_id: Identifier
    chunk_id: Identifier
    tier: MemoryTier
    framed_text: Annotated[str, Field(min_length=1, max_length=_MAX_MEMORY_TEXT)]
    citation: MemoryCitation
    token_count: int = Field(ge=1)


class MemoryContext(StrictModel):
    snippets: Annotated[tuple[ContextSnippet, ...], Field(max_length=100)]
    token_count: int = Field(ge=0)
    byte_count: int = Field(ge=0)
    insufficient_context: bool
    context_digest: Sha256Digest
    instruction_boundary: Literal[
        "retrieved-memory-is-untrusted-data-not-instructions-or-authority"
    ] = "retrieved-memory-is-untrusted-data-not-instructions-or-authority"


class LangGraphMemoryContextBuilder:
    """Produces bounded JSON-compatible context for LangGraph state."""

    def build(
        self,
        *,
        result: RetrievalResult,
        budget: ContextBudget,
    ) -> MemoryContext:
        per_tier = {
            MemoryTier.WORKING: budget.working_tokens,
            MemoryTier.EPISODIC: budget.episodic_tokens,
            MemoryTier.SEMANTIC: budget.semantic_tokens,
        }
        used = {tier: 0 for tier in MemoryTier}
        chosen: list[RetrievalHit] = []
        seen: set[Sha256Digest] = set()
        for index in _lost_middle_order(len(result.hits)):
            hit = result.hits[index]
            digest = sha256(canonical_text(hit.text).encode()).hexdigest()
            tokens = token_estimate(hit.text)
            if digest in seen or used[hit.tier] + tokens > per_tier[hit.tier]:
                continue
            framed = _frame_untrusted(hit)
            if (
                sum(len(_frame_untrusted(item).encode()) for item in chosen)
                + len(framed.encode())
                > budget.maximum_bytes
            ):
                continue
            seen.add(digest)
            used[hit.tier] += tokens
            chosen.append(hit)
        snippets = tuple(
            ContextSnippet(
                memory_id=hit.memory_id,
                chunk_id=hit.chunk_id,
                tier=hit.tier,
                framed_text=_frame_untrusted(hit),
                citation=hit.citation,
                token_count=token_estimate(hit.text),
            )
            for hit in chosen
        )
        insufficient = (
            len({item.citation.evidence_id for item in snippets})
            < budget.minimum_citations
        )
        material = {
            "snippets": [item.model_dump(mode="json") for item in snippets],
            "token_count": sum(item.token_count for item in snippets),
            "byte_count": sum(len(item.framed_text.encode()) for item in snippets),
            "insufficient_context": insufficient,
            "instruction_boundary": (
                "retrieved-memory-is-untrusted-data-not-instructions-or-authority"
            ),
        }
        return MemoryContext(**material, context_digest=canonical_digest(material))


class DeterministicSummarizer:
    """Extractive fallback summarizer with complete source citation coverage."""

    def summarize(self, request: SummaryRequest) -> SummaryResult:
        claims: list[SummaryClaim] = []
        texts: list[str] = []
        remaining = request.maximum_tokens
        for chunk in request.source_chunks:
            sentence = chunk.text.split(".", maxsplit=1)[0].strip()
            if not sentence:
                continue
            tokens = token_estimate(sentence)
            if tokens > remaining:
                continue
            claims.append(SummaryClaim(text=sentence, citations=(chunk.chunk_id,)))
            texts.append(sentence)
            remaining -= tokens
        if not claims:
            raise IntegrityFailure("summary budget cannot cover one source claim")
        material = {
            "operation_id": request.operation_id,
            "request_digest": request.request_digest,
            "summary": ". ".join(texts),
            "claims": [claim.model_dump(mode="json") for claim in claims],
            "source_coverage": len(
                {citation for claim in claims for citation in claim.citations}
            )
            / len(request.source_chunks),
            "fallback_used": True,
            "fence_token": request.fence_token,
        }
        return SummaryResult(**material, result_digest=canonical_digest(material))


class MemoryCompactor:
    def __init__(
        self,
        *,
        summarizer: SummarizationPort,
        minimum_coverage: float = 0.8,
        maximum_depth: int = 4,
    ) -> None:
        if not 0 < minimum_coverage <= 1 or maximum_depth < 1 or maximum_depth > 4:
            raise ValueError("compaction controls are invalid")
        self._summarizer = summarizer
        self._minimum_coverage = minimum_coverage
        self._maximum_depth = maximum_depth

    def compact(self, request: SummaryRequest) -> SummaryResult:
        if request.depth > self._maximum_depth:
            raise PolicyDenied("summary depth exceeds compaction policy")
        result = self._summarizer.summarize(request)
        allowed = {chunk.chunk_id for chunk in request.source_chunks}
        cited = {citation for claim in result.claims for citation in claim.citations}
        if (
            result.request_digest != request.request_digest
            or result.fence_token != request.fence_token
            or result.source_coverage < self._minimum_coverage
            or not cited.issubset(allowed)
            or any(
                not _claim_supported(claim, request.source_chunks)
                for claim in result.claims
            )
        ):
            fallback = DeterministicSummarizer().summarize(request)
            if fallback.source_coverage < self._minimum_coverage:
                raise IntegrityFailure("summary lacks required source coverage")
            return fallback
        return result


class MemoryLifecycleService:
    """Persists intent before nondeterministic work and validates fenced results."""

    def __init__(
        self,
        *,
        ledger: MemoryLedger,
        embedder: EmbeddingPort,
        index: InMemoryHybridIndex,
        chunker: DeterministicChunker,
        clock: Callable[[], datetime],
    ) -> None:
        self._ledger = ledger
        self._embedder = embedder
        self._index = index
        self._chunker = chunker
        self._clock = clock

    def ingest(
        self,
        *,
        record: MemoryRecord,
        evidence: NormalizedEvidence,
        actor_ref: str,
        acceptance: MemoryAcceptance,
        embedding_spec: EmbeddingSpec,
    ) -> MemoryProjection:
        if (
            evidence.tenant_id != record.tenant_id
            or evidence.evidence_id != record.provenance.evidence_id
            or evidence.content_hash != record.content_digest
            or record.chunker_version != self._chunker.version
            or record.embedder_model != embedding_spec.model
            or record.embedder_version != embedding_spec.version
            or record.embedding_dimensions != embedding_spec.dimensions
            or acceptance.tenant_id != record.tenant_id
            or acceptance.memory_id != record.memory_id
        ):
            raise IntegrityFailure("memory candidate bindings are invalid")
        if evidence.disposition not in {
            EvidenceDisposition.ACCEPTED,
            EvidenceDisposition.REDACTED,
        }:
            raise PolicyDenied("quarantined or duplicate evidence cannot become memory")
        self._ledger.put_record(record)
        projection = self._append(
            record,
            expected=0,
            fact_type=MemoryFactType.CANDIDATE_PROPOSED,
            suffix="candidate",
            actor_ref=actor_ref,
            payload={
                "record_digest": record.canonical_digest,
                "tier": record.tier.value,
                "trust": record.trust.value,
            },
        )
        if acceptance.disposition == "reject":
            return self._append(
                record,
                expected=projection.version,
                fact_type=MemoryFactType.CANDIDATE_REJECTED,
                suffix="reject",
                actor_ref=actor_ref,
                payload={
                    "reason_code": acceptance.reason_code,
                    "acceptance_digest": acceptance.digest,
                },
            )
        if record.status not in {MemoryStatus.ACCEPTED, MemoryStatus.ACTIVE}:
            raise PolicyDenied("durable memory requires explicit accepted record")
        projection = self._append(
            record,
            expected=projection.version,
            fact_type=MemoryFactType.CANDIDATE_ACCEPTED,
            suffix="accept",
            actor_ref=actor_ref,
            payload={
                "record_digest": record.canonical_digest,
                "acceptance_digest": acceptance.digest,
                "reviewer_kind": acceptance.reviewer_kind,
                "policy_digest": acceptance.policy_digest,
            },
        )
        for fact_type in (
            MemoryFactType.SCAN_REQUESTED,
            MemoryFactType.SCAN_COMPLETED,
            MemoryFactType.CHUNK_REQUESTED,
        ):
            projection = self._append(
                record,
                expected=projection.version,
                fact_type=fact_type,
                suffix=fact_type.value,
                actor_ref=actor_ref,
                payload={"content_digest": record.content_digest},
            )
        chunks = self._chunker.split(
            tenant_id=record.tenant_id,
            memory_id=record.memory_id,
            text=evidence.canonical_text,
            citation=record.citations[0],
        )
        projection = self._append(
            record,
            expected=projection.version,
            fact_type=MemoryFactType.CHUNK_COMPLETED,
            suffix="chunks",
            actor_ref=actor_ref,
            payload={
                "chunk_count": len(chunks),
                "chunk_set_digest": canonical_digest(chunks),
            },
        )
        request_material = {
            "operation_id": stable_id(
                "embed", record.tenant_id, record.memory_id, length=32
            ),
            "tenant_id": record.tenant_id,
            "run_id": record.run_id,
            "reservation_id": stable_id(
                "embedding-reservation",
                record.tenant_id,
                record.memory_id,
                length=32,
            ),
            "fence_token": stable_id(
                "embedding-fence",
                record.tenant_id,
                record.memory_id,
                str(projection.version),
                length=32,
            ),
            "spec": embedding_spec,
            "chunks": chunks,
        }
        request = EmbeddingRequest(
            **request_material,
            request_digest=canonical_digest(request_material),
        )
        projection = self._append(
            record,
            expected=projection.version,
            fact_type=MemoryFactType.EMBED_REQUESTED,
            suffix="embed-intent",
            actor_ref=actor_ref,
            payload={
                "request_digest": request.request_digest,
                "reservation_ref": request.reservation_id,
                "spec_digest": embedding_spec.digest,
            },
        )
        result = self._embedder.embed(request)
        projection = self._append(
            record,
            expected=projection.version,
            fact_type=MemoryFactType.EMBED_COMPLETED,
            suffix="embed-result",
            actor_ref=actor_ref,
            payload={
                "request_digest": request.request_digest,
                "result_digest": result.result_digest,
                "vector_count": len(result.vectors),
            },
        )
        projection = self._append(
            record,
            expected=projection.version,
            fact_type=MemoryFactType.INDEX_REQUESTED,
            suffix="index-intent",
            actor_ref=actor_ref,
            payload={"vector_set_digest": result.result_digest},
        )
        vectors = {vector.chunk_id: vector for vector in result.vectors}
        indexed_at = self._clock()
        for chunk in chunks:
            vector = vectors.get(chunk.chunk_id)
            if vector is None:
                raise IntegrityFailure("embedding result omitted a chunk")
            self._index.index(
                IndexedChunk(
                    record=record,
                    chunk=chunk,
                    vector=vector,
                    indexed_at=indexed_at,
                )
            )
        return self._append(
            record,
            expected=projection.version,
            fact_type=MemoryFactType.INDEX_COMPLETED,
            suffix="index-result",
            actor_ref=actor_ref,
            payload={
                "indexed_count": len(chunks),
                "vector_set_digest": result.result_digest,
            },
        )

    def rebuild_derived(
        self,
        *,
        tenant_id: str,
        memory_id: str,
        rebuild_id: str,
        evidence: NormalizedEvidence,
        actor_ref: str,
        embedding_spec: EmbeddingSpec,
    ) -> MemoryProjection:
        """Rebuild a disposable index from application facts and retained content."""

        record = self._ledger.record(tenant_id=tenant_id, memory_id=memory_id)
        if record is None:
            raise IntegrityFailure("cannot rebuild unknown memory")
        projection = self._ledger.projection(
            tenant_id=tenant_id,
            memory_id=memory_id,
        )
        if projection is None:
            raise IntegrityFailure("memory projection must be rebuilt before its index")
        if (
            evidence.tenant_id != record.tenant_id
            or evidence.evidence_id != record.provenance.evidence_id
            or evidence.content_hash != record.content_digest
            or record.chunker_version != self._chunker.version
            or record.embedder_model != embedding_spec.model
            or record.embedder_version != embedding_spec.version
            or record.embedding_dimensions != embedding_spec.dimensions
            or evidence.disposition
            not in {EvidenceDisposition.ACCEPTED, EvidenceDisposition.REDACTED}
            or projection.status is not MemoryStatus.ACTIVE
            or not projection.indexed
            or projection.tombstoned
            or projection.derived_purged
            or projection.blob_erased
        ):
            raise IntegrityFailure("memory rebuild bindings are invalid")
        chunks = self._chunker.split(
            tenant_id=record.tenant_id,
            memory_id=record.memory_id,
            text=evidence.canonical_text,
            citation=record.citations[0],
        )
        chunk_facts = tuple(
            fact
            for fact in self._ledger.facts(
                tenant_id=tenant_id,
                memory_id=memory_id,
            )
            if fact.fact_type is MemoryFactType.CHUNK_COMPLETED
        )
        if (
            len(chunk_facts) != 1
            or chunk_facts[0].payload.get("chunk_count") != len(chunks)
            or chunk_facts[0].payload.get("chunk_set_digest")
            != canonical_digest(chunks)
        ):
            raise IntegrityFailure("memory rebuild chunk set differs from ledger")
        request_material = {
            "operation_id": stable_id(
                "memory-rebuild-embed",
                tenant_id,
                memory_id,
                rebuild_id,
                length=32,
            ),
            "tenant_id": tenant_id,
            "run_id": record.run_id,
            "reservation_id": stable_id(
                "memory-rebuild-reservation",
                tenant_id,
                memory_id,
                rebuild_id,
                length=32,
            ),
            "fence_token": stable_id(
                "memory-rebuild-fence",
                tenant_id,
                memory_id,
                rebuild_id,
                length=32,
            ),
            "spec": embedding_spec,
            "chunks": chunks,
        }
        request = EmbeddingRequest(
            **request_material,
            request_digest=canonical_digest(request_material),
        )
        prior_rebuild_facts = tuple(
            fact
            for fact in self._ledger.facts(
                tenant_id=tenant_id,
                memory_id=memory_id,
            )
            if fact.fact_type
            in {
                MemoryFactType.REBUILD_REQUESTED,
                MemoryFactType.REBUILD_COMPLETED,
            }
            and fact.payload.get("rebuild_id") == rebuild_id
        )
        if any(
            fact.payload.get("request_digest") != request.request_digest
            for fact in prior_rebuild_facts
        ):
            raise IdempotencyConflict("memory rebuild replay changed")
        if any(
            fact.fact_type is MemoryFactType.REBUILD_COMPLETED
            for fact in prior_rebuild_facts
        ):
            return projection
        projection = self._append(
            record,
            expected=projection.version,
            fact_type=MemoryFactType.REBUILD_REQUESTED,
            suffix=f"rebuild-requested:{rebuild_id}",
            actor_ref=actor_ref,
            payload={
                "rebuild_id": rebuild_id,
                "request_digest": request.request_digest,
                "record_digest": record.canonical_digest,
                "spec_digest": embedding_spec.digest,
            },
        )
        result = self._embedder.embed(request)
        vectors = {vector.chunk_id: vector for vector in result.vectors}
        if len(vectors) != len(chunks):
            raise IntegrityFailure("memory rebuild embedding set is incomplete")
        indexed = tuple(
            IndexedChunk(
                record=record,
                chunk=chunk,
                vector=vectors[chunk.chunk_id],
                indexed_at=self._clock(),
            )
            for chunk in chunks
        )
        self._index.purge(tenant_id=tenant_id, memory_id=memory_id)
        for item in indexed:
            self._index.index(item)
        return self._append(
            record,
            expected=projection.version,
            fact_type=MemoryFactType.REBUILD_COMPLETED,
            suffix=f"rebuild-completed:{rebuild_id}",
            actor_ref=actor_ref,
            payload={
                "rebuild_id": rebuild_id,
                "indexed_count": len(indexed),
                "request_digest": request.request_digest,
                "result_digest": result.result_digest,
            },
        )

    def tombstone_and_erase(
        self,
        *,
        tenant_id: str,
        memory_id: str,
        actor_ref: str,
        reason_code: str,
        erase_blob: Callable[[ErasableBlobReference], None],
    ) -> MemoryProjection:
        record = self._ledger.record(tenant_id=tenant_id, memory_id=memory_id)
        projection = self._ledger.projection(tenant_id=tenant_id, memory_id=memory_id)
        if record is None or projection is None:
            raise IntegrityFailure("memory is missing")
        if projection.legal_hold_count or record.retention.held:
            raise PolicyDenied("memory is under legal hold")
        projection = self._append(
            record,
            expected=projection.version,
            fact_type=MemoryFactType.TOMBSTONED,
            suffix="tombstone",
            actor_ref=actor_ref,
            payload={"reason_code": reason_code},
        )
        purged = self._index.purge(tenant_id=tenant_id, memory_id=memory_id)
        projection = self._append(
            record,
            expected=projection.version,
            fact_type=MemoryFactType.DERIVED_PURGED,
            suffix="purge",
            actor_ref=actor_ref,
            payload={"purged_count": purged},
        )
        erase_blob(record.blob)
        return self._append(
            record,
            expected=projection.version,
            fact_type=MemoryFactType.CRYPTO_ERASED,
            suffix="crypto-erase",
            actor_ref=actor_ref,
            payload={
                "blob_ref_digest": sha256(record.blob.blob_ref.encode()).hexdigest()
            },
        )

    def supersede(
        self,
        *,
        replacement: MemoryRecord,
        replaced_memory_ids: Sequence[str],
        actor_ref: str,
    ) -> tuple[MemoryProjection, ...]:
        expected = tuple(sorted(set(replaced_memory_ids)))
        if replacement.supersedes != expected or replacement.status not in {
            MemoryStatus.ACCEPTED,
            MemoryStatus.ACTIVE,
        }:
            raise PolicyDenied("replacement memory lacks exact accepted supersession")
        projections: list[MemoryProjection] = []
        for memory_id in expected:
            record = self._ledger.record(
                tenant_id=replacement.tenant_id,
                memory_id=memory_id,
            )
            projection = self._ledger.projection(
                tenant_id=replacement.tenant_id,
                memory_id=memory_id,
            )
            if record is None or projection is None:
                raise IntegrityFailure("superseded memory is missing")
            if projection.status not in {
                MemoryStatus.ACCEPTED,
                MemoryStatus.ACTIVE,
            }:
                raise IntegrityFailure("superseded memory is not active")
            projections.append(
                self._append(
                    record,
                    expected=projection.version,
                    fact_type=MemoryFactType.SUPERSEDED,
                    suffix=f"superseded-by:{replacement.memory_id}",
                    actor_ref=actor_ref,
                    payload={
                        "replacement_ref": stable_id(
                            "memory-ref",
                            replacement.tenant_id,
                            replacement.memory_id,
                            length=32,
                        ),
                        "replacement_digest": replacement.canonical_digest,
                    },
                )
            )
            self._index.purge(
                tenant_id=replacement.tenant_id,
                memory_id=memory_id,
            )
        return tuple(projections)

    def set_legal_hold(
        self,
        *,
        tenant_id: str,
        memory_id: str,
        hold_ref: str,
        applied: bool,
        actor_ref: str,
    ) -> MemoryProjection:
        record = self._ledger.record(tenant_id=tenant_id, memory_id=memory_id)
        projection = self._ledger.projection(
            tenant_id=tenant_id,
            memory_id=memory_id,
        )
        if record is None or projection is None:
            raise IntegrityFailure("memory is missing")
        return self._append(
            record,
            expected=projection.version,
            fact_type=(
                MemoryFactType.LEGAL_HOLD_APPLIED
                if applied
                else MemoryFactType.LEGAL_HOLD_RELEASED
            ),
            suffix=f"legal-hold:{'apply' if applied else 'release'}:{hold_ref}",
            actor_ref=actor_ref,
            payload={"hold_ref_digest": sha256(hold_ref.encode()).hexdigest()},
        )

    def _append(
        self,
        record: MemoryRecord,
        *,
        expected: int,
        fact_type: MemoryFactType,
        suffix: str,
        actor_ref: str,
        payload: Mapping[str, JsonValue],
    ) -> MemoryProjection:
        return self._ledger.append(
            tenant_id=record.tenant_id,
            memory_id=record.memory_id,
            expected_version=expected,
            fact_type=fact_type,
            command_id=stable_id(
                "memory-command",
                record.tenant_id,
                record.memory_id,
                suffix,
                length=32,
            ),
            actor_ref=actor_ref,
            recorded_at=self._clock(),
            payload=payload,
        )


def memory_record_from_evidence(
    evidence: NormalizedEvidence,
    *,
    tier: MemoryTier,
    acl: MemoryACL,
    schema_name: str,
    schema_revision: int,
    chunker_version: str,
    embedding_spec: EmbeddingSpec,
    quality: float,
    confidence: float,
    retention: RetentionBinding,
    blob_ref: str,
    key_ref: str,
    key_version: int,
    accepted_at: datetime,
) -> MemoryRecord:
    if _SECRET.search(evidence.canonical_text):
        raise PolicyDenied("memory contains a secret")
    if _PII.search(evidence.canonical_text):
        raise PolicyDenied("memory contains unapproved PII")
    if _INJECTION.search(evidence.canonical_text):
        raise PolicyDenied("memory contains prompt injection")
    provenance = MemoryProvenance(
        tenant_id=evidence.tenant_id,
        incident_id=evidence.incident_id,
        run_id=evidence.provenance.run_id,
        source_id=evidence.provenance.source_id,
        source_type=evidence.kind.value,
        source_digest=evidence.provenance.source_digest,
        evidence_id=evidence.evidence_id,
        locator=evidence.provenance.locator,
        content_hash=evidence.content_hash,
        provenance_digest=evidence.provenance.digest,
        observed_at=evidence.provenance.observed_at,
        ingested_at=accepted_at,
    )
    citation = MemoryCitation(
        evidence_id=evidence.evidence_id,
        source_id=evidence.provenance.source_id,
        locator=evidence.provenance.locator,
        content_hash=evidence.content_hash,
        provenance_digest=evidence.provenance.digest,
    )
    memory_id = stable_id(
        "memory",
        evidence.tenant_id,
        tier.value,
        evidence.evidence_id,
        evidence.content_hash,
        length=32,
    )
    material = {
        "schema_version": 1,
        "memory_id": memory_id,
        "tenant_id": evidence.tenant_id,
        "tier": tier,
        "status": MemoryStatus.ACCEPTED,
        "incident_id": evidence.incident_id,
        "run_id": evidence.provenance.run_id,
        "source_type": evidence.kind.value,
        "provenance": provenance,
        "citations": (citation,),
        "acl": acl,
        "classification": evidence.provenance.classification,
        "trust": evidence.provenance.source_trust,
        "schema_name": schema_name,
        "schema_revision": schema_revision,
        "chunker_version": chunker_version,
        "embedder_model": embedding_spec.model,
        "embedder_version": embedding_spec.version,
        "embedding_dimensions": embedding_spec.dimensions,
        "content_digest": evidence.content_hash,
        "quality": quality,
        "confidence": confidence,
        "retention": retention,
        "blob": ErasableBlobReference(
            tenant_id=evidence.tenant_id,
            blob_ref=blob_ref,
            key_ref=key_ref,
            key_version=key_version,
            content_digest=evidence.content_hash,
            byte_count=len(evidence.canonical_text.encode()),
        ),
        "supersedes": (),
        "superseded_by": None,
        "tombstone_reason": None,
        "created_at": accepted_at,
        "accepted_at": accepted_at,
    }
    return MemoryRecord(**material, canonical_digest=canonical_digest(material))


def memory_digest(record: MemoryRecord) -> Sha256Digest:
    return canonical_digest(
        record.model_dump(mode="json", exclude={"canonical_digest"})
    )


def canonical_text(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
    normalized = "".join(
        character
        for character in normalized
        if character in "\n\t" or ord(character) >= 32
    )
    normalized = "\n".join(line.rstrip() for line in normalized.splitlines()).strip()
    if not normalized or len(normalized) > _MAX_MEMORY_TEXT:
        raise ValueError("memory text is empty or exceeds the bound")
    return normalized


def token_estimate(text: str) -> int:
    return max(1, math.ceil(len(text.encode()) / 4))


def _deterministic_vector(text: str, dimensions: int) -> tuple[float, ...]:
    values = [0.0] * dimensions
    for term in _terms(text):
        digest = sha256(term.encode()).digest()
        index = int.from_bytes(digest[:4], "big") % dimensions
        sign = 1.0 if digest[4] & 1 else -1.0
        values[index] += sign * (1.0 + digest[5] / 255.0)
    if not any(values):
        values[0] = 1.0
    norm = math.sqrt(sum(value * value for value in values))
    return tuple(value / norm for value in values)


def _terms(text: str) -> tuple[str, ...]:
    return tuple(_WORD.findall(canonical_text(text).lower()))


def _eligible(item: IndexedChunk, query: RetrievalQuery) -> bool:
    record = item.record
    return (
        record.tenant_id == query.tenant_id
        and record.status in {MemoryStatus.ACCEPTED, MemoryStatus.ACTIVE}
        and record.classification in query.allowed_classifications
        and record.acl.permits(
            roles=query.roles,
            principal_ref=query.principal_ref,
        )
        and record.accepted_at is not None
        and record.accepted_at <= query.as_of
        and record.retention.expires_at > query.as_of
        and record.superseded_by is None
        and record.tombstone_reason is None
    )


def _score(
    item: IndexedChunk,
    query: RetrievalQuery,
    *,
    query_vector: Sequence[float],
    query_terms: Counter[str],
) -> tuple[IndexedChunk, RetrievalHit]:
    terms = Counter(_terms(item.chunk.text))
    overlap = sum(min(count, terms[term]) for term, count in query_terms.items())
    lexical = overlap / max(sum(query_terms.values()), 1)
    cosine = sum(
        left * right
        for left, right in zip(query_vector, item.vector.values, strict=True)
    )
    vector = min(1.0, max(0.0, (cosine + 1.0) / 2.0))
    age = max(0.0, (query.as_of - item.indexed_at).total_seconds())
    recency = max(0.0, 1.0 - age / query.policy.freshness_seconds)
    quality = (item.record.quality + item.record.confidence) / 2.0
    combined = min(
        1.0,
        max(
            0.0,
            lexical * query.policy.lexical_weight
            + vector * query.policy.vector_weight
            + recency * query.policy.recency_weight
            + quality * query.policy.quality_weight,
        ),
    )
    return (
        item,
        RetrievalHit(
            memory_id=item.record.memory_id,
            chunk_id=item.chunk.chunk_id,
            tier=item.record.tier,
            text=item.chunk.text,
            citation=item.chunk.citation,
            lexical_score=lexical,
            vector_score=vector,
            recency_score=recency,
            quality_score=quality,
            combined_score=combined,
            stale=age > query.policy.freshness_seconds,
        ),
    )


def _mmr(
    candidates: Sequence[tuple[IndexedChunk, RetrievalHit]],
    policy: RetrievalPolicy,
) -> list[tuple[IndexedChunk, RetrievalHit]]:
    remaining = list(candidates)
    selected: list[tuple[IndexedChunk, RetrievalHit]] = []
    while remaining and len(selected) < policy.top_k:
        best = max(
            remaining,
            key=lambda pair: (
                policy.mmr_lambda * pair[1].combined_score
                - (1.0 - policy.mmr_lambda)
                * max(
                    (
                        max(
                            0.0,
                            sum(
                                left * right
                                for left, right in zip(
                                    pair[0].vector.values,
                                    chosen[0].vector.values,
                                    strict=True,
                                )
                            ),
                        )
                        for chosen in selected
                    ),
                    default=0.0,
                ),
                -pair[0].chunk.ordinal,
            ),
        )
        selected.append(best)
        remaining.remove(best)
    return selected


def _frame_untrusted(hit: RetrievalHit) -> str:
    escaped = hit.text.replace("<", "&lt;").replace(">", "&gt;")
    return (
        f'<untrusted-memory chunk="{hit.chunk_id}" '
        f'evidence="{hit.citation.evidence_id}">\n'
        f"{escaped}\n</untrusted-memory>"
    )


def _lost_middle_order(length: int) -> tuple[int, ...]:
    order: list[int] = []
    left = 0
    right = length - 1
    while left <= right:
        order.append(left)
        if right != left:
            order.append(right)
        left += 1
        right -= 1
    return tuple(order)


def _claim_key(text: str) -> str:
    terms = _terms(text)
    return "\x00".join(terms[:4])


def _claim_supported(
    claim: SummaryClaim,
    chunks: Sequence[MemoryChunk],
) -> bool:
    sources = {chunk.chunk_id: canonical_text(chunk.text).lower() for chunk in chunks}
    words = set(_terms(claim.text))
    cited_text = " ".join(sources.get(citation, "") for citation in claim.citations)
    return bool(words) and words.issubset(set(_terms(cited_text)))


def _bounded_count(value: JsonValue | None, *, maximum: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= maximum
    ):
        raise IntegrityFailure("memory fact count is invalid")
    return value
