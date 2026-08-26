"""Deterministic, redacted Layer 9 memory demonstration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256

from aegis_framework.evidence import (
    DataClassification,
    EvidenceDisposition,
    EvidenceProvenance,
    EvidenceSourceKind,
    NormalizedEvidence,
    SourceTrust,
)
from aegis_framework.memory import (
    AuditedMemoryRetrievalControl,
    ContextBudget,
    ControlledEmbeddingGateway,
    DeterministicChunker,
    DeterministicEmbeddingAdapter,
    EmbeddingSpec,
    InMemoryHybridIndex,
    InMemoryMemoryControl,
    InMemoryMemoryLedger,
    InMemoryMemoryOperationLedger,
    LangGraphMemoryContextBuilder,
    MemoryAcceptance,
    MemoryACL,
    MemoryContext,
    MemoryLifecycleService,
    MemoryProjection,
    MemoryRetrievalService,
    MemoryTier,
    RetentionBinding,
    RetrievalPolicy,
    RetrievalQuery,
    RetrievalResult,
    deterministic_query_vector,
    memory_record_from_evidence,
)

DEMO_MEMORY_TIME = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)


@dataclass(frozen=True)
class MemoryDemo:
    projection: MemoryProjection
    retrieval: RetrievalResult
    context: MemoryContext
    control: InMemoryMemoryControl
    retrieval_service: AuditedMemoryRetrievalControl


def run_memory_demo() -> MemoryDemo:
    evidence = demo_memory_evidence()
    spec = EmbeddingSpec(
        provider="fake",
        model="deterministic-hash",
        version="1.0.0",
        dimensions=64,
        timeout_seconds=2.0,
        maximum_attempts=1,
        maximum_batch_items=32,
        maximum_batch_tokens=8_192,
    )
    chunker = DeterministicChunker(maximum_tokens=32, overlap_tokens=4)
    record = memory_record_from_evidence(
        evidence,
        tier=MemoryTier.EPISODIC,
        acl=MemoryACL(roles=("incident-responder",)),
        schema_name="incident-lesson",
        schema_revision=1,
        chunker_version=chunker.version,
        embedding_spec=spec,
        quality=0.95,
        confidence=0.9,
        retention=RetentionBinding(
            policy_ref="retention:incident-lesson-v1",
            expires_at=DEMO_MEMORY_TIME + timedelta(days=365),
        ),
        blob_ref="blob:lesson-redacted-001",
        key_ref="key:lesson-001",
        key_version=1,
        accepted_at=DEMO_MEMORY_TIME,
    )
    ledger = InMemoryMemoryLedger()
    index = InMemoryHybridIndex()
    lifecycle = MemoryLifecycleService(
        ledger=ledger,
        embedder=ControlledEmbeddingGateway(
            adapter=DeterministicEmbeddingAdapter(dimensions=64),
        ),
        index=index,
        chunker=chunker,
        clock=lambda: DEMO_MEMORY_TIME,
    )
    projection = lifecycle.ingest(
        record=record,
        evidence=evidence,
        actor_ref="actor:memory-reviewer",
        acceptance=MemoryAcceptance(
            decision_id="memory-acceptance:demo-001",
            tenant_id=record.tenant_id,
            memory_id=record.memory_id,
            record_digest=record.canonical_digest,
            disposition="accept",
            reviewer_ref="actor:memory-reviewer",
            reviewer_kind="human",
            policy_id="memory-policy:demo-v1",
            policy_revision=1,
            policy_digest="3" * 64,
            reason_code="evidence_reviewed",
            decided_at=DEMO_MEMORY_TIME,
        ),
        embedding_spec=spec,
    )
    query_text = "checkout failures after deployment rollback"
    query = RetrievalQuery(
        query_id="memory-query:demo-001",
        tenant_id="tenant-acme",
        run_id="run:memory-demo",
        incident_id="incident:checkout-001",
        principal_ref="actor:responder",
        roles=("incident-responder",),
        allowed_classifications=frozenset({DataClassification.INTERNAL}),
        text=query_text,
        query_digest=sha256(query_text.encode()).hexdigest(),
        requested_at=DEMO_MEMORY_TIME,
        as_of=DEMO_MEMORY_TIME,
        policy=RetrievalPolicy(
            policy_id="retrieval:demo-v1",
            revision=1,
            lexical_weight=0.35,
            vector_weight=0.35,
            recency_weight=0.15,
            quality_weight=0.15,
            mmr_lambda=0.7,
            maximum_candidates=20,
            top_k=5,
            maximum_tokens=512,
            maximum_bytes=8_192,
            cache_ttl_seconds=60,
            freshness_seconds=86_400,
        ),
    )
    control = InMemoryMemoryControl(ledger=ledger, index=index, dimensions=64)
    operation_ledger = InMemoryMemoryOperationLedger()
    retrieval_svc = MemoryRetrievalService(
        index=index,
        operations=operation_ledger,
        clock=lambda: DEMO_MEMORY_TIME,
    )
    retrieval_control = AuditedMemoryRetrievalControl(
        service=retrieval_svc,
        embed=lambda text: deterministic_query_vector(text, 64),
    )
    retrieval = control.retrieve(query)
    context = LangGraphMemoryContextBuilder().build(
        result=retrieval,
        budget=ContextBudget(
            total_tokens=1_024,
            reserved_system_tokens=128,
            reserved_safety_tokens=128,
            working_tokens=128,
            episodic_tokens=384,
            semantic_tokens=128,
            maximum_bytes=8_192,
            minimum_citations=1,
        ),
    )
    return MemoryDemo(
        projection=projection,
        retrieval=retrieval,
        context=context,
        control=control,
        retrieval_service=retrieval_control,
    )


def demo_memory_evidence() -> NormalizedEvidence:
    text = (
        "Checkout failures increased after deployment deploy-42. "
        "Rolling back deploy-42 restored the error rate to baseline."
    )
    content_hash = sha256(text.encode()).hexdigest()
    provenance = EvidenceProvenance(
        tenant_id="tenant-acme",
        incident_id="incident:checkout-001",
        run_id="run:memory-demo",
        source_id="source:github-deployments",
        source_kind=EvidenceSourceKind.GITHUB,
        source_trust=SourceTrust.OPERATOR_APPROVED,
        source_digest="1" * 64,
        query_id="query:deployments-001",
        query_digest="2" * 64,
        page_number=1,
        locator="github:deployment:deploy-42",
        observed_at=DEMO_MEMORY_TIME - timedelta(minutes=10),
        retrieved_at=DEMO_MEMORY_TIME - timedelta(minutes=5),
        policy_revision=1,
        classification=DataClassification.INTERNAL,
        retention_ref="retention:evidence-v1",
        raw_content_hash=content_hash,
    )
    return NormalizedEvidence(
        evidence_id="evidence:deploy-42",
        tenant_id="tenant-acme",
        incident_id="incident:checkout-001",
        kind=EvidenceSourceKind.GITHUB,
        summary="deployment evidence",
        facts={"change_id": "deploy-42", "status": "rolled-back"},
        canonical_text=text,
        content_hash=content_hash,
        provenance=provenance,
        disposition=EvidenceDisposition.ACCEPTED,
    )
