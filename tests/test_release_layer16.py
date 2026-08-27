from __future__ import annotations

import json
import runpy
from datetime import date
from pathlib import Path

import pytest

from aegis_framework.errors import IdempotencyConflict, IntegrityFailure
from aegis_framework.evals import load_cases, run_eval_case
from aegis_framework.memory import (
    ControlledEmbeddingGateway,
    DeterministicChunker,
    DeterministicEmbeddingAdapter,
    EmbeddingSpec,
    MemoryLifecycleService,
)
from aegis_framework.memory_demo import (
    DEMO_MEMORY_TIME,
    demo_memory_evidence,
    run_memory_demo,
)


def test_layer16_release_evidence_is_machine_validated() -> None:
    module = runpy.run_path("tools/release_check.py")
    module["validate_readiness"]()
    module["validate_risks"](as_of=date(2026, 8, 18))
    module["validate_comparison"]()
    module["validate_governance"](as_of=date(2026, 8, 18))


def test_release_readiness_requires_explicit_signoff_fields() -> None:
    module = runpy.run_path("tools/release_check.py")
    payload = json.loads(Path("qualification/release-readiness.json").read_text())
    risk_payload = json.loads(Path("qualification/residual-risks.json").read_text())
    payload.pop("approver")

    with pytest.raises(ValueError, match="approver"):
        module["validate_readiness_signoff"](
            payload,
            risk_payload=risk_payload,
            today=date(2026, 8, 18),
        )


def test_vulnerability_policy_rejects_unknown_high_severity_ids() -> None:
    finding_from_match = runpy.run_path("tools/vulnerability_check.py")[
        "_finding_from_match"
    ]

    with pytest.raises(ValueError, match="vulnerability id is invalid"):
        finding_from_match(
            {
                "artifact": {"name": "libssl3", "version": "3.6.3-r4"},
                "vulnerability": {
                    "fix": {"versions": []},
                    "id": "runtime-ticket-123",
                    "severity": "High",
                },
            }
        )


def test_framework_loss_and_bypass_cases_preserve_application_authority() -> None:
    cases = {case.case_id: case for case in load_cases(Path("evals/cases.json"))}
    required = (
        "durable-framework-outage",
        "graph-authority-override",
        "orchestration-projection-rebuild",
        "observability-outage-correctness",
        "tenant-isolation",
        "protocol-confused-deputy",
        "protocol-proposal-only",
    )

    outcomes = tuple(run_eval_case(cases[case_id]) for case_id in required)

    assert all(outcome.passed for outcome in outcomes)
    assert tuple(outcome.case_id for outcome in outcomes) == required


def test_application_truth_rebuilds_memory_projection_and_derived_index() -> None:
    demo = run_memory_demo()
    ledger = demo.control._ledger
    index = demo.control._index
    record = ledger.record(
        tenant_id=demo.projection.tenant_id,
        memory_id=demo.projection.memory_id,
    )
    assert record is not None
    before = ledger.projection(
        tenant_id=demo.projection.tenant_id,
        memory_id=demo.projection.memory_id,
    )

    assert (
        index.purge(
            tenant_id=demo.projection.tenant_id,
            memory_id=demo.projection.memory_id,
        )
        > 0
    )
    assert (
        ledger.rebuild(
            tenant_id=demo.projection.tenant_id,
            memory_id=demo.projection.memory_id,
        )
        == before
    )
    lifecycle = MemoryLifecycleService(
        ledger=ledger,
        embedder=ControlledEmbeddingGateway(
            adapter=DeterministicEmbeddingAdapter(
                dimensions=record.embedding_dimensions,
            )
        ),
        index=index,
        chunker=DeterministicChunker(maximum_tokens=32, overlap_tokens=4),
        clock=lambda: DEMO_MEMORY_TIME,
    )
    spec = EmbeddingSpec(
        provider="fake",
        model=record.embedder_model,
        version=record.embedder_version,
        dimensions=record.embedding_dimensions,
        timeout_seconds=2.0,
        maximum_attempts=1,
        maximum_batch_items=32,
        maximum_batch_tokens=8_192,
    )
    rebuilt = lifecycle.rebuild_derived(
        tenant_id=record.tenant_id,
        memory_id=record.memory_id,
        rebuild_id="rebuild:layer16-loss-001",
        evidence=demo_memory_evidence(),
        actor_ref="actor:rebuild-operator",
        embedding_spec=spec,
    )
    assert rebuilt.version == before.version + 2
    assert demo.control.retrieve(demo.query).hits
    facts = ledger.facts(
        tenant_id=demo.projection.tenant_id,
        memory_id=demo.projection.memory_id,
    )
    assert (
        lifecycle.rebuild_derived(
            tenant_id=record.tenant_id,
            memory_id=record.memory_id,
            rebuild_id="rebuild:layer16-loss-001",
            evidence=demo_memory_evidence(),
            actor_ref="actor:rebuild-operator",
            embedding_spec=spec,
        )
        == rebuilt
    )
    assert (
        ledger.facts(
            tenant_id=demo.projection.tenant_id,
            memory_id=demo.projection.memory_id,
        )
        == facts
    )
    with pytest.raises(IntegrityFailure, match="unknown memory"):
        lifecycle.rebuild_derived(
            tenant_id=record.tenant_id,
            memory_id="memory:unknown",
            rebuild_id="rebuild:unknown",
            evidence=demo_memory_evidence(),
            actor_ref="actor:rebuild-operator",
            embedding_spec=spec,
        )
    with pytest.raises(IntegrityFailure, match="bindings"):
        lifecycle.rebuild_derived(
            tenant_id=record.tenant_id,
            memory_id=record.memory_id,
            rebuild_id="rebuild:wrong-evidence",
            evidence=demo_memory_evidence().model_copy(
                update={"tenant_id": "tenant-beta"}
            ),
            actor_ref="actor:rebuild-operator",
            embedding_spec=spec,
        )
    with pytest.raises(IdempotencyConflict, match="rebuild replay changed"):
        lifecycle.rebuild_derived(
            tenant_id=record.tenant_id,
            memory_id=record.memory_id,
            rebuild_id="rebuild:layer16-loss-001",
            evidence=demo_memory_evidence(),
            actor_ref="actor:rebuild-operator",
            embedding_spec=spec.model_copy(update={"timeout_seconds": 3.0}),
        )
