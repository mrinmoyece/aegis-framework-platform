from __future__ import annotations

import json
import runpy
from datetime import date
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError

from aegis_framework.errors import IntegrityFailure, PolicyDenied
from aegis_framework.production import (
    CapacityPlan,
    FailoverAuthorization,
    ProductionComponent,
    RegionTopology,
    RestoreLedgerEvent,
    TemporalBoundary,
    WorkerCapacity,
    authorize_failover,
    verify_restored_ledger,
)


def _worker(component: ProductionComponent, queue: str) -> WorkerCapacity:
    return WorkerCapacity(
        component=component,
        task_queue=queue,
        build_id="aegis-0.14.0-build-001",
        replicas=2,
        database_pool_per_replica=3,
        maximum_concurrent_activities=20,
        maximum_concurrent_workflow_tasks=50,
        task_queue_rate_per_second=100,
    )


def test_capacity_plan_preserves_database_headroom_and_queue_isolation() -> None:
    plan = CapacityPlan(
        database_max_connections=500,
        reserved_connections=30,
        headroom_percent=30,
        api_replicas=3,
        api_pool_per_replica=5,
        operator_replicas=2,
        operator_pool_per_replica=3,
        workers=(
            _worker(ProductionComponent.INVESTIGATION, "aegis-investigation-v1"),
            _worker(ProductionComponent.COGNITIVE, "aegis-cognitive-v1"),
            _worker(ProductionComponent.EVIDENCE, "aegis-evidence-v1"),
        ),
    )
    assert plan.planned_database_connections == 69

    with pytest.raises(ValidationError, match="task queues"):
        CapacityPlan.model_validate(
            {
                **plan.model_dump(),
                "workers": [
                    plan.workers[0].model_dump(),
                    {
                        **plan.workers[1].model_dump(),
                        "task_queue": plan.workers[0].task_queue,
                    },
                ],
            }
        )
    with pytest.raises(ValidationError, match="guarded capacity"):
        CapacityPlan.model_validate(
            {
                **plan.model_dump(),
                "database_max_connections": 100,
                "api_replicas": 100,
            }
        )


def test_temporal_production_boundary_fails_closed() -> None:
    boundary = TemporalBoundary(
        mode="temporal-cloud",
        address="private.a1b2c.tmprl.cloud:7233",
        namespace="aegis-production.a1b2c",
        server_name="private.a1b2c.tmprl.cloud",
        client_certificate_secret="temporal-client-cert",
        client_key_secret="temporal-client-key",
        api_key_secret="temporal-api-key",
        payload_codec_key_secret="temporal-payload-codec",
        visibility_retention_days=30,
        schedule_to_start_alert_seconds=30,
        worker_versioning_required=True,
        encrypted_payloads_required=True,
    )
    assert boundary.custom_search_attributes == ()
    with pytest.raises(ValidationError, match="must not be default"):
        TemporalBoundary.model_validate(
            {**boundary.model_dump(), "namespace": "default"}
        )
    with pytest.raises(ValidationError, match="API-key"):
        TemporalBoundary.model_validate(
            {
                **boundary.model_dump(),
                "api_key_secret": None,
                "client_certificate_secret": None,
                "client_key_secret": None,
            }
        )
    mtls = TemporalBoundary.model_validate(
        {
            **boundary.model_dump(),
            "api_key_secret": None,
        }
    )
    assert mtls.client_certificate_secret == "temporal-client-cert"
    with pytest.raises(ValidationError, match="paired"):
        TemporalBoundary.model_validate(
            {
                **boundary.model_dump(),
                "api_key_secret": None,
                "client_key_secret": None,
            }
        )


def test_fenced_single_writer_failover_rejects_stale_or_unapproved_transition() -> None:
    topology = RegionTopology(
        home_region="eu-west-1",
        writer_region="eu-west-1",
        standby_regions=("eu-central-1",),
        generation=7,
        ledger_mode="single-writer-home-region",
        temporal_namespace_strategy="one-namespace-per-region",
        regional_edges_stateless=True,
    )
    authorization = FailoverAuthorization(
        source_region="eu-west-1",
        target_region="eu-central-1",
        expected_generation=7,
        next_generation=8,
        approval_ref="approval:dr:008",
        fence_digest="a" * 64,
        source_writer_fenced=True,
        database_restore_verified=True,
        ledger_hashes_verified=True,
        temporal_operations_reconciled=True,
    )
    active = authorize_failover(topology, authorization)
    assert active.region == "eu-central-1"
    assert active.generation == 8

    with pytest.raises(PolicyDenied, match="stale"):
        authorize_failover(
            topology,
            authorization.model_copy(update={"expected_generation": 6}),
        )
    with pytest.raises(PolicyDenied, match="approved standby"):
        authorize_failover(
            topology,
            authorization.model_copy(update={"target_region": "us-east-1"}),
        )


def _event(
    *,
    cursor: int,
    aggregate_id: str,
    sequence: int,
    aggregate_previous_hash: str,
    tenant_previous_hash: str,
) -> RestoreLedgerEvent:
    payload_digest = sha256(f"payload:{cursor}".encode()).hexdigest()
    draft = RestoreLedgerEvent(
        cursor=cursor,
        aggregate_id=aggregate_id,
        aggregate_sequence=sequence,
        aggregate_previous_hash=aggregate_previous_hash,
        tenant_previous_hash=tenant_previous_hash,
        payload_digest=payload_digest,
        record_hash="0" * 64,
    )
    return draft.model_copy(update={"record_hash": draft.calculated_hash()})


def test_restore_drill_verifies_dual_hashes_sequences_and_rebuild_boundary() -> None:
    first = _event(
        cursor=1,
        aggregate_id="run:001",
        sequence=1,
        aggregate_previous_hash="0" * 64,
        tenant_previous_hash="0" * 64,
    )
    second = _event(
        cursor=2,
        aggregate_id="run:001",
        sequence=2,
        aggregate_previous_hash=first.record_hash,
        tenant_previous_hash=first.record_hash,
    )
    third = _event(
        cursor=3,
        aggregate_id="approval:001",
        sequence=1,
        aggregate_previous_hash="0" * 64,
        tenant_previous_hash=second.record_hash,
    )
    result = verify_restored_ledger((first, second, third))
    assert result.event_count == 3
    assert result.aggregate_count == 2
    assert result.projections_rebuild_required is True
    assert result.temporal_reconciliation_required is True

    with pytest.raises(IntegrityFailure, match="record hash"):
        verify_restored_ledger(
            (first, second.model_copy(update={"record_hash": "f" * 64}))
        )
    with pytest.raises(IntegrityFailure, match="cursor"):
        verify_restored_ledger((first, third))


def test_vulnerability_waiver_is_exact_short_lived_and_no_fix(
    tmp_path: Path,
) -> None:
    evaluate = runpy.run_path("tools/vulnerability_check.py")["evaluate"]
    report = tmp_path / "report.json"
    waivers = tmp_path / "waivers.json"
    finding = {
        "artifact": {"name": "libcrypto3", "version": "3.6.3-r4"},
        "vulnerability": {
            "fix": {"versions": []},
            "id": "CVE-2026-54876",
            "severity": "High",
        },
    }
    report.write_text(json.dumps({"matches": [finding]}))
    waiver = {
        "approved_on": "2026-08-18",
        "affected_scope": "test runtime",
        "compensating_controls": ["minimal runtime image"],
        "expires_on": "2026-08-25",
        "fixed_version_available": False,
        "id": "CVE-2026-54876",
        "owner": "platform-security",
        "package": "libcrypto3",
        "reason_code": "upstream-no-fixed-package-minimal-runtime",
        "reference": "change-ref://layer14-runtime-cve-review",
        "renewal_requires_new_review": True,
        "severity": "High",
        "version": "3.6.3-r4",
    }
    waivers.write_text(json.dumps({"schema_version": 2, "waivers": [waiver]}))
    result = evaluate(
        reports=(report,),
        waiver_path=waivers,
        today=date(2026, 8, 18),
    )
    assert result["waived_count"] == 1
    finding["vulnerability"]["fix"]["versions"] = ["3.6.3-r5"]
    report.write_text(json.dumps({"matches": [finding]}))
    with pytest.raises(ValueError, match="exact no-fix"):
        evaluate(
            reports=(report,),
            waiver_path=waivers,
            today=date(2026, 8, 18),
        )
