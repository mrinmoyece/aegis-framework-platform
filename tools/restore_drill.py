"""Emit deterministic, non-cloud restore/failover contract evidence."""

from __future__ import annotations

import argparse
import json
from hashlib import sha256
from pathlib import Path

from aegis_framework.production import (
    FailoverAuthorization,
    RegionTopology,
    RestoreLedgerEvent,
    authorize_failover,
    verify_restored_ledger,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    first = _event(1, "run:restore", 1, "0" * 64, "0" * 64)
    second = _event(
        2,
        "run:restore",
        2,
        first.record_hash,
        first.record_hash,
    )
    restored = verify_restored_ledger((first, second))
    active = authorize_failover(
        RegionTopology(
            home_region="eu-west-1",
            writer_region="eu-west-1",
            standby_regions=("eu-central-1",),
            generation=41,
            ledger_mode="single-writer-home-region",
            temporal_namespace_strategy="one-namespace-per-region",
            regional_edges_stateless=True,
        ),
        FailoverAuthorization(
            source_region="eu-west-1",
            target_region="eu-central-1",
            expected_generation=41,
            next_generation=42,
            approval_ref="approval:restore-drill",
            fence_digest="d" * 64,
            source_writer_fenced=True,
            database_restore_verified=True,
            ledger_hashes_verified=True,
            temporal_operations_reconciled=True,
        ),
    )
    evidence = {
        "application_ledger_authoritative": True,
        "cloud_apply_performed": False,
        "derived_caches_disposable": restored.derived_caches_disposable,
        "drill_kind": "deterministic-offline-contract",
        "event_count": restored.event_count,
        "failover_generation": active.generation,
        "langgraph_rebuild_from_ledger_required": (
            restored.langgraph_rebuild_from_ledger_required
        ),
        "last_cursor": restored.last_cursor,
        "last_tenant_hash": restored.last_tenant_hash,
        "live_managed_failover_performed": False,
        "objective_rpo_seconds": 300,
        "objective_rto_seconds": 3600,
        "outbox_and_effect_reconciliation_required": True,
        "projections_rebuild_required": restored.projections_rebuild_required,
        "schema_version": 1,
        "status": "contract-verified",
        "temporal_reconciliation_required": restored.temporal_reconciliation_required,
        "vector_index_rebuild_required": restored.vector_index_rebuild_required,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


def _event(
    cursor: int,
    aggregate_id: str,
    sequence: int,
    aggregate_previous_hash: str,
    tenant_previous_hash: str,
) -> RestoreLedgerEvent:
    draft = RestoreLedgerEvent(
        cursor=cursor,
        aggregate_id=aggregate_id,
        aggregate_sequence=sequence,
        aggregate_previous_hash=aggregate_previous_hash,
        tenant_previous_hash=tenant_previous_hash,
        payload_digest=sha256(f"restore:{cursor}".encode()).hexdigest(),
        record_hash="0" * 64,
    )
    return draft.model_copy(update={"record_hash": draft.calculated_hash()})


if __name__ == "__main__":
    raise SystemExit(main())
