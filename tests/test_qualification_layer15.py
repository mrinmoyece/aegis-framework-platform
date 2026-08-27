from __future__ import annotations

import json
import os
import runpy
import shutil
from hashlib import sha256
from pathlib import Path

import pytest

from aegis_framework.adapters import FixedClock
from aegis_framework.authorization import RoleCatalog
from aegis_framework.durability import (
    EventDraft,
    InMemoryDurability,
    event_material,
)
from aegis_framework.fixtures import DEMO_TIME, demo_identity, demo_request


def test_layer16_qualification_runs_real_paths_and_keeps_live_gaps() -> None:
    module = runpy.run_path("tools/qualification.py")
    evidence, chaos, performance = module["run_qualification"](as_of=DEMO_TIME.date())

    assert evidence["layer"] == 16
    assert evidence["parent_baseline_sha"] == "4f4b8924247367f959c910f8261baea3337967d6"
    assert evidence["source_revision"] == os.getenv("GITHUB_SHA", "working-tree")
    assert evidence["cross_layer_cases"]["passed"] == 58
    assert evidence["journey"]["approval_count"] == 2
    assert evidence["journey"]["ambiguity_reconciled"] is True
    assert evidence["journey"]["application_ledger_replay"] == "converged"
    assert evidence["boundaries"] == {
        "network_used": False,
        "live_credentials_used": False,
        "production_effect_claimed": False,
        "production_readiness_claimed": False,
        "live_evidence_required": True,
    }
    assert chaos["all_fault_points_covered"] is True
    assert len(chaos["scenarios"]) == 17
    assert all(item["passed"] for item in chaos["scenarios"])
    assert len(performance["profiles"]) == 12
    assert performance["production_extrapolation"] is False
    assert all(
        item.get("passed", True)
        for item in performance["profiles"]
        if item["status"] == "Locally Verified"
    )


def test_role_catalog_and_demo_fixture_do_not_overgrant_operations() -> None:
    admin = RoleCatalog.permissions_for("tenant-admin")
    auditor = RoleCatalog.permissions_for("tenant-auditor")
    responder = demo_identity()

    assert "operations:read" in admin
    assert "support:read" in admin
    assert "replay:read" in admin
    assert "projection:rebuild" in admin
    assert "support:read" in auditor
    assert "projection:rebuild" not in auditor
    assert set(responder.permissions) == set(
        RoleCatalog.permissions_for("incident-responder")
    )


def test_application_integrity_rejects_hash_valid_unknown_schema() -> None:
    store = InMemoryDurability(clock=FixedClock(DEMO_TIME))
    store.accept_run(
        identity=demo_identity(request_id="qualification-schema"),
        request=demo_request(),
        wait_for_signal=False,
    )
    event = store.events(tenant_id="tenant-acme")[0]
    draft = EventDraft(
        event_id=event.event_id,
        event_type=event.event_type,
        occurred_at=event.occurred_at,
        actor_ref=event.actor_ref,
        correlation_ref=event.correlation_ref,
        causation_ref=event.causation_ref,
        schema_version=2,
        payload=event.payload,
    )
    digest = sha256(
        event_material(
            tenant_id=event.tenant_id,
            aggregate_type=event.aggregate_type,
            aggregate_id=event.aggregate_id,
            aggregate_sequence=event.aggregate_sequence,
            tenant_cursor=event.tenant_cursor,
            draft=draft,
            aggregate_previous_hash=event.aggregate_previous_hash,
            tenant_previous_hash=event.tenant_previous_hash,
        ).encode()
    ).hexdigest()
    store._events["tenant-acme"][0] = event.model_copy(
        update={"schema_version": 2, "record_hash": digest}
    )

    assert store.verify_integrity(tenant_id="tenant-acme") is False


def test_residual_risk_expiry_fails_closed(tmp_path: Path) -> None:
    module = runpy.run_path("tools/qualification.py")
    qualification = tmp_path / "qualification"
    shutil.copytree("qualification", qualification)
    risks_path = qualification / "residual-risks.json"
    risks = json.loads(risks_path.read_text(encoding="utf-8"))
    risks["risks"][0]["review_by"] = "2000-01-01"
    risks_path.write_text(json.dumps(risks), encoding="utf-8")
    module["_validate_governance"].__globals__["QUALIFICATION"] = qualification

    with pytest.raises(ValueError, match="residual risk review is expired"):
        module["_validate_governance"](as_of=DEMO_TIME.date())
