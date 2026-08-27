"""Run the bounded, network-free Layer 16 enterprise qualification."""

from __future__ import annotations

import argparse
import json
import math
import os
import time
from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from aegis_framework.adapters import FixedClock
from aegis_framework.api import AppMode, create_app
from aegis_framework.durability import InMemoryDurability
from aegis_framework.evals import EvalCase, load_cases, run_eval_case, run_eval_suite
from aegis_framework.evaluation import FaultPlan, FaultPoint, run_fault_scenario
from aegis_framework.fixtures import (
    DEMO_TIME,
    DemoScenario,
    build_demo_bundle,
    demo_identity,
    demo_request,
)
from aegis_framework.memory_demo import run_memory_demo
from aegis_framework.remediation_demo import (
    RemediationDemoScenario,
    run_remediation_demo,
)
from aegis_framework.replay import ReplayDebugger

ROOT = Path(__file__).resolve().parents[1]
QUALIFICATION = ROOT / "qualification"
ALLOWED_STATUSES = {
    "Implemented",
    "Locally Verified",
    "Environment-Gated",
    "Live Evidence Required",
    "Deferred",
}
FORBIDDEN_OUTPUT_KEYS = {
    "actor_id",
    "credential",
    "evidence_locator",
    "prompt",
    "raw_evidence",
    "request_id",
    "secret",
    "tenant_id",
}
MAX_RISK_REVIEW_DAYS = 90


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _digest(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _contains_forbidden_key(value: object) -> bool:
    if isinstance(value, dict):
        return any(
            key in FORBIDDEN_OUTPUT_KEYS or _contains_forbidden_key(item)
            for key, item in value.items()
        )
    if isinstance(value, list | tuple):
        return any(_contains_forbidden_key(item) for item in value)
    return False


def _load(name: str) -> dict[str, Any]:
    payload = json.loads((QUALIFICATION / name).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{name} must contain an object")
    return payload


def _cases() -> tuple[EvalCase, ...]:
    return load_cases(ROOT / "evals/cases.json")


def _case_map(cases: tuple[EvalCase, ...]) -> dict[str, EvalCase]:
    return {case.case_id: case for case in cases}


def _run_case_ids(
    case_ids: list[str],
    cases: dict[str, EvalCase],
) -> tuple[str, ...]:
    missing = sorted(set(case_ids) - set(cases))
    if missing:
        raise ValueError(f"qualification references unknown eval cases: {missing}")
    failed = [
        case_id for case_id in case_ids if not run_eval_case(cases[case_id]).passed
    ]
    if failed:
        raise RuntimeError(f"qualification eval cases failed: {failed}")
    return tuple(sorted(case_ids))


def _api_checkout() -> None:
    request = demo_request()
    client = TestClient(create_app(mode=AppMode.DEMO))
    response = client.post(
        "/v1/investigations",
        headers={
            "Authorization": "Bearer demo-responder-token",
            "X-Request-ID": "qualification-api-checkout",
        },
        json={
            "scenario": "success",
            "incident_id": request.incident_id,
            "alert": request.alert.model_dump(mode="json"),
        },
    )
    if response.status_code != 200 or response.json()["status"] != "complete":
        raise RuntimeError("canonical API checkout did not complete")


def _investigation() -> None:
    bundle = build_demo_bundle(DemoScenario.SUCCESS)
    result = bundle.service.investigate(
        demo_identity(request_id="qualification-investigation"),
        demo_request(),
    )
    if result.proposal is None or not result.hypotheses:
        raise RuntimeError("canonical investigation did not reach a cited proposal")


def _ledger_replay() -> None:
    store = InMemoryDurability(clock=FixedClock(DEMO_TIME))
    run = store.accept_run(
        identity=demo_identity(request_id="qualification-ledger"),
        request=demo_request(),
        wait_for_signal=False,
    )
    events = store.events(tenant_id="tenant-acme")
    debugger = ReplayDebugger(events)
    if not store.verify_integrity(tenant_id="tenant-acme"):
        raise RuntimeError("application ledger integrity failed")
    if not debugger.verify().valid:
        raise RuntimeError("replay debugger rejected the application ledger")
    rebuilt = store.rebuild_run(tenant_id="tenant-acme", run_id=run.run_id)
    if not debugger.compare(aggregate_id=run.run_id, live=rebuilt).matches:
        raise RuntimeError("ledger projection did not converge")


def _remediation() -> None:
    result = run_remediation_demo(RemediationDemoScenario.AMBIGUITY)
    if result.approval_count != 2 or not result.reconciled:
        raise RuntimeError("approval/effect ambiguity did not reconcile")


def _memory() -> None:
    result = run_memory_demo()
    if not result.projection.indexed or not result.context.snippets:
        raise RuntimeError("memory lifecycle did not produce cited bounded context")


def _selected_cases(case_ids: tuple[str, ...]) -> None:
    cases = _case_map(_cases())
    _run_case_ids(list(case_ids), cases)


def _full_eval() -> None:
    report = run_eval_suite(_cases())
    if not report.passed:
        raise RuntimeError("governed evaluation suite failed")


DRIVERS: dict[str, Callable[[], None]] = {
    "api-checkout": _api_checkout,
    "investigation-connectors-graph-model": _investigation,
    "ledger-replay-outbox": _ledger_replay,
    "approval-effect-reconciliation": _remediation,
    "memory-retrieval-index-context": _memory,
    "sandbox-security-pack": lambda: _selected_cases(
        (
            "sandbox-input-security",
            "sandbox-archive-security",
            "sandbox-egress-security",
        )
    ),
    "protocol-mcp-a2a-pack": lambda: _selected_cases(
        (
            "protocol-poisoning",
            "protocol-confused-deputy",
            "protocol-schema-bomb",
            "protocol-ssrf",
            "protocol-proposal-only",
            "protocol-trust-revocation",
            "protocol-ambiguity",
            "protocol-denial-wallet",
        )
    ),
    "governed-evaluation-suite": _full_eval,
}


def _percentile(samples: list[float], percentile: float) -> float:
    ordered = sorted(samples)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return round(ordered[index], 3)


def run_performance() -> dict[str, object]:
    manifest = _load("performance-profiles.json")
    results: list[dict[str, object]] = []
    for profile in manifest["profiles"]:
        status = profile["status"]
        if status not in ALLOWED_STATUSES:
            raise ValueError("performance profile status is invalid")
        driver_name = profile.get("driver")
        if driver_name is None:
            results.append(
                {
                    "component": profile["component"],
                    "status": status,
                    "command": profile["command"],
                    "samples": 0,
                    "claim": "No local latency claim; execute the environment gate.",
                }
            )
            continue
        driver = DRIVERS.get(driver_name)
        if driver is None:
            raise ValueError(f"unknown performance driver: {driver_name}")
        runs = int(profile["runs"])
        if runs < 20 or runs > 500:
            raise ValueError("local performance samples must be between 20 and 500")
        samples: list[float] = []
        failures = 0
        first_error_code: str | None = None
        for _ in range(runs):
            started = time.perf_counter_ns()
            try:
                driver()
            except Exception as exc:
                failures += 1
                first_error_code = first_error_code or type(exc).__name__
            samples.append((time.perf_counter_ns() - started) / 1_000_000)
        p50 = _percentile(samples, 0.50)
        p95 = _percentile(samples, 0.95)
        p99 = _percentile(samples, 0.99)
        elapsed_seconds = sum(samples) / 1_000
        serial_rate = round(len(samples) / elapsed_seconds, 3)
        error_rate = failures / len(samples)
        passed = (
            p99 <= float(profile["p99_budget_ms"])
            and serial_rate >= float(profile["minimum_serial_iterations_per_second"])
            and error_rate <= float(profile["maximum_error_rate"])
        )
        results.append(
            {
                "component": profile["component"],
                "status": status,
                "samples": len(samples),
                "p50_ms": p50,
                "p95_ms": p95,
                "p99_ms": p99,
                "serial_iterations_per_second": serial_rate,
                "error_rate": error_rate,
                "p99_budget_ms": profile["p99_budget_ms"],
                "minimum_serial_iterations_per_second": profile[
                    "minimum_serial_iterations_per_second"
                ],
                "maximum_error_rate": profile["maximum_error_rate"],
                "first_error_code": first_error_code,
                "passed": passed,
            }
        )
        if not passed:
            raise RuntimeError(
                "performance budget failed: "
                f"{profile['component']} ({first_error_code or 'threshold'})"
            )
    return {
        "schema_version": 1,
        "methodology": manifest["methodology"],
        "profiles": results,
        "production_extrapolation": False,
    }


def run_chaos(cases: dict[str, EvalCase]) -> dict[str, object]:
    manifest = _load("chaos-matrix.json")
    scenarios = []
    covered_faults: set[str] = set()
    for index, scenario in enumerate(manifest["scenarios"], start=1):
        fault = FaultPoint(scenario["fault_point"])
        result = run_fault_scenario(FaultPlan(fault_point=fault, seed=index))
        executed_case_ids = _run_case_ids(scenario["case_ids"], cases)
        passed = all(
            (
                result.converged,
                result.unauthorized_effects == 0,
                result.duplicate_effects <= scenario["maximum_duplicate_effects"],
                result.tenant_isolated,
                result.audit_complete,
                result.cleanup_complete,
            )
        )
        if scenario["reconciliation_required"] and not result.reconciled:
            passed = False
        if not passed:
            raise RuntimeError(f"chaos invariant failed: {scenario['id']}")
        covered_faults.add(fault.value)
        scenarios.append(
            {
                "id": scenario["id"],
                "fault_point": fault.value,
                "case_ids": sorted(scenario["case_ids"]),
                "real_path_case_ids": executed_case_ids,
                "real_path_cases_passed": True,
                "contract_model_simulation": True,
                "converged": result.converged,
                "unauthorized_effects": result.unauthorized_effects,
                "duplicate_effects": result.duplicate_effects,
                "reconciled": result.reconciled,
                "tenant_isolated": result.tenant_isolated,
                "audit_complete": result.audit_complete,
                "cleanup_complete": result.cleanup_complete,
                "passed": passed,
            }
        )
    missing = sorted({point.value for point in FaultPoint} - covered_faults)
    if missing:
        raise ValueError(f"chaos matrix omits fault points: {missing}")
    return {
        "schema_version": 1,
        "scenarios": scenarios,
        "all_fault_points_covered": True,
        "contract_model_simulation": True,
        "production_chaos_claim": False,
    }


def _validate_governance(*, as_of: date | None = None) -> dict[str, object]:
    readiness = _load("readiness-scorecard.json")
    risks = _load("residual-risks.json")
    attacks = _load("adversarial-assessment.json")
    acceptance = _load("operational-acceptance.json")
    for item in readiness["items"]:
        if item["status"] not in ALLOWED_STATUSES:
            raise ValueError("readiness status is invalid")
        if not item["owner"] or not item["evidence"]:
            raise ValueError("readiness evidence governance is incomplete")
        if item["blocking"] and item["status"] in {"Implemented", "Locally Verified"}:
            raise ValueError("a hard go-live blocker cannot be locally cleared")
    if risks.get("schema_version") != 2:
        raise ValueError("residual risk schema is invalid")
    today = as_of or datetime.now(UTC).date()
    for risk in risks["risks"]:
        if not all(
            risk.get(field)
            for field in (
                "owner",
                "evidence",
                "mitigation",
                "trigger",
                "review_by",
                "target_date",
                "fail_closed",
            )
        ):
            raise ValueError("residual risk governance is incomplete")
        review_by = date.fromisoformat(risk["review_by"])
        target_date = date.fromisoformat(risk["target_date"])
        if review_by < today or review_by > today + timedelta(
            days=MAX_RISK_REVIEW_DAYS
        ):
            raise ValueError("residual risk review is expired or unbounded")
        if target_date < review_by:
            raise ValueError("residual risk target predates review")
    for family in attacks["families"]:
        if family["status"] not in ALLOWED_STATUSES:
            raise ValueError("adversarial assessment status is invalid")
    if acceptance.get("accepted_for_production") is not False:
        raise ValueError("local operational acceptance must not approve production")
    return {
        "readiness_items": len(readiness["items"]),
        "hard_go_live_blockers": sum(item["blocking"] for item in readiness["items"]),
        "residual_risks": len(risks["risks"]),
        "attack_families": len(attacks["families"]),
        "operational_phases": len(acceptance["phases"]),
        "accepted_for_production": False,
    }


def run_qualification(
    *, as_of: date | None = None
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    cases = _cases()
    case_by_id = _case_map(cases)
    eval_report = run_eval_suite(cases)
    if not eval_report.passed:
        raise RuntimeError("canonical cross-layer evaluation failed")

    bundle = build_demo_bundle(DemoScenario.SUCCESS)
    investigation = bundle.service.investigate(
        demo_identity(request_id="qualification-journey"),
        demo_request(),
    )
    remediation = run_remediation_demo(RemediationDemoScenario.SUCCESS)
    ambiguous = run_remediation_demo(RemediationDemoScenario.AMBIGUITY)
    memory = run_memory_demo()
    _ledger_replay()

    adversarial = _load("adversarial-assessment.json")
    security_case_ids = sorted(
        {
            case_id
            for family in adversarial["families"]
            for case_id in family["case_ids"]
        }
    )
    _run_case_ids(security_case_ids, case_by_id)
    chaos = run_chaos(case_by_id)
    performance = run_performance()
    governance = _validate_governance(as_of=as_of)

    deterministic_evidence = {
        "schema_version": 1,
        "layer": 16,
        "parent_baseline_sha": ("4f4b8924247367f959c910f8261baea3337967d6"),
        "source_revision": os.getenv("GITHUB_SHA", "working-tree"),
        "journey": {
            "authenticated_tenant_boundary": True,
            "investigation_status": investigation.status.value,
            "hypotheses": len(investigation.hypotheses),
            "citations": sum(
                len(hypothesis.citations) for hypothesis in investigation.hypotheses
            ),
            "graph_checkpoints": bundle.orchestrator.checkpoint_count(
                tenant_id=investigation.tenant_id,
                thread_ref=investigation.thread_ref,
            ),
            "approval_count": remediation.approval_count,
            "agent_authority": remediation.agent_authority,
            "effect_status": remediation.status.value,
            "ambiguity_reconciled": ambiguous.reconciled,
            "verification_satisfied": remediation.verification_satisfied,
            "memory_indexed": memory.projection.indexed,
            "memory_context_items": len(memory.context.snippets),
            "application_ledger_replay": "converged",
        },
        "cross_layer_cases": {
            "total": eval_report.total,
            "passed": eval_report.succeeded,
            "case_ids": sorted(outcome.case_id for outcome in eval_report.outcomes),
        },
        "security_case_ids": security_case_ids,
        "chaos_scenarios": [item["id"] for item in chaos["scenarios"]],
        "governance": governance,
        "boundaries": {
            "network_used": False,
            "live_credentials_used": False,
            "production_effect_claimed": False,
            "production_readiness_claimed": False,
            "live_evidence_required": True,
        },
    }
    deterministic_evidence["evidence_digest"] = _digest(deterministic_evidence)
    if _contains_forbidden_key(deterministic_evidence):
        raise RuntimeError("qualification output contains a forbidden field")
    return deterministic_evidence, chaos, performance


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("build/qualification"))
    args = parser.parse_args()
    try:
        evidence, chaos, performance = run_qualification()
    except (OSError, KeyError, TypeError, ValueError, RuntimeError) as exc:
        print(f"qualification: {type(exc).__name__}: {exc}")
        return 1
    args.output.mkdir(parents=True, exist_ok=True)
    for name, payload in (
        ("evidence.json", evidence),
        ("chaos.json", chaos),
        ("performance.json", performance),
    ):
        (args.output / name).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(
        "qualification: "
        f"{evidence['cross_layer_cases']['passed']} cases, "
        f"{len(chaos['scenarios'])} chaos scenarios, "
        f"{len(performance['profiles'])} capacity profiles passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
