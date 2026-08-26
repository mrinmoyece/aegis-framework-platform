"""Run the bounded, network-free Layer 15 enterprise qualification."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import time
from collections.abc import Callable
from datetime import UTC, date, datetime
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
    if not samples:
        raise ValueError("percentile requires at least one sample")
    if not 0 < percentile <= 1:
        raise ValueError("percentile must be within (0, 1]")
    ordered = sorted(samples)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return round(ordered[index], 3)


async def _run_profile_sample(
    driver: Callable[[], None],
) -> tuple[float, str | None]:
    started = time.perf_counter_ns()
    try:
        await asyncio.to_thread(driver)
    except Exception as exc:
        return (time.perf_counter_ns() - started) / 1_000_000, type(exc).__name__
    return (time.perf_counter_ns() - started) / 1_000_000, None


async def _run_profile_load(
    driver: Callable[[], None], *, runs: int, concurrency: int
) -> tuple[list[float], int, str | None, float]:
    samples: list[float] = []
    failures = 0
    first_error_code: str | None = None
    started = time.perf_counter_ns()
    for offset in range(0, runs, concurrency):
        batch_size = min(concurrency, runs - offset)
        batch = await asyncio.gather(
            *(_run_profile_sample(driver) for _ in range(batch_size))
        )
        for sample_ms, error_code in batch:
            samples.append(sample_ms)
            if error_code is not None:
                failures += 1
                first_error_code = first_error_code or error_code
    elapsed_seconds = (time.perf_counter_ns() - started) / 1_000_000_000
    if elapsed_seconds <= 0:
        raise RuntimeError("load profile elapsed time must be positive")
    return samples, failures, first_error_code, round(len(samples) / elapsed_seconds, 3)


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
        concurrency = int(profile["concurrency"])
        if concurrency < 1 or concurrency > runs:
            raise ValueError("local performance concurrency must be between 1 and runs")
        samples, failures, first_error_code, throughput = asyncio.run(
            _run_profile_load(driver, runs=runs, concurrency=concurrency)
        )
        p50 = _percentile(samples, 0.50)
        p95 = _percentile(samples, 0.95)
        p99 = _percentile(samples, 0.99)
        error_rate = failures / len(samples)
        passed = all(
            (
                p99 <= float(profile["p99_budget_ms"]),
                throughput >= float(profile["minimum_iterations_per_second"]),
                error_rate <= float(profile["maximum_error_rate"]),
            )
        )
        results.append(
            {
                "component": profile["component"],
                "status": status,
                "samples": len(samples),
                "concurrency": concurrency,
                "p50_ms": p50,
                "p95_ms": p95,
                "p99_ms": p99,
                "iterations_per_second": throughput,
                "error_rate": error_rate,
                "p99_budget_ms": profile["p99_budget_ms"],
                "minimum_iterations_per_second": profile[
                    "minimum_iterations_per_second"
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
                result.fault_injected,
                result.converged,
                result.unauthorized_effects == 0,
                result.duplicate_effects <= scenario["maximum_duplicate_effects"],
                result.recovery_verified,
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
                "fault_injected": result.fault_injected,
                "converged": result.converged,
                "unauthorized_effects": result.unauthorized_effects,
                "duplicate_effects": result.duplicate_effects,
                "reconciled": result.reconciled,
                "recovery_verified": result.recovery_verified,
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


def _validate_governance(
    *, as_of: date | None = None, local_slo_gates_passed: bool
) -> dict[str, object]:
    readiness = _load("readiness-scorecard.json")
    risks = _load("residual-risks.json")
    attacks = _load("adversarial-assessment.json")
    acceptance = _load("operational-acceptance.json")
    required_fields = (
        "owner",
        "approver",
        "date",
        "slo_gates_passed",
        "security_sign_off",
    )
    missing_fields = [field for field in required_fields if field not in readiness]
    if missing_fields:
        raise ValueError(
            f"readiness scorecard is missing required fields: {missing_fields}"
        )
    if not readiness["owner"] or not readiness["approver"]:
        raise ValueError("readiness ownership is incomplete")
    try:
        date.fromisoformat(readiness["date"])
    except ValueError as exc:
        raise ValueError("readiness date must be ISO-8601 yyyy-mm-dd") from exc
    if not isinstance(readiness["slo_gates_passed"], bool):
        raise ValueError("readiness slo_gates_passed must be boolean")
    if not isinstance(readiness["security_sign_off"], bool):
        raise ValueError("readiness security_sign_off must be boolean")
    if readiness["slo_gates_passed"] is not local_slo_gates_passed:
        raise ValueError("readiness SLO gate state does not match measured results")
    for item in readiness["items"]:
        if item["status"] not in ALLOWED_STATUSES:
            raise ValueError("readiness status is invalid")
        if not item["owner"] or not item["evidence"]:
            raise ValueError("readiness evidence governance is incomplete")
        if item["blocking"] and item["status"] in {"Implemented", "Locally Verified"}:
            raise ValueError("a hard go-live blocker cannot be locally cleared")
    for risk in risks["risks"]:
        if not all(risk.get(field) for field in ("owner", "expires_on", "fail_closed")):
            raise ValueError("residual risk governance is incomplete")
        expiry = (
            datetime.strptime(risk["expires_on"], "%Y-%m-%d").replace(tzinfo=UTC).date()
        )
        if expiry < (as_of or datetime.now(UTC).date()):
            raise ValueError("residual risk is expired")
    for family in attacks["families"]:
        if family["status"] not in ALLOWED_STATUSES:
            raise ValueError("adversarial assessment status is invalid")
    if acceptance.get("accepted_for_production") is not False:
        raise ValueError("local operational acceptance must not approve production")
    required_phases = {"day-0", "day-1", "day-2"}
    phase_ids = {p.get("id") for p in acceptance.get("phases", [])}
    if not required_phases.issubset(phase_ids):
        raise ValueError(
            "operational acceptance must include day-0, day-1, and day-2 phases"
        )
    for phase in acceptance["phases"]:
        if phase.get("id") not in required_phases:
            continue
        if not phase.get("owner"):
            raise ValueError(f"phase {phase['id']} is missing an owner")
        commands = phase.get("commands")
        if not commands or not isinstance(commands, list):
            raise ValueError(f"phase {phase['id']} must have at least one command")
        if not phase.get("rollback"):
            raise ValueError(f"phase {phase['id']} is missing a rollback action")
    return {
        "readiness_items": len(readiness["items"]),
        "hard_go_live_blockers": sum(item["blocking"] for item in readiness["items"]),
        "residual_risks": len(risks["risks"]),
        "attack_families": len(attacks["families"]),
        "operational_phases": len(acceptance["phases"]),
        "slo_gates_passed": readiness["slo_gates_passed"],
        "security_sign_off": readiness["security_sign_off"],
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
    local_slo_gates_passed = all(
        profile.get("passed", False)
        for profile in performance["profiles"]
        if profile["status"] == "Locally Verified"
    ) and all(item["passed"] for item in chaos["scenarios"])
    governance = _validate_governance(
        as_of=as_of, local_slo_gates_passed=local_slo_gates_passed
    )

    deterministic_evidence = {
        "schema_version": 1,
        "layer": 15,
        "parent_baseline_sha": ("60b120c6c6348044e716a2cc79e679b6bd29b758"),
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
    executed = [p for p in performance["profiles"] if p.get("samples", 0) > 0]
    env_gates = [p for p in performance["profiles"] if p.get("samples", 0) == 0]
    print(
        "qualification: "
        f"{evidence['cross_layer_cases']['passed']} cases, "
        f"{len(chaos['scenarios'])} chaos scenarios, "
        f"{len(executed)} capacity profiles executed locally"
        + (f", {len(env_gates)} deferred to environment gate" if env_gates else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
