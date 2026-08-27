from __future__ import annotations

import json
import socket
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from aegis_framework.evals import EvalCase, EvalOutcome, load_cases
from aegis_framework.evaluation import (
    BaselineContract,
    EvaluationRunner,
    ExecutionObservation,
    FaultPlan,
    FaultPoint,
    LegacyCaseExecutor,
    ObservedMetric,
    ScenarioContract,
    ScoreDirection,
    ScorerContract,
    WaiverContract,
    _within,
    build_case_contracts,
    canonical_digest,
    compare_results,
    create_baseline,
    load_baseline,
    load_dataset,
    load_suite,
    load_waivers,
    run_fault_scenario,
    write_reports,
)


@pytest.fixture
def governed_assets() -> tuple[
    object,
    object,
    BaselineContract,
    tuple[EvalCase, ...],
]:
    return (
        load_suite(Path("evals/suite.json")),
        load_dataset(Path("evals/dataset.json")),
        load_baseline(Path("evals/baseline.json")),
        load_cases(Path("evals/cases.json")),
    )


def test_governed_artifacts_are_complete_and_tamper_bound(
    governed_assets: tuple[object, object, BaselineContract, tuple[EvalCase, ...]],
) -> None:
    suite, dataset, baseline, cases = governed_assets
    contracts = build_case_contracts(suite, cases)  # type: ignore[arg-type]
    assert tuple(item.case_id for item in contracts) == tuple(
        sorted(case.case_id for case in cases)
    )
    assert baseline.suite_digest == suite.canonical_digest  # type: ignore[attr-defined]
    assert baseline.dataset_digest == dataset.canonical_digest  # type: ignore[attr-defined]
    assert set(baseline.case_ids) == {case.case_id for case in cases}
    assert load_waivers(Path("evals/waivers.json")) == ()

    outcomes = {
        scenario.expected_outcome.value  # type: ignore[union-attr]
        for scenario in suite.scenarios  # type: ignore[union-attr]
    }
    assert outcomes == {
        "success",
        "degraded",
        "denied",
        "partial",
        "ambiguous",
        "cancelled",
        "recovered",
        "safe-failure",
    }
    faults = {
        point
        for scenario in suite.scenarios  # type: ignore[union-attr]
        for point in scenario.fault_points
    }
    assert faults == set(FaultPoint)
    attack_tags = {
        tag
        for scenario in suite.scenarios  # type: ignore[union-attr]
        for tag in scenario.attack_tags
    }
    assert {
        "direct-prompt-injection",
        "indirect-prompt-injection",
        "tenant-exfiltration",
        "approval-spoofing",
        "ssrf",
        "shell-injection",
        "secret-leakage",
        "checkpoint-poisoning",
        "history-poisoning",
        "denial-of-wallet",
    }.issubset(attack_tags)


def test_every_fault_cut_point_converges_without_unsafe_effects() -> None:
    first = tuple(
        run_fault_scenario(
            FaultPlan(fault_point=point, occurrence=1, maximum_attempts=3, seed=41)
        )
        for point in FaultPoint
    )
    replayed = tuple(
        run_fault_scenario(
            FaultPlan(fault_point=point, occurrence=1, maximum_attempts=3, seed=41)
        )
        for point in reversed(FaultPoint)
    )
    assert {item.canonical_digest for item in first} == {
        item.canonical_digest for item in replayed
    }
    assert all(item.converged for item in first)
    assert all(item.unauthorized_effects == 0 for item in first)
    assert all(item.stale_effects == item.duplicate_effects == 0 for item in first)
    assert all(item.cleanup_complete and item.audit_complete for item in first)
    assert all(item.tenant_isolated for item in first)


def test_runner_is_repeatable_order_independent_and_shard_stable(
    governed_assets: tuple[object, object, BaselineContract, tuple[EvalCase, ...]],
) -> None:
    suite, dataset, baseline, cases = governed_assets
    runner = EvaluationRunner(
        suite=suite,  # type: ignore[arg-type]
        dataset=dataset,  # type: ignore[arg-type]
        baseline=baseline,
    )
    first = runner.run(cases)
    reordered = runner.run(tuple(reversed(cases)))
    assert first.canonical_digest == reordered.canonical_digest
    assert first.passed

    shard_zero = runner.list_cases(cases, shard_index=0, shard_count=3)
    shard_one = runner.list_cases(cases, shard_index=1, shard_count=3)
    shard_two = runner.list_cases(cases, shard_index=2, shard_count=3)
    shard_ids = [
        {item.case_id for item in shard} for shard in (shard_zero, shard_one, shard_two)
    ]
    assert not (shard_ids[0] & shard_ids[1])
    assert not (shard_ids[0] & shard_ids[2])
    assert not (shard_ids[1] & shard_ids[2])
    assert set.union(*shard_ids) == {case.case_id for case in cases}
    assert tuple(item.case_id for item in shard_zero) == tuple(
        sorted(item.case_id for item in shard_zero)
    )


def test_baseline_detects_tamper_missing_new_and_invalid_waivers(
    governed_assets: tuple[object, object, BaselineContract, tuple[EvalCase, ...]],
) -> None:
    suite, dataset, baseline, cases = governed_assets
    runner = EvaluationRunner(
        suite=suite,  # type: ignore[arg-type]
        dataset=dataset,  # type: ignore[arg-type]
        baseline=baseline,
    )
    report = runner.run(cases)
    changed = baseline.model_copy(update={"suite_digest": "0" * 64})
    comparison = compare_results(
        suite=suite,  # type: ignore[arg-type]
        dataset=dataset,  # type: ignore[arg-type]
        baseline=changed,
        results=report.results[:-1],
        waivers=(),
        now=suite.fixed_clock,  # type: ignore[attr-defined]
    )
    assert comparison.passed is False
    assert "suite-tamper-or-version-change" in comparison.violations
    assert "missing-baseline-cases" in comparison.violations

    extra = report.results[0].model_copy(
        update={"case_id": "new-unreviewed", "result_id": "f" * 64}
    )
    comparison = compare_results(
        suite=suite,  # type: ignore[arg-type]
        dataset=dataset,  # type: ignore[arg-type]
        baseline=baseline,
        results=(*report.results, extra),
        waivers=(),
        now=suite.fixed_clock,  # type: ignore[attr-defined]
    )
    assert comparison.new_case_ids == ("new-unreviewed",)
    assert "new-unreviewed-cases" in comparison.violations

    hard_waiver = WaiverContract(
        waiver_id="waiver-hard",
        baseline_id=baseline.baseline_id,
        scorer_id="privacy-isolation",
        case_ids=("tenant-isolation",),
        owner="security-owner",
        reason="Hard controls must remain non-waivable.",
        expires_at=suite.fixed_clock + timedelta(days=1),  # type: ignore[attr-defined]
    )
    comparison = compare_results(
        suite=suite,  # type: ignore[arg-type]
        dataset=dataset,  # type: ignore[arg-type]
        baseline=baseline,
        results=report.results,
        waivers=(hard_waiver,),
        now=suite.fixed_clock,  # type: ignore[attr-defined]
    )
    assert "hard-safety-waiver-forbidden:waiver-hard" in comparison.violations

    weakened_entry = baseline.entries[0].model_copy(
        update={"tolerance": 1_000_000.0, "hard_safety_invariant": False}
    )
    weakened = baseline.model_copy(
        update={"entries": (weakened_entry, *baseline.entries[1:])}
    )
    comparison = compare_results(
        suite=suite,  # type: ignore[arg-type]
        dataset=dataset,  # type: ignore[arg-type]
        baseline=weakened,
        results=report.results,
        waivers=(),
        now=suite.fixed_clock,  # type: ignore[attr-defined]
    )
    assert any(
        item.startswith("baseline-scorer-contract-mismatch:")
        for item in comparison.violations
    )


def test_soft_waiver_is_scoped_and_expiry_fails_closed(
    governed_assets: tuple[object, object, BaselineContract, tuple[EvalCase, ...]],
) -> None:
    suite, dataset, baseline, cases = governed_assets
    regressed_case = "budget-exhaustion"
    waiver = WaiverContract(
        waiver_id="waiver-confidence",
        baseline_id=baseline.baseline_id,
        scorer_id="confidence-calibration",
        case_ids=(regressed_case,),
        owner="evaluation-owner",
        reason="Known bounded calibration change under review.",
        expires_at=suite.fixed_clock + timedelta(days=1),  # type: ignore[attr-defined]
    )
    runner = EvaluationRunner(
        suite=suite,  # type: ignore[arg-type]
        dataset=dataset,  # type: ignore[arg-type]
        baseline=baseline,
        waivers=(waiver,),
        executor=_SoftRegressionExecutor(regressed_case),
        governance_clock=lambda: suite.fixed_clock,  # type: ignore[attr-defined]
    )
    report = runner.run(cases)
    assert report.passed
    assert report.comparison.waived == ("regression:confidence-calibration",)

    expired = waiver.model_copy(
        update={"expires_at": suite.fixed_clock - timedelta(seconds=1)}  # type: ignore[attr-defined]
    )
    expired_report = EvaluationRunner(
        suite=suite,  # type: ignore[arg-type]
        dataset=dataset,  # type: ignore[arg-type]
        baseline=baseline,
        waivers=(expired,),
        executor=_SoftRegressionExecutor(regressed_case),
        governance_clock=lambda: suite.fixed_clock,  # type: ignore[attr-defined]
    ).run(cases)
    assert "expired-waiver:waiver-confidence" in expired_report.comparison.violations
    assert "regression:confidence-calibration" in expired_report.comparison.violations

    wrong_scope = waiver.model_copy(update={"case_ids": ("contradiction",)})
    wrong_scope_report = EvaluationRunner(
        suite=suite,  # type: ignore[arg-type]
        dataset=dataset,  # type: ignore[arg-type]
        baseline=baseline,
        waivers=(wrong_scope,),
        executor=_SoftRegressionExecutor(regressed_case),
        governance_clock=lambda: suite.fixed_clock,  # type: ignore[attr-defined]
    ).run(cases)
    assert "waiver-scope-mismatch:confidence-calibration" in (
        wrong_scope_report.comparison.violations
    )


class _EscapingExecutor:
    def execute(self, case: EvalCase) -> ExecutionObservation:
        del case
        socket.create_connection(("127.0.0.1", 1))
        return ExecutionObservation(
            outcome=EvalOutcome(case_id="unreachable", passed=True, details=())
        )


class _SoftRegressionExecutor:
    def __init__(self, case_id: str) -> None:
        self._case_id = case_id
        self._legacy = LegacyCaseExecutor()

    def execute(self, case: EvalCase) -> ExecutionObservation:
        observation = self._legacy.execute(case)
        if case.case_id != self._case_id:
            return observation
        return observation.model_copy(
            update={
                "metrics": (
                    ObservedMetric(
                        scorer_id="confidence-calibration",
                        value=0.0,
                    ),
                )
            }
        )


class _HardMetricExecutor:
    def __init__(self) -> None:
        self._legacy = LegacyCaseExecutor()

    def execute(self, case: EvalCase) -> ExecutionObservation:
        return self._legacy.execute(case).model_copy(
            update={
                "metrics": (
                    ObservedMetric(
                        scorer_id="privacy-isolation",
                        value=0.0,
                    ),
                )
            }
        )


def test_hermetic_runner_denies_escape_and_redacts_failures(
    governed_assets: tuple[object, object, BaselineContract, tuple[EvalCase, ...]],
) -> None:
    suite, dataset, baseline, cases = governed_assets
    runner = EvaluationRunner(
        suite=suite,  # type: ignore[arg-type]
        dataset=dataset,  # type: ignore[arg-type]
        baseline=baseline,
        executor=_EscapingExecutor(),
    )
    report = runner.run(cases, filters=("success",))
    assert report.passed is False
    assert all(
        item.reason_codes == ("executor_error:RuntimeError",) for item in report.results
    )
    serialized = report.model_dump_json()
    assert "127.0.0.1" not in serialized
    assert "tenant-acme" not in serialized


def test_executor_cannot_override_hard_safety_metrics(
    governed_assets: tuple[object, object, BaselineContract, tuple[EvalCase, ...]],
) -> None:
    suite, dataset, baseline, cases = governed_assets
    report = EvaluationRunner(
        suite=suite,  # type: ignore[arg-type]
        dataset=dataset,  # type: ignore[arg-type]
        baseline=baseline,
        executor=_HardMetricExecutor(),
    ).run(cases, filters=("success",))
    assert report.passed is False
    assert all(
        item.reason_codes == ("executor_error:ValueError",) for item in report.results
    )


def test_reports_are_bounded_deterministic_and_redacted(
    tmp_path: Path,
    governed_assets: tuple[object, object, BaselineContract, tuple[EvalCase, ...]],
) -> None:
    suite, dataset, baseline, cases = governed_assets
    report = EvaluationRunner(
        suite=suite,  # type: ignore[arg-type]
        dataset=dataset,  # type: ignore[arg-type]
        baseline=baseline,
    ).run(cases, filters=("prompt-injection",))
    paths = write_reports(report, tmp_path)
    first = tuple(path.read_bytes() for path in paths)
    assert b'time="0"' in first[2]
    assert b"tenant-acme" not in b"".join(first)
    assert b"ignore previous instructions" not in b"".join(first)
    write_reports(report, tmp_path)
    assert first == tuple(path.read_bytes() for path in paths)
    with pytest.raises(ValueError, match="report exceeds byte bound"):
        write_reports(report, tmp_path, maximum_bytes=16)


def test_reviewed_baseline_creation_and_integration_gates(
    governed_assets: tuple[object, object, BaselineContract, tuple[EvalCase, ...]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite, dataset, baseline, cases = governed_assets
    created = create_baseline(
        suite=suite,  # type: ignore[arg-type]
        dataset=dataset,  # type: ignore[arg-type]
        case_ids=(case.case_id for case in cases),
        reviewed_by="release-reviewer",
        review_reason="Reviewed canonical deterministic Layer 10 update.",
    )
    assert created.case_ids == baseline.case_ids
    assert canonical_digest(created) == created.canonical_digest

    monkeypatch.delenv("AEGIS_TEST_POSTGRES_ADMIN_DSN", raising=False)
    monkeypatch.delenv("AEGIS_TEST_POSTGRES_RUNTIME_DSN", raising=False)
    runner = EvaluationRunner(
        suite=suite,  # type: ignore[arg-type]
        dataset=dataset,  # type: ignore[arg-type]
        baseline=baseline,
    )
    with pytest.raises(RuntimeError, match="postgres evaluation mode"):
        runner.run(cases, filters=("success",), mode="postgres")


def test_dataset_contract_rejects_private_or_changed_governance() -> None:
    payload = json.loads(Path("evals/dataset.json").read_text(encoding="utf-8"))
    payload["provenance"]["synthetic"] = False
    with pytest.raises(ValueError, match="synthetic data only"):
        load_dataset_from_payload(payload)

    payload["provenance"]["synthetic"] = True
    payload["provenance"]["classification"] = "restricted"
    with pytest.raises(ValueError, match="private production classifications"):
        load_dataset_from_payload(payload)

    payload["provenance"]["classification"] = "internal"
    payload["provenance"]["source_uri"] = "https://example.invalid/private"
    with pytest.raises(ValueError, match="repository-local"):
        load_dataset_from_payload(payload)


def test_contract_validators_and_exact_scorer_fail_closed() -> None:
    scenario = {
        "scenario_id": "invalid-scenario",
        "version": 1,
        "title": "invalid",
        "expected_outcome": "denied",
        "layers": [2, 1],
        "case_ids": ["one"],
    }
    with pytest.raises(ValueError, match="layers must be unique and sorted"):
        ScenarioContract.model_validate(scenario)
    scenario["layers"] = [1, 2]
    scenario["case_ids"] = ["one", "one"]
    with pytest.raises(ValueError, match="case IDs must be unique"):
        ScenarioContract.model_validate(scenario)
    scenario["case_ids"] = ["one"]
    scenario["attack_tags"] = ["z", "a"]
    with pytest.raises(ValueError, match="attack tags must be unique and sorted"):
        ScenarioContract.model_validate(scenario)

    with pytest.raises(ValueError, match="model judge cannot enforce"):
        ScorerContract(
            scorer_id="unsafe-judge",
            version=1,
            direction=ScoreDirection.EXACT,
            threshold=1.0,
            tolerance=0.0,
            hard_safety_invariant=True,
            model_judge=True,
        )
    assert _within(1.01, ScoreDirection.EXACT, 1.0, 0.02)
    assert not _within(1.03, ScoreDirection.EXACT, 1.0, 0.02)
    with pytest.raises(ValueError, match="timezone"):
        WaiverContract(
            waiver_id="naive",
            baseline_id="baseline",
            scorer_id="confidence-calibration",
            case_ids=("success",),
            owner="evaluation-owner",
            reason="Naive expiry must fail at the contract boundary.",
            expires_at=datetime(2026, 9, 1),
        )


def test_dataset_source_tamper_and_missing_source_are_rejected(tmp_path: Path) -> None:
    eval_dir = tmp_path / "evals"
    eval_dir.mkdir()
    source = eval_dir / "cases.json"
    source.write_text("[]", encoding="utf-8")
    payload = json.loads(Path("evals/dataset.json").read_text(encoding="utf-8"))
    payload["case_ids"] = ["case"]
    payload["provenance"]["source_content_digest"] = "0" * 64
    manifest = eval_dir / "dataset.json"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="source digest mismatch"):
        load_dataset(manifest)
    payload["provenance"]["source_uri"] = "repo://evals/missing.json"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="source is missing"):
        load_dataset(manifest)


def test_invalid_shard_and_waiver_shapes_are_rejected(
    governed_assets: tuple[object, object, BaselineContract, tuple[EvalCase, ...]],
) -> None:
    suite, dataset, baseline, cases = governed_assets
    runner = EvaluationRunner(
        suite=suite,  # type: ignore[arg-type]
        dataset=dataset,  # type: ignore[arg-type]
        baseline=baseline,
    )
    with pytest.raises(ValueError, match="invalid shard"):
        runner.list_cases(cases, shard_index=1, shard_count=1)

    report = runner.run(cases)

    def waiver(
        waiver_id: str,
        *,
        baseline_id: str = baseline.baseline_id,
        scorer_id: str = "confidence-calibration",
        case_ids: tuple[str, ...] = ("success",),
    ) -> WaiverContract:
        return WaiverContract(
            waiver_id=waiver_id,
            baseline_id=baseline_id,
            scorer_id=scorer_id,
            case_ids=case_ids,
            owner="evaluation-owner",
            reason="Invalid waiver shape for a deterministic meta-test.",
            expires_at=suite.fixed_clock + timedelta(days=1),  # type: ignore[attr-defined]
        )

    comparison = compare_results(
        suite=suite,  # type: ignore[arg-type]
        dataset=dataset,  # type: ignore[arg-type]
        baseline=baseline,
        results=report.results,
        waivers=(
            waiver("wrong-baseline", baseline_id="other"),
            waiver("unknown-scorer", scorer_id="missing"),
            waiver("unscoped", case_ids=("new-case",)),
        ),
        now=suite.fixed_clock,  # type: ignore[attr-defined]
    )
    assert {
        "wrong-baseline-waiver:wrong-baseline",
        "unknown-scorer-waiver:unknown-scorer",
        "unscoped-waiver:unscoped",
    }.issubset(comparison.violations)


def test_failed_report_contains_bounded_failure_nodes(
    tmp_path: Path,
    governed_assets: tuple[object, object, BaselineContract, tuple[EvalCase, ...]],
) -> None:
    suite, dataset, baseline, cases = governed_assets
    report = EvaluationRunner(
        suite=suite,  # type: ignore[arg-type]
        dataset=dataset,  # type: ignore[arg-type]
        baseline=baseline,
        executor=_EscapingExecutor(),
    ).run(cases, filters=("success",))
    json_path, markdown_path, junit_path = write_reports(report, tmp_path)
    assert '"passed": false' in json_path.read_text(encoding="utf-8")
    assert "## Violations" in markdown_path.read_text(encoding="utf-8")
    assert "<failure" in junit_path.read_text(encoding="utf-8")


def load_dataset_from_payload(payload: object) -> object:
    from aegis_framework.evaluation import DatasetContract

    return DatasetContract.model_validate(payload)
