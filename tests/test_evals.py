from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from aegis_framework.evals import EvalCase, load_cases, run_eval_suite


def test_repository_eval_cases_all_pass() -> None:
    cases = load_cases(Path("evals/cases.json"))
    report = run_eval_suite(cases)
    assert report.total == 50
    assert report.succeeded == 50
    assert report.passed is True
    assert all(outcome.passed for outcome in report.outcomes)


def test_empty_eval_suite_is_valid() -> None:
    report = run_eval_suite(())
    assert report.passed is True
    assert report.total == report.succeeded == 0


def test_invalid_eval_case_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps([{"case_id": "missing-fields"}]), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_cases(path)


def test_eval_mismatch_reports_all_dimensions() -> None:
    case = EvalCase(
        case_id="mismatch",
        scenario="success",
        expected_status="abstained",
        expected_critic="rejected",
        expected_reason="absent",
    )
    report = run_eval_suite((case,))
    assert report.passed is False
    assert report.succeeded == 0
    assert report.outcomes[0].details == (
        "status=complete",
        "critic=accepted",
        "reason_missing=absent",
    )
