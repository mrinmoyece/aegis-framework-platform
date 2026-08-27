"""Validate Layer 16 release, comparison, risk, and governance evidence."""

from __future__ import annotations

import argparse
import json
import re
import runpy
import shutil
import subprocess
import sys
import tomllib
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BASE_SHA = "536979cc0b0bff028134db644f27bbb9d8c1791a"
CUSTOM_SHA = "1cccd9363fec83f7f4b2748b0e913be3a123d5ce"
STATUSES = {
    "Locally Qualified",
    "Environment-Gated",
    "Live Evidence Required",
    "Deferred",
}
RISK_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
RISK_STATUSES = {"open", "mitigated", "accepted", "closed"}
REQUIRED_AXES = {
    "production_loc",
    "test_loc",
    "configuration_loc",
    "documentation_loc",
    "direct_dependencies",
    "locked_dependencies",
    "services",
    "implementation_effort_proxy",
    "deterministic_scenario_latency",
    "evaluation_coverage",
    "operational_burden",
    "failure_semantics",
    "portability_and_lock_in",
    "security_controls",
    "deployment_footprint",
    "learning_curve",
}
REQUIRED_FRAMEWORKS = {
    "LangGraph",
    "Temporal",
    "Langfuse",
    "FastAPI/Pydantic",
    "official model/connector/Kubernetes SDKs",
    "pgvector",
    "React/TanStack/Zod",
    "MCP/A2A",
    "infrastructure tooling",
}
GOVERNANCE_ASSETS = (
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    ".github/CODEOWNERS",
    ".github/pull_request_template.md",
    ".github/ISSUE_TEMPLATE/bug.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
    "docs/adr/README.md",
    "docs/governance.md",
    "docs/versioning.md",
    "docs/release-checklist.md",
    "docs/release-readiness.md",
    "docs/framework-comparison-final.md",
    "docs/framework-verdicts.md",
    "docs/learning-path.md",
)
READINESS_OPEN_RISK_STATUSES = {"open", "accepted"}


def _load(relative: str) -> dict[str, Any]:
    value = json.loads((ROOT / relative).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{relative} must contain an object")
    return value


def _path_exists(reference: str) -> bool:
    path = reference.split("#", 1)[0]
    return bool(path) and (ROOT / path).exists()


def _make_targets() -> set[str]:
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    return set(re.findall(r"^([a-z][a-z0-9-]*):", text, re.MULTILINE))


def _validate_command(command: str, targets: set[str]) -> None:
    parts = command.split()
    if len(parts) < 2 or parts[0] != "make":
        raise ValueError(
            f"release command must use a checked-in make target: {command}"
        )
    requested = [part for part in parts[1:] if "=" not in part]
    missing = sorted(set(requested) - targets)
    if missing:
        raise ValueError(f"release command references unknown targets: {missing}")


def validate_readiness_signoff(
    payload: dict[str, Any],
    *,
    risk_payload: dict[str, Any],
    today: date,
) -> None:
    for field in ("owner", "approver"):
        value = payload.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"release-readiness {field} is incomplete")
    as_of = date.fromisoformat(str(payload.get("as_of")))
    sign_off_date = date.fromisoformat(str(payload.get("sign_off_date")))
    if sign_off_date < as_of or sign_off_date > today:
        raise ValueError("release-readiness sign-off date is invalid")
    for field in ("slo_gates_passed", "security_review_complete"):
        if not isinstance(payload.get(field), bool):
            raise ValueError(f"release-readiness {field} must be a boolean")
    raw_open_risks = payload.get("open_risks")
    if (
        not isinstance(raw_open_risks, list)
        or not raw_open_risks
        or any(not isinstance(item, str) or not item for item in raw_open_risks)
        or len(set(raw_open_risks)) != len(raw_open_risks)
    ):
        raise ValueError("release-readiness open risks are incomplete")
    expected_open_risks = sorted(
        str(risk["id"])
        for risk in risk_payload.get("risks", [])
        if isinstance(risk, dict) and risk.get("status") in READINESS_OPEN_RISK_STATUSES
    )
    if sorted(raw_open_risks) != expected_open_risks:
        raise ValueError("release-readiness open risks are stale")


def validate_readiness() -> None:
    payload = _load("qualification/release-readiness.json")
    if (
        payload.get("schema_version") != 1
        or payload.get("layer") != 16
        or payload.get("framework_base_sha") != BASE_SHA
        or payload.get("production_ready") is not False
        or payload.get("certification_claimed") is not False
    ):
        raise ValueError("release-readiness header or claim boundary is invalid")
    validate_readiness_signoff(
        payload,
        risk_payload=_load("qualification/residual-risks.json"),
        today=datetime.now(UTC).date(),
    )
    if set(payload.get("status_definitions", {})) != STATUSES:
        raise ValueError("release-readiness status definitions are incomplete")
    capabilities = payload.get("capabilities")
    if not isinstance(capabilities, list) or len(capabilities) != 16:
        raise ValueError("release-readiness must contain exactly 16 capabilities")
    ids = [item.get("id") for item in capabilities if isinstance(item, dict)]
    if len(ids) != 16 or len(set(ids)) != 16:
        raise ValueError("release-readiness capability ids must be unique")
    eval_ids = {
        item["case_id"]
        for item in json.loads((ROOT / "evals/cases.json").read_text(encoding="utf-8"))
    }
    targets = _make_targets()
    for item in capabilities:
        if not isinstance(item, dict):
            raise TypeError("release-readiness capability must be an object")
        if item.get("status") not in STATUSES or not item.get("owner"):
            raise ValueError(f"capability governance is invalid: {item.get('id')}")
        for field in ("code", "tests", "evals", "ci", "runbooks", "commands"):
            values = item.get(field)
            if not isinstance(values, list) or not values:
                raise ValueError(f"capability {item['id']} has no {field}")
        for field in ("code", "tests", "ci", "runbooks"):
            missing = [
                reference for reference in item[field] if not _path_exists(reference)
            ]
            if missing:
                raise ValueError(
                    f"capability {item['id']} has missing {field}: {missing}"
                )
        unknown_evals = sorted(set(item["evals"]) - eval_ids)
        if unknown_evals:
            raise ValueError(
                f"capability {item['id']} references unknown evals: {unknown_evals}"
            )
        for command in item["commands"]:
            _validate_command(command, targets)
        if not item.get("release_gate"):
            raise ValueError(f"capability {item['id']} has no release gate")


def validate_risks(*, as_of: date | None = None) -> None:
    payload = _load("qualification/residual-risks.json")
    if (
        payload.get("schema_version") != 2
        or payload.get("layer") != 16
        or payload.get("production_approved") is not False
        or payload.get("certification_claimed") is not False
    ):
        raise ValueError("residual-risk header or claim boundary is invalid")
    effective_date = as_of or datetime.now(UTC).date()
    if date.fromisoformat(str(payload.get("as_of"))) > effective_date:
        raise ValueError("residual-risk register cannot be future-dated")
    risks = payload.get("risks")
    if not isinstance(risks, list) or len(risks) < 10:
        raise ValueError("residual-risk register is incomplete")
    ids: set[str] = set()
    for risk in risks:
        if not isinstance(risk, dict):
            raise TypeError("residual risk must be an object")
        risk_id = str(risk.get("id", ""))
        if not risk_id or risk_id in ids:
            raise ValueError("residual-risk ids must be present and unique")
        ids.add(risk_id)
        if risk.get("severity") not in RISK_SEVERITIES:
            raise ValueError(f"{risk_id} severity is invalid")
        if risk.get("status") not in RISK_STATUSES:
            raise ValueError(f"{risk_id} status is invalid")
        for field in (
            "title",
            "owner",
            "mitigation",
            "trigger",
            "fail_closed",
            "opened_on",
            "target_date",
            "review_by",
        ):
            if not isinstance(risk.get(field), str) or not risk[field]:
                raise ValueError(f"{risk_id} is missing {field}")
        opened = date.fromisoformat(risk["opened_on"])
        target = date.fromisoformat(risk["target_date"])
        review = date.fromisoformat(risk["review_by"])
        if opened > review or review > target:
            raise ValueError(f"{risk_id} dates are not ordered")
        if risk["status"] in {"open", "accepted"} and review < effective_date:
            raise ValueError(f"{risk_id} review is expired")
        evidence = risk.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            raise ValueError(f"{risk_id} has no evidence")
        missing = [reference for reference in evidence if not _path_exists(reference)]
        if missing:
            raise ValueError(f"{risk_id} has missing evidence: {missing}")


def _line_count(paths: list[Path]) -> int:
    return sum(
        len(path.read_text(encoding="utf-8", errors="strict").splitlines())
        for path in sorted(set(paths))
    )


def repository_metrics() -> dict[str, int]:
    production = list((ROOT / "src").rglob("*.py"))
    production.extend(
        path
        for path in (ROOT / "ui/src").rglob("*")
        if path.suffix in {".ts", ".tsx"}
        and ".test." not in path.name
        and path.name not in {"setup-tests.ts", "test-fixtures.ts"}
    )
    tests = list((ROOT / "tests").rglob("*.py"))
    tests.extend(
        path
        for path in (ROOT / "ui").rglob("*")
        if path.is_file()
        and path.suffix in {".ts", ".tsx"}
        and "node_modules" not in path.parts
        and "coverage" not in path.parts
        and "dist" not in path.parts
        and (
            ".test." in path.name
            or path.is_relative_to(ROOT / "ui/e2e")
            or path.name in {"setup-tests.ts", "test-fixtures.ts"}
        )
    )
    docs = [
        path
        for path in ROOT.rglob("*.md")
        if not {
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            ".terraform",
            ".venv",
            "build",
            "dist",
            "node_modules",
        }.intersection(path.parts)
    ]
    config: list[Path] = []
    for directory in (
        ".github",
        "deployment",
        "evals",
        "migrations",
        "observability",
        "qualification",
    ):
        config.extend(
            path
            for path in (ROOT / directory).rglob("*")
            if path.is_file()
            and not {
                ".terraform",
                "build",
                "dist",
                "node_modules",
            }.intersection(path.parts)
        )
    config.extend(
        ROOT / name
        for name in (
            ".pre-commit-config.yaml",
            "Dockerfile",
            "Makefile",
            "compose.yaml",
            "pyproject.toml",
        )
    )
    config.extend(
        path
        for path in (ROOT / "ui").iterdir()
        if path.is_file()
        and path.name not in {"package-lock.json"}
        and path.suffix in {".js", ".json", ".ts"}
    )
    python = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    uv_lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    npm_lock = json.loads((ROOT / "ui/package-lock.json").read_text(encoding="utf-8"))
    ui_package = json.loads((ROOT / "ui/package.json").read_text(encoding="utf-8"))
    return {
        "production_loc": _line_count(production),
        "test_loc": _line_count(tests),
        "configuration_loc": _line_count(config),
        "documentation_loc": _line_count(docs),
        "python_direct_dependencies": len(python["project"]["dependencies"]),
        "python_locked_packages": len(uv_lock["package"]),
        "ui_direct_dependencies": len(ui_package["dependencies"]),
        "ui_locked_packages": len(npm_lock["packages"]) - 1,
    }


def repository_effort() -> dict[str, object]:
    git = shutil.which("git")
    if git is None:
        raise ValueError("git is required to compute the effort proxy")
    result = subprocess.run(  # noqa: S603
        (git, "diff", "--numstat", BASE_SHA, "--", "."),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    additions = 0
    deletions = 0
    files: set[str] = set()
    for line in result.stdout.splitlines():
        added, deleted, path = line.split("\t", 2)
        if added == "-" or deleted == "-":
            raise ValueError(f"binary comparison input is unsupported: {path}")
        additions += int(added)
        deletions += int(deleted)
        files.add(path)
    untracked = subprocess.run(  # noqa: S603
        (git, "ls-files", "--others", "--exclude-standard"),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    for relative in untracked.stdout.splitlines():
        path = ROOT / relative
        if not path.is_file():
            continue
        additions += len(path.read_text(encoding="utf-8").splitlines())
        files.add(relative)
    return {
        "base_sha": BASE_SHA,
        "files_changed": len(files),
        "additions": additions,
        "deletions": deletions,
        "commits": 1,
    }


def _forbid_aggregate_score(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = key.lower().replace("-", "_")
            if "aggregate" in normalized and "score" in normalized:
                raise ValueError("comparison must not contain an aggregate score")
            _forbid_aggregate_score(item)
    elif isinstance(value, list):
        for item in value:
            _forbid_aggregate_score(item)


def validate_comparison() -> None:
    payload = _load("comparison/layer16-final.json")
    if payload.get("schema_version") != 16 or payload.get("layer") != 16:
        raise ValueError("Layer 16 comparison schema/layer is invalid")
    basis = payload.get("comparison_basis", {})
    if (
        basis.get("framework", {}).get("base_sha") != BASE_SHA
        or basis.get("custom", {}).get("sha") != CUSTOM_SHA
    ):
        raise ValueError("Layer 16 comparison commits are not pinned")
    axes = payload.get("axes")
    if not isinstance(axes, dict) or set(axes) != REQUIRED_AXES:
        raise ValueError("Layer 16 comparison axes are incomplete")
    for axis, result in axes.items():
        if not isinstance(result, dict):
            raise TypeError(f"comparison axis {axis} must be an object")
        for field in ("framework", "custom", "equivalence", "evidence", "conclusion"):
            if field not in result or result[field] in ("", [], None):
                raise ValueError(f"comparison axis {axis} is missing {field}")
        if result["equivalence"] not in {
            "equivalent",
            "partially-equivalent",
            "non-equivalent",
            "missing-data",
        }:
            raise ValueError(f"comparison axis {axis} has invalid equivalence")
    frameworks = payload.get("framework_verdicts")
    if not isinstance(frameworks, list):
        raise ValueError("framework verdicts are missing")
    names = {item.get("framework") for item in frameworks if isinstance(item, dict)}
    if names != REQUIRED_FRAMEWORKS:
        raise ValueError("framework verdict coverage is incomplete")
    for item in frameworks:
        for field in (
            "code_removed",
            "not_replaced",
            "operational_cost",
            "failure_and_upgrade_risks",
            "exit_strategy",
            "adopt_when",
            "reject_when",
            "verdict",
        ):
            if not item.get(field):
                raise ValueError(
                    f"framework verdict {item.get('framework')} is missing {field}"
                )
    if payload.get("framework_metrics") != repository_metrics():
        raise ValueError(
            "Layer 16 framework metrics are stale; run "
            "`python tools/release_check.py --update-comparison`"
        )
    effort = axes["implementation_effort_proxy"]["framework"]
    if effort != repository_effort():
        raise ValueError(
            "Layer 16 effort proxy is stale; run "
            "`python tools/release_check.py --update-comparison`"
        )
    if payload.get("production_ranking_supported") is not False:
        raise ValueError("comparison must reject unsupported production ranking")
    _forbid_aggregate_score(payload)


def update_comparison_metrics() -> None:
    path = ROOT / "comparison/layer16-final.json"
    payload = _load("comparison/layer16-final.json")
    payload["framework_metrics"] = repository_metrics()
    payload["axes"]["implementation_effort_proxy"]["framework"] = repository_effort()
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def validate_governance(*, as_of: date | None = None) -> None:
    missing = [
        relative for relative in GOVERNANCE_ASSETS if not (ROOT / relative).is_file()
    ]
    if missing:
        raise ValueError(f"governance assets are missing: {missing}")
    owners = (ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8")
    for required in (
        "/src/",
        "/tests/",
        "/qualification/",
        "/comparison/",
        "/security/",
        "/deployment/",
        "/docs/",
    ):
        if required not in owners:
            raise ValueError(f"CODEOWNERS does not route {required}")
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    if "0.16.x" not in security or "private" not in security.lower():
        raise ValueError(
            "security policy lacks supported-version/private-reporting detail"
        )
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if "0.16.0" not in changelog or "production certification" not in changelog.lower():
        raise ValueError("Layer 16 changelog claim boundary is incomplete")
    validate_waivers = runpy.run_path(ROOT / "tools/vulnerability_check.py")[
        "validate_waivers"
    ]
    validate_waivers(
        waiver_path=ROOT / "security/vulnerability-waivers.json",
        today=as_of or datetime.now(UTC).date(),
    )


def validate_all(*, as_of: date | None = None) -> None:
    validate_readiness()
    validate_risks(as_of=as_of)
    validate_comparison()
    validate_governance(as_of=as_of)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--update-comparison", action="store_true")
    args = parser.parse_args()
    try:
        if args.update_comparison:
            update_comparison_metrics()
        validate_all()
    except (
        OSError,
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        subprocess.CalledProcessError,
    ) as exc:
        print(f"release-check: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    metrics = repository_metrics()
    print(
        "release-check: 16 capabilities, "
        f"{len(_load('qualification/residual-risks.json')['risks'])} risks, "
        f"{len(REQUIRED_AXES)} comparison axes, "
        f"{metrics['production_loc']} production LOC validated"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
