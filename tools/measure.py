"""Measure repeatable Layer 2 size, dependencies, effort, and local runtime."""

from __future__ import annotations

import argparse
import json
import math
import platform
import shutil
import statistics
import subprocess
import sys
import time
import tomllib
from datetime import UTC, datetime
from pathlib import Path

from aegis_framework.fixtures import build_demo_bundle, demo_identity, demo_request

ROOT = Path(__file__).resolve().parents[1]
FOUNDATION_SHA = "ec297ad118e3f0040f15fe0507b5da7078eefdad"
CUSTOM_LAYER2 = {
    "repository": "mrinmoyece/aegis-agent-platform",
    "branch": "mrinmoyece-aegis-identity-governance",
    "sha": "81409792c97698479a9ca827a4143c6391f28d2b",
    "source_loc": {
        "production": 1947,
        "tests": 1272,
        "total": 3219,
    },
    "dependencies": {
        "direct_runtime": 3,
        "direct_optional": 6,
        "direct_development": 0,
        "locked_total": None,
    },
    "implementation_effort_proxy": {
        "additions": 4069,
        "deletions": 159,
        "changed_files": 44,
        "commits": 1,
    },
    "test_functions": 53,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=50)
    args = parser.parse_args()
    if args.runs < 10:
        parser.error("--runs must be at least 10")

    payload = measure(args.runs)
    destination = ROOT / args.write
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def measure(runs: int) -> dict[str, object]:
    production_loc = _source_loc(ROOT / "src")
    test_loc = _source_loc(ROOT / "tests")
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))

    bundle = build_demo_bundle(budget_units=(runs + 1) * 5)
    bundle.service.investigate(
        demo_identity(request_id="measure-warmup"),
        demo_request(),
    )
    durations_ms: list[float] = []
    for index in range(runs):
        started = time.perf_counter_ns()
        result = bundle.service.investigate(
            demo_identity(request_id=f"measure-{index:04d}"),
            demo_request(),
        )
        elapsed = (time.perf_counter_ns() - started) / 1_000_000
        if result.status.value != "complete":
            raise RuntimeError("measurement scenario did not complete")
        durations_ms.append(elapsed)

    ordered = sorted(durations_ms)
    percentile_index = math.ceil(0.95 * len(ordered)) - 1
    optional = pyproject["project"].get("optional-dependencies", {})
    dependency_groups = pyproject.get("dependency-groups", {})
    effort = _git_effort()
    return {
        "schema_version": 2,
        "layer": 2,
        "comparison_basis": {
            "foundation_sha": FOUNDATION_SHA,
            "custom": CUSTOM_LAYER2,
            "loc_definition": "non-blank, non-comment physical Python lines",
            "effort_definition": (
                "Git additions/deletions and changed files from each Layer 1 foundation"
            ),
        },
        "measured_at": datetime.now(UTC).isoformat(),
        "environment": {
            "machine": platform.machine(),
            "platform": platform.system(),
            "python": platform.python_version(),
        },
        "source_loc": {
            "production": production_loc,
            "tests": test_loc,
            "total": production_loc + test_loc,
        },
        "dependencies": {
            "direct_runtime": len(pyproject["project"]["dependencies"]),
            "direct_optional": sum(len(items) for items in optional.values()),
            "direct_development": sum(
                len(items) for items in dependency_groups.values()
            ),
            "locked_total": len(lock["package"]),
        },
        "implementation_effort_proxy": effort,
        "qualification_counts": _count_tests(),
        "framework_code_removed": [
            "custom graph scheduler",
            "parallel fan-out and deterministic join engine",
            "checkpoint serialization and state-history plumbing",
            "HTTP routing and OpenAPI generation",
            "JWT signature and registered-claim cryptography",
            "PostgreSQL connection-pool lifecycle",
        ],
        "remaining_custom_controls": [
            "issuer registry and bounded JWKS rotation policy",
            "authoritative principal and tenant resolution",
            "immutable RBAC, purpose, risk, and policy evaluation",
            "quota reservation and retry ownership",
            "forced RLS schema and transaction tenant context",
            "tenant-scoped checkpoint ownership",
            "secret-reference boundary",
            "redacted hash-chained durable audit",
            "API anti-enumeration and readiness failure policy",
        ],
        "lock_in_and_escape": {
            "langgraph": "OrchestratorPort plus JSON-compatible domain state",
            "pyjwt": (
                "AuthenticatorPort plus standard OIDC/JWT claims and JWK documents"
            ),
            "psycopg_postgresql": (
                "repository ports plus application-owned SQL migrations"
            ),
            "fastapi": "typed request/response models at the delivery adapter",
            "langfuse": "ObservabilityPort plus OpenTelemetry",
        },
        "runtime": {
            "scenario": "deterministic-success",
            "network": False,
            "runs": runs,
            "median_ms": round(statistics.median(durations_ms), 3),
            "p95_ms": round(ordered[percentile_index], 3),
        },
    }


def _git_effort() -> dict[str, int]:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to measure implementation effort")
    completed = subprocess.run(  # noqa: S603 - executable and arguments are fixed.
        [git, "diff", "--numstat", FOUNDATION_SHA, "--"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    additions = 0
    deletions = 0
    changed_files = 0
    for row in completed.stdout.splitlines():
        added, deleted, _ = row.split("\t", maxsplit=2)
        if added.isdigit() and deleted.isdigit():
            additions += int(added)
            deletions += int(deleted)
            changed_files += 1
    return {
        "additions": additions,
        "deletions": deletions,
        "changed_files": changed_files,
        "commits": 1,
    }


def _source_loc(root: Path) -> int:
    total = 0
    for path in sorted(root.rglob("*.py")):
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                total += 1
    return total


def _count_tests() -> dict[str, int | None]:
    """Run pytest in collect-only mode to count deterministic test items."""
    pytest = shutil.which("pytest") or str(ROOT / ".venv/bin/pytest")
    try:
        completed = subprocess.run(  # noqa: S603
            [pytest, "--collect-only", "-q", "--no-header", "-m", "not integration"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
        collected = sum(1 for line in completed.stdout.splitlines() if "::" in line)
    except Exception:
        collected = None
    return {
        "deterministic_tests_collected": collected,
        "postgres_integration_passed": None,
        "keycloak_integration_environment_gated": None,
    }


if __name__ == "__main__":
    sys.exit(main())
