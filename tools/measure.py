"""Measure repeatable Layer 1 size, dependency, and local runtime data."""

from __future__ import annotations

import argparse
import json
import math
import platform
import statistics
import sys
import time
import tomllib
from datetime import UTC, datetime
from pathlib import Path

from aegis_framework.fixtures import build_demo_bundle, demo_identity, demo_request

ROOT = Path(__file__).resolve().parents[1]


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
    return {
        "schema_version": 1,
        "measured_at": datetime.now(UTC).isoformat(),
        "environment": {
            "machine": platform.machine(),
            "platform": platform.system(),
            "python": platform.python_version(),
        },
        "source_loc": {
            "definition": "non-blank, non-comment physical Python lines",
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
        "runtime": {
            "scenario": "deterministic-success",
            "network": False,
            "runs": runs,
            "median_ms": round(statistics.median(durations_ms), 3),
            "p95_ms": round(ordered[percentile_index], 3),
        },
    }


def _source_loc(root: Path) -> int:
    total = 0
    for path in sorted(root.rglob("*.py")):
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                total += 1
    return total


if __name__ == "__main__":
    sys.exit(main())
