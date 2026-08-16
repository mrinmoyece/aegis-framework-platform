"""Measure repeatable Layer 6 size, dependencies, effort, and local runtime."""

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

from pydantic import Field

from aegis_framework.api import _demo_model_control
from aegis_framework.domain import (
    RiskLevel,
    StrictModel,
)
from aegis_framework.fixtures import build_demo_bundle, demo_identity, demo_request
from aegis_framework.model_gateway import (
    DataClassification,
    FakeModelProvider,
    ModelCallBinding,
    ModelFinishReason,
    ModelGateway,
    ModelMessage,
    ModelRequest,
    ModelRole,
    ModelUsage,
    ProviderResult,
    SafetyAssessment,
    StructuredOutputDefinition,
    TextContent,
)

ROOT = Path(__file__).resolve().parents[1]
FOUNDATION_SHA = "754e536d10b9643b40cac2f7b6c0d1de870fd630"
LAYER5_SHA = "a3f01e5709b0f32644909d55636a310d26eb9789"
CUSTOM_LAYER3 = {
    "repository": "mrinmoyece/aegis-agent-platform",
    "branch": "mrinmoyece-aegis-durable-ledger",
    "sha": "87cefe58adbf62e6a419d38e57e0928581b7003c",
    "source_loc": {
        "production": 3765,
        "tests": 2239,
        "total": 6004,
    },
    "dependencies": {
        "direct_runtime": 4,
        "direct_optional": 6,
        "direct_development": 0,
        "locked_total": None,
    },
    "implementation_effort_proxy": {
        "additions": 3901,
        "deletions": 176,
        "changed_files": 42,
        "commits": 1,
    },
    "test_functions": 77,
}
CUSTOM_LAYER4 = {
    "repository": "mrinmoyece/aegis-agent-platform",
    "branch": "mrinmoyece-aegis-worker-runtime",
    "sha": "171fa485819334a892684544c0a993a6e2fc4ace",
    "source_loc": {
        "production": 7452,
        "tests": 3687,
        "total": 11139,
    },
    "dependencies": {
        "direct_runtime": 6,
        "direct_optional": 6,
        "direct_development": 0,
        "locked_total": None,
    },
    "incremental_effort_from_layer3": {
        "additions": 6301,
        "deletions": 198,
        "changed_files": 47,
        "commits": 1,
    },
    "test_functions": 99,
}
CUSTOM_LAYER5 = {
    "repository": "mrinmoyece/aegis-agent-platform",
    "branch": "mrinmoyece-aegis-model-gateway",
    "sha": "7c22d380a66f57aad943fe926ffff3ca8fc06ed6",
    "source_loc": {
        "production": 11079,
        "tests": 5479,
        "total": 16558,
    },
    "dependencies": {
        "direct_runtime": 9,
        "direct_optional": 7,
        "direct_development": 0,
    },
    "incremental_effort_from_layer4": {
        "additions": 6568,
        "deletions": 109,
        "changed_files": 55,
        "commits": 1,
    },
    "test_functions": 141,
}
CUSTOM_LAYER6 = {
    "repository": "mrinmoyece/aegis-agent-platform",
    "branch": "mrinmoyece-aegis-evidence-connectors",
    "sha": "7a685bc52772e1c92467baba58a1c668646e9bf7",
    "source_loc": {
        "production": 17119,
        "tests": 8780,
        "total": 25899,
    },
    "dependencies": {
        "direct_runtime": 12,
        "direct_optional": 5,
        "direct_development": 0,
        "locked_total": None,
    },
    "incremental_effort_from_layer5": {
        "additions": 10954,
        "deletions": 123,
        "changed_files": 50,
        "commits": 1,
    },
    "test_functions": 204,
}
CUSTOM_LAYER7 = {
    "repository": "mrinmoyece/aegis-agent-platform",
    "branch": "mrinmoyece-aegis-specialist-dag",
    "sha": "dce0054a40c34ab4cc9d515aa753bc71d73fab57",
    "source_loc": {
        "production": 21581,
        "tests": 9975,
        "total": 31556,
    },
    "dependencies": {
        "direct_runtime": 12,
        "direct_optional": 6,
        "direct_development": 0,
        "locked_total": None,
    },
    "incremental_effort_from_layer6": {
        "additions": 6749,
        "deletions": 177,
        "changed_files": 41,
        "commits": 3,
    },
    "test_functions": 221,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=50)
    args = parser.parse_args()
    if args.runs < 10 or args.runs > 99_999:
        parser.error("--runs must be between 10 and 99999")

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
    gateway_runtime = _gateway_runtime(runs)
    evidence_runtime = _evidence_runtime(runs)
    return {
        "schema_version": 6,
        "layer": 6,
        "comparison_basis": {
            "foundation_sha": FOUNDATION_SHA,
            "custom_layer3": CUSTOM_LAYER3,
            "custom_layer4": CUSTOM_LAYER4,
            "custom_layer5": CUSTOM_LAYER5,
            "custom_layer6": CUSTOM_LAYER6,
            "custom_layer7": CUSTOM_LAYER7,
            "loc_definition": "non-blank, non-comment physical Python lines",
            "effort_definition": (
                "Git additions/deletions and changed files from each prior layer"
            ),
            "equivalent_gateway_scenario": (
                "tenant-scoped structured fake-provider call with explicit catalog, "
                "pre-call reservation, deterministic route, normalized usage/cost "
                "settlement, no network, and no production effect"
            ),
            "equivalent_evidence_scenario": (
                "three tenant-bound cited records correlated in process with stable "
                "timeline ordering, shared-fact links, no network, and no causal claim"
            ),
            "equivalent_orchestration_scenario": (
                "fixed-role checkout specialist fan-out/fan-in through critic, "
                "proposal-only planner and verification-plan gate using deterministic "
                "models, in-memory application facts, no network or production effect"
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
            "cross-process workflow scheduling and replay",
            "durable timers and signal delivery",
            "activity retry/backoff and worker crash recovery",
            "OpenAI and Anthropic wire protocol and SDK exception transport",
            "HTTP connection pooling and streaming response mechanics",
            "Kubernetes API object decoding and list transport",
            "safe YAML syntax parsing",
            "fixed specialist DAG scheduling and synchronized fan-in",
            "graph checkpoint serialization and replay traversal",
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
            "event envelope and dual integrity chains",
            "transactional inbox/outbox and idempotency",
            "projection rebuild and redacted cursor API",
            "activity authorization and retry ownership",
            "stale-result, poison-payload, and DLQ policy",
            "tenant model policy/catalog and price versions",
            "worst-case model token/cost reservations",
            "model routing, fallback, circuit, rate and concurrency policy",
            "immutable provider call and ambiguous-billing facts",
            "strict structured output, tools and citation controls",
            "source/resource allowlists and tenant-bound secret references",
            "SSRF, DNS, redirect, private-address and response bounds",
            "evidence canonicalization, provenance, redaction and quarantine",
            "durable page intent, cursor encryption and ambiguous-outcome handling",
            "deterministic non-causal correlation and extended citation validation",
            "fixed role capability and artifact transition policy",
            "immutable orchestration dispatch/artifact/decision facts",
            "graph-version and checkpoint compatibility gates",
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
            "temporal": (
                "opaque typed payloads plus application outbox, ActivityOperations, "
                "and application-owned ledger/projections"
            ),
            "openai_anthropic": (
                "ModelProviderAdapter plus neutral ModelRequest/ProviderResult"
            ),
            "httpx": "HttpTransport plus neutral connector records and pages",
            "kubernetes": "KubernetesApi protocol plus neutral connector records",
            "pyyaml": "canonical JSON/text boundary after safe syntax parsing",
        },
        "required_stateful_services": ["PostgreSQL", "Temporal Server"],
        "custom_comparison": {
            "layer3_services": ["PostgreSQL"],
            "layer4_services": ["PostgreSQL", "Redis Streams"],
            "layer5_services": ["PostgreSQL", "Redis Streams"],
            "layer6_services": ["PostgreSQL", "Redis Streams"],
            "layer7_services": ["PostgreSQL", "Redis Streams"],
            "temporal_tradeoff": (
                "Temporal removes scheduler, timers, signal history, retry/backoff, "
                "and crash recovery code but adds a second operational control plane"
            ),
            "runtime_comparison_status": (
                "Equivalent network-free fake gateway scenarios ran on the same "
                "machine; figures are local implementation latency, not provider or "
                "distributed throughput"
            ),
            "layer6_tradeoff": (
                "HTTPX, PyYAML, and the official Kubernetes client remove transport, "
                "syntax, and Kubernetes object decoding only. They do not remove "
                "tenant, provenance, SSRF, pagination, ledger, or quarantine controls"
            ),
            "layer7_tradeoff": (
                "LangGraph removes custom DAG scheduler, synchronized fan-in, reducers "
                "and checkpoint traversal, but application role policy, artifact "
                "transitions, fencing, facts, RLS, citations and final gates remain"
            ),
        },
        "runtime": {
            "scenario": "deterministic-success",
            "network": False,
            "runs": runs,
            "median_ms": round(statistics.median(durations_ms), 3),
            "p95_ms": round(ordered[percentile_index], 3),
        },
        "equivalent_gateway_benchmark": {
            "scenario": "deterministic-fake-reserve-route-settle",
            "network": False,
            "runs": runs,
            "framework_layer4": gateway_runtime,
            "custom_layer5": {
                "median_ms": 0.166,
                "p95_ms": 0.206,
                "sha": CUSTOM_LAYER5["sha"],
            },
            "limitations": (
                "Different internal sync/async APIs; no PostgreSQL, Temporal, Redis, "
                "provider network, serialization, or process boundary was included"
            ),
        },
        "equivalent_evidence_benchmark": {
            "scenario": "deterministic-three-record-non-causal-correlation",
            "network": False,
            "runs": runs,
            "framework_layer5": evidence_runtime,
            "custom_layer6": {
                "median_ms": 0.015,
                "p95_ms": 0.015,
                "sha": CUSTOM_LAYER6["sha"],
            },
            "limitations": (
                "Different Pydantic/dataclass contracts; excludes PostgreSQL, "
                "Temporal, Redis, connector networks, ingestion, and process boundaries"
            ),
        },
        "equivalent_orchestration_benchmark": {
            "scenario": "deterministic-fixed-role-specialist-investigation",
            "network": False,
            "runs": runs,
            "framework_layer6": {
                "median_ms": round(statistics.median(durations_ms), 3),
                "p95_ms": round(ordered[percentile_index], 3),
            },
            "custom_layer7": {
                "median_ms": 25.922,
                "p95_ms": 29.305,
                "sha": CUSTOM_LAYER7["sha"],
            },
            "limitations": (
                "Both use deterministic in-memory fixtures, but custom includes its "
                "async event repository and creates an event loop per sample while "
                "framework includes strict Pydantic artifacts and LangGraph "
                "checkpoints; no PostgreSQL, Temporal, Redis, network or process "
                "boundary is included"
            ),
        },
    }


def _git_effort() -> dict[str, int]:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to measure implementation effort")
    completed = subprocess.run(  # noqa: S603 - executable and arguments are fixed.
        [git, "diff", "--numstat", LAYER5_SHA, "--"],
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


class _BenchmarkOutput(StrictModel):
    answer: str = Field(min_length=1, max_length=32)


def _gateway_runtime(runs: int) -> dict[str, float]:
    result = ProviderResult(
        structured_output={"answer": "safe"},
        usage=ModelUsage(
            input_tokens=10,
            output_tokens=2,
            provider_reported=True,
        ),
        finish_reason=ModelFinishReason.STOP,
        safety=SafetyAssessment(blocked=False),
    )
    gateway = ModelGateway(
        store=_demo_model_control(),
        adapters=(FakeModelProvider((result,) * (runs + 1)),),
        rate_limit_per_minute=runs + 1,
    )

    def request(index: int) -> ModelRequest:
        return ModelRequest(
            binding=ModelCallBinding(
                tenant_id="tenant-acme",
                run_id=f"run:measure-gateway-{index}",
                call_id=f"call:measure-gateway-{index}",
                purpose="incident-response",
                data_classification=DataClassification.INTERNAL,
                risk=RiskLevel.MEDIUM,
            ),
            messages=(
                ModelMessage(
                    role=ModelRole.SYSTEM,
                    content=(TextContent(text="Return strict JSON."),),
                ),
            ),
            max_output_tokens=64,
            structured_output=StructuredOutputDefinition(
                name="benchmark",
                json_schema=_BenchmarkOutput.model_json_schema(),
            ),
        )

    gateway.generate(request(-1), _BenchmarkOutput)
    durations: list[float] = []
    for index in range(runs):
        started = time.perf_counter_ns()
        gateway.generate(request(index), _BenchmarkOutput)
        durations.append((time.perf_counter_ns() - started) / 1_000_000)
    ordered = sorted(durations)
    return {
        "median_ms": round(statistics.median(durations), 3),
        "p95_ms": round(ordered[math.ceil(0.95 * len(ordered)) - 1], 3),
    }


def _evidence_runtime(runs: int) -> dict[str, float]:
    from datetime import timedelta

    from aegis_framework.evidence import (
        DataClassification,
        EvidenceBounds,
        EvidenceQuery,
        EvidenceSource,
        EvidenceSourceKind,
        EvidenceTimeRange,
        SourceTrust,
    )
    from aegis_framework.evidence_runtime import (
        CursorVault,
        InMemoryEvidenceControlStore,
    )

    store = InMemoryEvidenceControlStore(
        cursor_vault=CursorVault(b"b" * 32),
    )
    now = datetime(2026, 8, 15, 12, 0, 0, tzinfo=UTC)
    source = EvidenceSource(
        tenant_id="tenant-bench",
        source_id="source-github",
        kind=EvidenceSourceKind.GITHUB,
        trust=SourceTrust.EXTERNAL_UNTRUSTED,
        classification=DataClassification.INTERNAL,
        region="eu-west-1",
        policy_revision=1,
        allowed_resources=("bench/repo/deployments",),
        enabled=True,
    )
    durations: list[float] = []
    for index in range(runs):
        query = EvidenceQuery(
            query_id=f"query-bench-{index}",
            tenant_id="tenant-bench",
            incident_id="bench-incident",
            run_id=f"run-bench-{index}",
            source=source,
            window=EvidenceTimeRange(
                start=now - timedelta(minutes=30),
                end=now,
            ),
            resource="bench/repo/deployments",
            parameters={},
            bounds=EvidenceBounds(),
            created_at=now,
        )
        started = time.perf_counter_ns()
        store.request(query, operation_id=f"op-bench-{index}")
        durations.append((time.perf_counter_ns() - started) / 1_000_000)
    ordered = sorted(durations)
    return {
        "median_ms": round(statistics.median(durations), 3),
        "p95_ms": round(ordered[math.ceil(0.95 * len(ordered)) - 1], 3),
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
