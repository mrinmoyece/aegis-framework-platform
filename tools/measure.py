"""Measure repeatable Layer 9 size, dependencies, effort, and local runtime."""

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
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import Field

from aegis_framework.adapters import FixedClock
from aegis_framework.api import _demo_model_control
from aegis_framework.correlation import correlate_evidence
from aegis_framework.domain import (
    Evidence,
    EvidenceKind,
    GrantBinding,
    IdentityContext,
    PrincipalKind,
    RiskLevel,
    StrictModel,
    evidence_hash,
)
from aegis_framework.fixtures import build_demo_bundle, demo_identity, demo_request
from aegis_framework.memory_demo import run_memory_demo
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
from aegis_framework.ports import Action, PolicyDecision
from aegis_framework.remediation_demo import (
    RemediationDemoScenario,
    run_remediation_demo,
)
from aegis_framework.sandbox import (
    InMemorySandboxLedger,
    InMemorySandboxQuota,
    OutputExpectation,
    RetryAndCleanup,
    SandboxApprovalBinding,
    SandboxControlService,
    SandboxExecutionRequest,
    SandboxNetworkPolicy,
    SandboxPolicy,
    SandboxPurpose,
    SandboxResources,
    SandboxSecurityContext,
    SandboxSpec,
    canonical_digest,
)
from aegis_framework.sandbox_adapters import DeterministicSandboxBackend

ROOT = Path(__file__).resolve().parents[1]
FOUNDATION_SHA = "754e536d10b9643b40cac2f7b6c0d1de870fd630"
LAYER6_SHA = "9a920b99e1f2eff34890e076cdd94bb3cdd034f3"
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
CUSTOM_LAYER8 = {
    "repository": "mrinmoyece/aegis-agent-platform",
    "branch": "mrinmoyece-aegis-remediation-approvals",
    "sha": "0ce9368d60f3b2fce7b805d7d7699d585f13cef2",
    "source_loc": {
        "production": 28056,
        "tests": 14031,
        "total": 42087,
    },
    "dependencies": {
        "direct_runtime": 12,
        "direct_optional": 6,
        "direct_development": 0,
        "locked_total": None,
    },
    "incremental_effort_from_layer7": {
        "additions": 12030,
        "deletions": 162,
        "changed_files": 48,
        "commits": 1,
    },
    "test_functions": 275,
}
CUSTOM_LAYER9 = {
    "repository": "mrinmoyece/aegis-agent-platform",
    "branch": "mrinmoyece-aegis-layer-9-sandbox",
    "sha": "ed16fb8bb62ca6d18bc53ec8ee4e0191ed6caa63",
    "source_loc": {
        "production": 35980,
        "tests": 18558,
        "total": 54538,
    },
    "dependencies": {
        "direct_runtime": 12,
        "direct_optional": 7,
        "direct_development": 0,
        "locked_total": None,
    },
    "incremental_effort_from_layer8": {
        "additions": 14283,
        "deletions": 95,
        "changed_files": 53,
        "commits": 1,
    },
    "test_functions": 307,
}
CUSTOM_LAYER10 = {
    "repository": "mrinmoyece/aegis-agent-platform",
    "branch": "mrinmoyece-aegis-layer-10-memory-rag",
    "sha": "c9474184af756ce93d19d86360c339541e8263fb",
    "source_loc": {
        "production": 44117,
        "tests": 22194,
        "total": 66311,
    },
    "dependencies": {
        "direct_runtime": 12,
        "direct_optional": 7,
        "direct_development": 0,
        "locked_total": None,
    },
    "incremental_effort_from_layer9": {
        "additions": 13545,
        "deletions": 104,
        "changed_files": 58,
        "commits": 1,
    },
    "test_functions": 395,
    "notes": [
        "Implements a live pgvector cosine ANN query "
        "(`embedding <=> %s::vector`) in its hybrid retrieval SQL, "
        "exercised by its own retrieval path. This framework now also "
        "implements and integration-tests an equivalent live "
        "forced-RLS hybrid query (`PostgresMemoryStore.hybrid_candidates`), "
        "but only at the store layer: it is not yet wired into this "
        "framework's `MemoryRetrievalService`/API retrieval-serving path. "
        "This framework's own comparison does not independently verify "
        "whether the custom target's query is wired into its serving path.",
    ],
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
    remediation_runtime = _remediation_runtime(runs)
    sandbox_runtime = _sandbox_runtime(runs)
    memory_runtime = _memory_runtime(runs)
    return {
        "schema_version": 9,
        "layer": 9,
        "comparison_basis": {
            "foundation_sha": FOUNDATION_SHA,
            "custom_layer3": CUSTOM_LAYER3,
            "custom_layer4": CUSTOM_LAYER4,
            "custom_layer5": CUSTOM_LAYER5,
            "custom_layer6": CUSTOM_LAYER6,
            "custom_layer7": CUSTOM_LAYER7,
            "custom_layer8": CUSTOM_LAYER8,
            "custom_layer9": CUSTOM_LAYER9,
            "custom_layer10": CUSTOM_LAYER10,
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
            "equivalent_remediation_scenario": (
                "high-risk checkout Kubernetes rollout-restart with exact immutable "
                "plan/action/target/policy digests, two distinct human approvals, "
                "dry-run, stable idempotency, deterministic fake effect and fresh "
                "verification; in-memory, no network or production credentials"
            ),
            "equivalent_sandbox_scenario": (
                "approval-bound immutable testing spec, current deny-default policy, "
                "application request/policy/approval facts, deterministic fake "
                "provision/result/cleanup, no process, cluster, network or credentials"
            ),
            "equivalent_memory_scenario": (
                "one tenant-bound incident memory candidate ingested from accepted "
                "evidence through the full scan/chunk/embed/index fact chain, "
                "deterministic hash-based embedding/chunking, hybrid in-memory "
                "retrieval, and a bounded LangGraph context build; no network, no "
                "real embedding provider, and no PostgreSQL round trip (the "
                "separately store-tested `hybrid_candidates` pgvector query is not "
                "exercised by this in-memory demo scenario)"
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
            "approval wait poller and durable timer state",
            "approval/effect signal history and workflow crash recovery",
            "effect Activity scheduling, retry/backoff, heartbeat and cancellation",
            "sandbox Job API wire/object mechanics and scheduling",
            "sandbox Activity scheduling, retry, heartbeat, cancellation and replay",
            "durable pgvector column storage and raw SQL cast plumbing",
            "memory ingest/compact/purge/rebuild Activity scheduling, periodic "
            "heartbeat and retry",
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
            "exact remediation/action/approval/effect/verification contracts",
            "current action policy and approval invalidation",
            "human SoD, quorum, expiry and revocation",
            "effect quota reservation, idempotency, claims and fencing",
            "ambiguous effect reconciliation and fresh verification",
            "compensation policy and immutable effect audit",
            "exact sandbox spec/request/result/artifact/attestation contracts",
            "sandbox policy, approval invalidation, quotas, claims and fencing",
            "safe path/archive/output scanning, redaction and quarantine",
            "ambiguous provision/delete reconciliation and cleanup ownership",
            "immutable memory ledger facts and banned-field payload discipline",
            "memory candidate evidence binding, version fencing and explicit "
            "human/policy `MemoryAcceptance` decision",
            "derived index/cache rebuildability, live pgvector hybrid-query "
            "prefilters, and tenant isolation",
            "legal hold, tombstone and crypto-erasure ordering",
            "retrieved-memory instruction-boundary framing and final "
            "MMR/context-budget selection atop any candidate source",
            "digest-only retrieval/context-build operation ledger and "
            "idempotent per-operation sequencing",
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
            "kubernetes_sandbox": (
                "SandboxBackend plus neutral immutable requests/results/attestations"
            ),
            "pyyaml": "canonical JSON/text boundary after safe syntax parsing",
            "pgvector": (
                "EmbeddingPort/SummarizationPort/MemoryReadPort plus immutable "
                "memory_facts replay; the raw vector cast is portable SQL, not a "
                "vendor abstraction"
            ),
        },
        "required_stateful_services": ["PostgreSQL", "Temporal Server"],
        "custom_comparison": {
            "layer3_services": ["PostgreSQL"],
            "layer4_services": ["PostgreSQL", "Redis Streams"],
            "layer5_services": ["PostgreSQL", "Redis Streams"],
            "layer6_services": ["PostgreSQL", "Redis Streams"],
            "layer7_services": ["PostgreSQL", "Redis Streams"],
            "layer8_services": ["PostgreSQL", "Redis Streams"],
            "layer9_services": ["PostgreSQL", "Redis Streams"],
            "layer10_services": ["PostgreSQL", "Redis Streams"],
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
            "layer8_tradeoff": (
                "Custom Layer 8 implements its own asynchronous remediation lifecycle "
                "over PostgreSQL and Redis delivery. Framework Layer 7 delegates "
                "durable waits, timers, signals, Activity retry/heartbeat/cancellation "
                "and replay to Temporal, but retains nearly all approval/effect "
                "security controls"
            ),
            "layer9_tradeoff": (
                "Both implementations retain approval, policy, ledger, artifact, "
                "fencing, reconciliation and cleanup security controls. Framework "
                "Layer 8 removes custom durable sandbox scheduling/waits/retry/"
                "heartbeat/cancellation/replay through Temporal and Kubernetes Job "
                "mechanics, at the cost of two operational control planes and their "
                "upgrade/lock-in surface"
            ),
            "layer10_tradeoff": (
                "Both implementations avoid LangChain, LlamaIndex, Haystack and "
                "pgvector-python, choosing raw SQL over pgvector instead; neither "
                "adds a new dependency for memory. Custom Layer 10 implements a live "
                "pgvector cosine ANN query actually exercised by its own retrieval "
                "path. Framework Layer 9 now implements and integration-tests an "
                "equivalent live forced-RLS hybrid SQL query "
                "(`hybrid_candidates`), closing the prior in-memory-only gap, but "
                "it is proven only at the store layer: this framework's "
                "`MemoryRetrievalService`/API retrieval path still serves from "
                "`InMemoryHybridIndex` pending that wiring. This framework does not "
                "independently verify whether the custom target's query is wired "
                "into its own serving path"
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
        "equivalent_remediation_benchmark": {
            "scenario": "deterministic-exact-scope-checkout-rollout-restart",
            "network": False,
            "runs": runs,
            "framework_layer7": remediation_runtime,
            "custom_layer8": {
                "median_ms": 5.983,
                "p95_ms": 7.21,
                "sha": CUSTOM_LAYER8["sha"],
            },
            "limitations": (
                "Both execute deterministic in-memory high-risk approval/effect paths. "
                "Custom is async and includes its event repository/lease machinery; "
                "framework is sync and includes strict Pydantic contracts/pure ledger. "
                "Neither benchmark includes PostgreSQL, Temporal, Redis, Kubernetes, "
                "network, serialization or process boundaries"
            ),
        },
        "equivalent_sandbox_benchmark": {
            "scenario": "deterministic-approval-bound-fake-sandbox-lifecycle",
            "network": False,
            "runs": runs,
            "framework_layer8": sandbox_runtime,
            "custom_layer9": {
                "median_ms": 4.055,
                "p95_ms": 4.552,
                "sha": CUSTOM_LAYER9["sha"],
            },
            "limitations": (
                "Both paths are deterministic, in-memory and execute no process. "
                "Custom includes its async event repository/orchestrator; framework "
                "includes strict Pydantic contracts, three application facts and fake "
                "backend lifecycle. Neither includes PostgreSQL, Temporal, Redis, "
                "Kubernetes, CSI, CNI, runtime isolation, serialization or network"
            ),
        },
        "equivalent_memory_benchmark": {
            "scenario": "deterministic-tenant-incident-memory-ingest-retrieve-context",
            "network": False,
            "runs": runs,
            "framework_layer9": memory_runtime,
            "custom_layer10": {
                "median_ms": 10.285,
                "p95_ms": 11.88,
                "sha": CUSTOM_LAYER10["sha"],
            },
            "limitations": (
                "Both paths are deterministic and execute no process, network, or "
                "real embedding provider. Custom Layer 10 exercises its own async "
                "event/index machinery including a SQL-shaped ANN scoring path; "
                "framework Layer 9's demo scenario exercises strict Pydantic "
                "contracts and the in-memory hybrid index only — it does not call "
                "the separately store-tested `hybrid_candidates` pgvector query, "
                "which requires a live PostgreSQL connection. Neither benchmark "
                "includes PostgreSQL, Temporal, a live embedding provider, "
                "serialization, or process startup, and neither measures "
                "retrieval-quality (precision/recall) parity"
            ),
        },
    }


def _git_effort() -> dict[str, int]:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to measure implementation effort")
    completed = subprocess.run(  # noqa: S603 - executable and arguments are fixed.
        [git, "diff", "--numstat", LAYER6_SHA, "--"],
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
    untracked = subprocess.run(  # noqa: S603 - executable and arguments are fixed.
        [git, "ls-files", "--others", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    for relative in untracked.stdout.splitlines():
        path = ROOT / relative
        if path.is_file():
            additions += len(path.read_bytes().splitlines())
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
    from aegis_framework.correlation import correlate_evidence
    from aegis_framework.domain import Evidence, EvidenceKind, evidence_hash

    now = datetime(2026, 8, 15, tzinfo=UTC)

    def record(index: int, offset_seconds: int) -> Evidence:
        observed_at = now + timedelta(seconds=offset_seconds)
        locator = f"source://evidence-{index}"
        facts = {"service": "checkout-api", "status": "error"}
        summary = "Checkout failure observed."
        return Evidence(
            evidence_id=f"evidence-{index}",
            tenant_id="tenant-acme",
            kind=EvidenceKind.TELEMETRY,
            source="benchmark",
            locator=locator,
            observed_at=observed_at,
            summary=summary,
            facts=facts,
            content_hash=evidence_hash(
                tenant_id="tenant-acme",
                kind=EvidenceKind.TELEMETRY,
                locator=locator,
                observed_at=observed_at,
                summary=summary,
                facts=facts,
            ),
        )

    evidence = (record(1, 0), record(2, 10), record(3, 20))
    correlate_evidence(evidence, reference_time=now)
    durations: list[float] = []
    for _ in range(runs):
        started = time.perf_counter_ns()
        correlate_evidence(evidence, reference_time=now)
        durations.append((time.perf_counter_ns() - started) / 1_000_000)
    ordered = sorted(durations)
    return {
        "median_ms": round(statistics.median(durations), 3),
        "p95_ms": round(ordered[math.ceil(0.95 * len(ordered)) - 1], 3),
    }


def _remediation_runtime(runs: int) -> dict[str, float]:
    run_remediation_demo(RemediationDemoScenario.SUCCESS)
    durations: list[float] = []
    for _ in range(runs):
        started = time.perf_counter_ns()
        result = run_remediation_demo(RemediationDemoScenario.SUCCESS)
        if result.status.value != "verified":
            raise RuntimeError("remediation measurement did not verify")
        durations.append((time.perf_counter_ns() - started) / 1_000_000)
    ordered = sorted(durations)
    return {
        "median_ms": round(statistics.median(durations), 3),
        "p95_ms": round(ordered[math.ceil(0.95 * len(ordered)) - 1], 3),
    }


class _BenchmarkOutput(StrictModel):
    answer: str = Field(min_length=1, max_length=32)


def _remediation_runtime(runs: int) -> dict[str, float]:
    run_remediation_demo(RemediationDemoScenario.SUCCESS)
    durations: list[float] = []
    for _ in range(runs):
        started = time.perf_counter_ns()
        result = run_remediation_demo(RemediationDemoScenario.SUCCESS)
        if result.status.value != "verified":
            raise RuntimeError("remediation measurement did not verify")
        durations.append((time.perf_counter_ns() - started) / 1_000_000)
    ordered = sorted(durations)
    return {
        "median_ms": round(statistics.median(durations), 3),
        "p95_ms": round(ordered[math.ceil(0.95 * len(ordered)) - 1], 3),
    }


class _SandboxApplicationPolicy:
    def authorize(
        self,
        identity: IdentityContext,
        action: Action,
        *,
        resource_tenant_id: str,
        purpose: str,
        risk: RiskLevel,
    ) -> PolicyDecision:
        return PolicyDecision(
            allowed=(
                identity.tenant_id == resource_tenant_id
                and action is Action.SANDBOX_EXECUTE
            ),
            policy_id="benchmark-application-policy",
            policy_revision=1,
            purpose=purpose,
            risk=risk,
            reason="benchmark",
        )


class _SandboxApprovals:
    def __init__(self, binding: SandboxApprovalBinding) -> None:
        self._binding = binding

    def current(
        self,
        *,
        tenant_id: str,
        approval_id: str,
    ) -> SandboxApprovalBinding | None:
        if (
            tenant_id == self._binding.tenant_id
            and approval_id == self._binding.approval_id
        ):
            return self._binding
        return None


def _sandbox_runtime(runs: int) -> dict[str, float]:
    now = datetime(2026, 8, 17, tzinfo=UTC)
    clock = FixedClock(now)
    resources = SandboxResources(
        cpu_millicores=250,
        memory_mib=256,
        pid_limit=64,
        ephemeral_storage_mib=512,
        timeout_seconds=120,
        output_bytes=1_048_576,
        output_files=8,
        output_file_bytes=262_144,
    )
    approval = SandboxApprovalBinding(
        tenant_id="tenant-acme",
        run_id="run-benchmark",
        task_id="task-benchmark",
        remediation_plan_id="plan-benchmark",
        remediation_action_id="action-benchmark",
        remediation_plan_digest="a" * 64,
        remediation_action_digest="b" * 64,
        approval_id="approval-benchmark",
        approval_digest="c" * 64,
        approval_policy_digest="d" * 64,
        approval_expires_at=now + timedelta(hours=1),
    )
    spec_material = {
        "schema_version": 1,
        "spec_version": "sandbox-spec-v1",
        "tenant_id": "tenant-acme",
        "run_id": approval.run_id,
        "task_id": approval.task_id,
        "purpose": SandboxPurpose.TESTING,
        "risk": RiskLevel.MEDIUM,
        "approval": approval,
        "image": ("registry.example.invalid/aegis/runner@sha256:" + ("e" * 64)),
        "argv": ("python", "-m", "pytest", "-q"),
        "working_directory": "workspace",
        "inputs": (),
        "mounts": (),
        "environment": (),
        "secrets": (),
        "network": SandboxNetworkPolicy(),
        "resources": resources,
        "security": SandboxSecurityContext(
            run_as_user=10001,
            run_as_group=10001,
            fs_group=10001,
            apparmor_profile="aegis-sandbox-v1",
        ),
        "required_runtime_class": "kata-aegis",
        "required_admission_policies": ("aegis-sandbox-baseline",),
        "expected_outputs": (
            OutputExpectation(
                logical_path="reports/result.json",
                media_types=("application/json",),
            ),
        ),
        "retry": RetryAndCleanup(
            maximum_attempts=3,
            cleanup_timeout_seconds=120,
            retain_failed_seconds=600,
        ),
    }
    spec = SandboxSpec(
        **spec_material,
        spec_digest=canonical_digest(spec_material),
    )
    policy_material = {
        "schema_version": 1,
        "tenant_id": "tenant-acme",
        "policy_id": "sandbox-policy",
        "revision": 1,
        "enabled": True,
        "allowed_image_digests": ("e" * 64,),
        "allowed_registries": ("registry.example.invalid",),
        "allowed_commands": ("python",),
        "allowed_purposes": (SandboxPurpose.TESTING,),
        "allowed_mount_prefixes": (),
        "allowed_secret_refs": (),
        "allowed_egress": (),
        "allowed_approval_policy_digests": ("d" * 64,),
        "maximum_resources": resources,
        "maximum_concurrency": 1,
        "maximum_lifetime_seconds": 120,
        "maximum_risk": RiskLevel.MEDIUM,
        "require_runtime_class": "kata-aegis",
        "require_admission_policies": ("aegis-sandbox-baseline",),
    }
    policy = SandboxPolicy(
        **policy_material,
        policy_digest=canonical_digest(policy_material),
    )
    identity = IdentityContext(
        tenant_id="tenant-acme",
        issuer="https://benchmark.example.invalid",
        subject_id="sandbox-benchmark",
        principal_kind=PrincipalKind.WORKLOAD,
        roles=("sandbox-worker",),
        permissions=(Action.SANDBOX_EXECUTE.value,),
        purposes=("incident-response",),
        grants=(
            GrantBinding(
                role="sandbox-worker",
                purpose="incident-response",
                permissions=(Action.SANDBOX_EXECUTE.value,),
                risk_ceiling=RiskLevel.MEDIUM,
                expires_at=now + timedelta(hours=1),
            ),
        ),
        grant_version=1,
        authenticated_at=now,
        expires_at=now + timedelta(hours=1),
        request_id="benchmark-request",
        trace_id="benchmark-trace",
    )

    def execute(index: int) -> None:
        request_material = {
            "schema_version": 1,
            "execution_id": f"sandbox-benchmark-{index}",
            "tenant_id": "tenant-acme",
            "run_id": spec.run_id,
            "task_id": spec.task_id,
            "spec": spec,
            "spec_digest": spec.spec_digest,
            "policy_digest": policy.policy_digest,
            "approval_digest": approval.approval_digest,
            "idempotency_key": f"sandbox-benchmark-key-{index}",
            "attempt": 1,
            "fence_token": f"sandbox-benchmark-fence-{index}",
            "requested_at": now,
        }
        request = SandboxExecutionRequest(
            **request_material,
            request_digest=canonical_digest(request_material),
        )
        SandboxControlService(
            application_policy=_SandboxApplicationPolicy(),
            sandbox_policy=policy,
            approvals=_SandboxApprovals(approval),
            quotas=InMemorySandboxQuota({"tenant-acme": 1}),
            ledger=InMemorySandboxLedger(),
            clock=clock,
        ).request(
            identity,
            request,
            active_executions=0,
            command_id=f"sandbox-benchmark-submit-{index}",
        )
        backend = DeterministicSandboxBackend(clock=clock)
        execution = backend.provision(request)
        if backend.wait(request, execution).outcome.value != "succeeded":
            raise RuntimeError("sandbox measurement did not succeed")
        backend.cleanup(request, execution)

    execute(-1)
    durations: list[float] = []
    for index in range(runs):
        started = time.perf_counter_ns()
        execute(index)
        durations.append((time.perf_counter_ns() - started) / 1_000_000)
    ordered = sorted(durations)
    return {
        "median_ms": round(statistics.median(durations), 3),
        "p95_ms": round(ordered[math.ceil(0.95 * len(ordered)) - 1], 3),
    }


def _git_effort() -> dict[str, int]:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to measure implementation effort")
    completed = subprocess.run(  # noqa: S603 - executable and arguments are fixed.
        [git, "diff", "--numstat", LAYER6_SHA, "--"],
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
    untracked = subprocess.run(  # noqa: S603 - executable and arguments are fixed.
        [git, "ls-files", "--others", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    for relative in untracked.stdout.splitlines():
        path = ROOT / relative
        if path.is_file():
            additions += len(path.read_bytes().splitlines())
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
    now = datetime(2026, 8, 15, tzinfo=UTC)

    def record(index: int, offset_seconds: int) -> Evidence:
        observed_at = now + timedelta(seconds=offset_seconds)
        locator = f"source://evidence-{index}"
        facts = {"service": "checkout-api", "status": "error"}
        return Evidence(
            evidence_id=f"evidence-{index}",
            tenant_id="tenant-acme",
            kind=EvidenceKind.TELEMETRY,
            source="benchmark",
            locator=locator,
            observed_at=observed_at,
            summary="Checkout failure observed.",
            facts=facts,
            content_hash=evidence_hash(
                tenant_id="tenant-acme",
                kind=EvidenceKind.TELEMETRY,
                locator=locator,
                observed_at=observed_at,
                facts=facts,
            ),
        )

    evidence = (record(1, 0), record(2, 10), record(3, 20))
    correlate_evidence(evidence, reference_time=now)
    durations: list[float] = []
    for _ in range(runs):
        started = time.perf_counter_ns()
        correlate_evidence(evidence, reference_time=now)
        durations.append((time.perf_counter_ns() - started) / 1_000_000)
    ordered = sorted(durations)
    return {
        "median_ms": round(statistics.median(durations), 3),
        "p95_ms": round(ordered[math.ceil(0.95 * len(ordered)) - 1], 3),
    }


def _remediation_runtime(runs: int) -> dict[str, float]:
    run_remediation_demo(RemediationDemoScenario.SUCCESS)
    durations: list[float] = []
    for _ in range(runs):
        started = time.perf_counter_ns()
        result = run_remediation_demo(RemediationDemoScenario.SUCCESS)
        if result.status.value != "verified":
            raise RuntimeError("remediation measurement did not verify")
        durations.append((time.perf_counter_ns() - started) / 1_000_000)
    ordered = sorted(durations)
    return {
        "median_ms": round(statistics.median(durations), 3),
        "p95_ms": round(ordered[math.ceil(0.95 * len(ordered)) - 1], 3),
    }


class _SandboxApplicationPolicy:
    def authorize(
        self,
        identity: IdentityContext,
        action: Action,
        *,
        resource_tenant_id: str,
        purpose: str,
        risk: RiskLevel,
    ) -> PolicyDecision:
        return PolicyDecision(
            allowed=(
                identity.tenant_id == resource_tenant_id
                and action is Action.SANDBOX_EXECUTE
            ),
            policy_id="benchmark-application-policy",
            policy_revision=1,
            purpose=purpose,
            risk=risk,
            reason="benchmark",
        )


class _SandboxApprovals:
    def __init__(self, binding: SandboxApprovalBinding) -> None:
        self._binding = binding

    def current(
        self,
        *,
        tenant_id: str,
        approval_id: str,
    ) -> SandboxApprovalBinding | None:
        if (
            tenant_id == self._binding.tenant_id
            and approval_id == self._binding.approval_id
        ):
            return self._binding
        return None


def _sandbox_runtime(runs: int) -> dict[str, float]:
    now = datetime(2026, 8, 17, tzinfo=UTC)
    clock = FixedClock(now)
    resources = SandboxResources(
        cpu_millicores=250,
        memory_mib=256,
        pid_limit=64,
        ephemeral_storage_mib=512,
        timeout_seconds=120,
        output_bytes=1_048_576,
        output_files=8,
        output_file_bytes=262_144,
    )
    approval = SandboxApprovalBinding(
        tenant_id="tenant-acme",
        run_id="run-benchmark",
        task_id="task-benchmark",
        remediation_plan_id="plan-benchmark",
        remediation_action_id="action-benchmark",
        remediation_plan_digest="a" * 64,
        remediation_action_digest="b" * 64,
        approval_id="approval-benchmark",
        approval_digest="c" * 64,
        approval_policy_digest="d" * 64,
        approval_expires_at=now + timedelta(hours=1),
    )
    spec_material = {
        "schema_version": 1,
        "spec_version": "sandbox-spec-v1",
        "tenant_id": "tenant-acme",
        "run_id": approval.run_id,
        "task_id": approval.task_id,
        "purpose": SandboxPurpose.TESTING,
        "risk": RiskLevel.MEDIUM,
        "approval": approval,
        "image": ("registry.example.invalid/aegis/runner@sha256:" + ("e" * 64)),
        "argv": ("python", "-m", "pytest", "-q"),
        "working_directory": "workspace",
        "inputs": (),
        "mounts": (),
        "environment": (),
        "secrets": (),
        "network": SandboxNetworkPolicy(),
        "resources": resources,
        "security": SandboxSecurityContext(
            run_as_user=10001,
            run_as_group=10001,
            fs_group=10001,
            apparmor_profile="aegis-sandbox-v1",
        ),
        "required_runtime_class": "kata-aegis",
        "required_admission_policies": ("aegis-sandbox-baseline",),
        "expected_outputs": (
            OutputExpectation(
                logical_path="reports/result.json",
                media_types=("application/json",),
            ),
        ),
        "retry": RetryAndCleanup(
            maximum_attempts=3,
            cleanup_timeout_seconds=120,
            retain_failed_seconds=600,
        ),
    }
    spec = SandboxSpec(
        **spec_material,
        spec_digest=canonical_digest(spec_material),
    )
    policy_material = {
        "schema_version": 1,
        "tenant_id": "tenant-acme",
        "policy_id": "sandbox-policy",
        "revision": 1,
        "enabled": True,
        "allowed_image_digests": ("e" * 64,),
        "allowed_registries": ("registry.example.invalid",),
        "allowed_commands": ("python",),
        "allowed_purposes": (SandboxPurpose.TESTING,),
        "allowed_mount_prefixes": (),
        "allowed_secret_refs": (),
        "allowed_egress": (),
        "allowed_approval_policy_digests": ("d" * 64,),
        "maximum_resources": resources,
        "maximum_concurrency": 1,
        "maximum_lifetime_seconds": 120,
        "maximum_risk": RiskLevel.MEDIUM,
        "require_runtime_class": "kata-aegis",
        "require_admission_policies": ("aegis-sandbox-baseline",),
    }
    policy = SandboxPolicy(
        **policy_material,
        policy_digest=canonical_digest(policy_material),
    )
    identity = IdentityContext(
        tenant_id="tenant-acme",
        issuer="https://benchmark.example.invalid",
        subject_id="sandbox-benchmark",
        principal_kind=PrincipalKind.WORKLOAD,
        roles=("sandbox-worker",),
        permissions=(Action.SANDBOX_EXECUTE.value,),
        purposes=("incident-response",),
        grants=(
            GrantBinding(
                role="sandbox-worker",
                purpose="incident-response",
                permissions=(Action.SANDBOX_EXECUTE.value,),
                risk_ceiling=RiskLevel.MEDIUM,
                expires_at=now + timedelta(hours=1),
            ),
        ),
        grant_version=1,
        authenticated_at=now,
        expires_at=now + timedelta(hours=1),
        request_id="benchmark-request",
        trace_id="benchmark-trace",
    )

    def execute(index: int) -> None:
        request_material = {
            "schema_version": 1,
            "execution_id": f"sandbox-benchmark-{index}",
            "tenant_id": "tenant-acme",
            "run_id": spec.run_id,
            "task_id": spec.task_id,
            "spec": spec,
            "spec_digest": spec.spec_digest,
            "policy_digest": policy.policy_digest,
            "approval_digest": approval.approval_digest,
            "idempotency_key": f"sandbox-benchmark-key-{index}",
            "attempt": 1,
            "fence_token": f"sandbox-benchmark-fence-{index}",
            "requested_at": now,
        }
        request = SandboxExecutionRequest(
            **request_material,
            request_digest=canonical_digest(request_material),
        )
        SandboxControlService(
            application_policy=_SandboxApplicationPolicy(),
            sandbox_policy=policy,
            approvals=_SandboxApprovals(approval),
            quotas=InMemorySandboxQuota({"tenant-acme": 1}),
            ledger=InMemorySandboxLedger(),
            clock=clock,
        ).request(
            identity,
            request,
            active_executions=0,
            command_id=f"sandbox-benchmark-submit-{index}",
        )
        backend = DeterministicSandboxBackend(clock=clock)
        execution = backend.provision(request)
        if backend.wait(request, execution).outcome.value != "succeeded":
            raise RuntimeError("sandbox measurement did not succeed")
        backend.cleanup(request, execution)

    execute(-1)
    durations: list[float] = []
    for index in range(runs):
        started = time.perf_counter_ns()
        execute(index)
        durations.append((time.perf_counter_ns() - started) / 1_000_000)
    ordered = sorted(durations)
    return {
        "median_ms": round(statistics.median(durations), 3),
        "p95_ms": round(ordered[math.ceil(0.95 * len(ordered)) - 1], 3),
    }


def _memory_runtime(runs: int) -> dict[str, float]:
    run_memory_demo()
    durations: list[float] = []
    for _ in range(runs):
        started = time.perf_counter_ns()
        result = run_memory_demo()
        durations.append((time.perf_counter_ns() - started) / 1_000_000)
        if result.context is None:
            raise RuntimeError("memory measurement did not build a context")
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
