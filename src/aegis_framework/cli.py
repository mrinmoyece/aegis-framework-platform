"""Command-line entrypoints for the demo, API, and deterministic evals."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

import uvicorn

from aegis_framework.errors import OptionalDependencyMissing
from aegis_framework.evals import load_cases, run_eval_suite
from aegis_framework.fixtures import (
    DemoScenario,
    build_demo_bundle,
    demo_identity,
    demo_request,
)
from aegis_framework.remediation_demo import (
    RemediationDemoScenario,
    run_remediation_demo,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis-framework")
    subparsers = parser.add_subparsers(dest="command", required=True)

    demo = subparsers.add_parser("demo", help="run a deterministic investigation")
    demo.add_argument(
        "--scenario",
        choices=[scenario.value for scenario in DemoScenario],
        default=DemoScenario.SUCCESS.value,
    )
    demo.add_argument("--tenant-id", default="tenant-acme")
    demo.add_argument("--subject-id", default="responder-alice")
    demo.add_argument("--request-id", default="request-cli-001")

    remediation = subparsers.add_parser(
        "remediation-demo",
        help="run a redacted deterministic approval/effect scenario",
    )
    remediation.add_argument(
        "--scenario",
        choices=[scenario.value for scenario in RemediationDemoScenario],
        default=RemediationDemoScenario.SUCCESS.value,
    )

    evaluate = subparsers.add_parser("eval", help="run deterministic eval cases")
    evaluate.add_argument(
        "--cases",
        type=Path,
        default=Path("evals/cases.json"),
    )
    evaluate.add_argument(
        "--publish-langfuse",
        action="store_true",
        help="publish only aggregate results using standard Langfuse environment keys",
    )

    serve = subparsers.add_parser("serve", help="run the FastAPI adapter")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "demo":
        scenario = DemoScenario(args.scenario)
        bundle = build_demo_bundle(scenario)
        result = bundle.service.investigate(
            demo_identity(
                tenant_id=args.tenant_id,
                subject_id=args.subject_id,
                request_id=args.request_id,
            ),
            demo_request(),
        )
        print(result.model_dump_json(indent=2))
        return 0
    if args.command == "eval":
        report = run_eval_suite(load_cases(args.cases))
        if args.publish_langfuse:
            try:
                from aegis_framework.langfuse_adapter import (
                    build_langfuse_observability,
                )

                build_langfuse_observability().publish_evaluation(
                    total=report.total,
                    succeeded=report.succeeded,
                    passed=report.passed,
                )
            except OptionalDependencyMissing as exc:
                parser.exit(2, f"{parser.prog}: error: {exc}\n")
        print(report.model_dump_json(indent=2))
        return 0 if report.passed else 1
    if args.command == "remediation-demo":
        remediation_result = run_remediation_demo(
            RemediationDemoScenario(args.scenario)
        )
        print(remediation_result.model_dump_json(indent=2))
        return 0

    uvicorn.run(
        "aegis_framework.api:app",
        host=args.host,
        port=args.port,
        access_log=False,
    )
    return 0
