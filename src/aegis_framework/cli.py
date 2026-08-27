"""Command-line entrypoints for the demo, API, and deterministic evals."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence
from pathlib import Path

import uvicorn

from aegis_framework.errors import IntegrityFailure
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
    subparsers.add_parser(
        "memory-demo",
        help="run deterministic three-tier memory ingestion and retrieval",
    )
    replay = subparsers.add_parser(
        "replay",
        help="validate and inspect an exported application-ledger event array",
    )
    replay.add_argument("--events", type=Path, required=True)
    replay.add_argument("--run-id", required=True)
    replay.add_argument("--cursor", type=int)
    replay.add_argument(
        "--view",
        choices=("verify", "state", "causal", "support", "projection"),
        default="support",
    )
    remediation.add_argument(
        "--scenario",
        choices=[scenario.value for scenario in RemediationDemoScenario],
        default=RemediationDemoScenario.SUCCESS.value,
    )

    evaluate = subparsers.add_parser("eval", help="run governed deterministic evals")
    evaluate.add_argument(
        "--cases",
        type=Path,
        default=Path("evals/cases.json"),
    )
    evaluate.add_argument("--suite", type=Path, default=Path("evals/suite.json"))
    evaluate.add_argument("--dataset", type=Path, default=Path("evals/dataset.json"))
    evaluate.add_argument("--baseline", type=Path, default=Path("evals/baseline.json"))
    evaluate.add_argument("--waivers", type=Path, default=Path("evals/waivers.json"))
    evaluate.add_argument(
        "--publish-langfuse",
        action="store_true",
        help="publish only aggregate results using standard Langfuse environment keys",
    )
    eval_actions = evaluate.add_subparsers(dest="eval_action")
    eval_list = eval_actions.add_parser("list", help="list canonical evaluation cases")
    eval_run = eval_actions.add_parser("run", help="run and report evaluation cases")
    eval_compare = eval_actions.add_parser(
        "compare",
        help="compare current deterministic results with the reviewed baseline",
    )
    eval_replay = eval_actions.add_parser(
        "replay",
        help="run twice and require byte-stable result identity",
    )
    eval_update = eval_actions.add_parser(
        "update-baseline",
        help="write an explicitly reviewed baseline",
    )
    for command in (eval_list, eval_run, eval_compare, eval_replay):
        command.add_argument("--filter", action="append", default=[])
        command.add_argument("--shard-index", type=int, default=0)
        command.add_argument("--shard-count", type=int, default=1)
    for command in (eval_run, eval_compare, eval_replay):
        command.add_argument(
            "--mode",
            choices=("offline", "postgres", "temporal"),
            default="offline",
        )
    eval_run.add_argument("--report-dir", type=Path)
    eval_update.add_argument("--reviewed-by", required=True)
    eval_update.add_argument("--reason", required=True)
    eval_update.add_argument(
        "--output",
        type=Path,
        default=Path("evals/baseline.json"),
    )

    serve = subparsers.add_parser("serve", help="run the FastAPI adapter")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    worker = subparsers.add_parser(
        "worker",
        help="run one fail-closed enterprise Temporal worker profile",
    )
    worker.add_argument(
        "--profile",
        required=True,
        choices=(
            "outbox",
            "reconciler",
            "investigation",
            "cognitive",
            "evidence",
            "remediation",
            "memory",
            "sandbox",
            "protocol",
            "protocol-gateway",
        ),
    )
    worker.add_argument("--task-queue", required=True)
    worker_health = subparsers.add_parser(
        "worker-health",
        help="check worker startup, readiness, or liveness",
    )
    worker_health.add_argument(
        "--kind",
        required=True,
        choices=("startup", "ready", "live"),
    )
    worker_drain = subparsers.add_parser(
        "worker-drain",
        help="remove readiness and request graceful worker drain",
    )
    worker_drain.add_argument("--timeout-seconds", type=int, default=90)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
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
        if args.eval_action is not None:
            return _run_governed_eval(args)
        report = run_eval_suite(load_cases(args.cases))
        if args.publish_langfuse:
            from aegis_framework.langfuse_adapter import build_langfuse_observability

            build_langfuse_observability().publish_evaluation(
                total=report.total,
                succeeded=report.succeeded,
                passed=report.passed,
            )
        print(report.model_dump_json(indent=2))
        return 0 if report.passed else 1
    if args.command == "remediation-demo":
        remediation_result = run_remediation_demo(
            RemediationDemoScenario(args.scenario)
        )
        print(remediation_result.model_dump_json(indent=2))
        return 0
    if args.command == "memory-demo":
        from aegis_framework.memory_demo import run_memory_demo

        memory_result = run_memory_demo()
        print(memory_result.context.model_dump_json(indent=2))
        return 0
    if args.command == "replay":
        from aegis_framework.replay import (
            ReplayDebugger,
            load_events,
            projection_document,
        )

        try:
            payload = json.loads(args.events.read_text(encoding="utf-8"))
            debugger = ReplayDebugger(load_events(payload))
            if args.view == "verify":
                replay_result: object = debugger.verify().model_dump(mode="json")
            elif args.view == "state":
                replay_result = debugger.state_at(
                    aggregate_id=args.run_id,
                    cursor=args.cursor,
                ).model_dump(mode="json")
            elif args.view == "causal":
                replay_result = [
                    item.model_dump(mode="json")
                    for item in debugger.causal_chain(aggregate_id=args.run_id)
                ]
            elif args.view == "projection":
                replay_result = projection_document(
                    debugger,
                    aggregate_id=args.run_id,
                    cursor=args.cursor,
                )
            else:
                replay_result = debugger.support_report(
                    aggregate_id=args.run_id,
                ).model_dump(mode="json")
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            ValueError,
            IntegrityFailure,
        ) as exc:
            print(
                json.dumps(
                    {"status": "rejected", "error": type(exc).__name__},
                    sort_keys=True,
                )
            )
            return 2
        print(json.dumps(replay_result, indent=2, sort_keys=True))
        return 0
    if args.command == "worker":
        from aegis_framework.worker_runtime import run_production_worker

        try:
            return run_production_worker(
                profile=args.profile,
                task_queue=args.task_queue,
                runtime_directory=_worker_runtime_directory(),
            )
        except (OSError, RuntimeError, ValueError):
            print(
                json.dumps(
                    {"status": "not_ready", "reason": "worker_bootstrap_unavailable"},
                    sort_keys=True,
                )
            )
            return 78
    if args.command == "worker-health":
        from aegis_framework.worker_runtime import WorkerControl

        try:
            healthy = WorkerControl(_worker_runtime_directory()).healthy(args.kind)
        except (OSError, ValueError):
            healthy = False
        return 0 if healthy else 1
    if args.command == "worker-drain":
        from aegis_framework.worker_runtime import WorkerControl

        if args.timeout_seconds < 1 or args.timeout_seconds > 120:
            return 2
        try:
            control = WorkerControl(_worker_runtime_directory())
            control.request_drain()
            control.wait_for_drain(timeout_seconds=args.timeout_seconds)
        except OSError:
            return 1
        return 0

    uvicorn.run(
        "aegis_framework.api:app",
        host=args.host,
        port=args.port,
        access_log=False,
    )
    return 0


def _worker_runtime_directory() -> Path:
    return Path(os.getenv("AEGIS_WORKER_RUNTIME_DIR", "/var/run/aegis"))


def _run_governed_eval(args: argparse.Namespace) -> int:
    from aegis_framework.evaluation import (
        EvaluationRunner,
        create_baseline,
        load_baseline,
        load_dataset,
        load_suite,
        load_waivers,
        write_baseline,
        write_reports,
    )

    suite = load_suite(args.suite)
    dataset = load_dataset(args.dataset)
    baseline = load_baseline(args.baseline)
    cases = load_cases(args.cases)
    runner = EvaluationRunner(
        suite=suite,
        dataset=dataset,
        baseline=baseline,
        waivers=load_waivers(args.waivers),
    )
    filters = tuple(getattr(args, "filter", ()))
    shard_index = getattr(args, "shard_index", 0)
    shard_count = getattr(args, "shard_count", 1)
    if args.eval_action == "list":
        contracts = runner.list_cases(
            cases,
            filters=filters,
            shard_index=shard_index,
            shard_count=shard_count,
        )
        print(
            json.dumps(
                [
                    item.model_dump(mode="json", exclude_computed_fields=True)
                    for item in contracts
                ],
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.eval_action == "update-baseline":
        reviewed = create_baseline(
            suite=suite,
            dataset=dataset,
            case_ids=(case.case_id for case in cases),
            reviewed_by=args.reviewed_by,
            review_reason=args.reason,
        )
        candidate_runner = EvaluationRunner(
            suite=suite,
            dataset=dataset,
            baseline=reviewed,
        )
        candidate_report = candidate_runner.run(cases)
        if not candidate_report.passed:
            print(candidate_report.model_dump_json(indent=2))
            return 1
        write_baseline(args.output, reviewed)
        print(reviewed.model_dump_json(indent=2))
        return 0
    report = runner.run(
        cases,
        filters=filters,
        shard_index=shard_index,
        shard_count=shard_count,
        mode=args.mode,
    )
    if args.eval_action == "replay":
        replayed = runner.run(
            tuple(reversed(cases)),
            filters=filters,
            shard_index=shard_index,
            shard_count=shard_count,
            mode=args.mode,
        )
        stable = report.canonical_digest == replayed.canonical_digest
        print(
            json.dumps(
                {
                    "stable": stable,
                    "first": report.canonical_digest,
                    "replay": replayed.canonical_digest,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if stable and report.passed else 1
    if args.eval_action == "compare":
        print(report.comparison.model_dump_json(indent=2))
        return 0 if report.comparison.passed else 1
    if args.report_dir is not None:
        write_reports(
            report,
            args.report_dir,
            maximum_bytes=suite.bounds.maximum_report_bytes,
        )
    if args.publish_langfuse:
        from aegis_framework.langfuse_adapter import build_langfuse_observability

        publisher = build_langfuse_observability()
        publisher.publish_dataset_manifest(dataset)
        publisher.publish_evaluation_report(report)
    print(report.model_dump_json(indent=2))
    return 0 if report.passed else 1
