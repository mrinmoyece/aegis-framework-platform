from __future__ import annotations

import asyncio
import os
from datetime import timedelta

import pytest
from temporalio.client import Client
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Replayer, Worker

from aegis_framework.activity_runtime import (
    CallbackActivityOperations,
    DurableActivityRuntime,
    InMemoryCurrentAuthority,
)
from aegis_framework.adapters import FixedClock, InMemoryBudget
from aegis_framework.durability import InMemoryDurability, RunStatus
from aegis_framework.errors import RepositoryUnavailable
from aegis_framework.fixtures import (
    DEMO_TIME,
    build_demo_bundle,
    demo_identity,
    demo_request,
)
from aegis_framework.temporal import (
    ActivityOutcome,
    AegisInvestigationWorkflow,
    TemporalActivities,
    TemporalClientAdapter,
    TemporalOutboxDispatcher,
    TemporalSignal,
    TemporalWorkflowInput,
    TemporalWorkflowResult,
    connect_temporal,
    temporal_data_converter,
)

_TASK_QUEUE = "aegis-integration-v1"


class _RetryOnceOperations(CallbackActivityOperations):
    def __init__(self) -> None:
        super().__init__(_outcomes())
        self.retry_attempts = 0

    async def collect_evidence(self, value: object) -> ActivityOutcome:
        if getattr(value, "run_id", None) == "run:retry":
            self.retry_attempts += 1
            if self.retry_attempts == 1:
                raise RepositoryUnavailable("synthetic activity outage")
        return ActivityOutcome(outcome="evidence_ready")


def _outcomes() -> dict[str, ActivityOutcome]:
    return {
        "authorize": ActivityOutcome(outcome="authorized"),
        "collect_evidence": ActivityOutcome(outcome="evidence_ready"),
        "run_graph": ActivityOutcome(
            outcome="graph_complete",
            result_ref="result:integration",
        ),
        "record_wait": ActivityOutcome(outcome="recorded"),
        "authorize_signal": ActivityOutcome(outcome="authorized"),
        "complete": ActivityOutcome(
            outcome="recorded",
            result_ref="result:integration",
        ),
        "cancel": ActivityOutcome(outcome="recorded"),
        "fail": ActivityOutcome(outcome="recorded"),
        "time_out": ActivityOutcome(outcome="recorded"),
    }


async def _client() -> tuple[Client, WorkflowEnvironment | None]:
    address = os.getenv("AEGIS_TEST_TEMPORAL_ADDRESS")
    if address:
        return (
            await connect_temporal(
                target_host=address,
                tracing=False,
            ),
            None,
        )
    test_server = os.getenv("AEGIS_TEST_TEMPORAL_TEST_SERVER")
    if not test_server:
        pytest.skip("local Temporal integration environment is not configured")
    environment = await WorkflowEnvironment.start_time_skipping(
        test_server_existing_path=test_server,
        data_converter=temporal_data_converter(),
    )
    return environment.client, environment


def _input(
    suffix: str,
    *,
    wait_for_signal: bool = False,
    wait_timeout_seconds: int = 3_600,
) -> TemporalWorkflowInput:
    return TemporalWorkflowInput(
        tenant_ref="tenant:opaque",
        actor_ref="actor:opaque",
        request_ref=f"request:{suffix}",
        run_id=f"run:{suffix}",
        workflow_id=f"workflow:{suffix}",
        wait_for_signal=wait_for_signal,
        wait_timeout_seconds=wait_timeout_seconds,
    )


@pytest.mark.temporal
def test_temporal_completion_signal_timeout_and_replay() -> None:
    async def execute() -> None:
        client, environment = await _client()
        operations = _RetryOnceOperations()
        activities = TemporalActivities(operations)
        worker = Worker(
            client,
            task_queue=_TASK_QUEUE,
            workflows=[AegisInvestigationWorkflow],
            activities=list(activities.registered()),
        )
        try:
            delayed = await client.start_workflow(
                AegisInvestigationWorkflow.run,
                _input("delayed-worker"),
                id="workflow:integration-delayed-worker",
                task_queue=_TASK_QUEUE,
                execution_timeout=timedelta(minutes=2),
            )
            await asyncio.sleep(0.2)
            async with worker:
                recovered = await delayed.result()
                assert recovered.status.value == "completed"

                completed = await client.execute_workflow(
                    AegisInvestigationWorkflow.run,
                    _input("complete"),
                    id="workflow:integration-complete",
                    task_queue=_TASK_QUEUE,
                    execution_timeout=timedelta(minutes=2),
                )
                assert isinstance(completed, TemporalWorkflowResult)
                assert completed.status.value == "completed"

                waiting = await client.start_workflow(
                    AegisInvestigationWorkflow.run,
                    _input("signal", wait_for_signal=True),
                    id="workflow:integration-signal",
                    task_queue=_TASK_QUEUE,
                    execution_timeout=timedelta(minutes=2),
                )
                await waiting.signal(
                    AegisInvestigationWorkflow.resume,
                    TemporalSignal(command_ref="command:resume"),
                )
                await waiting.signal(
                    AegisInvestigationWorkflow.resume,
                    TemporalSignal(command_ref="command:resume"),
                )
                resumed = await waiting.result()
                assert resumed.status.value == "completed"

                cancelled = await client.start_workflow(
                    AegisInvestigationWorkflow.run,
                    _input("cancel", wait_for_signal=True),
                    id="workflow:integration-cancel",
                    task_queue=_TASK_QUEUE,
                    execution_timeout=timedelta(minutes=2),
                )
                await cancelled.signal(
                    AegisInvestigationWorkflow.request_cancel,
                    TemporalSignal(command_ref="command:cancel"),
                )
                cancellation_result = await cancelled.result()
                assert cancellation_result.status.value == "cancelled"

                retried = await client.execute_workflow(
                    AegisInvestigationWorkflow.run,
                    _input("retry"),
                    id="workflow:integration-retry",
                    task_queue=_TASK_QUEUE,
                    execution_timeout=timedelta(minutes=2),
                )
                assert retried.status.value == "completed"
                assert operations.retry_attempts == 2

                invalid_operations = CallbackActivityOperations(
                    {
                        **_outcomes(),
                        "collect_evidence": ActivityOutcome(outcome="recorded"),
                    }
                )
                invalid_activities = TemporalActivities(invalid_operations)
                invalid_queue = "aegis-integration-invalid-v1"
                invalid_worker = Worker(
                    client,
                    task_queue=invalid_queue,
                    workflows=[AegisInvestigationWorkflow],
                    activities=list(invalid_activities.registered()),
                )
                async with invalid_worker:
                    invalid = await client.execute_workflow(
                        AegisInvestigationWorkflow.run,
                        _input("invalid-outcome"),
                        id="workflow:integration-invalid-outcome",
                        task_queue=invalid_queue,
                        execution_timeout=timedelta(minutes=2),
                    )
                assert invalid.status.value == "failed"
                assert invalid.failure_code == "integrityfailure"

                timed = await client.execute_workflow(
                    AegisInvestigationWorkflow.run,
                    _input(
                        "timeout",
                        wait_for_signal=True,
                        wait_timeout_seconds=1,
                    ),
                    id="workflow:integration-timeout",
                    task_queue=_TASK_QUEUE,
                    execution_timeout=timedelta(minutes=2),
                )
                assert timed.status.value == "timed_out"

            history = await client.get_workflow_handle(
                "workflow:integration-complete"
            ).fetch_history()
            replayed = await Replayer(
                workflows=[AegisInvestigationWorkflow],
                data_converter=temporal_data_converter(),
            ).replay_workflow(history)
            assert replayed.replay_failure is None
        finally:
            if environment is not None:
                await environment.shutdown()

    asyncio.run(execute())


@pytest.mark.temporal
def test_temporal_end_to_end_application_outbox_and_projection() -> None:
    async def execute() -> None:
        client, environment = await _client()
        bundle = build_demo_bundle()
        identity = demo_identity(request_id="temporal-e2e")
        store = InMemoryDurability(clock=FixedClock(DEMO_TIME))
        run = store.accept_run(
            identity=identity,
            request=demo_request(),
            wait_for_signal=False,
        )
        operations = DurableActivityRuntime(
            authority=InMemoryCurrentAuthority((identity,)),
            policy=bundle.policy,
            budget=InMemoryBudget({"tenant-acme": 5}),
            evidence=bundle.service._evidence,
            orchestrator=bundle.orchestrator,
            store=store,
        )
        queue = "aegis-integration-e2e-v1"
        activities = TemporalActivities(operations)
        worker = Worker(
            client,
            task_queue=queue,
            workflows=[AegisInvestigationWorkflow],
            activities=list(activities.registered()),
        )
        dispatcher = TemporalOutboxDispatcher(
            store=store,
            temporal=TemporalClientAdapter(client=client, task_queue=queue),
        )
        try:
            async with worker:
                delivered = await dispatcher.dispatch(
                    tenant_id=identity.tenant_id,
                    worker_ref="worker:e2e",
                    now=DEMO_TIME,
                )
                assert delivered == 1
                result = await client.get_workflow_handle(
                    run.workflow_id,
                    result_type=TemporalWorkflowResult,
                ).result()
                assert result.status is RunStatus.COMPLETED
            projection = store.get_run(
                tenant_id=identity.tenant_id,
                run_id=run.run_id,
            )
            assert projection is not None
            assert projection.status is RunStatus.COMPLETED
        finally:
            if environment is not None:
                await environment.shutdown()

    asyncio.run(execute())
