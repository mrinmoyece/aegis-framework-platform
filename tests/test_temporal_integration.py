from __future__ import annotations

import asyncio
import os
from datetime import timedelta
from uuid import uuid4

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
from aegis_framework.evidence import QueryStatus
from aegis_framework.evidence_temporal import (
    AegisEvidenceQueryWorkflow,
    EvidenceActivityInput,
    EvidenceActivityOperations,
    EvidenceActivityOutcome,
    EvidenceWorkflowInput,
    EvidenceWorkflowResult,
    TemporalEvidenceActivities,
)
from aegis_framework.fixtures import (
    DEMO_TIME,
    build_demo_bundle,
    demo_identity,
    demo_request,
)
from aegis_framework.memory_temporal import (
    AegisMemoryWorkflow,
    MemoryActivityInput,
    MemoryActivityOutcome,
    MemoryWorkflowInput,
    MemoryWorkflowResult,
    TemporalMemoryActivities,
)
from aegis_framework.remediation_temporal import (
    AegisRemediationWorkflow,
    RemediationActivityInput,
    RemediationActivityOutcome,
    RemediationSignal,
    RemediationWorkflowInput,
    RemediationWorkflowResult,
    TemporalRemediationActivities,
)
from aegis_framework.sandbox_temporal import (
    AegisSandboxWorkflow,
    SandboxActivityInput,
    SandboxActivityOutcome,
    SandboxWorkflowInput,
    SandboxWorkflowResult,
    TemporalSandboxActivities,
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
_EVIDENCE_TASK_QUEUE = "aegis-evidence-integration-v1"
_REMEDIATION_TASK_QUEUE = "aegis-remediation-integration-v1"
_SANDBOX_TASK_QUEUE = "aegis-sandbox-integration-v1"
_MEMORY_TASK_QUEUE = "aegis-memory-integration-v1"


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


class _MemoryOperations:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.fences: set[str] = set()
        self.embed_attempts = 0

    def _outcome(
        self,
        value: MemoryActivityInput,
        name: str,
        outcome: str,
    ) -> MemoryActivityOutcome:
        self.calls.append(name)
        self.fences.add(value.fence_token)
        return MemoryActivityOutcome(outcome=outcome)

    async def record_candidate(
        self, value: MemoryActivityInput
    ) -> MemoryActivityOutcome:
        return self._outcome(value, "record_candidate", "recorded")

    async def authorize(self, value: MemoryActivityInput) -> MemoryActivityOutcome:
        return self._outcome(value, "authorize", "authorized")

    async def scan(self, value: MemoryActivityInput) -> MemoryActivityOutcome:
        return self._outcome(value, "scan", "scanned")

    async def chunk(self, value: MemoryActivityInput) -> MemoryActivityOutcome:
        return self._outcome(value, "chunk", "chunked")

    async def embed(self, value: MemoryActivityInput) -> MemoryActivityOutcome:
        self.embed_attempts += 1
        self.fences.add(value.fence_token)
        if self.embed_attempts == 1:
            raise RepositoryUnavailable("synthetic embedding outage")
        self.calls.append("embed")
        return MemoryActivityOutcome(outcome="embedded")

    async def index(self, value: MemoryActivityInput) -> MemoryActivityOutcome:
        return self._outcome(value, "index", "indexed")

    async def compact(self, value: MemoryActivityInput) -> MemoryActivityOutcome:
        return self._outcome(value, "compact", "compacted")

    async def purge(self, value: MemoryActivityInput) -> MemoryActivityOutcome:
        return self._outcome(value, "purge", "purged")

    async def rebuild(self, value: MemoryActivityInput) -> MemoryActivityOutcome:
        return self._outcome(value, "rebuild", "rebuilt")


class _EvidenceOperations(EvidenceActivityOperations):
    def __init__(self) -> None:
        self.pages: list[int] = []
        self.cancelled = False

    async def authorize(self, value: EvidenceActivityInput) -> EvidenceActivityOutcome:
        del value
        return EvidenceActivityOutcome(outcome="authorized")

    async def fetch_page(self, value: EvidenceActivityInput) -> EvidenceActivityOutcome:
        self.pages.append(value.page_number)
        return EvidenceActivityOutcome(
            outcome="page_complete",
            has_next_page=value.page_number == 1,
            cursor_ref=("cursor:opaque" if value.page_number == 1 else None),
        )

    async def complete(self, value: EvidenceActivityInput) -> EvidenceActivityOutcome:
        del value
        return EvidenceActivityOutcome(
            outcome="query_complete",
            bundle_ref="bundle:opaque",
        )

    async def cancel(self, value: EvidenceActivityInput) -> EvidenceActivityOutcome:
        del value
        self.cancelled = True
        return EvidenceActivityOutcome(outcome="cancelled")

    async def reconcile(self, value: EvidenceActivityInput) -> EvidenceActivityOutcome:
        del value
        return EvidenceActivityOutcome(outcome="query_complete")


class _RemediationOperations:
    def __init__(
        self,
        *,
        ambiguous: bool = False,
        approval_outcomes: dict[str, str] | None = None,
    ) -> None:
        self.ambiguous = ambiguous
        self.approval_outcomes = approval_outcomes or {}
        self.calls: list[str] = []

    async def request_approval(
        self,
        value: RemediationActivityInput,
    ) -> RemediationActivityOutcome:
        del value
        self.calls.append("request_approval")
        return RemediationActivityOutcome(outcome="pending")

    async def load_approval_decision(
        self,
        value: RemediationActivityInput,
    ) -> RemediationActivityOutcome:
        assert value.command_ref is not None
        self.calls.append("load_approval_decision")
        return RemediationActivityOutcome(
            outcome=self.approval_outcomes.get(value.command_ref, "granted")
        )

    async def preflight(
        self,
        value: RemediationActivityInput,
    ) -> RemediationActivityOutcome:
        del value
        self.calls.append("preflight")
        return RemediationActivityOutcome(outcome="preflight_succeeded")

    async def execute(
        self,
        value: RemediationActivityInput,
    ) -> RemediationActivityOutcome:
        del value
        self.calls.append("execute")
        return RemediationActivityOutcome(
            outcome=("effect_ambiguous" if self.ambiguous else "effect_succeeded"),
            result_ref="effect:opaque",
        )

    async def reconcile(
        self,
        value: RemediationActivityInput,
    ) -> RemediationActivityOutcome:
        assert value.command_ref is not None
        self.calls.append("reconcile")
        return RemediationActivityOutcome(
            outcome="reconciled",
            result_ref="effect:opaque",
        )

    async def verify(
        self,
        value: RemediationActivityInput,
    ) -> RemediationActivityOutcome:
        del value
        self.calls.append("verify")
        return RemediationActivityOutcome(
            outcome="verified",
            result_ref="verification:opaque",
        )

    async def rollback(
        self,
        value: RemediationActivityInput,
    ) -> RemediationActivityOutcome:
        del value
        self.calls.append("rollback")
        return RemediationActivityOutcome(outcome="rolled_back")

    async def cancel(
        self,
        value: RemediationActivityInput,
    ) -> RemediationActivityOutcome:
        assert value.command_ref is not None
        self.calls.append("cancel")
        return RemediationActivityOutcome(outcome="cancelled")

    async def expire(
        self,
        value: RemediationActivityInput,
    ) -> RemediationActivityOutcome:
        del value
        self.calls.append("expire")
        return RemediationActivityOutcome(outcome="expired")

    async def escalate(
        self,
        value: RemediationActivityInput,
    ) -> RemediationActivityOutcome:
        del value
        self.calls.append("escalate")
        return RemediationActivityOutcome(outcome="escalated")


class _SandboxOperations:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def record_request(
        self, value: SandboxActivityInput
    ) -> SandboxActivityOutcome:
        del value
        self.calls.append("record_request")
        return SandboxActivityOutcome(outcome="recorded")

    async def authorize_and_claim(
        self, value: SandboxActivityInput
    ) -> SandboxActivityOutcome:
        del value
        self.calls.append("authorize_and_claim")
        return SandboxActivityOutcome(outcome="claimed")

    async def provision(self, value: SandboxActivityInput) -> SandboxActivityOutcome:
        del value
        self.calls.append("provision")
        return SandboxActivityOutcome(
            outcome="provisioned",
            provider_ref="sandbox:opaque",
        )

    async def wait_for_completion(
        self, value: SandboxActivityInput
    ) -> SandboxActivityOutcome:
        del value
        self.calls.append("wait_for_completion")
        return SandboxActivityOutcome(
            outcome="succeeded",
            result_ref="result:opaque",
        )

    async def capture_outputs(
        self, value: SandboxActivityInput
    ) -> SandboxActivityOutcome:
        del value
        self.calls.append("capture_outputs")
        return SandboxActivityOutcome(
            outcome="captured",
            result_ref="manifest:opaque",
        )

    async def attest(self, value: SandboxActivityInput) -> SandboxActivityOutcome:
        del value
        self.calls.append("attest")
        return SandboxActivityOutcome(
            outcome="attested",
            result_ref="attestation:opaque",
        )

    async def cleanup(self, value: SandboxActivityInput) -> SandboxActivityOutcome:
        del value
        self.calls.append("cleanup")
        return SandboxActivityOutcome(outcome="cleaned")

    async def cancel(self, value: SandboxActivityInput) -> SandboxActivityOutcome:
        del value
        self.calls.append("cancel")
        return SandboxActivityOutcome(outcome="cancelled")

    async def reconcile(self, value: SandboxActivityInput) -> SandboxActivityOutcome:
        del value
        self.calls.append("reconcile")
        return SandboxActivityOutcome(outcome="reconciled")

    async def redrive_orphan(
        self, value: SandboxActivityInput
    ) -> SandboxActivityOutcome:
        del value
        self.calls.append("redrive_orphan")
        return SandboxActivityOutcome(outcome="orphan_redriven")


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


def _remediation_input(suffix: str) -> RemediationWorkflowInput:
    return RemediationWorkflowInput(
        tenant_ref="tenant:opaque",
        actor_ref="actor:opaque",
        request_ref=f"request:{suffix}",
        run_id=f"run:{suffix}",
        plan_ref=f"plan:{suffix}",
        action_ref=f"action:{suffix}",
        workflow_id=f"workflow:{suffix}",
        approval_timeout_seconds=120,
        reconciliation_timeout_seconds=120,
    )


def _sandbox_input(suffix: str) -> SandboxWorkflowInput:
    return SandboxWorkflowInput(
        tenant_ref="tenant:opaque",
        actor_ref="actor:opaque",
        request_ref=f"request:{suffix}",
        execution_id=f"sandbox:{suffix}",
        workflow_id=f"workflow:{suffix}",
        attempt=1,
        execution_timeout_seconds=120,
        reconciliation_timeout_seconds=120,
        cleanup_timeout_seconds=120,
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
def test_temporal_sandbox_completion_cleanup_and_replay() -> None:
    async def execute() -> None:
        client, environment = await _client()
        operations = _SandboxOperations()
        activities = TemporalSandboxActivities(operations)
        worker = Worker(
            client,
            task_queue=_SANDBOX_TASK_QUEUE,
            workflows=[AegisSandboxWorkflow],
            activities=list(activities.registered()),
        )
        workflow_id = f"workflow:sandbox:complete:{uuid4().hex}"
        try:
            async with worker:
                result = await client.execute_workflow(
                    AegisSandboxWorkflow.run,
                    _sandbox_input("complete"),
                    id=workflow_id,
                    task_queue=_SANDBOX_TASK_QUEUE,
                    execution_timeout=timedelta(minutes=2),
                )
                assert isinstance(result, SandboxWorkflowResult)
                assert result.status == "succeeded"
                assert result.result_ref == "attestation:opaque"
                assert operations.calls == [
                    "record_request",
                    "authorize_and_claim",
                    "provision",
                    "wait_for_completion",
                    "capture_outputs",
                    "attest",
                    "cleanup",
                ]
            history = await client.get_workflow_handle(workflow_id).fetch_history()
            replayed = await Replayer(
                workflows=[AegisSandboxWorkflow],
                data_converter=temporal_data_converter(),
            ).replay_workflow(history)
            assert replayed.replay_failure is None
        finally:
            if environment is not None:
                await environment.shutdown()

    asyncio.run(execute())


@pytest.mark.temporal
def test_temporal_evidence_pagination_uses_opaque_references() -> None:
    async def execute() -> None:
        client, environment = await _client()
        operations = _EvidenceOperations()
        activities = TemporalEvidenceActivities(operations)
        worker = Worker(
            client,
            task_queue=_EVIDENCE_TASK_QUEUE,
            workflows=[AegisEvidenceQueryWorkflow],
            activities=list(activities.registered()),
        )
        value = EvidenceWorkflowInput(
            tenant_ref="tenant:opaque",
            actor_ref="actor:opaque",
            request_ref="request:opaque",
            run_id="run:evidence",
            query_ref="query:opaque",
            workflow_id="workflow:evidence",
            maximum_pages=2,
        )
        try:
            async with worker:
                completed = await client.execute_workflow(
                    AegisEvidenceQueryWorkflow.run,
                    value,
                    id=f"workflow:evidence:{uuid4().hex}",
                    task_queue=_EVIDENCE_TASK_QUEUE,
                    execution_timeout=timedelta(minutes=2),
                )
                assert isinstance(completed, EvidenceWorkflowResult)
                assert completed.status is QueryStatus.COMPLETED
                assert completed.bundle_ref == "bundle:opaque"
                assert operations.pages == [1, 2]
        finally:
            if environment is not None:
                await environment.shutdown()

    asyncio.run(execute())


@pytest.mark.temporal
def test_temporal_end_to_end_application_outbox_and_projection() -> None:
    async def execute() -> None:
        client, environment = await _client()
        bundle = build_demo_bundle()
        identity = demo_identity(request_id=f"temporal-e2e-{uuid4().hex}")
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


@pytest.mark.temporal
def test_temporal_remediation_wait_signal_reconcile_cancel_and_replay() -> None:
    async def execute() -> None:
        client, environment = await _client()
        success_operations = _RemediationOperations()
        success_activities = TemporalRemediationActivities(success_operations)
        worker = Worker(
            client,
            task_queue=_REMEDIATION_TASK_QUEUE,
            workflows=[AegisRemediationWorkflow],
            activities=list(success_activities.registered()),
        )
        try:
            async with worker:
                success = await client.start_workflow(
                    AegisRemediationWorkflow.run,
                    _remediation_input("success"),
                    id=f"workflow:remediation:success:{uuid4().hex}",
                    task_queue=_REMEDIATION_TASK_QUEUE,
                    execution_timeout=timedelta(minutes=2),
                )
                await success.signal(
                    AegisRemediationWorkflow.approval_decision,
                    RemediationSignal(command_ref="command:approval"),
                )
                await success.signal(
                    AegisRemediationWorkflow.approval_decision,
                    RemediationSignal(command_ref="command:approval"),
                )
                completed = await success.result()
                assert isinstance(completed, RemediationWorkflowResult)
                assert completed.status == "verified"
                assert success_operations.calls == [
                    "request_approval",
                    "load_approval_decision",
                    "preflight",
                    "execute",
                    "verify",
                ]

                pending_operations = _RemediationOperations(
                    approval_outcomes={
                        "command:approval:pending": "pending",
                        "command:approval:grant": "granted",
                    }
                )
                pending_activities = TemporalRemediationActivities(pending_operations)
                pending_queue = "aegis-remediation-pending-v1"
                pending_worker = Worker(
                    client,
                    task_queue=pending_queue,
                    workflows=[AegisRemediationWorkflow],
                    activities=list(pending_activities.registered()),
                )
                async with pending_worker:
                    pending = await client.start_workflow(
                        AegisRemediationWorkflow.run,
                        _remediation_input("pending"),
                        id=f"workflow:remediation:pending:{uuid4().hex}",
                        task_queue=pending_queue,
                        execution_timeout=timedelta(minutes=2),
                    )
                    await pending.signal(
                        AegisRemediationWorkflow.approval_decision,
                        RemediationSignal(command_ref="command:approval:pending"),
                    )
                    await pending.signal(
                        AegisRemediationWorkflow.approval_decision,
                        RemediationSignal(command_ref="command:approval:grant"),
                    )
                    pending_result = await pending.result()
                    assert pending_result.status == "verified"
                    assert pending_operations.calls == [
                        "request_approval",
                        "load_approval_decision",
                        "load_approval_decision",
                        "preflight",
                        "execute",
                        "verify",
                    ]

                cancelled = await client.start_workflow(
                    AegisRemediationWorkflow.run,
                    _remediation_input("cancel"),
                    id=f"workflow:remediation:cancel:{uuid4().hex}",
                    task_queue=_REMEDIATION_TASK_QUEUE,
                    execution_timeout=timedelta(minutes=2),
                )
                await cancelled.signal(
                    AegisRemediationWorkflow.request_cancel,
                    RemediationSignal(command_ref="command:cancel"),
                )
                assert (await cancelled.result()).status == "cancelled"

            ambiguous_operations = _RemediationOperations(ambiguous=True)
            ambiguous_activities = TemporalRemediationActivities(ambiguous_operations)
            ambiguous_queue = "aegis-remediation-ambiguous-v1"
            ambiguous_worker = Worker(
                client,
                task_queue=ambiguous_queue,
                workflows=[AegisRemediationWorkflow],
                activities=list(ambiguous_activities.registered()),
            )
            async with ambiguous_worker:
                ambiguous = await client.start_workflow(
                    AegisRemediationWorkflow.run,
                    _remediation_input("ambiguous"),
                    id=f"workflow:remediation:ambiguous:{uuid4().hex}",
                    task_queue=ambiguous_queue,
                    execution_timeout=timedelta(minutes=2),
                )
                await ambiguous.signal(
                    AegisRemediationWorkflow.approval_decision,
                    RemediationSignal(command_ref="command:approval"),
                )
                await ambiguous.signal(
                    AegisRemediationWorkflow.reconcile_effect,
                    RemediationSignal(command_ref="command:reconcile"),
                )
                assert (await ambiguous.result()).status == "verified"
                assert "reconcile" in ambiguous_operations.calls

            history = await success.fetch_history()
            replayed = await Replayer(
                workflows=[AegisRemediationWorkflow],
                data_converter=temporal_data_converter(),
            ).replay_workflow(history)
            assert replayed.replay_failure is None
        finally:
            if environment is not None:
                await environment.shutdown()

    asyncio.run(execute())


@pytest.mark.temporal
def test_temporal_memory_retry_fencing_completion_and_replay() -> None:
    async def execute() -> None:
        client, environment = await _client()
        operations = _MemoryOperations()
        activities = TemporalMemoryActivities(operations)
        worker = Worker(
            client,
            task_queue=_MEMORY_TASK_QUEUE,
            workflows=[AegisMemoryWorkflow],
            activities=list(activities.registered()),
        )
        value = MemoryWorkflowInput(
            tenant_ref="tenant:opaque",
            actor_ref="actor:opaque",
            request_ref="request:opaque",
            memory_id="memory:temporal",
            workflow_id="workflow:memory",
            fence_token="fence:memory:one",
            operation="ingest",
            activity_timeout_seconds=60,
        )
        try:
            async with worker:
                handle = await client.start_workflow(
                    AegisMemoryWorkflow.run,
                    value,
                    id=f"workflow:memory:{uuid4().hex}",
                    task_queue=_MEMORY_TASK_QUEUE,
                    execution_timeout=timedelta(minutes=2),
                )
                result = await handle.result()
                assert isinstance(result, MemoryWorkflowResult)
                assert result.status == "active"
                assert operations.embed_attempts == 2
                assert operations.calls == [
                    "record_candidate",
                    "authorize",
                    "scan",
                    "chunk",
                    "embed",
                    "index",
                ]
                assert operations.fences == {"fence:memory:one"}
            history = await handle.fetch_history()
            replayed = await Replayer(
                workflows=[AegisMemoryWorkflow],
                data_converter=temporal_data_converter(),
            ).replay_workflow(history)
            assert replayed.replay_failure is None
        finally:
            if environment is not None:
                await environment.shutdown()

    asyncio.run(execute())
