"""Temporal adapter for cross-process lifecycle durability around LangGraph."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol

from pydantic import Field, ValidationError
from temporalio import activity, workflow
from temporalio.api.common.v1 import Payload
from temporalio.client import Client, PayloadLimitsConfig
from temporalio.common import (
    RetryPolicy,
    WorkflowIDConflictPolicy,
    WorkflowIDReusePolicy,
)
from temporalio.contrib.opentelemetry import TracingInterceptor
from temporalio.contrib.pydantic import pydantic_data_converter
from temporalio.converter import DataConverter, PayloadCodec
from temporalio.exceptions import (
    ActivityError,
    ApplicationError,
    WorkflowAlreadyStartedError,
)
from temporalio.service import RPCError
from temporalio.worker import Worker

from aegis_framework.domain import Identifier, OpaqueReference, StrictModel
from aegis_framework.durability import (
    DeliveryClaim,
    OutboxPort,
    RunStatus,
)
from aegis_framework.errors import (
    AegisFrameworkError,
    IdempotencyConflict,
    IntegrityFailure,
    PayloadRejected,
    PolicyDenied,
)

_MAX_PAYLOAD_BYTES = 64 * 1024
_ACTIVITY_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=30),
    maximum_attempts=3,
    non_retryable_error_types=[
        "AuthorizationDenied",
        "IdempotencyConflict",
        "PayloadRejected",
        "IntegrityFailure",
        "FrameworkDefect",
    ],
)
_ACTIVITY_TIMEOUT = timedelta(minutes=5)
_HEARTBEAT_TIMEOUT = timedelta(seconds=30)


class TemporalWorkflowInput(StrictModel):
    """Only opaque application references cross into Temporal history."""

    tenant_ref: OpaqueReference
    actor_ref: Identifier
    request_ref: Identifier
    run_id: Identifier
    workflow_id: Identifier
    wait_for_signal: bool = False
    wait_timeout_seconds: int = Field(default=3_600, ge=1, le=86_400)


class TemporalActivityInput(StrictModel):
    tenant_ref: OpaqueReference
    actor_ref: Identifier
    request_ref: Identifier
    run_id: Identifier
    operation_id: Identifier
    command_ref: Identifier | None = None
    failure_code: Identifier | None = None


class TemporalSignal(StrictModel):
    command_ref: Identifier


class ActivityOutcome(StrictModel):
    outcome: Literal[
        "authorized",
        "recorded",
        "evidence_ready",
        "graph_complete",
        "duplicate",
        "denied",
    ]
    result_ref: Identifier | None = None


class TemporalWorkflowResult(StrictModel):
    run_id: Identifier
    status: RunStatus
    result_ref: Identifier | None = None
    failure_code: Identifier | None = None


class OperationalWorkflowState(StrictModel):
    """Non-authoritative query response for worker operations only."""

    stage: Identifier
    accepted_signal_count: int
    cancellation_requested: bool


class ActivityOperations(Protocol):
    async def authorize(self, value: TemporalActivityInput) -> ActivityOutcome: ...

    async def collect_evidence(
        self, value: TemporalActivityInput
    ) -> ActivityOutcome: ...

    async def run_graph(self, value: TemporalActivityInput) -> ActivityOutcome: ...

    async def record_wait(self, value: TemporalActivityInput) -> ActivityOutcome: ...

    async def authorize_signal(
        self, value: TemporalActivityInput
    ) -> ActivityOutcome: ...

    async def complete(self, value: TemporalActivityInput) -> ActivityOutcome: ...

    async def cancel(self, value: TemporalActivityInput) -> ActivityOutcome: ...

    async def fail(self, value: TemporalActivityInput) -> ActivityOutcome: ...

    async def time_out(self, value: TemporalActivityInput) -> ActivityOutcome: ...


class BoundedPayloadCodec(PayloadCodec):
    """Reject poison payloads before workflow/activity dispatch and after retrieval."""

    def __init__(self, maximum_bytes: int = _MAX_PAYLOAD_BYTES) -> None:
        if maximum_bytes < 1_024 or maximum_bytes > 2 * 1024 * 1024:
            raise ValueError("Temporal payload bound is invalid")
        self._maximum_bytes = maximum_bytes

    async def encode(self, payloads: Sequence[Payload]) -> list[Payload]:
        self._validate(payloads)
        return list(payloads)

    async def decode(self, payloads: Sequence[Payload]) -> list[Payload]:
        self._validate(payloads)
        return list(payloads)

    def _validate(self, payloads: Sequence[Payload]) -> None:
        if not payloads or len(payloads) > 32:
            raise PayloadRejected("Temporal payload count is outside the bound")
        total = 0
        for payload in payloads:
            size = len(payload.data) + sum(
                len(key.encode()) + len(value)
                for key, value in payload.metadata.items()
            )
            if size > self._maximum_bytes:
                raise PayloadRejected("Temporal payload exceeds the per-item bound")
            total += size
        if total > self._maximum_bytes * 2:
            raise PayloadRejected("Temporal payload batch exceeds the total bound")


def temporal_data_converter(
    *, maximum_payload_bytes: int = _MAX_PAYLOAD_BYTES
) -> DataConverter:
    return DataConverter(
        payload_converter_class=pydantic_data_converter.payload_converter_class,
        payload_codec=BoundedPayloadCodec(maximum_payload_bytes),
        failure_converter_class=pydantic_data_converter.failure_converter_class,
    )


@workflow.defn(name="aegis.investigation.v1")
class AegisInvestigationWorkflow:
    """Deterministic lifecycle scheduler; application Activities own every fact."""

    def __init__(self) -> None:
        self._stage = "created"
        self._signals: list[str] = []
        self._seen_signals: set[str] = set()
        self._cancellation_requested = False
        self._cancel_command_ref: str | None = None

    @workflow.run
    async def run(self, value: TemporalWorkflowInput) -> TemporalWorkflowResult:
        workflow.patched("aegis-investigation-lifecycle-v1")
        self._stage = "authorizing"
        try:
            cancelled = await self._cancel_if_requested(value)
            if cancelled is not None:
                return cancelled
            authorization = await self._activity(
                "aegis.authorize",
                self._input(value, "authorize"),
            )
            if authorization.outcome != "authorized":
                return TemporalWorkflowResult(
                    run_id=value.run_id,
                    status=RunStatus.FAILED,
                    failure_code="authorization_denied",
                )
            cancelled = await self._cancel_if_requested(value)
            if cancelled is not None:
                return cancelled

            self._stage = "collecting_evidence"
            await self._require_outcome(
                "aegis.collect_evidence",
                self._input(value, "collect-evidence"),
                "evidence_ready",
            )
            cancelled = await self._cancel_if_requested(value)
            if cancelled is not None:
                return cancelled
            self._stage = "running_graph"
            graph = await self._require_outcome(
                "aegis.run_graph",
                self._input(value, "run-graph"),
                "graph_complete",
            )
            cancelled = await self._cancel_if_requested(value)
            if cancelled is not None:
                return cancelled

            if value.wait_for_signal:
                self._stage = "waiting"
                await self._require_outcome(
                    "aegis.record_wait",
                    self._input(value, "record-wait"),
                    "recorded",
                )
                try:
                    await workflow.wait_condition(
                        lambda: bool(self._signals) or self._cancellation_requested,
                        timeout=timedelta(seconds=value.wait_timeout_seconds),
                        timeout_summary="bounded investigation signal wait",
                    )
                except TimeoutError:
                    self._stage = "timed_out"
                    await self._require_outcome(
                        "aegis.time_out",
                        self._input(value, "time-out"),
                        "recorded",
                    )
                    return TemporalWorkflowResult(
                        run_id=value.run_id,
                        status=RunStatus.TIMED_OUT,
                        failure_code="signal_timeout",
                    )
                cancelled = await self._cancel_if_requested(value)
                if cancelled is not None:
                    return cancelled
                command_ref = self._signals.pop(0)
                signal = await self._activity(
                    "aegis.authorize_signal",
                    self._input(
                        value,
                        "authorize-signal",
                        command_ref=command_ref,
                    ),
                )
                if signal.outcome not in {"authorized", "duplicate"}:
                    return TemporalWorkflowResult(
                        run_id=value.run_id,
                        status=RunStatus.FAILED,
                        failure_code="signal_denied",
                    )

            cancelled = await self._cancel_if_requested(value)
            if cancelled is not None:
                return cancelled
            self._stage = "completing"
            completed = await self._require_outcome(
                "aegis.complete",
                self._input(value, "complete"),
                "recorded",
            )
            self._stage = "completed"
            return TemporalWorkflowResult(
                run_id=value.run_id,
                status=RunStatus.COMPLETED,
                result_ref=completed.result_ref or graph.result_ref,
            )
        except ActivityError as exc:
            self._stage = "failed"
            if self._cancellation_requested:
                try:
                    cancelled = await self._cancel_if_requested(value)
                except ActivityError:
                    cancelled = None
                if cancelled is not None:
                    return cancelled
            failure_code = _activity_failure_code(exc)
            if not await self._record_failure(value, failure_code=failure_code):
                raise
            return TemporalWorkflowResult(
                run_id=value.run_id,
                status=RunStatus.FAILED,
                failure_code=failure_code,
            )
        except ApplicationError as exc:
            self._stage = "failed"
            failure_code = _application_failure_code(exc)
            if not await self._record_failure(value, failure_code=failure_code):
                raise
            return TemporalWorkflowResult(
                run_id=value.run_id,
                status=RunStatus.FAILED,
                failure_code=failure_code,
            )

    @workflow.signal(name="resume")
    def resume(self, value: TemporalSignal) -> None:
        if value.command_ref in self._seen_signals:
            return
        if len(self._seen_signals) >= 32:
            return
        self._seen_signals.add(value.command_ref)
        self._signals.append(value.command_ref)

    @workflow.signal(name="request_cancel")
    def request_cancel(self, value: TemporalSignal) -> None:
        if value.command_ref in self._seen_signals or self._cancellation_requested:
            return
        self._seen_signals.add(value.command_ref)
        self._cancellation_requested = True
        self._cancel_command_ref = value.command_ref

    @workflow.query(name="operational_state")
    def operational_state(self) -> OperationalWorkflowState:
        return OperationalWorkflowState(
            stage=self._stage,
            accepted_signal_count=len(self._seen_signals),
            cancellation_requested=self._cancellation_requested,
        )

    async def _require_outcome(
        self,
        activity_name: str,
        value: TemporalActivityInput,
        expected: str,
    ) -> ActivityOutcome:
        result = await self._activity(activity_name, value)
        if result.outcome != expected:
            raise ApplicationError(
                "activity returned an invalid outcome",
                type="IntegrityFailure",
                non_retryable=True,
            )
        return result

    async def _cancel_if_requested(
        self, value: TemporalWorkflowInput
    ) -> TemporalWorkflowResult | None:
        if not self._cancellation_requested:
            return None
        if self._cancel_command_ref is None:
            raise ApplicationError(
                "cancellation command reference is missing",
                type="IntegrityFailure",
                non_retryable=True,
            )
        self._stage = "cancelling"
        await self._require_outcome(
            "aegis.cancel",
            self._input(
                value,
                "cancel",
                command_ref=self._cancel_command_ref,
            ),
            "recorded",
        )
        self._stage = "cancelled"
        return TemporalWorkflowResult(
            run_id=value.run_id,
            status=RunStatus.CANCELLED,
        )

    @staticmethod
    async def _activity(
        activity_name: str,
        value: TemporalActivityInput,
    ) -> ActivityOutcome:
        result = await workflow.execute_activity(
            activity_name,
            value,
            result_type=ActivityOutcome,
            start_to_close_timeout=_ACTIVITY_TIMEOUT,
            schedule_to_close_timeout=timedelta(minutes=15),
            heartbeat_timeout=_HEARTBEAT_TIMEOUT,
            retry_policy=_ACTIVITY_RETRY,
        )
        return ActivityOutcome.model_validate(result)

    @staticmethod
    def _input(
        value: TemporalWorkflowInput,
        operation: str,
        *,
        command_ref: str | None = None,
        failure_code: str | None = None,
    ) -> TemporalActivityInput:
        return TemporalActivityInput(
            tenant_ref=value.tenant_ref,
            actor_ref=value.actor_ref,
            request_ref=value.request_ref,
            run_id=value.run_id,
            operation_id=f"{operation}:{value.run_id}",
            command_ref=command_ref,
            failure_code=failure_code,
        )

    @staticmethod
    async def _record_failure(
        value: TemporalWorkflowInput, *, failure_code: str
    ) -> bool:
        try:
            result = await workflow.execute_activity(
                "aegis.fail",
                AegisInvestigationWorkflow._input(
                    value,
                    "fail",
                    failure_code=failure_code,
                ),
                result_type=ActivityOutcome,
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RetryPolicy(maximum_attempts=1),
            )
            outcome = ActivityOutcome.model_validate(result)
            return outcome.outcome in {"recorded", "duplicate"}
        except ActivityError:
            # The application remains non-terminal for explicit operator reconciliation.
            return False


class TemporalActivities:
    """Contain adapter failures so a poison job cannot terminate the worker process."""

    def __init__(self, operations: ActivityOperations) -> None:
        self._operations = operations

    @activity.defn(name="aegis.authorize")
    async def authorize(self, value: TemporalActivityInput) -> ActivityOutcome:
        return await self._invoke("authorize", self._operations.authorize, value)

    @activity.defn(name="aegis.collect_evidence")
    async def collect_evidence(self, value: TemporalActivityInput) -> ActivityOutcome:
        return await self._invoke(
            "collect_evidence", self._operations.collect_evidence, value
        )

    @activity.defn(name="aegis.run_graph")
    async def run_graph(self, value: TemporalActivityInput) -> ActivityOutcome:
        return await self._invoke("run_graph", self._operations.run_graph, value)

    @activity.defn(name="aegis.record_wait")
    async def record_wait(self, value: TemporalActivityInput) -> ActivityOutcome:
        return await self._invoke("record_wait", self._operations.record_wait, value)

    @activity.defn(name="aegis.authorize_signal")
    async def authorize_signal(self, value: TemporalActivityInput) -> ActivityOutcome:
        return await self._invoke(
            "authorize_signal", self._operations.authorize_signal, value
        )

    @activity.defn(name="aegis.complete")
    async def complete(self, value: TemporalActivityInput) -> ActivityOutcome:
        return await self._invoke("complete", self._operations.complete, value)

    @activity.defn(name="aegis.cancel")
    async def cancel(self, value: TemporalActivityInput) -> ActivityOutcome:
        return await self._invoke("cancel", self._operations.cancel, value)

    @activity.defn(name="aegis.fail")
    async def fail(self, value: TemporalActivityInput) -> ActivityOutcome:
        return await self._invoke("fail", self._operations.fail, value)

    @activity.defn(name="aegis.time_out")
    async def time_out(self, value: TemporalActivityInput) -> ActivityOutcome:
        return await self._invoke("time_out", self._operations.time_out, value)

    @staticmethod
    async def _invoke(
        operation: str,
        callback: Callable[[TemporalActivityInput], Awaitable[ActivityOutcome]],
        value: TemporalActivityInput,
    ) -> ActivityOutcome:
        activity.heartbeat(f"{operation}:started")
        heartbeat_task = asyncio.create_task(TemporalActivities._heartbeat(operation))
        try:
            result = await callback(value)
        except PolicyDenied as exc:
            raise ApplicationError(
                "activity authorization denied",
                type="AuthorizationDenied",
                non_retryable=True,
            ) from exc
        except PayloadRejected as exc:
            raise ApplicationError(
                "activity payload rejected",
                type="PayloadRejected",
                non_retryable=True,
            ) from exc
        except IdempotencyConflict as exc:
            raise ApplicationError(
                "activity idempotency conflict",
                type="IdempotencyConflict",
                non_retryable=True,
            ) from exc
        except IntegrityFailure as exc:
            raise ApplicationError(
                "application integrity check failed",
                type="IntegrityFailure",
                non_retryable=True,
            ) from exc
        except AegisFrameworkError as exc:
            raise ApplicationError(
                "transient application activity failure",
                type=type(exc).__name__,
            ) from exc
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise ApplicationError(
                "activity adapter defect",
                type="FrameworkDefect",
                non_retryable=True,
            ) from exc
        finally:
            heartbeat_task.cancel()
            with suppress(asyncio.CancelledError):
                await heartbeat_task
        activity.heartbeat(f"{operation}:completed")
        return result

    @staticmethod
    async def _heartbeat(operation: str) -> None:
        while True:
            await asyncio.sleep(10)
            activity.heartbeat(f"{operation}:running")

    def registered(self) -> tuple[Callable[..., Awaitable[ActivityOutcome]], ...]:
        return (
            self.authorize,
            self.collect_evidence,
            self.run_graph,
            self.record_wait,
            self.authorize_signal,
            self.complete,
            self.cancel,
            self.fail,
            self.time_out,
        )


class TemporalClientAdapter:
    """Provider adapter; the application ledger remains the read/API authority."""

    def __init__(
        self,
        *,
        client: Client,
        task_queue: str = "aegis-investigations-v1",
    ) -> None:
        self._client = client
        self._task_queue = task_queue

    async def start(self, value: TemporalWorkflowInput) -> None:
        await self._client.start_workflow(
            AegisInvestigationWorkflow.run,
            value,
            id=value.workflow_id,
            task_queue=self._task_queue,
            execution_timeout=timedelta(days=2),
            run_timeout=timedelta(days=1),
            task_timeout=timedelta(seconds=10),
            id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
            id_conflict_policy=WorkflowIDConflictPolicy.USE_EXISTING,
            static_summary="Aegis bounded investigation lifecycle",
        )

    async def resume(self, *, workflow_id: str, command_ref: str) -> None:
        await self._client.get_workflow_handle(workflow_id).signal(
            AegisInvestigationWorkflow.resume,
            TemporalSignal(command_ref=command_ref),
        )

    async def request_cancel(self, *, workflow_id: str, command_ref: str) -> None:
        await self._client.get_workflow_handle(workflow_id).signal(
            AegisInvestigationWorkflow.request_cancel,
            TemporalSignal(command_ref=command_ref),
        )

    async def cancel(self, *, workflow_id: str) -> None:
        await self._client.get_workflow_handle(workflow_id).cancel()


class TemporalOutboxDispatcher:
    """Race-safe application outbox consumer for Temporal client commands."""

    def __init__(
        self,
        *,
        store: OutboxPort,
        temporal: TemporalClientAdapter,
    ) -> None:
        self._store = store
        self._temporal = temporal

    async def dispatch(
        self,
        *,
        tenant_id: str,
        worker_ref: str,
        now: datetime,
        limit: int = 20,
    ) -> int:
        if now.tzinfo is None:
            raise ValueError("dispatcher requires an aware datetime")
        claims = self._store.claim_outbox(
            tenant_id=tenant_id,
            worker_ref=worker_ref,
            now=now,
            claim_until=now + timedelta(seconds=30),
            limit=limit,
        )
        delivered = 0
        for claim in claims:
            try:
                await self._deliver(claim)
            except (
                KeyError,
                PayloadRejected,
                TypeError,
                ValidationError,
                ValueError,
            ):
                self._store.fail_outbox(
                    claim,
                    now=now,
                    error_code="poison_payload",
                    retry_at=now,
                    permanent=True,
                )
            except WorkflowAlreadyStartedError:
                self._store.complete_outbox(claim, now=now)
                delivered += 1
            except RPCError:
                self._store.fail_outbox(
                    claim,
                    now=now,
                    error_code="temporal_rpc_error",
                    retry_at=now + timedelta(seconds=min(30, 2**claim.attempt)),
                    permanent=False,
                )
            else:
                self._store.complete_outbox(claim, now=now)
                delivered += 1
        return delivered

    async def _deliver(self, claim: DeliveryClaim) -> None:
        payload = claim.payload

        def _str(key: str) -> str:
            val = payload.get(key)
            if not isinstance(val, str):
                raise PayloadRejected(f"outbox payload field '{key}' must be a string")
            return val

        def _bool(key: str) -> bool:
            val = payload.get(key)
            if not isinstance(val, bool):
                raise PayloadRejected(f"outbox payload field '{key}' must be a boolean")
            return val

        if claim.message_type == "investigation.start":
            await self._temporal.start(
                TemporalWorkflowInput(
                    tenant_ref=_str("tenant_ref"),
                    actor_ref=_str("actor_ref"),
                    request_ref=_str("request_ref"),
                    run_id=_str("run_id"),
                    workflow_id=_str("workflow_id"),
                    wait_for_signal=_bool("wait_for_signal"),
                )
            )
            return
        if claim.message_type == "investigation.resume_requested":
            await self._temporal.resume(
                workflow_id=_str("workflow_id"),
                command_ref=_str("command_ref"),
            )
            return
        if claim.message_type == "investigation.cancel_requested":
            await self._temporal.request_cancel(
                workflow_id=_str("workflow_id"),
                command_ref=_str("command_ref"),
            )
            return
        raise PayloadRejected("outbox message type is not supported")


class TemporalWorkerRuntime:
    """Run a Temporal worker and drain trusted tenant outbox partitions."""

    def __init__(
        self,
        *,
        worker: Worker,
        dispatcher: TemporalOutboxDispatcher,
        tenant_ids: tuple[Identifier, ...],
        poll_interval: timedelta = timedelta(seconds=1),
    ) -> None:
        if not tenant_ids or len(set(tenant_ids)) != len(tenant_ids):
            raise ValueError("worker tenant partitions must be non-empty and unique")
        if poll_interval <= timedelta(0) or poll_interval > timedelta(minutes=1):
            raise ValueError("worker poll interval is outside the permitted bound")
        self._worker = worker
        self._dispatcher = dispatcher
        self._tenant_ids = tuple(sorted(tenant_ids))
        self._poll_interval = poll_interval

    async def run_once(self, *, worker_ref: str, now: datetime) -> int:
        delivered = 0
        for tenant_id in self._tenant_ids:
            delivered += await self._dispatcher.dispatch(
                tenant_id=tenant_id,
                worker_ref=worker_ref,
                now=now,
            )
        return delivered

    async def run(
        self,
        *,
        worker_ref: str,
        stop: asyncio.Event,
    ) -> None:
        async with self._worker:
            while not stop.is_set():
                await self.run_once(
                    worker_ref=worker_ref,
                    now=datetime.now(UTC),
                )
                try:
                    await asyncio.wait_for(
                        stop.wait(),
                        timeout=self._poll_interval.total_seconds(),
                    )
                except TimeoutError:
                    continue


async def connect_temporal(
    *,
    target_host: str,
    namespace: str = "default",
    tracing: bool = False,
) -> Client:
    interceptors = [TracingInterceptor()] if tracing else []
    return await Client.connect(
        target_host,
        namespace=namespace,
        data_converter=temporal_data_converter(),
        interceptors=interceptors,
        payload_limits=PayloadLimitsConfig(
            payloads_warn_size=_MAX_PAYLOAD_BYTES,
            memo_warn_size=2_048,
        ),
    )


def build_temporal_worker(
    *,
    client: Client,
    operations: ActivityOperations,
    task_queue: str = "aegis-investigations-v1",
) -> Worker:
    activities = TemporalActivities(operations)
    return Worker(
        client,
        task_queue=task_queue,
        workflows=[AegisInvestigationWorkflow],
        activities=list(activities.registered()),
        max_concurrent_workflow_tasks=50,
        max_concurrent_activities=20,
    )


def _activity_failure_code(error: ActivityError) -> str:
    cause = error.cause
    if isinstance(cause, ApplicationError) and cause.type:
        normalized = "".join(
            character.lower() if character.isalnum() else "_"
            for character in cause.type
        ).strip("_")
        return normalized[:128] or "activity_failure"
    return "activity_failure"


def _application_failure_code(error: ApplicationError) -> str:
    if error.type:
        normalized = "".join(
            character.lower() if character.isalnum() else "_"
            for character in error.type
        ).strip("_")
        return normalized[:128] or "workflow_failure"
    return "workflow_failure"
