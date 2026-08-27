"""Temporal mechanics for the application-authoritative sandbox lifecycle."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from contextlib import suppress
from datetime import timedelta
from typing import Literal, Protocol, cast

from pydantic import Field
from temporalio import activity, workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError, ApplicationError

from aegis_framework.domain import Identifier, OpaqueReference, StrictModel
from aegis_framework.errors import (
    AegisFrameworkError,
    ArtifactQuarantined,
    ConcurrencyConflict,
    IdempotencyConflict,
    IntegrityFailure,
    PayloadRejected,
    PolicyDenied,
    SandboxRejected,
)

_RETRY_POLICY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=30),
    maximum_attempts=3,
    non_retryable_error_types=[
        "ArtifactQuarantined",
        "AuthorizationDenied",
        "ConcurrencyConflict",
        "IdempotencyConflict",
        "IntegrityFailure",
        "PayloadRejected",
        "PolicyDenied",
        "SandboxRejected",
        "FrameworkDefect",
    ],
)


class SandboxWorkflowInput(StrictModel):
    """Only opaque references and bounds enter Temporal history."""

    tenant_ref: OpaqueReference
    actor_ref: Identifier
    request_ref: Identifier
    execution_id: Identifier
    workflow_id: Identifier
    attempt: int = Field(ge=1, le=16)
    execution_timeout_seconds: int = Field(ge=1, le=3_600)
    reconciliation_timeout_seconds: int = Field(default=900, ge=30, le=86_400)
    cleanup_timeout_seconds: int = Field(default=300, ge=10, le=900)


class SandboxActivityInput(StrictModel):
    tenant_ref: OpaqueReference
    actor_ref: Identifier
    request_ref: Identifier
    execution_id: Identifier
    operation_id: Identifier
    attempt: int = Field(ge=1, le=16)
    command_ref: Identifier | None = None


class SandboxSignal(StrictModel):
    command_ref: Identifier


class SandboxActivityOutcome(StrictModel):
    outcome: Literal[
        "recorded",
        "authorized",
        "claimed",
        "absent",
        "provisioned",
        "running",
        "succeeded",
        "failed",
        "timed_out",
        "oom_killed",
        "violation",
        "cancelled",
        "captured",
        "quarantined",
        "attested",
        "cleaned",
        "ambiguous",
        "reconciled",
        "orphan_redriven",
        "duplicate",
    ]
    result_ref: Identifier | None = None
    provider_ref: Identifier | None = None


class SandboxWorkflowResult(StrictModel):
    execution_id: Identifier
    status: Literal[
        "succeeded",
        "failed",
        "timed_out",
        "oom_killed",
        "violation",
        "cancelled",
        "quarantined",
        "escalated",
    ]
    result_ref: Identifier | None = None
    failure_code: Identifier | None = None


class SandboxOperationalState(StrictModel):
    """Non-authoritative workflow state for operations only."""

    stage: Identifier
    cancellation_requested: bool
    reconciliation_signal_count: int
    orphan_redrive_signal_count: int


class SandboxActivityOperations(Protocol):
    async def record_request(
        self, value: SandboxActivityInput
    ) -> SandboxActivityOutcome: ...

    async def authorize_and_claim(
        self, value: SandboxActivityInput
    ) -> SandboxActivityOutcome: ...

    async def provision(
        self, value: SandboxActivityInput
    ) -> SandboxActivityOutcome: ...

    async def wait_for_completion(
        self, value: SandboxActivityInput
    ) -> SandboxActivityOutcome: ...

    async def capture_outputs(
        self, value: SandboxActivityInput
    ) -> SandboxActivityOutcome: ...

    async def attest(self, value: SandboxActivityInput) -> SandboxActivityOutcome: ...

    async def cleanup(self, value: SandboxActivityInput) -> SandboxActivityOutcome: ...

    async def cancel(self, value: SandboxActivityInput) -> SandboxActivityOutcome: ...

    async def reconcile(
        self, value: SandboxActivityInput
    ) -> SandboxActivityOutcome: ...

    async def redrive_orphan(
        self, value: SandboxActivityInput
    ) -> SandboxActivityOutcome: ...


@workflow.defn(name="aegis.sandbox.v1")
class AegisSandboxWorkflow:
    """Durable scheduling only; every authoritative transition is an Activity."""

    def __init__(self) -> None:
        self._stage = "created"
        self._cancel_command: str | None = None
        self._reconcile_commands: list[str] = []
        self._orphan_commands: list[str] = []
        self._seen_commands: set[str] = set()

    @workflow.run
    async def run(self, value: SandboxWorkflowInput) -> SandboxWorkflowResult:
        workflow.patched("aegis-sandbox-lifecycle-v1")
        terminal: SandboxWorkflowResult | None = None
        try:
            self._stage = "recording_request"
            await self._require(
                "aegis.sandbox.record_request",
                self._input(value, "record-request"),
                {"recorded", "duplicate"},
            )
            self._stage = "authorizing_and_claiming"
            await self._require(
                "aegis.sandbox.authorize_and_claim",
                self._input(value, "authorize-claim"),
                {"authorized", "claimed", "duplicate"},
            )
            cancelled = await self._cancel_if_requested(value)
            if cancelled is not None:
                terminal = cancelled
            if terminal is None:
                self._stage = "provisioning"
                provision = await self._activity(
                    "aegis.sandbox.provision",
                    self._input(value, "provision"),
                    start_to_close=timedelta(minutes=5),
                    heartbeat=timedelta(seconds=30),
                )
                if provision.outcome == "ambiguous":
                    provision = await self._reconcile_ambiguous(
                        value,
                        failure_code="ambiguous_create",
                    )
                if provision.outcome not in {"provisioned", "running", "duplicate"}:
                    terminal = self._failed(value, "provision_failed")
            cancelled = await self._cancel_if_requested(value)
            if cancelled is not None:
                terminal = cancelled
            if terminal is None:
                self._stage = "waiting"
                execution = await self._activity(
                    "aegis.sandbox.wait_for_completion",
                    self._input(value, "wait"),
                    start_to_close=timedelta(
                        seconds=value.execution_timeout_seconds + 60
                    ),
                    heartbeat=timedelta(seconds=30),
                )
                terminal = await self._handle_execution(value, execution)
            if terminal.status == "succeeded":
                self._stage = "capturing_outputs"
                capture = await self._activity(
                    "aegis.sandbox.capture_outputs",
                    self._input(value, "capture"),
                    start_to_close=timedelta(minutes=5),
                    heartbeat=timedelta(seconds=30),
                )
                if capture.outcome == "quarantined":
                    terminal = SandboxWorkflowResult(
                        execution_id=value.execution_id,
                        status="quarantined",
                        result_ref=capture.result_ref,
                        failure_code="artifact_quarantined",
                    )
                elif capture.outcome not in {"captured", "duplicate"}:
                    terminal = self._failed(value, "capture_failed")
                else:
                    self._stage = "attesting"
                    attestation = await self._activity(
                        "aegis.sandbox.attest",
                        self._input(value, "attest"),
                    )
                    if attestation.outcome not in {"attested", "duplicate"}:
                        terminal = self._failed(value, "attestation_failed")
                    else:
                        terminal = terminal.model_copy(
                            update={
                                "result_ref": (
                                    attestation.result_ref
                                    or capture.result_ref
                                    or terminal.result_ref
                                )
                            }
                        )
        except ActivityError as exc:
            terminal = self._failed(value, _activity_failure_code(exc))
        except ApplicationError as exc:
            terminal = self._failed(value, _application_failure_code(exc))
        finally:
            try:
                self._stage = "cleaning"
                cleanup = await self._activity(
                    "aegis.sandbox.cleanup",
                    self._input(value, "cleanup"),
                    start_to_close=timedelta(seconds=value.cleanup_timeout_seconds),
                    heartbeat=timedelta(seconds=30),
                )
                if cleanup.outcome == "ambiguous":
                    await self._reconcile_ambiguous(
                        value,
                        failure_code="ambiguous_delete",
                    )
                elif cleanup.outcome not in {"cleaned", "absent", "duplicate"}:
                    terminal = self._failed(value, "cleanup_failed")
            except (ActivityError, ApplicationError):
                terminal = self._failed(value, "cleanup_failed")
        self._stage = terminal.status
        return terminal

    @workflow.signal(name="request_cancel")
    def request_cancel(self, value: SandboxSignal) -> None:
        if value.command_ref in self._seen_commands or self._cancel_command is not None:
            return
        if len(self._seen_commands) >= 64:
            return
        self._seen_commands.add(value.command_ref)
        self._cancel_command = value.command_ref

    @workflow.signal(name="reconcile_sandbox")
    def reconcile_sandbox(self, value: SandboxSignal) -> None:
        if value.command_ref in self._seen_commands or len(self._seen_commands) >= 64:
            return
        self._seen_commands.add(value.command_ref)
        self._reconcile_commands.append(value.command_ref)

    @workflow.signal(name="redrive_orphan")
    def redrive_orphan(self, value: SandboxSignal) -> None:
        if value.command_ref in self._seen_commands or len(self._seen_commands) >= 64:
            return
        self._seen_commands.add(value.command_ref)
        self._orphan_commands.append(value.command_ref)

    @workflow.query(name="operational_state")
    def operational_state(self) -> SandboxOperationalState:
        return SandboxOperationalState(
            stage=self._stage,
            cancellation_requested=self._cancel_command is not None,
            reconciliation_signal_count=len(self._reconcile_commands),
            orphan_redrive_signal_count=len(self._orphan_commands),
        )

    async def _handle_execution(
        self,
        value: SandboxWorkflowInput,
        outcome: SandboxActivityOutcome,
    ) -> SandboxWorkflowResult:
        if outcome.outcome == "ambiguous":
            outcome = await self._reconcile_ambiguous(
                value,
                failure_code="ambiguous_execution",
            )
        if outcome.outcome in {
            "succeeded",
            "failed",
            "timed_out",
            "oom_killed",
            "violation",
            "cancelled",
            "quarantined",
        }:
            return SandboxWorkflowResult(
                execution_id=value.execution_id,
                status=outcome.outcome,
                result_ref=outcome.result_ref,
                failure_code=(
                    None
                    if outcome.outcome == "succeeded"
                    else f"sandbox_{outcome.outcome}"
                ),
            )
        return self._failed(value, "invalid_execution_outcome")

    async def _reconcile_ambiguous(
        self,
        value: SandboxWorkflowInput,
        *,
        failure_code: str,
    ) -> SandboxActivityOutcome:
        self._stage = "waiting_for_reconciliation"
        try:
            await workflow.wait_condition(
                lambda: (
                    bool(self._reconcile_commands)
                    or bool(self._orphan_commands)
                    or self._cancel_command is not None
                ),
                timeout=timedelta(seconds=value.reconciliation_timeout_seconds),
                timeout_summary="sandbox reconciliation wait",
            )
        except TimeoutError as exc:
            raise ApplicationError(
                failure_code,
                type="SandboxAmbiguous",
                non_retryable=True,
            ) from exc
        if self._cancel_command is not None:
            return await self._activity(
                "aegis.sandbox.cancel",
                self._input(
                    value,
                    "cancel",
                    command_ref=self._cancel_command,
                ),
            )
        if self._orphan_commands:
            command = self._orphan_commands.pop(0)
            return await self._activity(
                "aegis.sandbox.redrive_orphan",
                self._input(value, "orphan-redrive", command_ref=command),
            )
        command = self._reconcile_commands.pop(0)
        self._stage = "reconciling"
        return await self._activity(
            "aegis.sandbox.reconcile",
            self._input(value, "reconcile", command_ref=command),
        )

    async def _cancel_if_requested(
        self,
        value: SandboxWorkflowInput,
    ) -> SandboxWorkflowResult | None:
        if self._cancel_command is None:
            return None
        self._stage = "cancelling"
        outcome = await self._activity(
            "aegis.sandbox.cancel",
            self._input(
                value,
                "cancel",
                command_ref=self._cancel_command,
            ),
        )
        if outcome.outcome not in {"cancelled", "absent", "duplicate"}:
            return self._failed(value, "cancel_failed")
        return SandboxWorkflowResult(
            execution_id=value.execution_id,
            status="cancelled",
            result_ref=outcome.result_ref,
            failure_code="sandbox_cancelled",
        )

    async def _require(
        self,
        name: str,
        value: SandboxActivityInput,
        allowed: set[str],
    ) -> SandboxActivityOutcome:
        result = await self._activity(name, value)
        if result.outcome not in allowed:
            raise ApplicationError(
                "sandbox Activity returned an invalid outcome",
                type="IntegrityFailure",
                non_retryable=True,
            )
        return result

    async def _activity(
        self,
        name: str,
        value: SandboxActivityInput,
        *,
        start_to_close: timedelta = timedelta(minutes=2),
        heartbeat: timedelta | None = None,
    ) -> SandboxActivityOutcome:
        return cast(
            SandboxActivityOutcome,
            await workflow.execute_activity(
                name,
                value,
                result_type=SandboxActivityOutcome,
                start_to_close_timeout=start_to_close,
                heartbeat_timeout=heartbeat,
                retry_policy=_RETRY_POLICY,
            ),
        )

    @staticmethod
    def _input(
        value: SandboxWorkflowInput,
        operation: str,
        *,
        command_ref: str | None = None,
    ) -> SandboxActivityInput:
        return SandboxActivityInput(
            tenant_ref=value.tenant_ref,
            actor_ref=value.actor_ref,
            request_ref=value.request_ref,
            execution_id=value.execution_id,
            operation_id=f"{value.execution_id}-{operation}",
            attempt=value.attempt,
            command_ref=command_ref,
        )

    @staticmethod
    def _failed(value: SandboxWorkflowInput, code: str) -> SandboxWorkflowResult:
        return SandboxWorkflowResult(
            execution_id=value.execution_id,
            status="failed",
            failure_code=code[:128].replace(" ", "_"),
        )


class TemporalSandboxActivities:
    def __init__(self, operations: SandboxActivityOperations) -> None:
        self._operations = operations

    @activity.defn(name="aegis.sandbox.record_request")
    async def record_request(
        self,
        value: SandboxActivityInput,
    ) -> SandboxActivityOutcome:
        return await self._invoke(self._operations.record_request, value)

    @activity.defn(name="aegis.sandbox.authorize_and_claim")
    async def authorize_and_claim(
        self,
        value: SandboxActivityInput,
    ) -> SandboxActivityOutcome:
        return await self._invoke(self._operations.authorize_and_claim, value)

    @activity.defn(name="aegis.sandbox.provision")
    async def provision(self, value: SandboxActivityInput) -> SandboxActivityOutcome:
        return await self._invoke(self._operations.provision, value)

    @activity.defn(name="aegis.sandbox.wait_for_completion")
    async def wait_for_completion(
        self,
        value: SandboxActivityInput,
    ) -> SandboxActivityOutcome:
        return await self._invoke(self._operations.wait_for_completion, value)

    @activity.defn(name="aegis.sandbox.capture_outputs")
    async def capture_outputs(
        self,
        value: SandboxActivityInput,
    ) -> SandboxActivityOutcome:
        return await self._invoke(self._operations.capture_outputs, value)

    @activity.defn(name="aegis.sandbox.attest")
    async def attest(self, value: SandboxActivityInput) -> SandboxActivityOutcome:
        return await self._invoke(self._operations.attest, value)

    @activity.defn(name="aegis.sandbox.cleanup")
    async def cleanup(self, value: SandboxActivityInput) -> SandboxActivityOutcome:
        return await self._invoke(self._operations.cleanup, value)

    @activity.defn(name="aegis.sandbox.cancel")
    async def cancel(self, value: SandboxActivityInput) -> SandboxActivityOutcome:
        return await self._invoke(self._operations.cancel, value)

    @activity.defn(name="aegis.sandbox.reconcile")
    async def reconcile(self, value: SandboxActivityInput) -> SandboxActivityOutcome:
        return await self._invoke(self._operations.reconcile, value)

    @activity.defn(name="aegis.sandbox.redrive_orphan")
    async def redrive_orphan(
        self,
        value: SandboxActivityInput,
    ) -> SandboxActivityOutcome:
        return await self._invoke(self._operations.redrive_orphan, value)

    def registered(
        self,
    ) -> tuple[
        Callable[
            [SandboxActivityInput],
            Awaitable[SandboxActivityOutcome],
        ],
        ...,
    ]:
        return (
            self.record_request,
            self.authorize_and_claim,
            self.provision,
            self.wait_for_completion,
            self.capture_outputs,
            self.attest,
            self.cleanup,
            self.cancel,
            self.reconcile,
            self.redrive_orphan,
        )

    @staticmethod
    async def _invoke(
        operation: Callable[
            [SandboxActivityInput],
            Awaitable[SandboxActivityOutcome],
        ],
        value: SandboxActivityInput,
    ) -> SandboxActivityOutcome:
        activity.heartbeat({"operation_id": value.operation_id})
        heartbeat = asyncio.create_task(
            TemporalSandboxActivities._heartbeat(value.operation_id)
        )
        try:
            return await operation(value)
        except AegisFrameworkError as exc:
            error_type = type(exc).__name__
            raise ApplicationError(
                str(exc),
                type=error_type,
                non_retryable=isinstance(
                    exc,
                    (
                        ArtifactQuarantined,
                        ConcurrencyConflict,
                        IdempotencyConflict,
                        IntegrityFailure,
                        PayloadRejected,
                        PolicyDenied,
                        SandboxRejected,
                    ),
                ),
            ) from exc
        except Exception as exc:
            raise ApplicationError(
                "unexpected sandbox Activity failure",
                type="FrameworkDefect",
                non_retryable=True,
            ) from exc
        finally:
            heartbeat.cancel()
            with suppress(asyncio.CancelledError):
                await heartbeat

    @staticmethod
    async def _heartbeat(operation_id: str) -> None:
        while True:
            await asyncio.sleep(10)
            activity.heartbeat({"operation_id": operation_id})


def _activity_failure_code(exc: ActivityError) -> str:
    cause = exc.cause
    error_type = getattr(cause, "type", None)
    if isinstance(error_type, str) and error_type:
        return error_type[:128].replace(" ", "_")
    return "activity_failed"


def _application_failure_code(exc: ApplicationError) -> str:
    error_type = getattr(exc, "type", None)
    if isinstance(error_type, str) and error_type:
        return error_type[:128].replace(" ", "_")
    return "workflow_failed"
