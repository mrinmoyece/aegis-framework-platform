"""Temporal protocol scheduling with application-owned authoritative facts."""

from __future__ import annotations

from datetime import timedelta
from enum import StrEnum
from typing import Literal, Protocol

from pydantic import Field
from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError, ApplicationError

from aegis_framework.domain import Identifier, OpaqueReference, StrictModel
from aegis_framework.interoperability import ProtocolKind, TaskState

_INTEROP_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=20),
    maximum_attempts=3,
    non_retryable_error_types=[
        "AuthenticationDenied",
        "AuthorizationDenied",
        "IdempotencyConflict",
        "PayloadRejected",
        "IntegrityFailure",
        "TrustRevoked",
        # Ambiguous transport outcomes require human reconciliation — retrying would
        # compound the ambiguity and produce duplicate side effects.
        "PolicyDenied",
        "ReconciliationRequired",
    ],
)
_ACTIVITY_TIMEOUT = timedelta(minutes=3)
_HEARTBEAT_TIMEOUT = timedelta(seconds=30)


class InteropOperation(StrEnum):
    MCP_INVOKE = "mcp-invoke"
    A2A_TASK = "a2a-task"


class InteropWorkflowInput(StrictModel):
    """Only opaque references and digests enter Temporal history."""

    tenant_ref: OpaqueReference
    principal_ref: Identifier
    operation_id: Identifier
    peer_id: Identifier
    protocol: ProtocolKind
    operation: InteropOperation
    request_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    trust_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    policy_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    idempotency_key_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    fence_token: Identifier


class InteropActivityInput(StrictModel):
    tenant_ref: OpaqueReference
    principal_ref: Identifier
    operation_id: Identifier
    peer_id: Identifier
    request_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    operation_ref: Identifier
    fence_token: Identifier
    command_ref: Identifier | None = None


class InteropActivityOutcome(StrictModel):
    outcome: Literal[
        "authorized",
        "reserved",
        "intent-recorded",
        "completed",
        "failed",
        "ambiguous",
        "reconciled",
        "cancelled",
        "quarantined",
    ]
    result_ref: OpaqueReference | None = None
    result_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    cursor_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    error_code: Identifier | None = None


class InteropWorkflowResult(StrictModel):
    operation_id: Identifier
    state: TaskState
    result_ref: OpaqueReference | None = None
    result_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    error_code: Identifier | None = None


class InteropActivityOperations(Protocol):
    async def authorize(
        self, value: InteropActivityInput
    ) -> InteropActivityOutcome: ...

    async def reserve_quota(
        self, value: InteropActivityInput
    ) -> InteropActivityOutcome: ...

    async def persist_intent(
        self, value: InteropActivityInput
    ) -> InteropActivityOutcome: ...

    async def invoke_mcp(
        self, value: InteropActivityInput
    ) -> InteropActivityOutcome: ...

    async def send_a2a_task(
        self, value: InteropActivityInput
    ) -> InteropActivityOutcome: ...

    async def reconcile(
        self, value: InteropActivityInput
    ) -> InteropActivityOutcome: ...

    async def persist_result(
        self, value: InteropActivityInput
    ) -> InteropActivityOutcome: ...

    async def cancel(self, value: InteropActivityInput) -> InteropActivityOutcome: ...

    async def quarantine(
        self, value: InteropActivityInput
    ) -> InteropActivityOutcome: ...


class _InteropWorkflow:
    def __init__(self) -> None:
        self._cancellation_requested = False
        self._cancel_command_ref: str | None = None
        self._stage = "created"

    async def execute(
        self,
        value: InteropWorkflowInput,
    ) -> InteropWorkflowResult:
        workflow.patched("aegis-interoperability-lifecycle-v1")
        try:
            cancelled = await self._cancel_if_requested(value)
            if cancelled is not None:
                return cancelled
            self._stage = "authorizing"
            await self._require(
                "aegis.interop.authorize",
                self._input(value, "authorize"),
                "authorized",
            )
            self._stage = "reserving"
            await self._require(
                "aegis.interop.reserve_quota",
                self._input(value, "reserve-quota"),
                "reserved",
            )
            self._stage = "recording_intent"
            await self._require(
                "aegis.interop.persist_intent",
                self._input(value, "persist-intent"),
                "intent-recorded",
            )
            cancelled = await self._cancel_if_requested(value)
            if cancelled is not None:
                return cancelled
            self._stage = "network"
            outcome = await self._activity(
                (
                    "aegis.interop.invoke_mcp"
                    if value.operation is InteropOperation.MCP_INVOKE
                    else "aegis.interop.send_a2a_task"
                ),
                self._input(value, "network"),
            )
            cancelled = await self._cancel_if_requested(value)
            if cancelled is not None:
                return cancelled
            if outcome.outcome == "ambiguous":
                self._stage = "reconciling"
                outcome = await self._activity(
                    "aegis.interop.reconcile",
                    self._input(value, "reconcile"),
                )
                if outcome.outcome != "reconciled":
                    return InteropWorkflowResult(
                        operation_id=value.operation_id,
                        state=TaskState.RECONCILIATION_REQUIRED,
                        error_code=outcome.error_code or "reconciliation-inconclusive",
                    )
            if outcome.outcome == "quarantined":
                await self._activity(
                    "aegis.interop.quarantine",
                    self._input(value, "quarantine"),
                )
                return InteropWorkflowResult(
                    operation_id=value.operation_id,
                    state=TaskState.QUARANTINED,
                    error_code=outcome.error_code or "peer-result-quarantined",
                )
            if outcome.outcome not in {"completed", "reconciled"}:
                return InteropWorkflowResult(
                    operation_id=value.operation_id,
                    state=TaskState.FAILED,
                    error_code=outcome.error_code or "peer-operation-failed",
                )
            self._stage = "recording_result"
            persisted = await self._require(
                "aegis.interop.persist_result",
                self._input(value, "persist-result"),
                "completed",
            )
            self._stage = "completed"
            return InteropWorkflowResult(
                operation_id=value.operation_id,
                state=TaskState.COMPLETED,
                result_ref=persisted.result_ref or outcome.result_ref,
                result_digest=persisted.result_digest or outcome.result_digest,
            )
        except ActivityError as exc:
            cause = exc.cause
            code = (
                cause.type
                if isinstance(cause, ApplicationError) and cause.type
                else "interop-activity-failed"
            )
            return InteropWorkflowResult(
                operation_id=value.operation_id,
                state=TaskState.FAILED,
                error_code=code,
            )

    @workflow.signal(name="cancel")
    async def cancel(self, command_ref: Identifier) -> None:
        if not self._cancellation_requested:
            self._cancellation_requested = True
            self._cancel_command_ref = command_ref

    @workflow.query(name="state")
    def state(self) -> dict[str, str | bool | None]:
        return {
            "stage": self._stage,
            "cancellation_requested": self._cancellation_requested,
            "cancel_command_ref": self._cancel_command_ref,
        }

    async def _cancel_if_requested(
        self,
        value: InteropWorkflowInput,
    ) -> InteropWorkflowResult | None:
        if not self._cancellation_requested:
            return None
        self._stage = "cancelling"
        await self._require(
            "aegis.interop.cancel",
            self._input(
                value,
                "cancel",
                command_ref=self._cancel_command_ref,
            ),
            "cancelled",
        )
        self._stage = "cancelled"
        return InteropWorkflowResult(
            operation_id=value.operation_id,
            state=TaskState.CANCELLED,
        )

    def _input(
        self,
        value: InteropWorkflowInput,
        operation: str,
        *,
        command_ref: str | None = None,
    ) -> InteropActivityInput:
        return InteropActivityInput(
            tenant_ref=value.tenant_ref,
            principal_ref=value.principal_ref,
            operation_id=value.operation_id,
            peer_id=value.peer_id,
            request_digest=value.request_digest,
            operation_ref=f"{value.operation_id}-{operation}",
            fence_token=value.fence_token,
            command_ref=command_ref,
        )

    async def _require(
        self,
        name: str,
        value: InteropActivityInput,
        expected: str,
    ) -> InteropActivityOutcome:
        result = await self._activity(name, value)
        if result.outcome != expected:
            raise ApplicationError(
                f"interoperability activity returned {result.outcome}",
                type="IntegrityFailure",
                non_retryable=True,
            )
        return result

    async def _activity(
        self,
        name: str,
        value: InteropActivityInput,
    ) -> InteropActivityOutcome:
        return InteropActivityOutcome.model_validate(
            await workflow.execute_activity(
                name,
                value,
                result_type=InteropActivityOutcome,
                start_to_close_timeout=_ACTIVITY_TIMEOUT,
                heartbeat_timeout=_HEARTBEAT_TIMEOUT,
                retry_policy=_INTEROP_RETRY,
            )
        )


@workflow.defn(name="aegis.mcp.invocation.v1")
class AegisMcpInvocationWorkflow(_InteropWorkflow):
    @workflow.run
    async def run(self, value: InteropWorkflowInput) -> InteropWorkflowResult:
        if (
            value.protocol is not ProtocolKind.MCP
            or value.operation is not InteropOperation.MCP_INVOKE
        ):
            raise ApplicationError(
                "MCP workflow input is invalid",
                type="PayloadRejected",
                non_retryable=True,
            )
        return await self.execute(value)


@workflow.defn(name="aegis.a2a.task.v1")
class AegisA2ATaskWorkflow(_InteropWorkflow):
    @workflow.run
    async def run(self, value: InteropWorkflowInput) -> InteropWorkflowResult:
        if (
            value.protocol is not ProtocolKind.A2A
            or value.operation is not InteropOperation.A2A_TASK
        ):
            raise ApplicationError(
                "A2A workflow input is invalid",
                type="PayloadRejected",
                non_retryable=True,
            )
        return await self.execute(value)
