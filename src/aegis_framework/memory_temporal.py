"""Temporal mechanics for fenced memory ingestion, compaction, purge, and rebuild."""

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
    ConcurrencyConflict,
    IdempotencyConflict,
    IntegrityFailure,
    PayloadRejected,
    PolicyDenied,
)

_RETRY_POLICY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=30),
    maximum_attempts=3,
    non_retryable_error_types=[
        "AuthorizationDenied",
        "ConcurrencyConflict",
        "IdempotencyConflict",
        "IntegrityFailure",
        "PayloadRejected",
        "PolicyDenied",
        "MemoryRejected",
        "FrameworkDefect",
    ],
)


class MemoryWorkflowInput(StrictModel):
    """Only opaque references, fencing, and bounds enter Temporal history."""

    tenant_ref: OpaqueReference
    actor_ref: Identifier
    request_ref: Identifier
    memory_id: Identifier
    workflow_id: Identifier
    fence_token: Identifier
    operation: Literal["ingest", "compact", "purge", "rebuild"]
    maximum_chunks: int = Field(default=256, ge=1, le=1_000)
    maximum_tokens: int = Field(default=65_536, ge=16, le=1_000_000)
    activity_timeout_seconds: int = Field(default=300, ge=10, le=3_600)


class MemoryActivityInput(StrictModel):
    tenant_ref: OpaqueReference
    actor_ref: Identifier
    request_ref: Identifier
    memory_id: Identifier
    operation_id: Identifier
    fence_token: Identifier
    maximum_chunks: int = Field(ge=1, le=1_000)
    maximum_tokens: int = Field(ge=16, le=1_000_000)


class MemoryActivityOutcome(StrictModel):
    outcome: Literal[
        "recorded",
        "authorized",
        "scanned",
        "chunked",
        "embedded",
        "indexed",
        "compacted",
        "purged",
        "rebuilt",
        "rejected",
        "quarantined",
        "duplicate",
        "ambiguous",
    ]
    result_ref: Identifier | None = None
    result_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class MemoryWorkflowResult(StrictModel):
    memory_id: Identifier
    status: Literal[
        "active",
        "compacted",
        "purged",
        "rebuilt",
        "rejected",
        "quarantined",
        "escalated",
    ]
    result_ref: Identifier | None = None
    failure_code: Identifier | None = None


class MemoryActivityOperations(Protocol):
    async def record_candidate(
        self, value: MemoryActivityInput
    ) -> MemoryActivityOutcome: ...

    async def authorize(self, value: MemoryActivityInput) -> MemoryActivityOutcome: ...

    async def scan(self, value: MemoryActivityInput) -> MemoryActivityOutcome: ...

    async def chunk(self, value: MemoryActivityInput) -> MemoryActivityOutcome: ...

    async def embed(self, value: MemoryActivityInput) -> MemoryActivityOutcome: ...

    async def index(self, value: MemoryActivityInput) -> MemoryActivityOutcome: ...

    async def compact(self, value: MemoryActivityInput) -> MemoryActivityOutcome: ...

    async def purge(self, value: MemoryActivityInput) -> MemoryActivityOutcome: ...

    async def rebuild(self, value: MemoryActivityInput) -> MemoryActivityOutcome: ...


@workflow.defn(name="aegis.memory.v1")
class AegisMemoryWorkflow:
    """Durable scheduler; Activities reload application truth and current policy."""

    @workflow.run
    async def run(self, value: MemoryWorkflowInput) -> MemoryWorkflowResult:
        workflow.patched("aegis-memory-lifecycle-v1")
        try:
            await self._require(
                "aegis.memory.record_candidate",
                self._input(value, "record-candidate"),
                {"recorded", "duplicate"},
                value.activity_timeout_seconds,
            )
            authorized = await self._activity(
                "aegis.memory.authorize",
                self._input(value, "authorize"),
                value.activity_timeout_seconds,
            )
            if authorized.outcome in {"rejected", "quarantined"}:
                return MemoryWorkflowResult(
                    memory_id=value.memory_id,
                    status=authorized.outcome,
                    result_ref=authorized.result_ref,
                    failure_code=f"memory_{authorized.outcome}",
                )
            if authorized.outcome not in {"authorized", "duplicate"}:
                return self._failed(value, "authorization_failed")
            if value.operation == "ingest":
                return await self._ingest(value)
            if value.operation == "compact":
                result = await self._require(
                    "aegis.memory.compact",
                    self._input(value, "compact"),
                    {"compacted", "duplicate"},
                    value.activity_timeout_seconds,
                )
                return MemoryWorkflowResult(
                    memory_id=value.memory_id,
                    status="compacted",
                    result_ref=result.result_ref,
                )
            if value.operation == "purge":
                result = await self._require(
                    "aegis.memory.purge",
                    self._input(value, "purge"),
                    {"purged", "duplicate"},
                    value.activity_timeout_seconds,
                )
                return MemoryWorkflowResult(
                    memory_id=value.memory_id,
                    status="purged",
                    result_ref=result.result_ref,
                )
            result = await self._require(
                "aegis.memory.rebuild",
                self._input(value, "rebuild"),
                {"rebuilt", "duplicate"},
                value.activity_timeout_seconds,
            )
            return MemoryWorkflowResult(
                memory_id=value.memory_id,
                status="rebuilt",
                result_ref=result.result_ref,
            )
        except ActivityError as exc:
            return self._failed(value, _failure_code(exc))
        except ApplicationError as exc:
            return self._failed(value, str(exc.type or "memory_application_failure"))

    async def _ingest(self, value: MemoryWorkflowInput) -> MemoryWorkflowResult:
        for name, suffix, allowed in (
            ("aegis.memory.scan", "scan", {"scanned", "duplicate"}),
            ("aegis.memory.chunk", "chunk", {"chunked", "duplicate"}),
            ("aegis.memory.embed", "embed", {"embedded", "duplicate"}),
            ("aegis.memory.index", "index", {"indexed", "duplicate"}),
        ):
            result = await self._activity(
                name,
                self._input(value, suffix),
                value.activity_timeout_seconds,
            )
            if result.outcome in {"rejected", "quarantined", "ambiguous"}:
                return self._failed(value, f"{suffix}_{result.outcome}")
            if result.outcome not in allowed:
                return self._failed(value, f"{suffix}_failed")
        return MemoryWorkflowResult(memory_id=value.memory_id, status="active")

    async def _require(
        self,
        name: str,
        value: MemoryActivityInput,
        allowed: set[str],
        timeout_seconds: int,
    ) -> MemoryActivityOutcome:
        result = await self._activity(name, value, timeout_seconds)
        if result.outcome not in allowed:
            raise ApplicationError(
                "memory Activity returned an invalid outcome",
                type="IntegrityFailure",
                non_retryable=True,
            )
        return result

    @staticmethod
    async def _activity(
        name: str,
        value: MemoryActivityInput,
        timeout_seconds: int,
    ) -> MemoryActivityOutcome:
        return cast(
            MemoryActivityOutcome,
            await workflow.execute_activity(
                name,
                value,
                result_type=MemoryActivityOutcome,
                start_to_close_timeout=timedelta(seconds=timeout_seconds),
                heartbeat_timeout=timedelta(seconds=30),
                retry_policy=_RETRY_POLICY,
            ),
        )

    @staticmethod
    def _input(value: MemoryWorkflowInput, suffix: str) -> MemoryActivityInput:
        from aegis_framework.domain import stable_id

        return MemoryActivityInput(
            tenant_ref=value.tenant_ref,
            actor_ref=value.actor_ref,
            request_ref=value.request_ref,
            memory_id=value.memory_id,
            operation_id=stable_id(
                "memory-operation",
                value.memory_id,
                value.fence_token,
                suffix,
                length=32,
            ),
            fence_token=value.fence_token,
            maximum_chunks=value.maximum_chunks,
            maximum_tokens=value.maximum_tokens,
        )

    @staticmethod
    def _failed(
        value: MemoryWorkflowInput,
        code: str,
    ) -> MemoryWorkflowResult:
        safe = "".join(character if character.isalnum() else "_" for character in code)
        return MemoryWorkflowResult(
            memory_id=value.memory_id,
            status="escalated",
            failure_code=safe[:128] or "memory_failed",
        )


def _failure_code(exc: ActivityError) -> str:
    cause = exc.cause
    if isinstance(cause, ApplicationError) and cause.type:
        return str(cause.type)
    return "memory_activity_failure"


class TemporalMemoryActivities:
    """Named Temporal adapters around application-owned memory operations."""

    def __init__(self, operations: MemoryActivityOperations) -> None:
        self._operations = operations

    def registered(
        self,
    ) -> tuple[
        Callable[[MemoryActivityInput], Awaitable[MemoryActivityOutcome]],
        ...,
    ]:
        return (
            self.record_candidate,
            self.authorize,
            self.scan,
            self.chunk,
            self.embed,
            self.index,
            self.compact,
            self.purge,
            self.rebuild,
        )

    @activity.defn(name="aegis.memory.record_candidate")
    async def record_candidate(
        self, value: MemoryActivityInput
    ) -> MemoryActivityOutcome:
        return await self._invoke(self._operations.record_candidate, value)

    @activity.defn(name="aegis.memory.authorize")
    async def authorize(self, value: MemoryActivityInput) -> MemoryActivityOutcome:
        return await self._invoke(self._operations.authorize, value)

    @activity.defn(name="aegis.memory.scan")
    async def scan(self, value: MemoryActivityInput) -> MemoryActivityOutcome:
        return await self._invoke(self._operations.scan, value)

    @activity.defn(name="aegis.memory.chunk")
    async def chunk(self, value: MemoryActivityInput) -> MemoryActivityOutcome:
        return await self._invoke(self._operations.chunk, value)

    @activity.defn(name="aegis.memory.embed")
    async def embed(self, value: MemoryActivityInput) -> MemoryActivityOutcome:
        return await self._invoke(self._operations.embed, value)

    @activity.defn(name="aegis.memory.index")
    async def index(self, value: MemoryActivityInput) -> MemoryActivityOutcome:
        return await self._invoke(self._operations.index, value)

    @activity.defn(name="aegis.memory.compact")
    async def compact(self, value: MemoryActivityInput) -> MemoryActivityOutcome:
        return await self._invoke(self._operations.compact, value)

    @activity.defn(name="aegis.memory.purge")
    async def purge(self, value: MemoryActivityInput) -> MemoryActivityOutcome:
        return await self._invoke(self._operations.purge, value)

    @activity.defn(name="aegis.memory.rebuild")
    async def rebuild(self, value: MemoryActivityInput) -> MemoryActivityOutcome:
        return await self._invoke(self._operations.rebuild, value)

    @staticmethod
    async def _invoke(
        operation: Callable[
            [MemoryActivityInput],
            Awaitable[MemoryActivityOutcome],
        ],
        value: MemoryActivityInput,
    ) -> MemoryActivityOutcome:
        activity.heartbeat({"operation_id": value.operation_id})
        heartbeat = asyncio.create_task(
            TemporalMemoryActivities._heartbeat(value.operation_id)
        )
        try:
            return await operation(value)
        except AegisFrameworkError as exc:
            raise ApplicationError(
                str(exc),
                type=type(exc).__name__,
                non_retryable=isinstance(
                    exc,
                    (
                        ConcurrencyConflict,
                        IdempotencyConflict,
                        IntegrityFailure,
                        PayloadRejected,
                        PolicyDenied,
                    ),
                ),
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
