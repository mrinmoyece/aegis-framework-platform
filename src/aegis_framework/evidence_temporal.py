"""Temporal ownership for durable evidence query pagination using opaque references."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from contextlib import suppress
from datetime import timedelta
from typing import Literal, Protocol

from temporalio import activity, workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError, ApplicationError

from aegis_framework.domain import Identifier, OpaqueReference, StrictModel
from aegis_framework.errors import (
    AegisFrameworkError,
    IdempotencyConflict,
    IntegrityFailure,
    PayloadRejected,
    PolicyDenied,
    ReconciliationRequired,
)
from aegis_framework.evidence import QueryStatus

_EVIDENCE_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=30),
    maximum_attempts=3,
    non_retryable_error_types=[
        "AuthorizationDenied",
        "IdempotencyConflict",
        "IntegrityFailure",
        "PayloadRejected",
        "ReconciliationRequired",
        "FrameworkDefect",
    ],
)


class EvidenceWorkflowInput(StrictModel):
    """No query, cursor, URL, credential, or evidence enters workflow history."""

    tenant_ref: OpaqueReference
    actor_ref: Identifier
    request_ref: Identifier
    run_id: Identifier
    query_ref: Identifier
    workflow_id: Identifier
    maximum_pages: int


class EvidenceActivityInput(StrictModel):
    tenant_ref: OpaqueReference
    actor_ref: Identifier
    request_ref: Identifier
    run_id: Identifier
    query_ref: Identifier
    operation_id: Identifier
    page_number: int
    command_ref: Identifier | None = None


class EvidenceActivityOutcome(StrictModel):
    outcome: Literal[
        "authorized",
        "page_complete",
        "query_complete",
        "cancelled",
        "denied",
    ]
    has_next_page: bool = False
    cursor_ref: Identifier | None = None
    bundle_ref: Identifier | None = None


class EvidenceWorkflowResult(StrictModel):
    query_ref: Identifier
    status: QueryStatus
    bundle_ref: Identifier | None = None
    failure_code: Identifier | None = None


class EvidenceActivityOperations(Protocol):
    async def authorize(
        self, value: EvidenceActivityInput
    ) -> EvidenceActivityOutcome: ...

    async def fetch_page(
        self, value: EvidenceActivityInput
    ) -> EvidenceActivityOutcome: ...

    async def complete(
        self, value: EvidenceActivityInput
    ) -> EvidenceActivityOutcome: ...

    async def cancel(self, value: EvidenceActivityInput) -> EvidenceActivityOutcome: ...

    async def reconcile(
        self, value: EvidenceActivityInput
    ) -> EvidenceActivityOutcome: ...


@workflow.defn(name="aegis.evidence-query.v1")
class AegisEvidenceQueryWorkflow:
    def __init__(self) -> None:
        self._cancel_requested = False
        self._cancel_ref: str | None = None
        self._stage = "created"

    @workflow.run
    async def run(self, value: EvidenceWorkflowInput) -> EvidenceWorkflowResult:
        workflow.patched("aegis-evidence-query-v1")
        if value.maximum_pages < 1 or value.maximum_pages > 100:
            raise ApplicationError(
                "evidence page bound is invalid",
                type="PayloadRejected",
                non_retryable=True,
            )
        try:
            self._stage = "authorizing"
            authorized = await self._activity(
                "aegis.evidence.authorize",
                self._input(value, operation="authorize", page_number=0),
            )
            if authorized.outcome != "authorized":
                return EvidenceWorkflowResult(
                    query_ref=value.query_ref,
                    status=QueryStatus.FAILED,
                    failure_code="authorization_denied",
                )
            for page_number in range(1, value.maximum_pages + 1):
                cancelled = await self._cancel_if_requested(value, page_number)
                if cancelled is not None:
                    return cancelled
                self._stage = "fetching_page"
                page = await self._activity(
                    "aegis.evidence.fetch-page",
                    self._input(
                        value,
                        operation=f"page-{page_number}",
                        page_number=page_number,
                    ),
                )
                if page.outcome != "page_complete":
                    raise ApplicationError(
                        "evidence page returned an invalid outcome",
                        type="IntegrityFailure",
                        non_retryable=True,
                    )
                if not page.has_next_page:
                    break
                if page.cursor_ref is None:
                    raise ApplicationError(
                        "evidence page omitted cursor reference",
                        type="IntegrityFailure",
                        non_retryable=True,
                    )
            else:
                raise ApplicationError(
                    "evidence page bound exhausted",
                    type="PayloadRejected",
                    non_retryable=True,
                )
            cancelled = await self._cancel_if_requested(value, value.maximum_pages)
            if cancelled is not None:
                return cancelled
            self._stage = "completing"
            completed = await self._activity(
                "aegis.evidence.complete",
                self._input(value, operation="complete", page_number=0),
            )
            if completed.outcome != "query_complete" or completed.bundle_ref is None:
                raise ApplicationError(
                    "evidence completion omitted bundle reference",
                    type="IntegrityFailure",
                    non_retryable=True,
                )
            self._stage = "completed"
            return EvidenceWorkflowResult(
                query_ref=value.query_ref,
                status=QueryStatus.COMPLETED,
                bundle_ref=completed.bundle_ref,
            )
        except ActivityError:
            self._stage = "reconciling"
            with suppress(ActivityError):
                await self._activity(
                    "aegis.evidence.reconcile",
                    self._input(value, operation="reconcile", page_number=0),
                    attempts=1,
                )
            return EvidenceWorkflowResult(
                query_ref=value.query_ref,
                status=QueryStatus.RECONCILIATION_REQUIRED,
                failure_code="activity_outcome_ambiguous",
            )

    @workflow.signal(name="request_cancel")
    def request_cancel(self, command_ref: str) -> None:
        if self._cancel_requested or not command_ref or len(command_ref) > 128:
            return
        self._cancel_requested = True
        self._cancel_ref = command_ref

    async def _cancel_if_requested(
        self,
        value: EvidenceWorkflowInput,
        page_number: int,
    ) -> EvidenceWorkflowResult | None:
        if not self._cancel_requested:
            return None
        if self._cancel_ref is None:
            raise ApplicationError(
                "evidence cancellation reference is missing",
                type="IntegrityFailure",
                non_retryable=True,
            )
        self._stage = "cancelling"
        outcome = await self._activity(
            "aegis.evidence.cancel",
            self._input(
                value,
                operation="cancel",
                page_number=page_number,
                command_ref=self._cancel_ref,
            ),
        )
        if outcome.outcome != "cancelled":
            raise ApplicationError(
                "evidence cancellation was not durably recorded",
                type="IntegrityFailure",
                non_retryable=True,
            )
        self._stage = "cancelled"
        return EvidenceWorkflowResult(
            query_ref=value.query_ref,
            status=QueryStatus.CANCELLED,
        )

    @staticmethod
    def _input(
        value: EvidenceWorkflowInput,
        *,
        operation: str,
        page_number: int,
        command_ref: str | None = None,
    ) -> EvidenceActivityInput:
        return EvidenceActivityInput(
            tenant_ref=value.tenant_ref,
            actor_ref=value.actor_ref,
            request_ref=value.request_ref,
            run_id=value.run_id,
            query_ref=value.query_ref,
            operation_id=f"evidence-{operation}:{value.query_ref}",
            page_number=page_number,
            command_ref=command_ref,
        )

    @staticmethod
    async def _activity(
        name: str,
        value: EvidenceActivityInput,
        *,
        attempts: int = 3,
    ) -> EvidenceActivityOutcome:
        retry = (
            _EVIDENCE_RETRY if attempts == 3 else RetryPolicy(maximum_attempts=attempts)
        )
        result = await workflow.execute_activity(
            name,
            value,
            result_type=EvidenceActivityOutcome,
            start_to_close_timeout=timedelta(minutes=5),
            schedule_to_close_timeout=timedelta(minutes=15),
            heartbeat_timeout=timedelta(seconds=30),
            retry_policy=retry,
        )
        return EvidenceActivityOutcome.model_validate(result)


class TemporalEvidenceActivities:
    def __init__(self, operations: EvidenceActivityOperations) -> None:
        self._operations = operations

    @activity.defn(name="aegis.evidence.authorize")
    async def authorize(self, value: EvidenceActivityInput) -> EvidenceActivityOutcome:
        return await self._invoke("authorize", self._operations.authorize, value)

    @activity.defn(name="aegis.evidence.fetch-page")
    async def fetch_page(self, value: EvidenceActivityInput) -> EvidenceActivityOutcome:
        return await self._invoke("fetch_page", self._operations.fetch_page, value)

    @activity.defn(name="aegis.evidence.complete")
    async def complete(self, value: EvidenceActivityInput) -> EvidenceActivityOutcome:
        return await self._invoke("complete", self._operations.complete, value)

    @activity.defn(name="aegis.evidence.cancel")
    async def cancel(self, value: EvidenceActivityInput) -> EvidenceActivityOutcome:
        return await self._invoke("cancel", self._operations.cancel, value)

    @activity.defn(name="aegis.evidence.reconcile")
    async def reconcile(self, value: EvidenceActivityInput) -> EvidenceActivityOutcome:
        return await self._invoke("reconcile", self._operations.reconcile, value)

    @staticmethod
    async def _invoke(
        operation: str,
        callback: Callable[
            [EvidenceActivityInput],
            Awaitable[EvidenceActivityOutcome],
        ],
        value: EvidenceActivityInput,
    ) -> EvidenceActivityOutcome:
        activity.heartbeat(f"{operation}:started")
        heartbeat = asyncio.create_task(
            TemporalEvidenceActivities._heartbeat(operation)
        )
        try:
            return await callback(value)
        except PolicyDenied as exc:
            raise ApplicationError(
                "evidence activity authorization denied",
                type="AuthorizationDenied",
                non_retryable=True,
            ) from exc
        except IdempotencyConflict as exc:
            raise ApplicationError(
                "evidence activity idempotency conflict",
                type="IdempotencyConflict",
                non_retryable=True,
            ) from exc
        except IntegrityFailure as exc:
            raise ApplicationError(
                "evidence activity integrity failure",
                type="IntegrityFailure",
                non_retryable=True,
            ) from exc
        except PayloadRejected as exc:
            raise ApplicationError(
                "evidence activity payload rejected",
                type="PayloadRejected",
                non_retryable=True,
            ) from exc
        except ReconciliationRequired as exc:
            raise ApplicationError(
                "evidence activity requires reconciliation",
                type="ReconciliationRequired",
                non_retryable=True,
            ) from exc
        except asyncio.CancelledError:
            raise
        except AegisFrameworkError as exc:
            raise ApplicationError(
                "transient evidence activity failure",
                type=type(exc).__name__,
            ) from exc
        except Exception as exc:
            raise ApplicationError(
                "evidence activity adapter defect",
                type="FrameworkDefect",
                non_retryable=True,
            ) from exc
        finally:
            heartbeat.cancel()
            with suppress(asyncio.CancelledError):
                await heartbeat

    @staticmethod
    async def _heartbeat(operation: str) -> None:
        while True:
            await asyncio.sleep(10)
            activity.heartbeat(f"{operation}:running")

    def registered(
        self,
    ) -> tuple[Callable[..., Awaitable[EvidenceActivityOutcome]], ...]:
        return (
            self.authorize,
            self.fetch_page,
            self.complete,
            self.cancel,
            self.reconcile,
        )
