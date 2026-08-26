"""Temporal durable approval and controlled-effect lifecycle."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from contextlib import suppress
from datetime import timedelta
from typing import Literal, Protocol

from pydantic import Field
from temporalio import activity, workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError, ApplicationError

from aegis_framework.domain import Identifier, OpaqueReference, StrictModel, stable_id
from aegis_framework.errors import (
    AegisFrameworkError,
    ApprovalDenied,
    ApprovalExpired,
    ApprovalRevoked,
    EffectAmbiguous,
    EffectConflict,
    IdempotencyConflict,
    IntegrityFailure,
    PayloadRejected,
    PolicyDenied,
    VerificationFailed,
)

_RETRY_POLICY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=30),
    maximum_attempts=3,
    non_retryable_error_types=[
        "ApprovalDenied",
        "ApprovalExpired",
        "ApprovalRevoked",
        "AuthorizationDenied",
        "EffectConflict",
        "IdempotencyConflict",
        "IntegrityFailure",
        "PayloadRejected",
        "VerificationFailed",
        "FrameworkDefect",
    ],
)


class RemediationWorkflowInput(StrictModel):
    """Only opaque references and bounds enter Temporal history."""

    tenant_ref: OpaqueReference
    actor_ref: Identifier
    request_ref: Identifier
    run_id: Identifier
    plan_ref: Identifier
    action_ref: Identifier
    workflow_id: Identifier
    approval_timeout_seconds: int = Field(default=7_200, ge=60, le=604_800)
    reconciliation_timeout_seconds: int = Field(default=900, ge=30, le=86_400)


class RemediationActivityInput(StrictModel):
    tenant_ref: OpaqueReference
    actor_ref: Identifier
    request_ref: Identifier
    run_id: Identifier
    plan_ref: Identifier
    action_ref: Identifier
    operation_id: Identifier
    command_ref: Identifier | None = None


class RemediationSignal(StrictModel):
    command_ref: Identifier


class RemediationActivityOutcome(StrictModel):
    outcome: Literal[
        "recorded",
        "pending",
        "granted",
        "denied",
        "expired",
        "revoked",
        "preflight_succeeded",
        "effect_succeeded",
        "effect_failed",
        "effect_ambiguous",
        "reconciled",
        "verified",
        "verification_failed",
        "rolled_back",
        "escalated",
        "cancelled",
        "duplicate",
    ]
    result_ref: Identifier | None = None


class RemediationWorkflowResult(StrictModel):
    run_id: Identifier
    plan_ref: Identifier
    status: Literal[
        "denied",
        "expired",
        "revoked",
        "cancelled",
        "verified",
        "rolled_back",
        "escalated",
        "failed",
    ]
    result_ref: Identifier | None = None
    failure_code: Identifier | None = None


class RemediationOperationalState(StrictModel):
    """Non-authoritative workflow query for operations only."""

    stage: Identifier
    approval_signal_count: int
    reconciliation_signal_count: int
    cancellation_requested: bool


class RemediationActivityOperations(Protocol):
    async def request_approval(
        self, value: RemediationActivityInput
    ) -> RemediationActivityOutcome: ...

    async def load_approval_decision(
        self, value: RemediationActivityInput
    ) -> RemediationActivityOutcome: ...

    async def preflight(
        self, value: RemediationActivityInput
    ) -> RemediationActivityOutcome: ...

    async def execute(
        self, value: RemediationActivityInput
    ) -> RemediationActivityOutcome: ...

    async def reconcile(
        self, value: RemediationActivityInput
    ) -> RemediationActivityOutcome: ...

    async def verify(
        self, value: RemediationActivityInput
    ) -> RemediationActivityOutcome: ...

    async def rollback(
        self, value: RemediationActivityInput
    ) -> RemediationActivityOutcome: ...

    async def cancel(
        self, value: RemediationActivityInput
    ) -> RemediationActivityOutcome: ...

    async def expire(
        self, value: RemediationActivityInput
    ) -> RemediationActivityOutcome: ...

    async def escalate(
        self, value: RemediationActivityInput
    ) -> RemediationActivityOutcome: ...


@workflow.defn(name="aegis.remediation.v1")
class AegisRemediationWorkflow:
    """Durable mechanics only; every authoritative transition is an Activity."""

    def __init__(self) -> None:
        self._stage = "created"
        self._approval_commands: list[str] = []
        self._reconciliation_commands: list[str] = []
        self._seen_commands: set[str] = set()
        self._cancel_command: str | None = None

    @workflow.run
    async def run(
        self,
        value: RemediationWorkflowInput,
    ) -> RemediationWorkflowResult:
        workflow.patched("aegis-remediation-lifecycle-v1")
        try:
            self._stage = "requesting_approval"
            await self._require(
                "aegis.remediation.request_approval",
                self._input(value, "request-approval"),
                {"recorded", "pending", "duplicate"},
            )
            approval_deadline = workflow.time() + value.approval_timeout_seconds
            while True:
                expired = await self._wait_for_approval(value, approval_deadline)
                if expired is not None:
                    return expired
                cancelled = await self._cancel_if_requested(value)
                if cancelled is not None:
                    return cancelled

                command = self._approval_commands.pop(0)
                self._stage = "loading_approval"
                decision = await self._activity(
                    "aegis.remediation.load_approval_decision",
                    self._input(
                        value,
                        "load-approval",
                        command_ref=command,
                    ),
                )
                if decision.outcome in {"denied", "expired", "revoked"}:
                    return RemediationWorkflowResult(
                        run_id=value.run_id,
                        plan_ref=value.plan_ref,
                        status=decision.outcome,
                    )
                if decision.outcome == "granted":
                    break
                if decision.outcome not in {"pending", "duplicate"}:
                    raise ApplicationError(
                        "approval Activity returned an invalid outcome",
                        type="IntegrityFailure",
                        non_retryable=True,
                    )
                cancelled = await self._cancel_if_requested(value)
                if cancelled is not None:
                    return cancelled

            self._stage = "preflight"
            await self._require(
                "aegis.remediation.preflight",
                self._input(value, "preflight"),
                {"preflight_succeeded", "duplicate"},
            )
            cancelled = await self._cancel_if_requested(value)
            if cancelled is not None:
                return cancelled

            self._stage = "executing"
            effect = await self._activity(
                "aegis.remediation.execute",
                self._input(value, "execute"),
            )
            if effect.outcome == "effect_ambiguous":
                self._stage = "waiting_for_reconciliation"
                try:
                    await workflow.wait_condition(
                        lambda: (
                            bool(self._reconciliation_commands)
                            or self._cancel_command is not None
                        ),
                        timeout=timedelta(seconds=value.reconciliation_timeout_seconds),
                        timeout_summary="ambiguous effect reconciliation wait",
                    )
                except TimeoutError:
                    return await self._escalate(
                        value,
                        failure_code="reconciliation_timeout",
                    )
                cancelled = await self._cancel_if_requested(value)
                if cancelled is not None:
                    return cancelled
                reconcile_command = self._reconciliation_commands.pop(0)
                self._stage = "reconciling"
                effect = await self._activity(
                    "aegis.remediation.reconcile",
                    self._input(
                        value,
                        "reconcile",
                        command_ref=reconcile_command,
                    ),
                )
                if effect.outcome != "reconciled":
                    return await self._escalate(
                        value,
                        failure_code="reconciliation_inconclusive",
                    )
            elif effect.outcome not in {"effect_succeeded", "duplicate"}:
                return await self._escalate(
                    value,
                    failure_code="effect_failed",
                )
            # Do NOT check for cancellation here: the effect has already been applied
            # (succeeded or reconciled). Returning cancelled would leave an applied
            # production change unverified. Continue to mandatory verification.

            self._stage = "verifying"
            verification = await self._activity(
                "aegis.remediation.verify",
                self._input(value, "verify"),
            )
            if verification.outcome == "verified":
                self._stage = "verified"
                return RemediationWorkflowResult(
                    run_id=value.run_id,
                    plan_ref=value.plan_ref,
                    status="verified",
                    result_ref=verification.result_ref or effect.result_ref,
                )
            if verification.outcome != "verification_failed":
                raise ApplicationError(
                    "verification Activity returned an invalid outcome",
                    type="IntegrityFailure",
                    non_retryable=True,
                )
            self._stage = "rolling_back"
            rollback = await self._activity(
                "aegis.remediation.rollback",
                self._input(value, "rollback"),
            )
            if rollback.outcome == "rolled_back":
                self._stage = "rolled_back"
                return RemediationWorkflowResult(
                    run_id=value.run_id,
                    plan_ref=value.plan_ref,
                    status="rolled_back",
                    result_ref=rollback.result_ref,
                    failure_code="verification_failed",
                )
            return await self._escalate(value, failure_code="rollback_failed")
        except ActivityError as exc:
            if self._cancel_command is not None:
                try:
                    cancelled = await self._cancel_if_requested(value)
                except ActivityError:
                    cancelled = None
                if cancelled is not None:
                    return cancelled
            return RemediationWorkflowResult(
                run_id=value.run_id,
                plan_ref=value.plan_ref,
                status="failed",
                failure_code=_activity_failure_code(exc),
            )
        except ApplicationError as exc:
            return RemediationWorkflowResult(
                run_id=value.run_id,
                plan_ref=value.plan_ref,
                status="failed",
                failure_code=_application_failure_code(exc),
            )

    @workflow.signal(name="approval_decision")
    def approval_decision(self, value: RemediationSignal) -> None:
        if value.command_ref in self._seen_commands or len(self._seen_commands) >= 32:
            return
        self._seen_commands.add(value.command_ref)
        self._approval_commands.append(value.command_ref)

    @workflow.signal(name="reconcile_effect")
    def reconcile_effect(self, value: RemediationSignal) -> None:
        if value.command_ref in self._seen_commands or len(self._seen_commands) >= 32:
            return
        self._seen_commands.add(value.command_ref)
        self._reconciliation_commands.append(value.command_ref)

    @workflow.signal(name="request_cancel")
    def request_cancel(self, value: RemediationSignal) -> None:
        if value.command_ref in self._seen_commands or self._cancel_command is not None:
            return
        self._seen_commands.add(value.command_ref)
        self._cancel_command = value.command_ref

    @workflow.query(name="operational_state")
    def operational_state(self) -> RemediationOperationalState:
        return RemediationOperationalState(
            stage=self._stage,
            approval_signal_count=len(self._approval_commands),
            reconciliation_signal_count=len(self._reconciliation_commands),
            cancellation_requested=self._cancel_command is not None,
        )

    async def _cancel_if_requested(
        self,
        value: RemediationWorkflowInput,
    ) -> RemediationWorkflowResult | None:
        if self._cancel_command is None:
            return None
        self._stage = "cancelling"
        await self._require(
            "aegis.remediation.cancel",
            self._input(
                value,
                "cancel",
                command_ref=self._cancel_command,
            ),
            {"cancelled", "duplicate"},
        )
        self._stage = "cancelled"
        return RemediationWorkflowResult(
            run_id=value.run_id,
            plan_ref=value.plan_ref,
            status="cancelled",
        )

    async def _wait_for_approval(
        self,
        value: RemediationWorkflowInput,
        deadline: float,
    ) -> RemediationWorkflowResult | None:
        self._stage = "waiting_for_approval"
        remaining = deadline - workflow.time()
        if remaining <= 0:
            return await self._expire_approval(value)
        try:
            await workflow.wait_condition(
                lambda: (
                    bool(self._approval_commands) or self._cancel_command is not None
                ),
                timeout=timedelta(seconds=remaining),
                timeout_summary="exact-scope human approval wait",
            )
        except TimeoutError:
            return await self._expire_approval(value)
        return None

    async def _expire_approval(
        self,
        value: RemediationWorkflowInput,
    ) -> RemediationWorkflowResult:
        self._stage = "expiring"
        await self._require(
            "aegis.remediation.expire",
            self._input(value, "expire"),
            {"expired", "duplicate"},
        )
        return RemediationWorkflowResult(
            run_id=value.run_id,
            plan_ref=value.plan_ref,
            status="expired",
        )

    async def _escalate(
        self,
        value: RemediationWorkflowInput,
        *,
        failure_code: str,
    ) -> RemediationWorkflowResult:
        self._stage = "escalating"
        escalated = await self._require(
            "aegis.remediation.escalate",
            self._input(value, f"escalate-{failure_code}"),
            {"escalated", "duplicate"},
        )
        self._stage = "escalated"
        return RemediationWorkflowResult(
            run_id=value.run_id,
            plan_ref=value.plan_ref,
            status="escalated",
            result_ref=escalated.result_ref,
            failure_code=failure_code,
        )

    @staticmethod
    async def _require(
        activity_name: str,
        value: RemediationActivityInput,
        expected: set[str],
    ) -> RemediationActivityOutcome:
        outcome = await AegisRemediationWorkflow._activity(activity_name, value)
        if outcome.outcome not in expected:
            raise ApplicationError(
                "remediation Activity returned an invalid outcome",
                type="IntegrityFailure",
                non_retryable=True,
            )
        return outcome

    @staticmethod
    async def _activity(
        activity_name: str,
        value: RemediationActivityInput,
    ) -> RemediationActivityOutcome:
        result = await workflow.execute_activity(
            activity_name,
            value,
            result_type=RemediationActivityOutcome,
            start_to_close_timeout=timedelta(minutes=5),
            schedule_to_close_timeout=timedelta(minutes=15),
            heartbeat_timeout=timedelta(seconds=30),
            retry_policy=_RETRY_POLICY,
        )
        return RemediationActivityOutcome.model_validate(result)

    @staticmethod
    def _input(
        value: RemediationWorkflowInput,
        operation: str,
        *,
        command_ref: str | None = None,
    ) -> RemediationActivityInput:
        operation_id = stable_id(
            "operation",
            operation,
            value.run_id,
            value.plan_ref,
            command_ref or "",
            length=48,
        )
        return RemediationActivityInput(
            tenant_ref=value.tenant_ref,
            actor_ref=value.actor_ref,
            request_ref=value.request_ref,
            run_id=value.run_id,
            plan_ref=value.plan_ref,
            action_ref=value.action_ref,
            operation_id=operation_id,
            command_ref=command_ref,
        )


class TemporalRemediationActivities:
    """Map typed failures without allowing adapter defects to crash the worker."""

    def __init__(self, operations: RemediationActivityOperations) -> None:
        self._operations = operations

    @activity.defn(name="aegis.remediation.request_approval")
    async def request_approval(
        self,
        value: RemediationActivityInput,
    ) -> RemediationActivityOutcome:
        return await self._invoke(
            "request_approval",
            self._operations.request_approval,
            value,
        )

    @activity.defn(name="aegis.remediation.load_approval_decision")
    async def load_approval_decision(
        self,
        value: RemediationActivityInput,
    ) -> RemediationActivityOutcome:
        return await self._invoke(
            "load_approval_decision",
            self._operations.load_approval_decision,
            value,
        )

    @activity.defn(name="aegis.remediation.preflight")
    async def preflight(
        self,
        value: RemediationActivityInput,
    ) -> RemediationActivityOutcome:
        return await self._invoke("preflight", self._operations.preflight, value)

    @activity.defn(name="aegis.remediation.execute")
    async def execute(
        self,
        value: RemediationActivityInput,
    ) -> RemediationActivityOutcome:
        return await self._invoke("execute", self._operations.execute, value)

    @activity.defn(name="aegis.remediation.reconcile")
    async def reconcile(
        self,
        value: RemediationActivityInput,
    ) -> RemediationActivityOutcome:
        return await self._invoke("reconcile", self._operations.reconcile, value)

    @activity.defn(name="aegis.remediation.verify")
    async def verify(
        self,
        value: RemediationActivityInput,
    ) -> RemediationActivityOutcome:
        return await self._invoke("verify", self._operations.verify, value)

    @activity.defn(name="aegis.remediation.rollback")
    async def rollback(
        self,
        value: RemediationActivityInput,
    ) -> RemediationActivityOutcome:
        return await self._invoke("rollback", self._operations.rollback, value)

    @activity.defn(name="aegis.remediation.cancel")
    async def cancel(
        self,
        value: RemediationActivityInput,
    ) -> RemediationActivityOutcome:
        return await self._invoke("cancel", self._operations.cancel, value)

    @activity.defn(name="aegis.remediation.expire")
    async def expire(
        self,
        value: RemediationActivityInput,
    ) -> RemediationActivityOutcome:
        return await self._invoke("expire", self._operations.expire, value)

    @activity.defn(name="aegis.remediation.escalate")
    async def escalate(
        self,
        value: RemediationActivityInput,
    ) -> RemediationActivityOutcome:
        return await self._invoke("escalate", self._operations.escalate, value)

    @staticmethod
    async def _invoke(
        name: str,
        callback: Callable[
            [RemediationActivityInput],
            Awaitable[RemediationActivityOutcome],
        ],
        value: RemediationActivityInput,
    ) -> RemediationActivityOutcome:
        activity.heartbeat(f"{name}:started")
        heartbeat = asyncio.create_task(TemporalRemediationActivities._heartbeat(name))
        try:
            result = await callback(value)
            activity.heartbeat(f"{name}:completed")
            return result
        except PolicyDenied as exc:
            raise ApplicationError(
                "current authorization denied",
                type="AuthorizationDenied",
                non_retryable=True,
            ) from exc
        except ApprovalDenied as exc:
            raise _non_retryable("ApprovalDenied", exc) from exc
        except ApprovalExpired as exc:
            raise _non_retryable("ApprovalExpired", exc) from exc
        except ApprovalRevoked as exc:
            raise _non_retryable("ApprovalRevoked", exc) from exc
        except EffectConflict as exc:
            raise _non_retryable("EffectConflict", exc) from exc
        except VerificationFailed as exc:
            raise _non_retryable("VerificationFailed", exc) from exc
        except PayloadRejected as exc:
            raise _non_retryable("PayloadRejected", exc) from exc
        except IdempotencyConflict as exc:
            raise _non_retryable("IdempotencyConflict", exc) from exc
        except IntegrityFailure as exc:
            raise _non_retryable("IntegrityFailure", exc) from exc
        except EffectAmbiguous:
            return RemediationActivityOutcome(outcome="effect_ambiguous")
        except asyncio.CancelledError:
            raise
        except AegisFrameworkError as exc:
            raise ApplicationError(
                "transient remediation Activity failure",
                type=type(exc).__name__,
            ) from exc
        except Exception as exc:
            raise ApplicationError(
                "remediation Activity adapter defect",
                type="FrameworkDefect",
                non_retryable=True,
            ) from exc
        finally:
            heartbeat.cancel()
            with suppress(asyncio.CancelledError):
                await heartbeat

    def registered(
        self,
    ) -> tuple[
        Callable[
            [RemediationActivityInput],
            Awaitable[RemediationActivityOutcome],
        ],
        ...,
    ]:
        return (
            self.request_approval,
            self.load_approval_decision,
            self.preflight,
            self.execute,
            self.reconcile,
            self.verify,
            self.rollback,
            self.cancel,
            self.expire,
            self.escalate,
        )

    @staticmethod
    async def _heartbeat(name: str) -> None:
        while True:
            await asyncio.sleep(10)
            activity.heartbeat(f"{name}:running")


def _non_retryable(error_type: str, exc: Exception) -> ApplicationError:
    return ApplicationError(
        "remediation Activity rejected",
        type=error_type,
        non_retryable=True,
    )


def _activity_failure_code(exc: ActivityError) -> str:
    cause = exc.cause
    if isinstance(cause, ApplicationError) and cause.type:
        return _safe_code(cause.type)
    return "activity_failure"


def _application_failure_code(exc: ApplicationError) -> str:
    return _safe_code(exc.type or "workflow_failure")


def _safe_code(value: str) -> str:
    normalized = "".join(
        character.lower() if character.isalnum() else "_" for character in value
    ).strip("_")
    return normalized[:64] or "unknown_failure"
