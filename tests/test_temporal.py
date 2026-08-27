from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError
from temporalio.api.common.v1 import Payload
from temporalio.exceptions import ApplicationError, WorkflowAlreadyStartedError
from temporalio.testing import ActivityEnvironment
from temporalio.worker import WorkerDeploymentConfig

from aegis_framework.activity_runtime import CallbackActivityOperations
from aegis_framework.adapters import FixedClock
from aegis_framework.durability import (
    DeliveryStatus,
    EventDraft,
    InMemoryDurability,
    OutboxDraft,
)
from aegis_framework.errors import (
    EffectAmbiguous,
    EffectConflict,
    IntegrityFailure,
    PayloadRejected,
    PolicyDenied,
)
from aegis_framework.fixtures import DEMO_TIME
from aegis_framework.remediation_temporal import (
    RemediationActivityInput,
    RemediationActivityOutcome,
    RemediationSignal,
    RemediationWorkflowInput,
    TemporalRemediationActivities,
)
from aegis_framework.temporal import (
    ActivityOutcome,
    BoundedPayloadCodec,
    TemporalActivities,
    TemporalActivityInput,
    TemporalOutboxDispatcher,
    TemporalSignal,
    TemporalWorkflowInput,
    build_temporal_worker,
    connect_temporal,
    temporal_data_converter,
)


def _activity_input() -> TemporalActivityInput:
    return TemporalActivityInput(
        tenant_ref="tenant:opaque",
        actor_ref="actor:opaque",
        request_ref="request:opaque",
        run_id="run:opaque",
        operation_id="operation:opaque",
    )


def test_payload_codec_enforces_count_item_and_total_bounds() -> None:
    codec = BoundedPayloadCodec(1_024)

    async def execute() -> None:
        valid = Payload(metadata={"encoding": b"json/plain"}, data=b"{}")
        assert await codec.encode((valid,)) == [valid]
        assert await codec.decode((valid,)) == [valid]
        with pytest.raises(PayloadRejected, match="count"):
            await codec.encode(())
        with pytest.raises(PayloadRejected, match="per-item"):
            await codec.encode((Payload(data=b"x" * 1_025),))
        with pytest.raises(PayloadRejected, match="total"):
            await codec.encode(tuple(Payload(data=b"x" * 100) for _ in range(21)))

    asyncio.run(execute())
    with pytest.raises(ValueError, match="bound"):
        BoundedPayloadCodec(100)
    converter = temporal_data_converter(maximum_payload_bytes=2_048)
    assert isinstance(converter.payload_codec, BoundedPayloadCodec)


def test_production_temporal_connection_requires_paired_mtls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    async def connect(target_host: str, **kwargs: object) -> object:
        observed.update(target_host=target_host, **kwargs)
        return object()

    monkeypatch.setattr("aegis_framework.temporal.Client.connect", connect)
    client = asyncio.run(
        connect_temporal(
            target_host="private.example.invalid:7233",
            namespace="aegis-production",
            api_key="injected",
            tls_server_name="private.example.invalid",
            client_certificate=b"certificate",
            client_private_key=b"private-key",
            identity="aegis-worker-build-001",
            tracing=False,
        )
    )
    assert client is not None
    assert observed["namespace"] == "aegis-production"
    assert observed["api_key"] == "injected"
    assert observed["identity"] == "aegis-worker-build-001"
    assert observed["tls"] is not None
    with pytest.raises(ValueError, match="paired"):
        asyncio.run(
            connect_temporal(
                target_host="private.example.invalid:7233",
                tls_server_name="private.example.invalid",
                client_certificate=b"certificate",
            )
        )
    with pytest.raises(ValueError, match="verified server name"):
        asyncio.run(
            connect_temporal(
                target_host="private.example.invalid:7233",
                client_certificate=b"certificate",
                client_private_key=b"private-key",
            )
        )


def test_production_worker_uses_pinned_deployment_version_and_rate_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def worker(client: object, **kwargs: object) -> object:
        captured.update(client=client, **kwargs)
        return object()

    monkeypatch.setattr("aegis_framework.temporal.Worker", worker)
    built = build_temporal_worker(
        client=object(),  # type: ignore[arg-type]
        operations=CallbackActivityOperations({}),
        task_queue="aegis-production-investigation-v1",
        identity="worker:investigation:001",
        deployment_name="aegis-investigation",
        build_id="aegis-0.14.0-build-001",
        maximum_activities_per_second=50,
        maximum_task_queue_activities_per_second=100,
    )
    assert built is not None
    deployment = captured["deployment_config"]
    assert isinstance(deployment, WorkerDeploymentConfig)
    assert deployment.version.build_id == "aegis-0.14.0-build-001"
    assert captured["max_activities_per_second"] == 50
    with pytest.raises(ValueError, match="paired"):
        build_temporal_worker(
            client=object(),  # type: ignore[arg-type]
            operations=CallbackActivityOperations({}),
            deployment_name="aegis-investigation",
        )


def test_temporal_models_are_strict_bounded_and_opaque() -> None:
    value = TemporalWorkflowInput(
        tenant_ref="tenant:opaque",
        actor_ref="actor:opaque",
        request_ref="request:opaque",
        run_id="run:opaque",
        workflow_id="workflow:opaque",
    )
    rendered = value.model_dump_json()
    assert "tenant-acme" not in rendered
    with pytest.raises(ValidationError):
        TemporalSignal(command_ref="bad command")
    with pytest.raises(ValidationError):
        TemporalWorkflowInput.model_validate(
            {**value.model_dump(), "unexpected": "authority"}
        )


def test_activity_wrapper_heartbeats_and_returns_typed_outcome() -> None:
    operations = CallbackActivityOperations(
        {"authorize": ActivityOutcome(outcome="authorized")}
    )
    activities = TemporalActivities(operations)

    async def execute() -> tuple[ActivityOutcome, list[object]]:
        environment = ActivityEnvironment()
        heartbeats: list[object] = []
        environment.on_heartbeat = lambda *details: heartbeats.extend(details)
        result = await environment.run(
            activities.authorize,
            _activity_input(),
        )
        return result, heartbeats

    result, heartbeats = asyncio.run(execute())
    assert result.outcome == "authorized"
    assert heartbeats == ["authorize:started", "authorize:completed"]


class _DeniedOperations(CallbackActivityOperations):
    async def authorize(self, value: TemporalActivityInput) -> ActivityOutcome:
        del value
        raise PolicyDenied("revoked")


class _DefectiveOperations(CallbackActivityOperations):
    async def authorize(self, value: TemporalActivityInput) -> ActivityOutcome:
        del value
        raise RuntimeError("framework defect")


class _TransientOperations(CallbackActivityOperations):
    async def authorize(self, value: TemporalActivityInput) -> ActivityOutcome:
        del value
        raise IntegrityFailure("temporary repository integrity read")


@pytest.mark.parametrize(
    ("operations", "error_type", "non_retryable"),
    [
        (_DeniedOperations({}), "AuthorizationDenied", True),
        (_DefectiveOperations({}), "FrameworkDefect", True),
        (_TransientOperations({}), "IntegrityFailure", True),
    ],
)
def test_activity_wrapper_contains_failures(
    operations: CallbackActivityOperations,
    error_type: str,
    non_retryable: bool,
) -> None:
    activities = TemporalActivities(operations)

    async def execute() -> None:
        environment = ActivityEnvironment()
        with pytest.raises(ApplicationError) as raised:
            await environment.run(activities.authorize, _activity_input())
        assert raised.value.type == error_type
        assert raised.value.non_retryable is non_retryable

    asyncio.run(execute())


class _FakeTemporal:
    def __init__(self) -> None:
        self.starts: list[TemporalWorkflowInput] = []
        self.resumes: list[tuple[str, str]] = []
        self.cancels: list[tuple[str, str]] = []

    async def start(self, value: TemporalWorkflowInput) -> None:
        self.starts.append(value)

    async def resume(self, *, workflow_id: str, command_ref: str) -> None:
        self.resumes.append((workflow_id, command_ref))

    async def request_cancel(self, *, workflow_id: str, command_ref: str) -> None:
        self.cancels.append((workflow_id, command_ref))


class _DuplicateTemporal(_FakeTemporal):
    async def start(self, value: TemporalWorkflowInput) -> None:
        raise WorkflowAlreadyStartedError(
            value.workflow_id,
            "aegis.investigation.v1",
        )


def test_outbox_dispatches_only_opaque_temporal_references() -> None:
    store = InMemoryDurability(clock=FixedClock(DEMO_TIME))
    store.append(
        tenant_id="tenant-acme",
        aggregate_type="case",
        aggregate_id="case:one",
        expected_version=0,
        drafts=(
            EventDraft(
                event_id="event:one",
                event_type="case.created",
                occurred_at=DEMO_TIME,
                actor_ref="actor:opaque",
                correlation_ref="request:opaque",
            ),
        ),
        outbox=(
            OutboxDraft(
                message_id="outbox:start",
                destination="temporal",
                message_type="investigation.start",
                available_at=DEMO_TIME,
                payload={
                    "actor_ref": "actor:opaque",
                    "request_ref": "request:opaque",
                    "run_id": "run:opaque",
                    "tenant_ref": "tenant:opaque",
                    "wait_for_signal": False,
                    "workflow_id": "workflow:opaque",
                },
            ),
        ),
    )
    temporal = _FakeTemporal()
    dispatcher = TemporalOutboxDispatcher(store=store, temporal=temporal)
    assert (
        asyncio.run(
            dispatcher.dispatch(
                tenant_id="tenant-acme",
                worker_ref="worker:one",
                now=DEMO_TIME,
            )
        )
        == 1
    )
    assert temporal.starts[0].tenant_ref == "tenant:opaque"
    assert "tenant-acme" not in temporal.starts[0].model_dump_json()


def test_outbox_dispatcher_validates_aware_clock() -> None:
    store = InMemoryDurability(clock=FixedClock(DEMO_TIME))
    dispatcher = TemporalOutboxDispatcher(
        store=store,
        temporal=_FakeTemporal(),
    )
    with pytest.raises(ValueError, match="aware"):
        asyncio.run(
            dispatcher.dispatch(
                tenant_id="tenant-acme",
                worker_ref="worker:one",
                now=DEMO_TIME.replace(tzinfo=None),
            )
        )


@pytest.mark.parametrize(
    ("temporal", "message_type", "expected_status", "delivered"),
    [
        (
            _DuplicateTemporal(),
            "investigation.start",
            DeliveryStatus.DELIVERED,
            1,
        ),
        (
            _FakeTemporal(),
            "unsupported.poison",
            DeliveryStatus.DEAD_LETTER,
            0,
        ),
    ],
)
def test_dispatcher_contains_duplicate_start_and_poison_messages(
    temporal: _FakeTemporal,
    message_type: str,
    expected_status: DeliveryStatus,
    delivered: int,
) -> None:
    store = InMemoryDurability(clock=FixedClock(DEMO_TIME))
    store.append(
        tenant_id="tenant-acme",
        aggregate_type="case",
        aggregate_id=f"case:{message_type}",
        expected_version=0,
        drafts=(
            EventDraft(
                event_id=f"event:{message_type}",
                event_type="case.created",
                occurred_at=DEMO_TIME,
                actor_ref="actor:opaque",
                correlation_ref="request:opaque",
            ),
        ),
        outbox=(
            OutboxDraft(
                message_id=f"outbox:{message_type}",
                destination="temporal",
                message_type=message_type,
                available_at=DEMO_TIME,
                payload={
                    "actor_ref": "actor:opaque",
                    "request_ref": "request:opaque",
                    "run_id": "run:opaque",
                    "tenant_ref": "tenant:opaque",
                    "wait_for_signal": False,
                    "workflow_id": "workflow:opaque",
                },
            ),
        ),
    )
    dispatcher = TemporalOutboxDispatcher(store=store, temporal=temporal)
    assert (
        asyncio.run(
            dispatcher.dispatch(
                tenant_id="tenant-acme",
                worker_ref="worker:one",
                now=DEMO_TIME,
            )
        )
        == delivered
    )
    record = store.delivery(
        tenant_id="tenant-acme",
        direction="outbox",
        message_id=f"outbox:{message_type}",
    )
    assert record is not None
    assert record.status is expected_status


def test_callback_operations_require_explicit_outcome() -> None:
    operations = CallbackActivityOperations({})
    with pytest.raises(IntegrityFailure, match="missing"):
        asyncio.run(operations.authorize(_activity_input()))


def test_callback_operations_cover_each_workflow_boundary() -> None:
    outcomes = {
        "authorize": ActivityOutcome(outcome="authorized"),
        "collect_evidence": ActivityOutcome(outcome="evidence_ready"),
        "run_graph": ActivityOutcome(outcome="graph_complete"),
        "record_wait": ActivityOutcome(outcome="recorded"),
        "authorize_signal": ActivityOutcome(outcome="authorized"),
        "complete": ActivityOutcome(outcome="recorded"),
        "cancel": ActivityOutcome(outcome="recorded"),
        "fail": ActivityOutcome(outcome="recorded"),
        "time_out": ActivityOutcome(outcome="recorded"),
    }
    operations = CallbackActivityOperations(outcomes)

    async def execute() -> list[str]:
        value = _activity_input()
        results = [
            await operations.authorize(value),
            await operations.collect_evidence(value),
            await operations.run_graph(value),
            await operations.record_wait(value),
            await operations.authorize_signal(value),
            await operations.complete(value),
            await operations.cancel(value),
            await operations.fail(value),
            await operations.time_out(value),
        ]
        return [result.outcome for result in results]

    assert asyncio.run(execute()) == [
        "authorized",
        "evidence_ready",
        "graph_complete",
        "recorded",
        "authorized",
        "recorded",
        "recorded",
        "recorded",
        "recorded",
    ]


class _RemediationOperations:
    def __init__(
        self,
        outcome: RemediationActivityOutcome | None = None,
        error: Exception | None = None,
    ) -> None:
        self.outcome = outcome or RemediationActivityOutcome(outcome="recorded")
        self.error = error

    async def _call(
        self,
        value: RemediationActivityInput,
    ) -> RemediationActivityOutcome:
        del value
        if self.error is not None:
            raise self.error
        return self.outcome

    request_approval = _call
    load_approval_decision = _call
    preflight = _call
    execute = _call
    reconcile = _call
    verify = _call
    rollback = _call
    cancel = _call
    expire = _call
    escalate = _call


def _remediation_activity_input() -> RemediationActivityInput:
    return RemediationActivityInput(
        tenant_ref="tenant:opaque",
        actor_ref="actor:opaque",
        request_ref="request:opaque",
        run_id="run:opaque",
        plan_ref="plan:opaque",
        action_ref="action:opaque",
        operation_id="operation:opaque",
    )


def test_remediation_temporal_contracts_are_strict_bounded_and_opaque() -> None:
    value = RemediationWorkflowInput(
        tenant_ref="tenant:opaque",
        actor_ref="actor:opaque",
        request_ref="request:opaque",
        run_id="run:opaque",
        plan_ref="plan:opaque",
        action_ref="action:opaque",
        workflow_id="workflow:opaque",
    )
    assert "tenant-acme" not in value.model_dump_json()
    with pytest.raises(ValidationError):
        RemediationWorkflowInput.model_validate(
            {**value.model_dump(), "tenant_id": "tenant-acme"}
        )
    with pytest.raises(ValidationError):
        RemediationSignal(command_ref="forged command")


def test_remediation_activity_wrapper_heartbeats_and_registers_all_boundaries() -> None:
    activities = TemporalRemediationActivities(
        _RemediationOperations(
            RemediationActivityOutcome(outcome="preflight_succeeded")
        )
    )

    async def execute() -> tuple[RemediationActivityOutcome, list[object]]:
        environment = ActivityEnvironment()
        heartbeats: list[object] = []
        environment.on_heartbeat = lambda *details: heartbeats.extend(details)
        result = await environment.run(
            activities.preflight,
            _remediation_activity_input(),
        )
        return result, heartbeats

    result, heartbeats = asyncio.run(execute())
    assert result.outcome == "preflight_succeeded"
    assert heartbeats == ["preflight:started", "preflight:completed"]
    assert len(activities.registered()) == 10


@pytest.mark.parametrize(
    ("error", "error_type", "returns_ambiguous"),
    [
        (PolicyDenied("revoked"), "AuthorizationDenied", False),
        (EffectConflict("target changed"), "EffectConflict", False),
        (IntegrityFailure("tampered"), "IntegrityFailure", False),
        (RuntimeError("adapter defect"), "FrameworkDefect", False),
        (EffectAmbiguous("timeout"), "", True),
    ],
)
def test_remediation_activity_wrapper_contains_adapter_failures(
    error: Exception,
    error_type: str,
    returns_ambiguous: bool,
) -> None:
    activities = TemporalRemediationActivities(_RemediationOperations(error=error))

    async def execute() -> None:
        environment = ActivityEnvironment()
        if returns_ambiguous:
            result = await environment.run(
                activities.execute,
                _remediation_activity_input(),
            )
            assert result.outcome == "effect_ambiguous"
            return
        with pytest.raises(ApplicationError) as raised:
            await environment.run(
                activities.execute,
                _remediation_activity_input(),
            )
        assert raised.value.type == error_type
        assert raised.value.non_retryable is True

    asyncio.run(execute())
