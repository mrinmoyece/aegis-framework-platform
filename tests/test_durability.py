from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from aegis_framework.activity_runtime import (
    DurableActivityRuntime,
    InMemoryCurrentAuthority,
)
from aegis_framework.adapters import FixedClock, InMemoryBudget
from aegis_framework.api import ApiRuntime, AppMode, create_app
from aegis_framework.domain import RiskLevel, stable_id
from aegis_framework.durability import (
    CursorCodec,
    DeliveryStatus,
    DurableInvestigationService,
    EventDraft,
    InMemoryDurability,
    LegacyEvent,
    OutboxDraft,
    RunStatus,
    SignalCommand,
)
from aegis_framework.errors import (
    ConcurrencyConflict,
    IdempotencyConflict,
    IntegrityFailure,
    MessageClaimConflict,
    PayloadRejected,
    PolicyDenied,
    RepositoryUnavailable,
)
from aegis_framework.fixtures import (
    DEMO_TIME,
    build_demo_bundle,
    demo_identity,
    demo_request,
)
from aegis_framework.references import TenantReferenceCodec
from aegis_framework.temporal import TemporalActivityInput


def _store() -> InMemoryDurability:
    return InMemoryDurability(clock=FixedClock(DEMO_TIME))


def _draft(event_id: str, event_type: str = "aggregate.changed") -> EventDraft:
    return EventDraft(
        event_id=event_id,
        event_type=event_type,
        occurred_at=DEMO_TIME,
        actor_ref="actor:test",
        correlation_ref="request:test",
        payload={"value": event_id},
    )


def test_event_ledger_expected_version_cursor_and_integrity() -> None:
    store = _store()
    alpha = store.append(
        tenant_id="tenant-acme",
        aggregate_type="case",
        aggregate_id="case-one",
        expected_version=0,
        drafts=(_draft("event:one"), _draft("event:two")),
    )
    other = store.append(
        tenant_id="tenant-acme",
        aggregate_type="case",
        aggregate_id="case-two",
        expected_version=0,
        drafts=(_draft("event:three"),),
    )
    beta = store.append(
        tenant_id="tenant-beta",
        aggregate_type="case",
        aggregate_id="case-one",
        expected_version=0,
        drafts=(_draft("event:one"),),
    )
    assert [event.aggregate_sequence for event in alpha] == [1, 2]
    assert [event.tenant_cursor for event in (*alpha, *other)] == [1, 2, 3]
    assert beta[0].tenant_cursor == 1
    assert alpha[1].aggregate_previous_hash == alpha[0].record_hash
    assert other[0].tenant_previous_hash == alpha[1].record_hash
    assert store.verify_integrity(tenant_id="tenant-acme")
    with pytest.raises(ConcurrencyConflict):
        store.append(
            tenant_id="tenant-acme",
            aggregate_type="case",
            aggregate_id="case-one",
            expected_version=1,
            drafts=(_draft("event:stale"),),
        )


def test_ledger_and_outbox_are_atomic_on_conflict() -> None:
    store = _store()
    message = OutboxDraft(
        message_id="outbox:duplicate",
        destination="temporal",
        message_type="case.start",
        available_at=DEMO_TIME,
        payload={"case_ref": "case:one"},
    )
    store.append(
        tenant_id="tenant-acme",
        aggregate_type="case",
        aggregate_id="case-one",
        expected_version=0,
        drafts=(_draft("event:one"),),
        outbox=(message,),
    )
    with pytest.raises(IdempotencyConflict):
        store.append(
            tenant_id="tenant-acme",
            aggregate_type="case",
            aggregate_id="case-two",
            expected_version=0,
            drafts=(_draft("event:must-not-commit"),),
            outbox=(message,),
        )
    assert (
        store.events(
            tenant_id="tenant-acme",
            aggregate_type="case",
            aggregate_id="case-two",
        )
        == ()
    )


def test_durable_run_idempotency_projection_and_rebuild() -> None:
    store = _store()
    identity = demo_identity(request_id="durable-request")
    first = store.accept_run(
        identity=identity,
        request=demo_request(),
        wait_for_signal=False,
    )
    replay = store.accept_run(
        identity=identity,
        request=demo_request(),
        wait_for_signal=False,
    )
    assert first.status is RunStatus.QUEUED
    assert replay.run_id == first.run_id
    assert replay.replayed
    with pytest.raises(IdempotencyConflict):
        store.accept_run(
            identity=identity,
            request=demo_request(incident_id="checkout-other"),
            wait_for_signal=False,
        )
    checkpoint = store.rebuild_run_projections(tenant_id=identity.tenant_id)
    rebuilt = store.get_run(tenant_id=identity.tenant_id, run_id=first.run_id)
    assert rebuilt == first
    assert checkpoint.last_cursor == 1
    assert checkpoint.version == 1


def test_cursor_is_opaque_tenant_and_run_bound() -> None:
    codec = CursorCodec(b"a" * 32)
    token = codec.encode(tenant_id="tenant-acme", run_id="run:one", cursor=42)
    assert "tenant-acme" not in token
    assert codec.decode(token, tenant_id="tenant-acme", run_id="run:one") == 42
    for tenant_id, run_id, candidate in (
        ("tenant-beta", "run:one", token),
        ("tenant-acme", "run:two", token),
        ("tenant-acme", "run:one", token[:-1] + "x"),
    ):
        with pytest.raises(ValueError, match="invalid"):
            codec.decode(candidate, tenant_id=tenant_id, run_id=run_id)
    with pytest.raises(ValueError, match="32 bytes"):
        CursorCodec(b"short")


def test_tenant_reference_is_encrypted_tamper_evident_and_bounded() -> None:
    codec = TenantReferenceCodec(b"tenant-reference-test-key-0000001")
    first = codec.encode("tenant-acme")
    second = codec.encode("tenant-acme")
    assert first != second
    assert "tenant-acme" not in first
    assert codec.decode(first) == "tenant-acme"
    with pytest.raises(ValueError, match="invalid"):
        codec.decode(first[:-1] + ("a" if first[-1] != "a" else "b"))
    with pytest.raises(ValueError, match="invalid"):
        codec.decode("tenant:untrusted")
    with pytest.raises(ValueError, match="32 bytes"):
        TenantReferenceCodec(b"short")


def test_timeline_redacts_payload_and_pages_deterministically() -> None:
    store = _store()
    identity = demo_identity(request_id="timeline-request")
    run = store.accept_run(
        identity=identity,
        request=demo_request(),
        wait_for_signal=False,
    )
    store.record_transition(
        tenant_id=identity.tenant_id,
        run_id=run.run_id,
        event_type="investigation.started",
        operation_id="op:start",
        actor_ref="actor:test",
        request_ref=run.request_ref,
    )
    codec = CursorCodec(b"b" * 32)
    first = store.timeline(
        tenant_id=identity.tenant_id,
        run_id=run.run_id,
        after_cursor=0,
        limit=1,
        cursor_codec=codec,
    )
    assert len(first.items) == 1
    assert first.next_cursor is not None
    assert "payload" not in first.model_dump_json()
    second = store.timeline(
        tenant_id=identity.tenant_id,
        run_id=run.run_id,
        after_cursor=codec.decode(
            first.next_cursor,
            tenant_id=identity.tenant_id,
            run_id=run.run_id,
        ),
        limit=1,
        cursor_codec=codec,
    )
    assert second.items[0].status is RunStatus.RUNNING
    assert second.next_cursor is None


def test_stale_activity_cannot_overwrite_cancel_intent() -> None:
    store = _store()
    identity = demo_identity(request_id="cancel-race")
    run = store.accept_run(
        identity=identity,
        request=demo_request(),
        wait_for_signal=True,
    )
    store.accept_signal(
        identity=identity,
        command=SignalCommand(
            command_id="cancel-command",
            run_id=run.run_id,
            command_type="cancel",
        ),
    )
    with pytest.raises(IntegrityFailure, match="state machine"):
        store.record_transition(
            tenant_id=identity.tenant_id,
            run_id=run.run_id,
            event_type="investigation.graph_completed",
            operation_id="stale-graph",
            actor_ref="actor:test",
            request_ref=run.request_ref,
            attributes={"result": {}},
        )
    current = store.get_run(tenant_id=identity.tenant_id, run_id=run.run_id)
    assert current is not None
    assert current.status is RunStatus.CANCEL_REQUESTED
    assert (
        len(
            store.events(
                tenant_id=identity.tenant_id,
                aggregate_type="investigation",
                aggregate_id=run.run_id,
            )
        )
        == 2
    )


def test_duplicate_signal_and_terminal_signal_fail_closed() -> None:
    store = _store()
    identity = demo_identity(request_id="duplicate-signal")
    run = store.accept_run(
        identity=identity,
        request=demo_request(),
        wait_for_signal=True,
    )
    command = SignalCommand(
        command_id="resume-command",
        run_id=run.run_id,
        command_type="resume",
    )
    first = store.accept_signal(identity=identity, command=command)
    duplicate = store.accept_signal(identity=identity, command=command)
    assert first.status is RunStatus.QUEUED
    assert duplicate.replayed
    store.record_transition(
        tenant_id=identity.tenant_id,
        run_id=run.run_id,
        event_type="investigation.started",
        operation_id="start-after-resume",
        actor_ref="actor:test",
        request_ref=run.request_ref,
    )
    store.record_transition(
        tenant_id=identity.tenant_id,
        run_id=run.run_id,
        event_type="investigation.completed",
        operation_id="complete-after-resume",
        actor_ref="actor:test",
        request_ref=run.request_ref,
    )
    with pytest.raises(IntegrityFailure):
        store.accept_signal(
            identity=identity,
            command=SignalCommand(
                command_id="late-command",
                run_id=run.run_id,
                command_type="resume",
            ),
        )
    assert (
        store.delivery(
            tenant_id=identity.tenant_id,
            direction="inbox",
            message_id="late-command",
        )
        is None
    )

    other = store.accept_run(
        identity=demo_identity(request_id="duplicate-signal-other"),
        request=demo_request(incident_id="checkout-other"),
        wait_for_signal=True,
    )
    with pytest.raises(IdempotencyConflict, match="conflicts"):
        store.accept_signal(
            identity=identity,
            command=SignalCommand(
                command_id="resume-command",
                run_id=other.run_id,
                command_type="cancel",
            ),
        )


def test_resume_command_count_is_bounded() -> None:
    store = _store()
    identity = demo_identity(request_id="bounded-signals")
    run = store.accept_run(
        identity=identity,
        request=demo_request(),
        wait_for_signal=True,
    )
    for index in range(32):
        store.accept_signal(
            identity=identity,
            command=SignalCommand(
                command_id=f"resume:{index}",
                run_id=run.run_id,
                command_type="resume",
            ),
        )
    with pytest.raises(PayloadRejected, match="bound"):
        store.accept_signal(
            identity=identity,
            command=SignalCommand(
                command_id="resume:overflow",
                run_id=run.run_id,
                command_type="resume",
            ),
        )


def test_outbox_claims_are_race_safe_and_stale_claims_fail() -> None:
    store = _store()
    store.append(
        tenant_id="tenant-acme",
        aggregate_type="case",
        aggregate_id="case-one",
        expected_version=0,
        drafts=(_draft("event:one"),),
        outbox=(
            OutboxDraft(
                message_id="outbox:one",
                destination="temporal",
                message_type="case.start",
                available_at=DEMO_TIME,
                payload={"case_ref": "case:one"},
            ),
        ),
    )

    def claim(index: int) -> tuple[object, ...]:
        return store.claim_outbox(
            tenant_id="tenant-acme",
            worker_ref=f"worker:{index}",
            now=DEMO_TIME,
            claim_until=DEMO_TIME + timedelta(seconds=30),
            limit=1,
        )

    with ThreadPoolExecutor(max_workers=4) as executor:
        claims = tuple(executor.map(claim, range(4)))
    winners = [claim[0] for claim in claims if claim]
    assert len(winners) == 1
    winner = winners[0]
    store.complete_outbox(winner, now=DEMO_TIME)
    record = store.delivery(
        tenant_id="tenant-acme",
        direction="outbox",
        message_id="outbox:one",
    )
    assert record is not None
    assert record.status is DeliveryStatus.DELIVERED
    with pytest.raises(MessageClaimConflict):
        store.complete_outbox(winner, now=DEMO_TIME)


def test_outbox_retry_reaches_dead_letter() -> None:
    store = _store()
    store.append(
        tenant_id="tenant-acme",
        aggregate_type="case",
        aggregate_id="case-one",
        expected_version=0,
        drafts=(_draft("event:one"),),
        outbox=(
            OutboxDraft(
                message_id="outbox:poison",
                destination="temporal",
                message_type="case.start",
                available_at=DEMO_TIME,
                payload={"case_ref": "case:one"},
            ),
        ),
    )
    now = DEMO_TIME
    for attempt in range(1, 6):
        claim = store.claim_outbox(
            tenant_id="tenant-acme",
            worker_ref="worker:retry",
            now=now,
            claim_until=now + timedelta(seconds=1),
            limit=1,
        )[0]
        assert claim.attempt == attempt
        now += timedelta(seconds=2)
        store.fail_outbox(
            claim,
            now=now,
            error_code="poison_payload",
            retry_at=now,
        )
    record = store.delivery(
        tenant_id="tenant-acme",
        direction="outbox",
        message_id="outbox:poison",
    )
    assert record is not None
    assert record.status is DeliveryStatus.DEAD_LETTER
    assert record.attempts == 5


def test_legacy_replay_upcasts_and_hashes() -> None:
    store = _store()
    calls = 0

    def upcast(event: LegacyEvent) -> tuple[str, dict[str, object]]:
        nonlocal calls
        calls += 1
        return (
            "investigation.requested",
            {
                "incident_id": "incident-legacy",
                "request": demo_request(incident_id="incident-legacy").model_dump(
                    mode="json"
                ),
                "request_ref": "request:legacy",
                "run_id": "run:legacy",
                "tenant_ref": "tenant:legacy",
                "wait_for_signal": False,
                "workflow_id": "workflow:legacy",
                "legacy_type": event.event_type,
            },
        )

    events = store.replay_legacy(
        tenant_id="tenant-acme",
        aggregate_id="run:legacy",
        actor_ref="actor:legacy",
        correlation_ref="request:legacy",
        legacy=(
            LegacyEvent(
                event_type="legacy.started",
                occurred_at=DEMO_TIME,
                payload={"old_status": "started"},
            ),
        ),
        upcast=upcast,
    )
    assert calls == 1
    assert events[0].schema_version == 1
    assert events[0].payload["legacy_type"] == "legacy.started"
    assert store.verify_integrity(tenant_id="tenant-acme")


def _activity_runtime() -> tuple[
    DurableActivityRuntime,
    InMemoryDurability,
    InMemoryCurrentAuthority,
    TemporalActivityInput,
]:
    bundle = build_demo_bundle()
    identity = demo_identity(request_id="activity-run")
    authority = InMemoryCurrentAuthority((identity,))
    store = _store()
    run = store.accept_run(
        identity=identity,
        request=demo_request(),
        wait_for_signal=False,
    )
    runtime = DurableActivityRuntime(
        authority=authority,
        policy=bundle.policy,
        budget=InMemoryBudget({"tenant-acme": 5}),
        evidence=bundle.service._evidence,
        orchestrator=bundle.orchestrator,
        store=store,
    )
    value = TemporalActivityInput(
        tenant_ref=stable_id("tenant", identity.tenant_id, length=32),
        actor_ref=stable_id("actor", identity.issuer, identity.subject_id, length=32),
        request_ref=run.request_ref,
        run_id=run.run_id,
        operation_id="authorize:activity-run",
    )
    return runtime, store, authority, value


def test_activity_runtime_persists_intent_and_result_idempotently() -> None:
    runtime, store, _, value = _activity_runtime()

    async def execute() -> None:
        assert (await runtime.authorize(value)).outcome == "authorized"
        assert (await runtime.authorize(value)).outcome == "authorized"
        evidence = await runtime.collect_evidence(
            value.model_copy(update={"operation_id": "evidence:activity-run"})
        )
        assert evidence.outcome == "evidence_ready"
        graph = await runtime.run_graph(
            value.model_copy(update={"operation_id": "graph:activity-run"})
        )
        assert graph.outcome == "graph_complete"
        completed = await runtime.complete(
            value.model_copy(update={"operation_id": "complete:activity-run"})
        )
        assert completed.result_ref == graph.result_ref

    asyncio.run(execute())
    run = store.get_run(tenant_id="tenant-acme", run_id=value.run_id)
    assert run is not None
    assert run.status is RunStatus.COMPLETED
    assert store.verify_integrity(tenant_id="tenant-acme")


def test_activity_reauthorization_blocks_revocation_and_tenant_attack() -> None:
    runtime, store, authority, value = _activity_runtime()
    asyncio.run(runtime.authorize(value))
    authority.revoke(tenant_id="tenant-acme", actor_ref=value.actor_ref)
    with pytest.raises(PolicyDenied):
        asyncio.run(
            runtime.collect_evidence(
                value.model_copy(update={"operation_id": "evidence:revoked"})
            )
        )
    current = store.get_run(tenant_id="tenant-acme", run_id=value.run_id)
    assert current is not None
    assert current.status is RunStatus.RUNNING
    with pytest.raises(PolicyDenied):
        asyncio.run(
            runtime.collect_evidence(
                value.model_copy(
                    update={
                        "tenant_ref": stable_id("tenant", "tenant-beta", length=32),
                        "operation_id": "evidence:tenant-attack",
                    }
                )
            )
        )


def test_activity_wait_signal_timeout_and_terminal_failure_paths() -> None:
    runtime, store, _, value = _activity_runtime()
    identity = demo_identity(request_id="activity-wait")

    async def execute() -> None:
        await runtime.authorize(value)
        with pytest.raises(IntegrityFailure, match="graph result"):
            await runtime.complete(
                value.model_copy(update={"operation_id": "complete:missing"})
            )
        await runtime.record_wait(
            value.model_copy(update={"operation_id": "wait:activity"})
        )
        store.accept_signal(
            identity=identity,
            command=SignalCommand(
                command_id="resume:activity",
                run_id=value.run_id,
                command_type="resume",
            ),
        )
        signal = await runtime.authorize_signal(
            value.model_copy(
                update={
                    "command_ref": "resume:activity",
                    "operation_id": "signal:activity",
                }
            )
        )
        assert signal.outcome == "authorized"
        timed_out = await runtime.time_out(
            value.model_copy(update={"operation_id": "timeout:activity"})
        )
        assert timed_out.outcome == "recorded"
        assert (
            await runtime.fail(
                value.model_copy(update={"operation_id": "fail:duplicate"})
            )
        ).outcome == "duplicate"
        with pytest.raises(IntegrityFailure, match="request reference"):
            await runtime.fail(
                value.model_copy(
                    update={
                        "request_ref": "request:forged",
                        "operation_id": "fail:forged",
                    }
                )
            )

    asyncio.run(execute())
    current = store.get_run(tenant_id="tenant-acme", run_id=value.run_id)
    assert current is not None
    assert current.status is RunStatus.TIMED_OUT


def test_activity_budget_denial_and_invalid_signal_fail_closed() -> None:
    bundle = build_demo_bundle()
    identity = demo_identity(request_id="activity-budget")
    authority = InMemoryCurrentAuthority((identity,))
    store = _store()
    run = store.accept_run(
        identity=identity,
        request=demo_request(),
        wait_for_signal=True,
    )
    value = TemporalActivityInput(
        tenant_ref=stable_id("tenant", identity.tenant_id, length=32),
        actor_ref=stable_id("actor", identity.issuer, identity.subject_id, length=32),
        request_ref=run.request_ref,
        run_id=run.run_id,
        operation_id="authorize:budget",
    )
    runtime = DurableActivityRuntime(
        authority=authority,
        policy=bundle.policy,
        budget=InMemoryBudget({"tenant-acme": 0}),
        evidence=bundle.service._evidence,
        orchestrator=bundle.orchestrator,
        store=store,
    )

    async def execute() -> None:
        denied = await runtime.authorize(value)
        assert denied.outcome == "denied"
        with pytest.raises(IntegrityFailure, match="command reference"):
            await runtime.authorize_signal(value)

    asyncio.run(execute())
    current = store.get_run(tenant_id="tenant-acme", run_id=run.run_id)
    assert current is not None
    assert current.failure_code == "tenant_budget_exhausted"


def test_activity_cancellation_reaches_terminal_cancelled() -> None:
    runtime, store, _, value = _activity_runtime()
    identity = demo_identity(request_id="activity-cancel")

    async def execute() -> None:
        await runtime.authorize(value)
        store.accept_signal(
            identity=identity,
            command=SignalCommand(
                command_id="cancel:activity",
                run_id=value.run_id,
                command_type="cancel",
            ),
        )
        cancelled = await runtime.cancel(
            value.model_copy(
                update={
                    "command_ref": "cancel:activity",
                    "operation_id": "cancel:activity",
                }
            )
        )
        assert cancelled.outcome == "recorded"

    asyncio.run(execute())
    current = store.get_run(tenant_id="tenant-acme", run_id=value.run_id)
    assert current is not None
    assert current.status is RunStatus.CANCELLED


def test_activity_failure_cannot_override_accepted_cancellation() -> None:
    runtime, store, _, value = _activity_runtime()
    identity = demo_identity(request_id="activity-cancel-failure")

    async def execute() -> None:
        await runtime.authorize(value)
        store.accept_signal(
            identity=identity,
            command=SignalCommand(
                command_id="cancel:failure",
                run_id=value.run_id,
                command_type="cancel",
            ),
        )
        outcome = await runtime.fail(
            value.model_copy(update={"operation_id": "fail:after-cancel"})
        )
        assert outcome.outcome == "recorded"

    asyncio.run(execute())
    current = store.get_run(tenant_id="tenant-acme", run_id=value.run_id)
    assert current is not None
    assert current.status is RunStatus.CANCELLED


def test_activity_failure_persists_specific_failure_code() -> None:
    runtime, store, _, value = _activity_runtime()

    async def execute() -> None:
        await runtime.authorize(value)
        outcome = await runtime.fail(
            value.model_copy(
                update={
                    "failure_code": "authorization_denied",
                    "operation_id": "fail:specific-code",
                }
            )
        )
        assert outcome.outcome == "recorded"

    asyncio.run(execute())
    current = store.get_run(tenant_id="tenant-acme", run_id=value.run_id)
    assert current is not None
    assert current.status is RunStatus.FAILED
    assert current.failure_code == "authorization_denied"
    failure_event = store.events(
        tenant_id="tenant-acme",
        aggregate_type="investigation",
        aggregate_id=value.run_id,
    )[-1]
    assert failure_event.event_type == "investigation.failed"
    assert failure_event.payload["failure_code"] == "authorization_denied"


def test_signal_authorization_uses_current_signaller_not_workflow_payload() -> None:
    runtime, store, authority, value = _activity_runtime()
    identity = demo_identity(request_id="signal-current")
    run = store.get_run(tenant_id=identity.tenant_id, run_id=value.run_id)
    assert run is not None
    store.accept_signal(
        identity=identity,
        command=SignalCommand(
            command_id="resume-current",
            run_id=run.run_id,
            command_type="resume",
        ),
    )
    authority.revoke(tenant_id="tenant-acme", actor_ref=value.actor_ref)
    with pytest.raises(PolicyDenied):
        asyncio.run(
            runtime.authorize_signal(
                value.model_copy(
                    update={
                        "command_ref": "resume-current",
                        "operation_id": "signal:resume-current",
                    }
                )
            )
        )


def test_durable_service_policy_and_cursor_boundary() -> None:
    bundle = build_demo_bundle()
    service = DurableInvestigationService(
        policy=bundle.policy,
        store=_store(),
        cursor_codec=CursorCodec(b"c" * 32),
    )
    viewer = demo_identity(
        request_id="durable-viewer",
        roles=("incident-viewer",),
    )
    with pytest.raises(PolicyDenied):
        service.submit(viewer, demo_request(), wait_for_signal=False)
    responder = demo_identity(request_id="durable-authorized")
    run = service.submit(responder, demo_request(), wait_for_signal=False)
    assert service.get(responder, run_id=run.run_id) == run
    assert (
        service.get(
            demo_identity(
                tenant_id="tenant-beta",
                subject_id="responder-bob",
                request_id="durable-beta",
            ),
            run_id=run.run_id,
        )
        is None
    )


_RESPONDER_TOKEN = "demo-responder-token"


def _headers(request_id: str, token: str = _RESPONDER_TOKEN) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "X-Request-ID": request_id,
    }


def _durable_payload(wait: bool = False) -> dict[str, object]:
    request = demo_request()
    return {
        "incident_id": request.incident_id,
        "alert": request.alert.model_dump(mode="json"),
        "wait_for_signal": wait,
    }


def test_durable_api_uses_projection_and_redacted_timeline() -> None:
    client = TestClient(create_app(mode=AppMode.DEMO))
    created = client.post(
        "/v1/durable-investigations",
        headers=_headers("durable-api"),
        json=_durable_payload(wait=True),
    )
    assert created.status_code == 202
    run = created.json()
    assert "tenant_id" not in run
    fetched = client.get(
        f"/v1/durable-investigations/{run['run_id']}",
        headers=_headers("durable-api-read"),
    )
    assert fetched.status_code == 200
    timeline = client.get(
        f"/v1/durable-investigations/{run['run_id']}/timeline",
        headers=_headers("durable-api-timeline"),
    )
    assert timeline.status_code == 200
    assert "payload" not in timeline.text
    signalled = client.post(
        f"/v1/durable-investigations/{run['run_id']}/signals/resume",
        headers=_headers("durable-api-signal"),
        json={"command_id": "resume-api"},
    )
    assert signalled.status_code == 202
    assert signalled.json()["status"] == "queued"
    duplicate = client.post(
        f"/v1/durable-investigations/{run['run_id']}/signals/resume",
        headers=_headers("durable-api-signal"),
        json={"command_id": "resume-api"},
    )
    assert duplicate.json()["replayed"] is True


def test_durable_api_denial_enumeration_and_invalid_cursor() -> None:
    client = TestClient(create_app(mode=AppMode.DEMO))
    denied = client.post(
        "/v1/durable-investigations",
        headers=_headers("durable-denied", "demo-viewer-token"),
        json=_durable_payload(),
    )
    assert denied.status_code == 403
    assert (
        client.get(
            "/v1/durable-investigations/run:unknown",
            headers=_headers("durable-missing"),
        ).status_code
        == 404
    )
    created = client.post(
        "/v1/durable-investigations",
        headers=_headers("durable-cursor-source"),
        json=_durable_payload(),
    ).json()
    invalid = client.get(
        f"/v1/durable-investigations/{created['run_id']}/timeline",
        headers=_headers("durable-invalid-cursor"),
        params={"cursor": "tampered"},
    )
    assert invalid.status_code == 400


@pytest.mark.parametrize(
    ("failure", "expected_status"),
    [
        (ConcurrencyConflict("race"), 409),
        (RepositoryUnavailable("offline"), 503),
    ],
)
def test_durable_api_maps_repository_failures(
    failure: Exception,
    expected_status: int,
) -> None:
    bundle = build_demo_bundle()

    class _FailingDurable:
        def submit(self, *args: object, **kwargs: object) -> object:
            del args, kwargs
            raise failure

    runtime = ApiRuntime(
        authenticator=bundle.authenticator,
        governance=bundle.governance,
        policy=bundle.policy,
        service_for=lambda scenario: bundle.service,
        durable=_FailingDurable(),
    )
    response = TestClient(create_app(mode=AppMode.TEST, runtime=runtime)).post(
        "/v1/durable-investigations",
        headers=_headers(f"durable-failure-{expected_status}"),
        json=_durable_payload(),
    )
    assert response.status_code == expected_status


def test_event_and_signal_models_reject_unbounded_or_invalid_data() -> None:
    with pytest.raises(ValidationError, match="payload exceeds"):
        _draft("event:large").model_copy(
            update={"payload": {"data": "x" * 40_000}}
        ).__class__.model_validate(
            {
                **_draft("event:large").model_dump(),
                "payload": {"data": "x" * 40_000},
            }
        )
    with pytest.raises(ValidationError):
        SignalCommand(
            command_id="signal:bad",
            run_id="run:one",
            command_type="approve",
        )


def test_current_authority_registry_replaces_identity() -> None:
    identity = demo_identity()
    registry = InMemoryCurrentAuthority((identity,))
    actor_ref = stable_id("actor", identity.issuer, identity.subject_id, length=32)
    replaced = identity.model_copy(
        update={
            "grants": tuple(
                grant.model_copy(update={"risk_ceiling": RiskLevel.LOW})
                for grant in identity.grants
            )
        }
    )
    registry.replace(replaced)
    resolved = registry.identity(
        tenant_id=identity.tenant_id,
        actor_ref=actor_ref,
        request_ref="request:current",
    )
    assert resolved is not None
    assert resolved.grants[0].risk_ceiling is RiskLevel.LOW
