from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import JsonValue, ValidationError

from aegis_framework.a2a_interop import (
    A2APeerGateway,
    A2APeerRegistration,
    A2ASdkClientPort,
    A2AServerAuthorizationPort,
    A2AServerPort,
    A2ASkillName,
    A2ATaskRequest,
    A2ATaskResponse,
    BoundedA2AServer,
    build_aegis_agent_card,
)
from aegis_framework.domain import RiskLevel
from aegis_framework.errors import (
    AuthenticationFailed,
    ConcurrencyConflict,
    IdempotencyConflict,
    IntegrityFailure,
    PayloadRejected,
    PolicyDenied,
    ReconciliationRequired,
    RepositoryUnavailable,
)
from aegis_framework.interoperability import (
    AgentCardContract,
    ArtifactContract,
    CapabilityContract,
    CapabilityOperation,
    CircuitBreaker,
    CitationContract,
    DataClassification,
    ExternalInvocationGateway,
    InMemoryReplayCache,
    InteroperabilityFactType,
    InteroperabilityLedger,
    InvocationProjection,
    InvocationQuota,
    InvocationState,
    MessageContract,
    MessagePart,
    PolicyContract,
    PrincipalContract,
    ProtocolKind,
    ProtocolPolicyPort,
    ProtocolTransportPort,
    ResourceContract,
    StatusContract,
    TaskContract,
    TaskState,
    ToolContract,
    TransportKind,
    TrustEntry,
    TrustRegistry,
    TrustStatus,
    TrustTier,
    WorkloadIdentityAssertion,
    WorkloadIdentityPolicy,
    WorkloadIdentityValidator,
    canonical_json,
    digest_value,
    reject_raw_ledger_payload,
    validate_untrusted_text,
)
from aegis_framework.interoperability_temporal import (
    AegisA2ATaskWorkflow,
    AegisMcpInvocationWorkflow,
    InteropOperation,
    InteropWorkflowInput,
)
from aegis_framework.mcp_interop import (
    CuratedMcpServer,
    FixedStdioRegistration,
    HardenedMcpClient,
    McpApplicationPort,
    McpCallRequest,
    McpCallResult,
    McpClientRegistration,
    McpInitialization,
    McpSdkClientPort,
    McpServerAuthorizationPort,
    McpToolName,
    NetworkMcpRegistration,
    ProposalReceipt,
    ProposalSubmission,
    curated_capabilities,
    curated_tools,
)
from aegis_framework.protocol_adapters import (
    A2A_PROTOCOL_VERSION,
    A2A_SDK_VERSION,
    A2A_SPEC_TAG,
    MCP_SDK_VERSION,
    MCP_SPEC_VERSION,
    DigestCardSigner,
    McpPrincipalResolver,
    OfficialMcpServerAdapter,
    parse_official_agent_card,
)

NOW = datetime(2026, 8, 17, 19, 0, tzinfo=UTC)
DIGEST = "a" * 64


def _principal() -> PrincipalContract:
    return PrincipalContract(
        principal_ref="workload-aegis",
        kind="workload",
        issuer_digest="1" * 64,
        audience="aegis-protocol",
        scopes=("interop:invoke",),
        tenant_ref="tenant-ref-acme",
        purpose="incident-response",
        proof_digest="2" * 64,
        authenticated_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def _capability(
    protocol: ProtocolKind = ProtocolKind.MCP,
    *,
    capability_id: str = "mcp-aegis-status-read",
) -> CapabilityContract:
    return CapabilityContract(
        capability_id=capability_id,
        protocol=protocol,
        operation=CapabilityOperation.STATUS,
        resource_kind="status",
        risk=RiskLevel.LOW,
        input_schema_digest="3" * 64,
        output_schema_digest="4" * 64,
        maximum_input_bytes=4096,
        maximum_output_bytes=8192,
    )


def _message(text: str = "Investigate checkout status.") -> MessageContract:
    return MessageContract(
        message_id="message-001",
        role="user",
        parts=(
            MessagePart(
                part_id="part-001",
                kind="text",
                media_type="text/plain",
                text=text,
                content_digest=digest_value(text),
            ),
        ),
        created_at=NOW,
    )


def _trust(
    protocol: ProtocolKind = ProtocolKind.MCP,
    *,
    status: TrustStatus = TrustStatus.ACTIVE,
    revision: int = 2,
    peer_id: str = "peer-001",
    capability: str = "mcp-aegis-status-read",
    card_digest: str | None = None,
) -> TrustEntry:
    return TrustEntry(
        peer_id=peer_id,
        protocol=protocol,
        owner_ref="team-platform",
        environment="staging",
        trust_tier=TrustTier.PARTNER,
        status=status,
        revision=revision,
        expires_at=NOW + timedelta(days=30),
        review_after=NOW + timedelta(days=7),
        card_digest=("5" * 64 if protocol is ProtocolKind.A2A else card_digest),
        schema_digest="6" * 64,
        certificate_digest="7" * 64,
        key_digest="8" * 64,
        allowed_classifications=(DataClassification.INTERNAL,),
        allowed_risks=(RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH),
        allowed_capabilities=(capability,),
        allowed_transports=(TransportKind.STREAMABLE_HTTP,),
        egress_origins=("https://peer.example.com",),
        maximum_request_bytes=8192,
        maximum_response_bytes=16384,
        maximum_requests_per_minute=100,
        maximum_cost_units_per_hour=1000,
        change_digest="9" * 64,
        reviewed_by=("reviewer-001",) if status is TrustStatus.ACTIVE else (),
        reviewed_at=NOW if status is TrustStatus.ACTIVE else None,
    )


def _status(state: TaskState, *, sequence: int = 1) -> StatusContract:
    material = {
        "state": state,
        "progress": 100 if state is TaskState.COMPLETED else 0,
        "sequence": sequence,
    }
    return StatusContract(
        state=state,
        progress_percent=100 if state is TaskState.COMPLETED else 0,
        sequence=sequence,
        status_digest=digest_value(material),
        occurred_at=NOW,
    )


def _artifact(
    *,
    task: TaskContract,
    peer: TrustEntry,
    capability: CapabilityContract,
) -> ArtifactContract:
    part = MessagePart(
        part_id="artifact-part",
        kind="data",
        media_type="application/json",
        data={"status": "bounded"},
        content_digest=digest_value({"status": "bounded"}),
    )
    material: dict[str, Any] = {
        "artifact_id": "artifact-001",
        "task_id": task.task_id,
        "kind": "status-report",
        "parts": [part.model_dump(mode="json")],
        "citations": [],
        "producer_peer_id": peer.peer_id,
        "card_digest": peer.card_digest or "0" * 64,
        "capability_digest": digest_value(capability.model_dump(mode="json")),
        "created_at": NOW,
        "schema_version": 1,
    }
    return ArtifactContract(
        **material,
        artifact_digest=digest_value(material),
    )


def test_canonical_bounds_unicode_redaction_and_contract_integrity() -> None:
    assert canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'
    assert digest_value({"a": 1}) == digest_value({"a": 1})
    with pytest.raises(ValueError, match="NFC"):
        validate_untrusted_text("e\u0301")
    with pytest.raises(ValueError, match="bidirectional"):
        validate_untrusted_text("safe\u202eevil")
    deep: object = "deep"
    for _ in range(14):
        deep = [deep]
    with pytest.raises(PayloadRejected, match="nesting"):
        canonical_json(deep)
    with pytest.raises(IntegrityFailure, match="raw protocol"):
        reject_raw_ledger_payload({"prompt": "never persist"})
    with pytest.raises(ValidationError, match="digest"):
        MessagePart(
            part_id="part-bad",
            kind="text",
            media_type="text/plain",
            text="safe",
            content_digest=DIGEST,
        )
    citation = CitationContract(
        evidence_id="evidence-001",
        locator_digest="1" * 64,
        content_hash="2" * 64,
        provenance_digest="3" * 64,
    )
    part = MessagePart(
        part_id="finding-part",
        kind="text",
        media_type="text/plain",
        text="Cited finding.",
        content_digest=digest_value("Cited finding."),
    )
    material = {
        "artifact_id": "finding-001",
        "task_id": "task-001",
        "kind": "investigation-finding",
        "parts": [part.model_dump(mode="json")],
        "citations": [citation.model_dump(mode="json")],
        "producer_peer_id": "peer-001",
        "card_digest": "4" * 64,
        "capability_digest": "5" * 64,
        "created_at": NOW,
        "schema_version": 1,
    }
    assert ArtifactContract(
        **material, artifact_digest=digest_value(material)
    ).citations == (citation,)
    with pytest.raises(ValidationError, match="citations"):
        ArtifactContract(
            **{**material, "citations": []},
            artifact_digest=digest_value({**material, "citations": []}),
        )


def test_trust_registry_review_quarantine_revocation_and_expiry() -> None:
    registry = TrustRegistry()
    pending = _trust(status=TrustStatus.PENDING_REVIEW, revision=1)
    registry.register(pending)
    with pytest.raises(ConcurrencyConflict):
        registry.register(pending)
    with pytest.raises(PayloadRejected, match="confirmation"):
        registry.review(
            peer_id=pending.peer_id,
            expected_revision=1,
            reviewer_ref="reviewer-002",
            now=NOW,
            typed_confirmation="wrong",
        )
    active = registry.review(
        peer_id=pending.peer_id,
        expected_revision=1,
        reviewer_ref="reviewer-002",
        now=NOW,
        typed_confirmation="TRUST peer-001",
    )
    assert active.status is TrustStatus.ACTIVE
    assert (
        registry.require_active(
            peer_id="peer-001",
            protocol=ProtocolKind.MCP,
            capability_id="mcp-aegis-status-read",
            risk=RiskLevel.LOW,
            classification=DataClassification.INTERNAL,
            now=NOW,
        ).revision
        == 2
    )
    quarantined = registry.quarantine(
        peer_id="peer-001",
        expected_revision=2,
        reviewer_ref="reviewer-003",
        now=NOW,
        typed_confirmation="QUARANTINE peer-001",
    )
    assert quarantined.status is TrustStatus.QUARANTINED
    with pytest.raises(PolicyDenied, match="not active"):
        registry.require_active(
            peer_id="peer-001",
            protocol=ProtocolKind.MCP,
            capability_id="mcp-aegis-status-read",
            risk=RiskLevel.LOW,
            classification=DataClassification.INTERNAL,
            now=NOW,
        )
    revoked = registry.revoke(
        peer_id="peer-001",
        expected_revision=3,
        reviewer_ref="reviewer-003",
        now=NOW,
        typed_confirmation="REVOKE peer-001",
    )
    assert revoked.status is TrustStatus.REVOKED
    with pytest.raises(PolicyDenied, match="terminal"):
        registry.emergency_disable(
            peer_id="peer-001",
            expected_revision=4,
            reviewer_ref="reviewer-003",
            now=NOW,
            typed_confirmation="DISABLE peer-001",
        )
    assert len(registry.history("peer-001")) == 4


def test_trust_contract_requires_network_pins_and_a2a_card() -> None:
    with pytest.raises(ValidationError, match="certificate"):
        _trust().model_copy(
            update={
                "environment": "production",
                "certificate_digest": None,
            }
        ).model_validate(
            _trust().model_dump()
            | {"environment": "production", "certificate_digest": None}
        )
    with pytest.raises(ValidationError, match="agent card"):
        TrustEntry.model_validate(
            _trust(protocol=ProtocolKind.A2A).model_dump() | {"card_digest": None}
        )


def test_workload_identity_fails_closed_and_rejects_replay() -> None:
    cache = InMemoryReplayCache(maximum_entries=2)
    policy = WorkloadIdentityPolicy(
        audience="aegis-protocol",
        allowed_issuer_digests=("1" * 64,),
        required_scopes=("interop:invoke",),
        allowed_purposes=("incident-response",),
        maximum_lifetime_seconds=600,
        require_mutual_tls=True,
        allowed_principals=("workload-aegis",),
    )
    assertion = WorkloadIdentityAssertion(
        principal_ref="workload-aegis",
        issuer_digest="1" * 64,
        audience="aegis-protocol",
        scopes=("interop:invoke",),
        tenant_ref="tenant-ref-acme",
        purpose="incident-response",
        token_id_digest="2" * 64,
        proof_digest="3" * 64,
        confirmation_digest="4" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )
    production = WorkloadIdentityValidator(
        policy=policy,
        replay_cache=cache,
        mutual_tls_ready=lambda: True,
        production=True,
    )
    assert production.ready() is False
    with pytest.raises(RepositoryUnavailable, match="distributed"):
        production.validate(
            assertion,
            expected_tenant_ref="tenant-ref-acme",
            expected_purpose="incident-response",
            channel_binding_digest="4" * 64,
            now=NOW,
        )
    validator = WorkloadIdentityValidator(
        policy=policy,
        replay_cache=cache,
        mutual_tls_ready=lambda: True,
        production=False,
    )
    assert (
        validator.validate(
            assertion,
            expected_tenant_ref="tenant-ref-acme",
            expected_purpose="incident-response",
            channel_binding_digest="4" * 64,
            now=NOW,
        ).principal_ref
        == "workload-aegis"
    )
    with pytest.raises(AuthenticationFailed, match="replay"):
        validator.validate(
            assertion,
            expected_tenant_ref="tenant-ref-acme",
            expected_purpose="incident-response",
            channel_binding_digest="4" * 64,
            now=NOW,
        )
    changed = assertion.model_copy(update={"token_id_digest": "5" * 64})
    with pytest.raises(PolicyDenied, match="tenant"):
        validator.validate(
            changed,
            expected_tenant_ref="tenant-ref-other",
            expected_purpose="incident-response",
            channel_binding_digest="4" * 64,
            now=NOW,
        )


def test_digest_only_ledger_idempotency_projection_and_chain() -> None:
    ledger = InteroperabilityLedger()
    projection = InvocationProjection(
        operation_id="operation-001",
        tenant_ref="tenant-ref-acme",
        peer_id="peer-001",
        protocol=ProtocolKind.MCP,
        capability_id="mcp-aegis-status-read",
        risk=RiskLevel.LOW,
        state=InvocationState.REQUESTED,
        version=1,
        request_digest="1" * 64,
        trust_digest="2" * 64,
        policy_digest="3" * 64,
        trust_revision=2,
        fence_token="fence-001",
        updated_at=NOW,
    )
    fact = ledger.append(
        operation_id="operation-001",
        fact_type=InteroperabilityFactType.INVOCATION_REQUESTED,
        command_ref="command-001",
        actor_ref="workload-aegis",
        peer_id="peer-001",
        payload={"request_digest": "1" * 64, "cost_units": 1},
        recorded_at=NOW,
        projection=projection,
    )
    replay = ledger.append(
        operation_id="operation-001",
        fact_type=InteroperabilityFactType.INVOCATION_REQUESTED,
        command_ref="command-001",
        actor_ref="workload-aegis",
        peer_id="peer-001",
        payload={"request_digest": "1" * 64, "cost_units": 1},
        recorded_at=NOW,
    )
    assert replay == fact
    assert ledger.verify("operation-001")
    assert ledger.projection("operation-001") == projection
    with pytest.raises(ConcurrencyConflict, match="duplicate"):
        ledger.append(
            operation_id="operation-001",
            fact_type=InteroperabilityFactType.INVOCATION_REQUESTED,
            command_ref="command-001",
            actor_ref="workload-aegis",
            peer_id="peer-001",
            payload={"request_digest": "1" * 64, "cost_units": 1},
            recorded_at=NOW,
            projection=projection,
        )
    with pytest.raises(IdempotencyConflict):
        ledger.append(
            operation_id="operation-001",
            fact_type=InteroperabilityFactType.INVOCATION_FAILED,
            command_ref="command-001",
            actor_ref="workload-aegis",
            peer_id="peer-001",
            payload={"request_digest": "9" * 64},
            recorded_at=NOW,
        )
    with pytest.raises(IntegrityFailure):
        ledger.append(
            operation_id="operation-001",
            fact_type=InteroperabilityFactType.INVOCATION_FAILED,
            command_ref="command-002",
            actor_ref="workload-aegis",
            peer_id="peer-001",
            payload={"raw": "forbidden"},
            recorded_at=NOW,
        )


class _AllowPolicy(ProtocolPolicyPort):
    def authorize(
        self,
        *,
        principal: PrincipalContract,
        peer: TrustEntry,
        capability: CapabilityContract,
        request_digest: str,
    ) -> PolicyContract:
        del peer, request_digest
        material = {
            "principal": principal.principal_ref,
            "capability": capability.capability_id,
        }
        return PolicyContract(
            policy_id="interop-policy",
            revision=1,
            decision="allow",
            capability_id=capability.capability_id,
            principal_ref=principal.principal_ref,
            peer_id="peer-001",
            purpose=principal.purpose,
            risk=capability.risk,
            maximum_cost_units=100,
            reason_code="allowed",
            policy_digest=digest_value(material),
        )


class _Transport(ProtocolTransportPort):
    def __init__(self, capability: CapabilityContract) -> None:
        self.capability = capability
        self.mode = "success"

    def invoke(
        self,
        *,
        peer: TrustEntry,
        task: TaskContract,
        message: MessageContract,
        timeout_seconds: float,
        cancelled: Callable[[], bool],
    ) -> tuple[StatusContract, tuple[ArtifactContract, ...]]:
        del message, timeout_seconds, cancelled
        if self.mode == "ambiguous":
            raise TimeoutError
        if self.mode == "invalid":
            artifact = _artifact(task=task, peer=peer, capability=self.capability)
            return _status(TaskState.COMPLETED), (
                artifact.model_copy(update={"producer_peer_id": "forged"}),
            )
        return _status(TaskState.COMPLETED), (
            _artifact(task=task, peer=peer, capability=self.capability),
        )

    def reconcile(
        self,
        *,
        peer: TrustEntry,
        task: TaskContract,
        timeout_seconds: float,
    ) -> tuple[StatusContract, tuple[ArtifactContract, ...]]:
        del timeout_seconds
        return _status(TaskState.COMPLETED), (
            _artifact(task=task, peer=peer, capability=self.capability),
        )

    def cancel(
        self,
        *,
        peer: TrustEntry,
        task: TaskContract,
        timeout_seconds: float,
    ) -> StatusContract:
        del peer, task, timeout_seconds
        return _status(TaskState.CANCELLED)


def _gateway(
    transport: _Transport,
) -> tuple[ExternalInvocationGateway, InteroperabilityLedger]:
    registry = TrustRegistry()
    registry._entries["peer-001"].append(_trust())
    ledger = InteroperabilityLedger()
    return (
        ExternalInvocationGateway(
            registry=registry,
            policy=_AllowPolicy(),
            ledger=ledger,
            quota=InvocationQuota(request_limit=10, cost_limit=100),
            circuit=CircuitBreaker(failure_threshold=2),
            transport=transport,
            now=lambda: NOW,
        ),
        ledger,
    )


def test_gateway_intent_before_network_success_and_replay() -> None:
    capability = _capability()
    transport = _Transport(capability)
    gateway, ledger = _gateway(transport)
    result = gateway.invoke(
        principal=_principal(),
        capability=capability,
        peer_id="peer-001",
        message=_message(),
        operation_id="operation-success",
        command_ref="command-success",
        idempotency_key="idempotency-success",
        tenant_ref="tenant-ref-acme",
        classification=DataClassification.INTERNAL,
        cost_units=5,
        timeout_seconds=10,
        cancelled=lambda: False,
    )
    assert result.task.state is TaskState.COMPLETED
    assert [fact.fact_type for fact in ledger.facts("operation-success")] == [
        InteroperabilityFactType.INVOCATION_REQUESTED,
        InteroperabilityFactType.INVOCATION_CLAIMED,
        InteroperabilityFactType.INVOCATION_SUCCEEDED,
    ]
    replay = gateway.invoke(
        principal=_principal(),
        capability=capability,
        peer_id="peer-001",
        message=_message(),
        operation_id="operation-success",
        command_ref="command-replay",
        idempotency_key="idempotency-success",
        tenant_ref="tenant-ref-acme",
        classification=DataClassification.INTERNAL,
        cost_units=5,
        timeout_seconds=10,
        cancelled=lambda: False,
    )
    assert replay.replayed
    assert len(ledger.facts("operation-success")) == 3


def test_gateway_ambiguity_reconciliation_and_forged_artifact() -> None:
    capability = _capability()
    transport = _Transport(capability)
    transport.mode = "ambiguous"
    gateway, ledger = _gateway(transport)
    with pytest.raises(ReconciliationRequired):
        gateway.invoke(
            principal=_principal(),
            capability=capability,
            peer_id="peer-001",
            message=_message(),
            operation_id="operation-ambiguous",
            command_ref="command-ambiguous",
            idempotency_key="idempotency-ambiguous",
            tenant_ref="tenant-ref-acme",
            classification=DataClassification.INTERNAL,
            cost_units=5,
            timeout_seconds=10,
            cancelled=lambda: False,
        )
    assert (
        ledger.projection("operation-ambiguous").state  # type: ignore[union-attr]
        is InvocationState.AMBIGUOUS
    )
    reconciled = gateway.reconcile(
        principal=_principal(),
        operation_id="operation-ambiguous",
        command_ref="command-reconcile",
        classification=DataClassification.INTERNAL,
        timeout_seconds=10,
    )
    assert reconciled.status.state is TaskState.COMPLETED

    invalid_transport = _Transport(capability)
    invalid_transport.mode = "invalid"
    invalid_gateway, invalid_ledger = _gateway(invalid_transport)
    with pytest.raises(PayloadRejected, match="provenance"):
        invalid_gateway.invoke(
            principal=_principal(),
            capability=capability,
            peer_id="peer-001",
            message=_message(),
            operation_id="operation-forged",
            command_ref="command-forged",
            idempotency_key="idempotency-forged",
            tenant_ref="tenant-ref-acme",
            classification=DataClassification.INTERNAL,
            cost_units=1,
            timeout_seconds=10,
            cancelled=lambda: False,
        )
    assert (
        invalid_ledger.projection("operation-forged").state  # type: ignore[union-attr]
        is InvocationState.FAILED
    )


def test_quota_and_circuit_are_bounded() -> None:
    quota = InvocationQuota(request_limit=1, cost_limit=5)
    quota.reserve(
        tenant_ref="tenant-ref-acme",
        reservation_id="reservation-001",
        cost_units=5,
    )
    quota.reserve(
        tenant_ref="tenant-ref-acme",
        reservation_id="reservation-001",
        cost_units=5,
    )
    assert quota.usage("tenant-ref-acme") == (1, 5)
    with pytest.raises(PolicyDenied, match="quota"):
        quota.reserve(
            tenant_ref="tenant-ref-acme",
            reservation_id="reservation-002",
            cost_units=1,
        )
    circuit = CircuitBreaker(failure_threshold=2)
    circuit.record("peer-001", success=False)
    assert circuit.allow("peer-001")
    circuit.record("peer-001", success=False)
    assert not circuit.allow("peer-001")
    circuit.record("peer-001", success=True)
    assert circuit.allow("peer-001")


class _McpAuthorization(McpServerAuthorizationPort):
    allowed = True

    def authorize(
        self,
        *,
        principal: PrincipalContract,
        tool: Any,
        resource_ref: str,
    ) -> bool:
        del principal, tool, resource_ref
        return self.allowed


class _McpApplication(McpApplicationPort):
    def _resource(self, kind: str) -> ResourceContract:
        return ResourceContract(
            resource_ref=f"{kind}-001",
            resource_kind=kind,
            media_type="application/json",
            content_digest="1" * 64,
            size_bytes=128,
            classification=DataClassification.INTERNAL,
            redacted=True,
            provenance_digest="2" * 64,
            expires_at=NOW + timedelta(hours=1),
        )

    def _content(self, value: str) -> tuple[MessagePart, ...]:
        return (
            MessagePart(
                part_id="content-001",
                kind="text",
                media_type="text/plain",
                text=value,
                content_digest=digest_value(value),
                redacted=True,
            ),
        )

    def _citation(self) -> CitationContract:
        return CitationContract(
            evidence_id="evidence-001",
            locator_digest="3" * 64,
            content_hash="4" * 64,
            provenance_digest="5" * 64,
        )

    def read_incident(
        self, *, principal: PrincipalContract, incident_ref: str
    ) -> tuple[ResourceContract, tuple[MessagePart, ...], tuple[CitationContract, ...]]:
        del principal, incident_ref
        return (
            self._resource("incident"),
            self._content("redacted"),
            (self._citation(),),
        )

    def list_evidence(
        self,
        *,
        principal: PrincipalContract,
        incident_ref: str,
        offset: int,
        limit: int,
    ) -> tuple[tuple[ResourceContract, ...], bool]:
        del principal, incident_ref, limit
        return (self._resource("evidence"),), offset == 0

    def search_memory(
        self,
        *,
        principal: PrincipalContract,
        query_digest: str,
        incident_ref: str,
        limit: int,
    ) -> tuple[tuple[ResourceContract, ...], tuple[CitationContract, ...]]:
        del principal, query_digest, incident_ref, limit
        return (self._resource("memory"),), (self._citation(),)

    def read_runbook(
        self, *, principal: PrincipalContract, runbook_ref: str
    ) -> tuple[ResourceContract, tuple[MessagePart, ...], tuple[CitationContract, ...]]:
        del principal, runbook_ref
        return (
            self._resource("runbook"),
            self._content("safe steps"),
            (self._citation(),),
        )

    def read_status(
        self, *, principal: PrincipalContract, run_ref: str
    ) -> tuple[ResourceContract, tuple[MessagePart, ...]]:
        del principal, run_ref
        return self._resource("status"), self._content("working")

    def submit_investigation(
        self,
        *,
        principal: PrincipalContract,
        incident_ref: str,
        request_digest: str,
        idempotency_key: str,
    ) -> str:
        del principal, incident_ref, request_digest, idempotency_key
        return "investigation-ref-001"

    def submit_layer7_proposal(
        self,
        *,
        principal: PrincipalContract,
        submission: ProposalSubmission,
        idempotency_key: str,
    ) -> ProposalReceipt:
        del principal, submission, idempotency_key
        return ProposalReceipt(
            proposal_ref="proposal-ref-001",
            proposal_digest="6" * 64,
            status="layer7-proposal-recorded",
        )


def _mcp_server() -> CuratedMcpServer:
    return CuratedMcpServer(
        application=_McpApplication(),
        authorization=_McpAuthorization(),
        tools=curated_tools(),
        now=lambda: NOW,
    )


@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        (McpToolName.INCIDENT_READ, {"resource_ref": "incident-001"}),
        (
            McpToolName.EVIDENCE_LIST,
            {"resource_ref": "incident-001", "limit": 10},
        ),
        (
            McpToolName.MEMORY_SEARCH,
            {"resource_ref": "incident-001", "query": "checkout", "limit": 3},
        ),
        (McpToolName.RUNBOOK_READ, {"resource_ref": "runbook-001"}),
        (McpToolName.STATUS_READ, {"resource_ref": "run-001"}),
        (
            McpToolName.INVESTIGATION_SUBMIT,
            {"resource_ref": "incident-001"},
        ),
    ],
)
def test_curated_mcp_server_tools(
    name: McpToolName,
    arguments: dict[str, JsonValue],
) -> None:
    result = _mcp_server().call(
        principal=_principal(),
        request=McpCallRequest(
            call_id=f"call-{name.name.lower()}",
            tool_name=name,
            arguments=arguments,
            idempotency_key=f"key-{name.name.lower()}",
        ),
        cancelled=lambda: False,
    )
    assert result.status == "completed"
    assert result.result_digest


def test_mcp_proposal_only_pagination_cancel_and_authority_rejection() -> None:
    citation = _McpApplication()._citation()
    proposal = {
        "title": "Restart checkout proposal",
        "summary": "Cited bounded proposal for independent Layer 7 review.",
        "risk": "high",
        "citations": [citation.model_dump(mode="json")],
        "requested_action_kind": "kubernetes-rollout-restart",
    }
    result = _mcp_server().call(
        principal=_principal(),
        request=McpCallRequest(
            call_id="call-proposal",
            tool_name=McpToolName.PROPOSAL_SUBMIT,
            arguments={"resource_ref": "incident-001", "proposal": proposal},
            idempotency_key="key-proposal",
        ),
        cancelled=lambda: False,
    )
    assert result.proposal_ref == "proposal-ref-001"
    assert "approval" not in result.model_dump_json()
    assert "effect" not in result.model_dump_json()
    cancelled = _mcp_server().call(
        principal=_principal(),
        request=McpCallRequest(
            call_id="call-cancelled",
            tool_name=McpToolName.STATUS_READ,
            arguments={"resource_ref": "run-001"},
            idempotency_key="key-cancelled",
        ),
        cancelled=lambda: True,
    )
    assert cancelled.status == "cancelled"
    with pytest.raises(ValidationError, match="authority"):
        McpCallRequest(
            call_id="call-forged",
            tool_name=McpToolName.STATUS_READ,
            arguments={
                "resource_ref": "run-001",
                "tenant_id": "attacker",
                "roles": ["admin"],
            },
            idempotency_key="key-forged",
        )


class _McpSdk(McpSdkClientPort):
    loop = False

    def initialize(
        self,
        *,
        registration: McpClientRegistration,
        peer: TrustEntry,
    ) -> McpInitialization:
        del registration, peer
        return McpInitialization(
            negotiated_protocol_version=MCP_SPEC_VERSION,
            client_name_digest="1" * 64,
            client_version_digest="2" * 64,
            capabilities=("tools",),
            session_ref="session-ref",
            initialized_at=NOW,
        )

    def list_tools(
        self,
        *,
        registration: McpClientRegistration,
        initialization: McpInitialization,
        cursor: str | None,
    ) -> tuple[tuple[Any, ...], str | None]:
        del registration, initialization
        return (curated_tools()[4],), ("same" if self.loop else None)

    def call_tool(
        self,
        *,
        registration: McpClientRegistration,
        initialization: McpInitialization,
        name: str,
        arguments: Mapping[str, JsonValue],
        timeout_seconds: float,
        cancelled: Callable[[], bool],
    ) -> McpCallResult:
        del registration, initialization, timeout_seconds, cancelled
        material = {
            "call_id": "call-sdk",
            "status": "completed",
            "resources": [],
            "content": [],
            "citations": [],
            "next_cursor": None,
            "proposal_ref": None,
            "redaction_count": 0,
            "schema_version": 1,
        }
        assert name == McpToolName.STATUS_READ
        assert arguments["resource_ref"] == "run-001"
        return McpCallResult(**material, result_digest=digest_value(material))

    def close(
        self,
        *,
        registration: McpClientRegistration,
        initialization: McpInitialization,
    ) -> None:
        del registration, initialization


def _mcp_registration() -> McpClientRegistration:
    return McpClientRegistration(
        registration_id="mcp-registration",
        tenant_ref="tenant-ref-acme",
        peer_id="peer-001",
        required_peer_environment="staging",
        minimum_trust_tier=TrustTier.PARTNER,
        supported_protocol_versions=(MCP_SPEC_VERSION,),
        required_capabilities=("tools",),
        allowed_tools=(McpToolName.STATUS_READ,),
        allowed_resources=("status",),
        schema_digest="6" * 64,
        risk_ceiling=RiskLevel.LOW,
        maximum_calls_per_minute=100,
        maximum_cost_units_per_hour=100,
        maximum_concurrency=2,
        maximum_response_bytes=8192,
        transport=NetworkMcpRegistration(
            endpoint_origin="https://peer.example.com",
            endpoint_path="/mcp",
            secret_reference="secret-mcp",
            secret_version=1,
            certificate_digest="7" * 64,
            server_name="peer.example.com",
            timeout_seconds=10,
        ),
    )


def test_hardened_mcp_client_negotiation_allowlist_and_cursor_loop() -> None:
    sdk = _McpSdk()
    client = HardenedMcpClient(
        registration=_mcp_registration(),
        peer=_trust(),
        sdk=sdk,
        now=lambda: NOW,
    )
    assert client.initialize().negotiated_protocol_version == MCP_SPEC_VERSION
    assert client.discover_tools()[0].name == McpToolName.STATUS_READ
    result = client.call(
        name=McpToolName.STATUS_READ,
        arguments={"resource_ref": "run-001"},
        timeout_seconds=10,
        cancelled=lambda: False,
    )
    assert result.status == "completed"
    with pytest.raises(PolicyDenied, match="allowlisted"):
        client.call(
            name="untrusted.tool",
            arguments={},
            timeout_seconds=10,
            cancelled=lambda: False,
        )
    client.close()

    loop_sdk = _McpSdk()
    loop_sdk.loop = True
    loop_client = HardenedMcpClient(
        registration=_mcp_registration(),
        peer=_trust(),
        sdk=loop_sdk,
        now=lambda: NOW,
    )
    loop_client.initialize()
    with pytest.raises(PayloadRejected, match="cursor loop"):
        loop_client.discover_tools()

    class _HighRiskSdk(_McpSdk):
        def list_tools(
            self,
            *,
            registration: McpClientRegistration,
            initialization: McpInitialization,
            cursor: str | None,
        ) -> tuple[tuple[ToolContract, ...], str | None]:
            del registration, initialization, cursor
            base = curated_tools()[4]
            return (base.model_copy(update={"risk": RiskLevel.HIGH}),), None

    high_risk = HardenedMcpClient(
        registration=_mcp_registration(),
        peer=_trust(),
        sdk=_HighRiskSdk(),
        now=lambda: NOW,
    )
    high_risk.initialize()
    with pytest.raises(PolicyDenied, match="untrusted tool"):
        high_risk.discover_tools()


class _A2AAuthorization(A2AServerAuthorizationPort):
    def authorize(
        self,
        *,
        principal: PrincipalContract,
        skill: Any,
        resource_ref: str,
    ) -> bool:
        del principal, skill, resource_ref
        return True


class _A2AApplication(A2AServerPort):
    def start_investigation(
        self,
        *,
        principal: PrincipalContract,
        message: MessageContract,
        idempotency_key_digest: str,
    ) -> str:
        del principal, message, idempotency_key_digest
        return "a2a-task-ref-001"

    def read_status(
        self, *, principal: PrincipalContract, task_ref: str
    ) -> StatusContract:
        del principal, task_ref
        return _status(TaskState.WORKING)

    def read_artifacts(
        self,
        *,
        principal: PrincipalContract,
        task_ref: str,
        cursor_digest: str | None,
        limit: int,
    ) -> tuple[tuple[ArtifactContract, ...], str | None]:
        del principal, task_ref, cursor_digest, limit
        return (), None

    def submit_layer7_proposal(
        self,
        *,
        principal: PrincipalContract,
        message: MessageContract,
        idempotency_key_digest: str,
    ) -> str:
        del principal, message, idempotency_key_digest
        return "proposal-ref-001"

    def cancel(
        self,
        *,
        principal: PrincipalContract,
        task_ref: str,
        command_digest: str,
    ) -> StatusContract:
        del principal, task_ref, command_digest
        return _status(TaskState.CANCELLED)


def _card() -> tuple[AgentCardContract, DigestCardSigner]:
    signer = DigestCardSigner({"key-ref": "secret-signing-material"})
    return (
        build_aegis_agent_card(
            peer_id="a2a-peer",
            protocol_version=A2A_PROTOCOL_VERSION,
            endpoint_origin="https://peer.example.com/a2a",
            key_ref="key-ref",
            key_digest=digest_value("secret-signing-material"),
            signer=signer,
            issued_at=NOW,
            expires_at=NOW + timedelta(days=1),
        ),
        signer,
    )


def test_a2a_card_server_skills_idempotency_and_cancel() -> None:
    card, _ = _card()
    server = BoundedA2AServer(
        card=card,
        application=_A2AApplication(),
        authorization=_A2AAuthorization(),
        now=lambda: NOW,
    )
    for skill in A2ASkillName:
        response = server.submit(
            principal=_principal(),
            request=A2ATaskRequest(
                request_id=f"request-{skill.name.lower()}",
                skill_id=skill,
                message=_message(),
                resource_ref="task-ref-001",
                idempotency_key_digest=digest_value(skill),
            ),
        )
        assert response.response_digest
        assert response.status.occurred_at == NOW
    request = A2ATaskRequest(
        request_id="request-replay",
        skill_id=A2ASkillName.INVESTIGATE,
        message=_message(),
        resource_ref="incident-001",
        idempotency_key_digest="f" * 64,
    )
    assert server.submit(principal=_principal(), request=request) == server.submit(
        principal=_principal(), request=request
    )
    with pytest.raises(IdempotencyConflict):
        server.submit(
            principal=_principal(),
            request=request.model_copy(update={"resource_ref": "changed"}),
        )
    assert (
        server.cancel(
            principal=_principal(),
            task_ref="task-ref-001",
            command_digest="1" * 64,
        ).status.state
        is TaskState.CANCELLED
    )


class _A2ASdk(A2ASdkClientPort):
    def __init__(self, card: AgentCardContract) -> None:
        self.card = card
        self.mode = "success"

    def discover_card(
        self, *, registration: A2APeerRegistration
    ) -> Mapping[str, JsonValue]:
        del registration
        return self.card.model_dump(mode="json")

    def accept_card(
        self,
        *,
        registration: A2APeerRegistration,
        card: AgentCardContract,
    ) -> None:
        del registration
        if card != self.card:
            raise PolicyDenied("card changed")

    def _response(self, task: TaskContract, state: TaskState) -> A2ATaskResponse:
        status = _status(state)
        material = {
            "task_ref": task.task_id,
            "status": status.model_dump(mode="json"),
            "artifacts": [],
            "next_cursor_digest": None,
            "proposal_ref": None,
            "schema_version": 1,
        }
        return A2ATaskResponse(**material, response_digest=digest_value(material))

    def send_task(
        self,
        *,
        registration: A2APeerRegistration,
        card: AgentCardContract,
        task: TaskContract,
        message: MessageContract,
        streaming: bool,
        cancelled: Callable[[], bool],
    ) -> A2ATaskResponse:
        del registration, card, message, streaming, cancelled
        if self.mode == "ambiguous":
            raise TimeoutError
        return self._response(task, TaskState.COMPLETED)

    def poll_task(
        self,
        *,
        registration: A2APeerRegistration,
        card: AgentCardContract,
        task: TaskContract,
    ) -> A2ATaskResponse:
        del registration, card
        return self._response(task, TaskState.COMPLETED)

    def cancel_task(
        self,
        *,
        registration: A2APeerRegistration,
        card: AgentCardContract,
        task: TaskContract,
    ) -> A2ATaskResponse:
        del registration, card
        return self._response(task, TaskState.CANCELLED)


def _a2a_registration(card: AgentCardContract) -> A2APeerRegistration:
    return A2APeerRegistration(
        registration_id="a2a-registration",
        tenant_ref="tenant-ref-acme",
        peer_id="a2a-peer",
        required_peer_environment="staging",
        minimum_trust_tier=TrustTier.PARTNER,
        discovery_origin="https://peer.example.com",
        rpc_path="/a2a",
        supported_protocol_versions=(A2A_PROTOCOL_VERSION,),
        allowed_skills=tuple(skill.skill_id for skill in card.skills),
        allowed_transports=(TransportKind.JSON_RPC_HTTP,),
        card_digest=card.card_digest,
        schema_digest="6" * 64,
        certificate_digest="7" * 64,
        secret_reference="secret-a2a",
        secret_version=1,
        maximum_response_bytes=8192,
        timeout_seconds=10,
        poll_interval_seconds=1,
        maximum_poll_attempts=10,
        stream_event_limit=100,
    )


def _a2a_task(card: AgentCardContract) -> TaskContract:
    return TaskContract(
        task_id="task-a2a",
        protocol=ProtocolKind.A2A,
        peer_id="a2a-peer",
        capability_id=A2ASkillName.STATUS,
        tenant_ref="tenant-ref-acme",
        principal_ref="workload-aegis",
        purpose="incident-response",
        request_digest="1" * 64,
        idempotency_key_digest="2" * 64,
        policy_digest="3" * 64,
        trust_revision=2,
        fence_token="fence-a2a",
        state=TaskState.SUBMITTED,
        created_at=NOW,
        updated_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def test_a2a_gateway_signed_discovery_send_poll_cancel_and_ambiguity() -> None:
    card, _ = _card()
    sdk = _A2ASdk(card)
    trust = _trust(
        protocol=ProtocolKind.A2A,
        peer_id="a2a-peer",
        capability=A2ASkillName.STATUS,
        card_digest=card.card_digest,
    ).model_copy(
        update={
            "card_digest": card.card_digest,
            "key_digest": card.key_digest,
            "allowed_transports": (TransportKind.JSON_RPC_HTTP,),
        }
    )
    gateway = A2APeerGateway(
        registration=_a2a_registration(card),
        trust=trust,
        sdk=sdk,
        parse_card=lambda _: card,
        now=lambda: NOW,
    )
    assert gateway.discover() == card
    task = _a2a_task(card)
    assert (
        gateway.send(
            task=task,
            message=_message(),
            streaming=True,
            cancelled=lambda: False,
        ).status.state
        is TaskState.COMPLETED
    )
    assert gateway.poll(task=task).status.state is TaskState.COMPLETED
    assert gateway.cancel(task=task).status.state is TaskState.CANCELLED
    sdk.mode = "ambiguous"
    with pytest.raises(ReconciliationRequired):
        gateway.send(
            task=task,
            message=_message(),
            streaming=False,
            cancelled=lambda: False,
        )


class _PrincipalResolver(McpPrincipalResolver):
    def resolve(self, context: Any) -> PrincipalContract:
        del context
        return _principal()


def test_official_sdk_versions_and_mcp_server_surface() -> None:
    assert MCP_SPEC_VERSION == "2026-07-28"
    assert MCP_SDK_VERSION == "2.0.0"
    assert A2A_PROTOCOL_VERSION == "1.0"
    assert A2A_SPEC_TAG == "v1.0.1"
    assert A2A_SDK_VERSION == "1.1.2"
    adapter = OfficialMcpServerAdapter(
        server=_mcp_server(),
        principals=_PrincipalResolver(),
        cancelled=lambda: False,
    )
    sdk = adapter.build()
    tools = asyncio.run(sdk.list_tools())
    assert tuple(tool.name for tool in tools) == tuple(
        tool.name for tool in curated_tools()
    )
    assert all(
        type(middleware).__name__ != "OpenTelemetryMiddleware"
        for middleware in sdk.middleware
    )
    app = adapter.streamable_http_app(
        allowed_hosts=("mcp.example.com",),
        allowed_origins=("https://operator.example.com",),
    )
    assert app is not None
    assert {item.protocol for item in curated_capabilities()} == {ProtocolKind.MCP}


def test_temporal_protocol_inputs_are_opaque_and_workflows_are_versioned() -> None:
    value = InteropWorkflowInput(
        tenant_ref="tenant-ref-acme",
        principal_ref="workload-aegis",
        operation_id="operation-temporal",
        peer_id="peer-001",
        protocol=ProtocolKind.MCP,
        operation=InteropOperation.MCP_INVOKE,
        request_digest="1" * 64,
        trust_digest="2" * 64,
        policy_digest="3" * 64,
        idempotency_key_digest="4" * 64,
        fence_token="fence-temporal",
    )
    dumped = value.model_dump(mode="json")
    assert not {
        "content",
        "message",
        "prompt",
        "raw",
        "secret",
        "tenant_id",
        "token",
        "url",
    }.intersection(dumped)
    with pytest.raises(ValidationError):
        InteropWorkflowInput.model_validate(dumped | {"raw": "forbidden"})
    assert (
        AegisMcpInvocationWorkflow.__temporal_workflow_definition.name
        == "aegis.mcp.invocation.v1"
    )
    assert (
        AegisA2ATaskWorkflow.__temporal_workflow_definition.name == "aegis.a2a.task.v1"
    )


def test_protocol_contract_edge_bounds_fail_closed() -> None:
    with pytest.raises(ValidationError, match="at least one"):
        PrincipalContract.model_validate(_principal().model_dump() | {"scopes": []})
    with pytest.raises(ValidationError, match="expire"):
        PrincipalContract.model_validate(
            _principal().model_dump() | {"expires_at": NOW}
        )
    with pytest.raises(ValidationError, match="exactly one"):
        MessagePart(
            part_id="part-shape",
            kind="text",
            media_type="text/plain",
            text="one",
            data={"two": True},
            content_digest=digest_value("one"),
        )
    with pytest.raises(ValidationError, match="kind"):
        MessagePart(
            part_id="part-kind",
            kind="data",
            media_type="text/plain",
            text="one",
            content_digest=digest_value("one"),
        )
    with pytest.raises(PayloadRejected, match="non-finite"):
        canonical_json({"value": float("inf")})
    with pytest.raises(PayloadRejected, match="unsupported"):
        canonical_json({1, 2})
    with pytest.raises(PayloadRejected, match="member"):
        canonical_json({f"k-{index}": index for index in range(129)})
    with pytest.raises(ValueError, match="control"):
        validate_untrusted_text("unsafe\x00text")


def test_registry_denies_wrong_scope_expiry_and_invalid_transitions() -> None:
    registry = TrustRegistry()
    pending = _trust(status=TrustStatus.PENDING_REVIEW, revision=1).model_copy(
        update={"allowed_risks": (RiskLevel.LOW,)}
    )
    registry.register(pending)
    with pytest.raises(PolicyDenied, match="unavailable"):
        registry.quarantine(
            peer_id="missing",
            expected_revision=1,
            reviewer_ref="reviewer",
            now=NOW,
            typed_confirmation="QUARANTINE missing",
        )
    active = registry.review(
        peer_id="peer-001",
        expected_revision=1,
        reviewer_ref="reviewer",
        now=NOW,
        typed_confirmation="TRUST peer-001",
    )
    with pytest.raises(PolicyDenied, match="pending"):
        registry.review(
            peer_id="peer-001",
            expected_revision=active.revision,
            reviewer_ref="reviewer",
            now=NOW,
            typed_confirmation="TRUST peer-001",
        )
    for changes, match in (
        ({"protocol": ProtocolKind.A2A}, "protocol"),
        ({"capability_id": "unknown"}, "capability"),
        ({"risk": RiskLevel.MEDIUM}, "risk"),
        ({"classification": DataClassification.RESTRICTED}, "classification"),
        ({"now": NOW + timedelta(days=8)}, "expired"),
        ({"expected_environment": "production"}, "environment"),
        ({"minimum_trust_tier": TrustTier.INTERNAL}, "tier"),
    ):
        arguments: dict[str, Any] = {
            "peer_id": "peer-001",
            "protocol": ProtocolKind.MCP,
            "capability_id": "mcp-aegis-status-read",
            "risk": RiskLevel.LOW,
            "classification": DataClassification.INTERNAL,
            "now": NOW,
        }
        arguments.update(changes)
        with pytest.raises(PolicyDenied, match=match):
            registry.require_active(**arguments)
    changed_protocol = pending.model_copy(
        update={
            "revision": 3,
            "protocol": ProtocolKind.A2A,
            "card_digest": "5" * 64,
        }
    )
    with pytest.raises(IntegrityFailure, match="protocol"):
        registry.register(changed_protocol)


@pytest.mark.parametrize(
    ("update", "error"),
    [
        ({"issuer_digest": "f" * 64}, "issuer"),
        ({"audience": "wrong"}, "audience"),
        ({"principal_ref": "other"}, "principal"),
        ({"purpose": "other"}, "purpose"),
        ({"scopes": ("other",)}, "scopes"),
        ({"confirmation_digest": "f" * 64}, "channel"),
        ({"issued_at": NOW + timedelta(seconds=1)}, "validity"),
        (
            {"expires_at": NOW + timedelta(minutes=20)},
            "lifetime",
        ),
    ],
)
def test_workload_identity_claim_failures(
    update: dict[str, object],
    error: str,
) -> None:
    policy = WorkloadIdentityPolicy(
        audience="aegis-protocol",
        allowed_issuer_digests=("1" * 64,),
        required_scopes=("interop:invoke",),
        allowed_purposes=("incident-response",),
        maximum_lifetime_seconds=600,
        require_mutual_tls=True,
        allowed_principals=("workload-aegis",),
    )
    assertion = WorkloadIdentityAssertion(
        principal_ref="workload-aegis",
        issuer_digest="1" * 64,
        audience="aegis-protocol",
        scopes=("interop:invoke",),
        tenant_ref="tenant-ref-acme",
        purpose="incident-response",
        token_id_digest=digest_value(update),
        proof_digest="3" * 64,
        confirmation_digest="4" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    ).model_copy(update=update)
    validator = WorkloadIdentityValidator(
        policy=policy,
        replay_cache=InMemoryReplayCache(),
        mutual_tls_ready=lambda: True,
        production=False,
    )
    expected = (
        PolicyDenied
        if error in {"principal", "purpose", "scopes"}
        else AuthenticationFailed
    )
    with pytest.raises(expected, match=error):
        validator.validate(
            assertion,
            expected_tenant_ref="tenant-ref-acme",
            expected_purpose="incident-response",
            channel_binding_digest="4" * 64,
            now=NOW,
        )


def test_workload_identity_replay_scope_is_transport_bound() -> None:
    policy = WorkloadIdentityPolicy(
        audience="aegis-global",
        allowed_issuer_digests=("1" * 64, "2" * 64),
        required_scopes=("interop:invoke",),
        allowed_purposes=("incident-response",),
        maximum_lifetime_seconds=600,
        require_mutual_tls=True,
        allowed_principals=("workload-aegis",),
    )
    validator = WorkloadIdentityValidator(
        policy=policy,
        replay_cache=InMemoryReplayCache(),
        mutual_tls_ready=lambda: True,
        production=False,
    )
    shared = {
        "principal_ref": "workload-aegis",
        "scopes": ("interop:invoke",),
        "tenant_ref": "tenant-ref-acme",
        "purpose": "incident-response",
        "token_id_digest": "2" * 64,
        "proof_digest": "3" * 64,
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=5),
    }
    first = WorkloadIdentityAssertion(
        **shared,
        issuer_digest="1" * 64,
        audience="mcp-http",
        confirmation_digest="4" * 64,
    )
    second = WorkloadIdentityAssertion(
        **shared,
        issuer_digest="2" * 64,
        audience="a2a-jsonrpc",
        confirmation_digest="5" * 64,
    )
    assert (
        validator.validate(
            first,
            expected_tenant_ref="tenant-ref-acme",
            expected_purpose="incident-response",
            channel_binding_digest="4" * 64,
            expected_audience="mcp-http",
            allowed_issuer_digests=("1" * 64,),
            now=NOW,
        ).audience
        == "mcp-http"
    )
    assert (
        validator.validate(
            second,
            expected_tenant_ref="tenant-ref-acme",
            expected_purpose="incident-response",
            channel_binding_digest="5" * 64,
            expected_audience="a2a-jsonrpc",
            allowed_issuer_digests=("2" * 64,),
            now=NOW,
        ).audience
        == "a2a-jsonrpc"
    )


def test_ledger_projection_and_quota_conflicts_are_explicit() -> None:
    ledger = InteroperabilityLedger()
    base = InvocationProjection(
        operation_id="operation-conflict",
        tenant_ref="tenant-ref-acme",
        peer_id="peer-001",
        protocol=ProtocolKind.MCP,
        capability_id="mcp-aegis-status-read",
        risk=RiskLevel.LOW,
        state=InvocationState.REQUESTED,
        version=1,
        request_digest="1" * 64,
        trust_digest="2" * 64,
        policy_digest="3" * 64,
        trust_revision=2,
        fence_token="fence-conflict",
        updated_at=NOW,
    )
    ledger.append(
        operation_id=base.operation_id,
        fact_type=InteroperabilityFactType.INVOCATION_REQUESTED,
        command_ref="command-base",
        actor_ref="actor",
        peer_id=base.peer_id,
        payload={"request_digest": base.request_digest},
        recorded_at=NOW,
        projection=base,
    )
    with pytest.raises(ConcurrencyConflict, match="projection"):
        ledger.append(
            operation_id=base.operation_id,
            fact_type=InteroperabilityFactType.INVOCATION_CLAIMED,
            command_ref="command-stale",
            actor_ref="actor",
            peer_id=base.peer_id,
            payload={"request_digest": base.request_digest},
            recorded_at=NOW,
            projection=base.model_copy(update={"version": 3}),
        )
    with pytest.raises(ValueError, match="quota"):
        InvocationQuota(request_limit=0, cost_limit=0)
    quota = InvocationQuota(request_limit=2, cost_limit=2)
    quota.reserve(
        tenant_ref="tenant-ref-acme",
        reservation_id="reservation-conflict",
        cost_units=1,
    )
    with pytest.raises(IdempotencyConflict, match="conflicts"):
        quota.reserve(
            tenant_ref="tenant-ref-other",
            reservation_id="reservation-conflict",
            cost_units=1,
        )
    with pytest.raises(ValueError, match="negative"):
        quota.reserve(
            tenant_ref="tenant-ref-acme",
            reservation_id="reservation-negative",
            cost_units=-1,
        )
    with pytest.raises(ValueError, match="threshold"):
        CircuitBreaker(failure_threshold=0)


def test_gateway_cancellation_conflicts_and_invalid_commands() -> None:
    capability = _capability()
    gateway, ledger = _gateway(_Transport(capability))
    cancelled = gateway.invoke(
        principal=_principal(),
        capability=capability,
        peer_id="peer-001",
        message=_message(),
        operation_id="operation-cancel",
        command_ref="command-cancel",
        idempotency_key="idempotency-cancel",
        tenant_ref="tenant-ref-acme",
        classification=DataClassification.INTERNAL,
        cost_units=1,
        timeout_seconds=10,
        cancelled=lambda: True,
    )
    assert cancelled.task.state is TaskState.CANCELLED
    assert ledger.projection("operation-cancel").cancellation_requested  # type: ignore[union-attr]
    with pytest.raises(PolicyDenied, match="terminal"):
        gateway.cancel(
            principal=_principal(),
            operation_id="operation-cancel",
            command_ref="command-cancel-again",
            timeout_seconds=10,
        )
    with pytest.raises(PolicyDenied, match="unavailable"):
        gateway.cancel(
            principal=_principal(),
            operation_id="missing",
            command_ref="command-missing",
            timeout_seconds=10,
        )
    with pytest.raises(PolicyDenied, match="ambiguous"):
        gateway.reconcile(
            principal=_principal(),
            operation_id="operation-cancel",
            command_ref="command-invalid-reconcile",
            classification=DataClassification.INTERNAL,
            timeout_seconds=10,
        )
    with pytest.raises(PolicyDenied, match="tenant"):
        gateway.invoke(
            principal=_principal(),
            capability=capability,
            peer_id="peer-001",
            message=_message(),
            operation_id="operation-tenant",
            command_ref="command-tenant",
            idempotency_key="idempotency-tenant",
            tenant_ref="tenant-ref-other",
            classification=DataClassification.INTERNAL,
            cost_units=1,
            timeout_seconds=10,
            cancelled=lambda: False,
        )
    with pytest.raises(PayloadRejected, match="timeout"):
        gateway.invoke(
            principal=_principal(),
            capability=capability,
            peer_id="peer-001",
            message=_message(),
            operation_id="operation-timeout",
            command_ref="command-timeout",
            idempotency_key="idempotency-timeout",
            tenant_ref="tenant-ref-acme",
            classification=DataClassification.INTERNAL,
            cost_units=1,
            timeout_seconds=121,
            cancelled=lambda: False,
        )


def test_mcp_registration_and_client_fail_closed_edges() -> None:
    with pytest.raises(ValidationError, match="absolute"):
        FixedStdioRegistration(
            executable="relative-command",
            arguments=(),
            executable_digest="1" * 64,
            working_directory="/opt/aegis",
        )
    sdk = _McpSdk()
    registration = _mcp_registration()
    with pytest.raises(ValueError, match="schema pin"):
        HardenedMcpClient(
            registration=registration,
            peer=_trust().model_copy(update={"schema_digest": "f" * 64}),
            sdk=sdk,
            now=lambda: NOW,
        )
    client = HardenedMcpClient(
        registration=registration,
        peer=_trust(),
        sdk=sdk,
        now=lambda: NOW,
    )
    with pytest.raises(PolicyDenied, match="initialized"):
        client.call(
            name=McpToolName.STATUS_READ,
            arguments={},
            timeout_seconds=1,
            cancelled=lambda: False,
        )
    with pytest.raises(PolicyDenied, match="initialized"):
        client.close()


def test_a2a_server_and_gateway_reject_unknown_or_unverified_peers() -> None:
    card, _ = _card()

    class _Denied(A2AServerAuthorizationPort):
        def authorize(
            self,
            *,
            principal: PrincipalContract,
            skill: Any,
            resource_ref: str,
        ) -> bool:
            del principal, skill, resource_ref
            return False

    server = BoundedA2AServer(
        card=card,
        application=_A2AApplication(),
        authorization=_Denied(),
        now=lambda: NOW,
    )
    with pytest.raises(PolicyDenied, match="denied"):
        server.submit(
            principal=_principal(),
            request=A2ATaskRequest(
                request_id="request-denied",
                skill_id=A2ASkillName.STATUS,
                message=_message(),
                resource_ref="task-001",
                idempotency_key_digest="1" * 64,
            ),
        )
    sdk = _A2ASdk(card)
    trust = _trust(
        protocol=ProtocolKind.A2A,
        peer_id="a2a-peer",
        capability=A2ASkillName.STATUS,
        card_digest=card.card_digest,
    ).model_copy(
        update={
            "card_digest": card.card_digest,
            "key_digest": card.key_digest,
            "allowed_transports": (TransportKind.JSON_RPC_HTTP,),
        }
    )
    gateway = A2APeerGateway(
        registration=_a2a_registration(card),
        trust=trust,
        sdk=sdk,
        parse_card=lambda _: card,
        now=lambda: NOW,
    )
    with pytest.raises(PolicyDenied, match="discovered"):
        gateway.send(
            task=_a2a_task(card),
            message=_message(),
            streaming=False,
            cancelled=lambda: False,
        )
    wrong = card.model_copy(update={"peer_id": "wrong-peer"})
    bad_gateway = A2APeerGateway(
        registration=_a2a_registration(card),
        trust=trust,
        sdk=sdk,
        parse_card=lambda _: wrong,
        now=lambda: NOW,
    )
    with pytest.raises(PolicyDenied, match="peer identity"):
        bad_gateway.discover()


def test_review_regressions_preserve_tenant_and_card_pins() -> None:
    capability = _capability()
    transport = _Transport(capability)
    transport.mode = "ambiguous"
    gateway, ledger = _gateway(transport)
    with pytest.raises(ReconciliationRequired):
        gateway.invoke(
            principal=_principal(),
            capability=capability,
            peer_id="peer-001",
            message=_message(),
            operation_id="operation-tenant-bound",
            command_ref="command-tenant-bound",
            idempotency_key="idempotency-tenant-bound",
            tenant_ref="tenant-ref-acme",
            classification=DataClassification.INTERNAL,
            cost_units=1,
            timeout_seconds=10,
            cancelled=lambda: False,
        )
    attacker = _principal().model_copy(update={"tenant_ref": "tenant-ref-attacker"})
    with pytest.raises(PolicyDenied, match="tenant binding"):
        gateway.reconcile(
            principal=attacker,
            operation_id="operation-tenant-bound",
            command_ref="command-cross-tenant-reconcile",
            classification=DataClassification.INTERNAL,
            timeout_seconds=10,
        )
    with pytest.raises(PolicyDenied, match="tenant binding"):
        gateway.cancel(
            principal=attacker,
            operation_id="operation-tenant-bound",
            command_ref="command-cross-tenant-cancel",
            timeout_seconds=10,
        )
    projection = ledger.projection("operation-tenant-bound")
    assert projection is not None
    assert projection.tenant_ref == "tenant-ref-acme"

    document: dict[str, Any] = {
        "name": "Partner investigator",
        "description": "Bounded status peer",
        "supportedInterfaces": [
            {
                "url": "https://peer.example.com/a2a",
                "protocolBinding": "JSONRPC",
                "protocolVersion": "1.0",
            }
        ],
        "skills": [
            {
                "id": "read-investigation-status",
                "name": "Read status",
                "description": "Read bounded status",
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            }
        ],
        "signatures": [
            {
                "protected": base64.urlsafe_b64encode(
                    json.dumps(
                        {"alg": "ES256", "kid": "partner-key", "typ": "JOSE"},
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode()
                )
                .rstrip(b"=")
                .decode(),
                "signature": "signature",
            }
        ],
    }
    first = parse_official_agent_card(document)
    second = parse_official_agent_card(document)
    assert first.card_digest == second.card_digest
    assert first.issued_at == second.issued_at
    resigned = parse_official_agent_card(
        document
        | {
            "signatures": [
                {
                    **document["signatures"][0],
                    "signature": "different-signature",
                }
            ]
        }
    )
    assert resigned.card_digest == first.card_digest
    with pytest.raises(PayloadRejected, match="bytes"):
        parse_official_agent_card(
            document
            | {
                "signatures": [
                    {
                        "protected": document["signatures"][0]["protected"],
                    }
                ]
            }
        )


def test_transport_clients_reject_environment_and_tier_drift() -> None:
    registration = _mcp_registration()
    with pytest.raises(PolicyDenied, match="environment"):
        HardenedMcpClient(
            registration=registration.model_copy(
                update={"required_peer_environment": "production"}
            ),
            peer=_trust(),
            sdk=_McpSdk(),
            now=lambda: NOW,
        ).initialize()
    with pytest.raises(PolicyDenied, match="tier"):
        HardenedMcpClient(
            registration=registration.model_copy(
                update={"minimum_trust_tier": TrustTier.INTERNAL}
            ),
            peer=_trust(),
            sdk=_McpSdk(),
            now=lambda: NOW,
        ).initialize()
    card, _ = _card()
    trust = _trust(
        protocol=ProtocolKind.A2A,
        peer_id="a2a-peer",
        capability=A2ASkillName.STATUS,
        card_digest=card.card_digest,
    ).model_copy(
        update={
            "card_digest": card.card_digest,
            "key_digest": card.key_digest,
            "allowed_transports": (TransportKind.JSON_RPC_HTTP,),
        }
    )
    with pytest.raises(PolicyDenied, match="environment"):
        A2APeerGateway(
            registration=_a2a_registration(card).model_copy(
                update={"required_peer_environment": "production"}
            ),
            trust=trust,
            sdk=_A2ASdk(card),
            parse_card=lambda _: card,
            now=lambda: NOW,
        ).discover()
    with pytest.raises(PolicyDenied, match="tier"):
        A2APeerGateway(
            registration=_a2a_registration(card).model_copy(
                update={"minimum_trust_tier": TrustTier.INTERNAL}
            ),
            trust=trust,
            sdk=_A2ASdk(card),
            parse_card=lambda _: card,
            now=lambda: NOW,
        ).discover()


def test_a2a_idempotency_reauthorizes_and_circuit_recovers() -> None:
    card, _ = _card()

    class _TenantAuthorization(A2AServerAuthorizationPort):
        def authorize(
            self,
            *,
            principal: PrincipalContract,
            skill: Any,
            resource_ref: str,
        ) -> bool:
            del skill, resource_ref
            return principal.tenant_ref == "tenant-ref-acme"

    server = BoundedA2AServer(
        card=card,
        application=_A2AApplication(),
        authorization=_TenantAuthorization(),
        now=lambda: NOW,
        maximum_idempotency_entries=1,
    )
    request = A2ATaskRequest(
        request_id="request-principal-cache",
        skill_id=A2ASkillName.STATUS,
        message=_message(),
        resource_ref="task-001",
        idempotency_key_digest="d" * 64,
    )
    server.submit(principal=_principal(), request=request)
    attacker = _principal().model_copy(update={"tenant_ref": "tenant-ref-attacker"})
    with pytest.raises(PolicyDenied, match="denied"):
        server.submit(principal=attacker, request=request)

    observed = [0.0]
    circuit = CircuitBreaker(
        failure_threshold=1,
        cooldown_seconds=10,
        clock=lambda: observed[0],
    )
    circuit.record("peer", success=False)
    assert circuit.allow("peer") is False
    observed[0] = 11.0
    assert circuit.allow("peer") is True
    circuit.record("peer", success=True)
    assert circuit.allow("peer") is True


def test_remaining_protocol_digest_and_state_guards() -> None:
    task = _a2a_task(_card()[0])
    with pytest.raises(ValidationError, match="timestamps"):
        TaskContract.model_validate(task.model_dump() | {"updated_at": task.expires_at})
    artifact = _artifact(
        task=task,
        peer=_trust(),
        capability=_capability(),
    )
    with pytest.raises(ValidationError, match="artifact digest"):
        ArtifactContract.model_validate(
            artifact.model_dump() | {"artifact_digest": "f" * 64}
        )
    with pytest.raises(ValidationError, match="review must"):
        TrustEntry.model_validate(
            _trust().model_dump()
            | {
                "review_after": NOW + timedelta(days=31),
                "expires_at": NOW + timedelta(days=30),
            }
        )
    with pytest.raises(ValidationError, match="egress"):
        TrustEntry.model_validate(_trust().model_dump() | {"egress_origins": []})
    with pytest.raises(ValidationError, match="explicit review"):
        TrustEntry.model_validate(
            _trust().model_dump() | {"reviewed_by": [], "reviewed_at": None}
        )
    registry = TrustRegistry()
    with pytest.raises(PolicyDenied, match="await review"):
        registry.register(_trust(revision=1))
    material = {
        "call_id": "call-invalid-result",
        "status": "failed",
        "resources": [],
        "content": [],
        "citations": [],
        "next_cursor": None,
        "proposal_ref": "proposal-forged",
        "redaction_count": 0,
        "schema_version": 1,
    }
    with pytest.raises(ValidationError, match="failed MCP"):
        McpCallResult(**material, result_digest=digest_value(material))
    response_material = {
        "task_ref": "task-invalid",
        "status": _status(TaskState.FAILED).model_dump(mode="json"),
        "artifacts": [],
        "next_cursor_digest": None,
        "proposal_ref": None,
        "schema_version": 1,
    }
    with pytest.raises(ValidationError, match="response digest"):
        A2ATaskResponse(**response_material, response_digest="f" * 64)
    card, _ = _card()
    server = BoundedA2AServer(
        card=card,
        application=_A2AApplication(),
        authorization=_A2AAuthorization(),
        now=lambda: NOW,
    )
    with pytest.raises(PolicyDenied, match="unavailable"):
        server.submit(
            principal=_principal(),
            request=A2ATaskRequest(
                request_id="request-unknown-skill",
                skill_id="unknown-skill",
                message=_message(),
                resource_ref="task-001",
                idempotency_key_digest="e" * 64,
            ),
        )
