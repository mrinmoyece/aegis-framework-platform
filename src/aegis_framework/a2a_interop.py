"""Application-owned A2A cards, skills, task lifecycle, and provenance."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Protocol, Self
from urllib.parse import urlsplit

from pydantic import Field, JsonValue, field_validator, model_validator

from aegis_framework.domain import Identifier, OpaqueReference, RiskLevel, StrictModel
from aegis_framework.errors import (
    AmbiguousTransportError,
    IdempotencyConflict,
    PayloadRejected,
    PolicyDenied,
    ReconciliationRequired,
)
from aegis_framework.interoperability import (
    MAX_PROTOCOL_DOCUMENT_BYTES,
    AgentCardContract,
    AgentSkillContract,
    ArtifactContract,
    MessageContract,
    PrincipalContract,
    StatusContract,
    TaskContract,
    TaskState,
    TransportKind,
    TrustEntry,
    canonical_json,
    digest_value,
)


class A2ASkillName(StrEnum):
    INVESTIGATE = "investigate-incident"
    STATUS = "read-investigation-status"
    ARTIFACT = "read-investigation-artifact"
    PROPOSE = "submit-remediation-proposal"


class A2ACardSignerPort(Protocol):
    def sign_card_digest(self, *, key_ref: str, card_digest: str) -> str: ...

    def verify_card_digest(
        self,
        *,
        key_digest: str,
        card_digest: str,
        signature_digest: str,
    ) -> bool: ...


class A2AServerPort(Protocol):
    """Explicit server port; external agents cannot become internal roles."""

    def start_investigation(
        self,
        *,
        principal: PrincipalContract,
        message: MessageContract,
        idempotency_key_digest: str,
    ) -> OpaqueReference: ...

    def read_status(
        self,
        *,
        principal: PrincipalContract,
        task_ref: str,
    ) -> StatusContract: ...

    def read_artifacts(
        self,
        *,
        principal: PrincipalContract,
        task_ref: str,
        cursor_digest: str | None,
        limit: int,
    ) -> tuple[tuple[ArtifactContract, ...], str | None]: ...

    def submit_layer7_proposal(
        self,
        *,
        principal: PrincipalContract,
        message: MessageContract,
        idempotency_key_digest: str,
    ) -> OpaqueReference: ...

    def cancel(
        self,
        *,
        principal: PrincipalContract,
        task_ref: str,
        command_digest: str,
    ) -> StatusContract: ...


class A2AServerAuthorizationPort(Protocol):
    def authorize(
        self,
        *,
        principal: PrincipalContract,
        skill: AgentSkillContract,
        resource_ref: str,
    ) -> bool: ...


class A2ATaskRequest(StrictModel):
    schema_version: Literal[1] = 1
    request_id: Identifier
    skill_id: Identifier
    message: MessageContract
    resource_ref: OpaqueReference
    idempotency_key_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    cursor_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    limit: int = Field(default=50, ge=1, le=100)


class A2ATaskResponse(StrictModel):
    schema_version: Literal[1] = 1
    task_ref: OpaqueReference
    status: StatusContract
    artifacts: tuple[ArtifactContract, ...] = Field(default=(), max_length=64)
    next_cursor_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    proposal_ref: OpaqueReference | None = None
    response_digest: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def validate_response_digest(self) -> Self:
        if (
            digest_value(self.model_dump(mode="json", exclude={"response_digest"}))
            != self.response_digest
        ):
            raise ValueError("A2A response digest is invalid")
        return self


class BoundedA2AServer:
    """A2A server facade for four bounded, non-effect skills."""

    def __init__(
        self,
        *,
        card: AgentCardContract,
        application: A2AServerPort,
        authorization: A2AServerAuthorizationPort,
        now: Callable[[], datetime],
        maximum_idempotency_entries: int = 10_000,
    ) -> None:
        if maximum_idempotency_entries < 1:
            raise ValueError("A2A idempotency cache bound is invalid")
        self.card = card
        self._application = application
        self._authorization = authorization
        self._now = now
        self._maximum_idempotency_entries = maximum_idempotency_entries
        expected = {item.value for item in A2ASkillName}
        if {skill.skill_id for skill in card.skills} != expected:
            raise ValueError("A2A card must expose exactly the bounded Aegis skills")
        if any(skill.permits_effect for skill in card.skills):
            raise ValueError("A2A server cannot advertise effect permission")
        self._skills = {skill.skill_id: skill for skill in card.skills}
        self._idempotency: dict[tuple[str, str, str], tuple[str, A2ATaskResponse]] = {}

    def submit(
        self,
        *,
        principal: PrincipalContract,
        request: A2ATaskRequest,
    ) -> A2ATaskResponse:
        request_digest = digest_value(request.model_dump(mode="json"))
        skill = self._skills.get(request.skill_id)
        if skill is None:
            raise PolicyDenied("A2A skill is unavailable")
        if not self._authorization.authorize(
            principal=principal,
            skill=skill,
            resource_ref=request.resource_ref,
        ):
            raise PolicyDenied("application policy denied the A2A task")
        cache_key = (
            principal.tenant_ref,
            principal.principal_ref,
            request.idempotency_key_digest,
        )
        existing = self._idempotency.get(cache_key)
        if existing is not None:
            if existing[0] != request_digest:
                raise IdempotencyConflict("A2A idempotency key changed request")
            return existing[1]
        if skill.skill_id == A2ASkillName.INVESTIGATE:
            task_ref = self._application.start_investigation(
                principal=principal,
                message=request.message,
                idempotency_key_digest=request.idempotency_key_digest,
            )
            response = self._response(
                task_ref=task_ref,
                status=_status(TaskState.SUBMITTED, 0, 1, self._now()),
            )
        elif skill.skill_id == A2ASkillName.STATUS:
            status = self._application.read_status(
                principal=principal,
                task_ref=request.resource_ref,
            )
            response = self._response(
                task_ref=request.resource_ref,
                status=status,
            )
        elif skill.skill_id == A2ASkillName.ARTIFACT:
            artifacts, cursor = self._application.read_artifacts(
                principal=principal,
                task_ref=request.resource_ref,
                cursor_digest=request.cursor_digest,
                limit=request.limit,
            )
            response = self._response(
                task_ref=request.resource_ref,
                status=_status(TaskState.COMPLETED, 100, 1, self._now()),
                artifacts=artifacts,
                next_cursor_digest=cursor,
            )
        elif skill.skill_id == A2ASkillName.PROPOSE:
            proposal_ref = self._application.submit_layer7_proposal(
                principal=principal,
                message=request.message,
                idempotency_key_digest=request.idempotency_key_digest,
            )
            response = self._response(
                task_ref=request.resource_ref,
                status=_status(TaskState.COMPLETED, 100, 1, self._now()),
                proposal_ref=proposal_ref,
            )
        else:
            raise PolicyDenied("A2A skill is unavailable")
        if len(self._idempotency) >= self._maximum_idempotency_entries:
            del self._idempotency[next(iter(self._idempotency))]
        self._idempotency[cache_key] = (
            request_digest,
            response,
        )
        return response

    def cancel(
        self,
        *,
        principal: PrincipalContract,
        task_ref: str,
        command_digest: str,
    ) -> A2ATaskResponse:
        status = self._application.cancel(
            principal=principal,
            task_ref=task_ref,
            command_digest=command_digest,
        )
        if status.state is not TaskState.CANCELLED:
            raise ReconciliationRequired("A2A cancellation was not confirmed")
        return self._response(task_ref=task_ref, status=status)

    def _response(
        self,
        *,
        task_ref: str,
        status: StatusContract,
        artifacts: Sequence[ArtifactContract] = (),
        next_cursor_digest: str | None = None,
        proposal_ref: str | None = None,
    ) -> A2ATaskResponse:
        material: dict[str, object] = {
            "artifacts": [artifact.model_dump(mode="json") for artifact in artifacts],
            "next_cursor_digest": next_cursor_digest,
            "proposal_ref": proposal_ref,
            "schema_version": 1,
            "status": status.model_dump(mode="json"),
            "task_ref": task_ref,
        }
        if len(canonical_json(material)) > MAX_PROTOCOL_DOCUMENT_BYTES:
            raise PayloadRejected("A2A response exceeds the bound")
        return A2ATaskResponse(**material, response_digest=digest_value(material))


class A2APeerRegistration(StrictModel):
    schema_version: Literal[1] = 1
    registration_id: Identifier
    tenant_ref: OpaqueReference
    peer_id: Identifier
    discovery_origin: Annotated[
        str,
        Field(pattern=r"^https://[a-zA-Z0-9][a-zA-Z0-9.-]*(?::[0-9]+)?$"),
    ]
    rpc_path: Annotated[
        str, Field(min_length=1, max_length=256, pattern=r"^/[a-zA-Z0-9._~/-]+$")
    ]
    supported_protocol_versions: tuple[Identifier, ...] = Field(
        min_length=1, max_length=8
    )
    allowed_skills: tuple[Identifier, ...] = Field(min_length=1, max_length=16)
    allowed_transports: tuple[TransportKind, ...] = Field(min_length=1, max_length=3)
    card_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    schema_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    certificate_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    secret_reference: Identifier
    secret_version: int = Field(ge=1)
    maximum_response_bytes: int = Field(ge=1_024, le=MAX_PROTOCOL_DOCUMENT_BYTES)
    timeout_seconds: float = Field(gt=0, le=120)
    poll_interval_seconds: float = Field(ge=0.1, le=30)
    maximum_poll_attempts: int = Field(ge=1, le=100)
    stream_event_limit: int = Field(ge=1, le=10_000)
    retry_attempts: Literal[1] = 1
    maximum_redirects: Literal[0] = 0

    @field_validator(
        "supported_protocol_versions",
        "allowed_skills",
        "allowed_transports",
    )
    @classmethod
    def normalize_sets(cls, value: tuple[object, ...]) -> tuple[object, ...]:
        return tuple(sorted(set(value), key=str))


class A2ASdkClientPort(Protocol):
    """Neutral facade implemented in the official A2A SDK adapter module."""

    def discover_card(
        self, *, registration: A2APeerRegistration
    ) -> Mapping[str, JsonValue]: ...

    def accept_card(
        self,
        *,
        registration: A2APeerRegistration,
        card: AgentCardContract,
    ) -> None: ...

    def send_task(
        self,
        *,
        registration: A2APeerRegistration,
        card: AgentCardContract,
        task: TaskContract,
        message: MessageContract,
        streaming: bool,
        cancelled: Callable[[], bool],
    ) -> A2ATaskResponse: ...

    def poll_task(
        self,
        *,
        registration: A2APeerRegistration,
        card: AgentCardContract,
        task: TaskContract,
    ) -> A2ATaskResponse: ...

    def cancel_task(
        self,
        *,
        registration: A2APeerRegistration,
        card: AgentCardContract,
        task: TaskContract,
    ) -> A2ATaskResponse: ...


class A2APeerGateway:
    """Pinned-card gateway with lifecycle, provenance, and ambiguity controls."""

    def __init__(
        self,
        *,
        registration: A2APeerRegistration,
        trust: TrustEntry,
        sdk: A2ASdkClientPort,
        parse_card: Callable[[Mapping[str, JsonValue]], AgentCardContract],
        now: Callable[[], datetime],
    ) -> None:
        if trust.peer_id != registration.peer_id:
            raise ValueError("A2A registration does not match trust entry")
        if (
            registration.discovery_origin not in trust.egress_origins
            or registration.card_digest != trust.card_digest
            or registration.schema_digest != trust.schema_digest
            or registration.certificate_digest != trust.certificate_digest
        ):
            raise ValueError("A2A registration pins do not match trust")
        self._registration = registration
        self._trust = trust
        self._sdk = sdk
        self._parse_card = parse_card
        self._now = now
        self._card: AgentCardContract | None = None

    def discover(self) -> AgentCardContract:
        card = self._parse_card(
            self._sdk.discover_card(registration=self._registration)
        )
        if card.peer_id != self._registration.peer_id:
            raise PolicyDenied("A2A agent card peer identity is invalid")
        if card.card_digest != self._registration.card_digest:
            raise PolicyDenied("A2A agent card digest pin changed")
        if card.protocol_version not in self._registration.supported_protocol_versions:
            raise PolicyDenied("A2A protocol version is unsupported")
        if self._trust.expires_at <= self._now():
            raise PolicyDenied("A2A peer trust is expired")
        if card.key_digest != self._trust.key_digest:
            raise PolicyDenied("A2A agent card key pin is invalid")
        trusted_origins = {
            digest_value(origin) for origin in self._trust.egress_origins
        }
        if not set(card.interface_origin_digests).issubset(trusted_origins):
            raise PolicyDenied("A2A agent card origin is not trusted")
        registered_endpoint = digest_value(
            f"{self._registration.discovery_origin}{self._registration.rpc_path}"
        )
        if registered_endpoint not in card.interface_endpoint_digests:
            raise PolicyDenied("A2A agent card endpoint is not registered")
        advertised = {skill.skill_id for skill in card.skills}
        if not set(self._registration.allowed_skills).issubset(advertised):
            raise PolicyDenied("A2A agent card lacks required skills")
        if any(skill.permits_effect for skill in card.skills):
            raise PolicyDenied("A2A agent card advertises direct effects")
        self._sdk.accept_card(registration=self._registration, card=card)
        self._card = card
        return card

    def send(
        self,
        *,
        task: TaskContract,
        message: MessageContract,
        streaming: bool,
        cancelled: Callable[[], bool],
    ) -> A2ATaskResponse:
        card = self._require_card()
        if task.peer_id != card.peer_id or task.capability_id not in (
            self._registration.allowed_skills
        ):
            raise PolicyDenied("A2A task is outside the registered peer scope")
        try:
            response = self._sdk.send_task(
                registration=self._registration,
                card=card,
                task=task,
                message=message,
                streaming=streaming,
                cancelled=cancelled,
            )
        except (AmbiguousTransportError, TimeoutError, ConnectionError) as exc:
            raise ReconciliationRequired(
                "A2A task delivery is ambiguous; poll before retry"
            ) from exc
        self._validate_response(task=task, card=card, response=response)
        return response

    def poll(self, *, task: TaskContract) -> A2ATaskResponse:
        response = self._sdk.poll_task(
            registration=self._registration,
            card=self._require_card(),
            task=task,
        )
        self._validate_response(
            task=task,
            card=self._require_card(),
            response=response,
        )
        return response

    def cancel(self, *, task: TaskContract) -> A2ATaskResponse:
        response = self._sdk.cancel_task(
            registration=self._registration,
            card=self._require_card(),
            task=task,
        )
        if response.status.state is not TaskState.CANCELLED:
            raise ReconciliationRequired("A2A task cancellation remains ambiguous")
        self._validate_response(
            task=task,
            card=self._require_card(),
            response=response,
        )
        return response

    def _require_card(self) -> AgentCardContract:
        if self._card is None:
            raise PolicyDenied("A2A peer card has not been discovered and verified")
        return self._card

    def _validate_response(
        self,
        *,
        task: TaskContract,
        card: AgentCardContract,
        response: A2ATaskResponse,
    ) -> None:
        if len(canonical_json(response.model_dump(mode="json"))) > (
            self._registration.maximum_response_bytes
        ):
            raise PayloadRejected("A2A response exceeds the registration bound")
        for artifact in response.artifacts:
            if (
                artifact.task_id != task.task_id
                or artifact.producer_peer_id != card.peer_id
                or artifact.card_digest != card.card_digest
            ):
                raise PayloadRejected("A2A artifact provenance is invalid")
            if artifact.kind in {"investigation-finding", "proposal"} and (
                not artifact.citations
            ):
                raise PayloadRejected("A2A artifact lacks required citations")
        if response.proposal_ref is not None and task.capability_id != (
            A2ASkillName.PROPOSE
        ):
            raise PayloadRejected("A2A peer forged a proposal reference")


def build_aegis_agent_card(
    *,
    peer_id: str,
    protocol_version: str,
    endpoint_origin: str,
    key_ref: str,
    key_digest: str,
    signer: A2ACardSignerPort,
    issued_at: datetime,
    expires_at: datetime,
) -> AgentCardContract:
    parsed_endpoint = urlsplit(endpoint_origin)
    if parsed_endpoint.scheme != "https" or not parsed_endpoint.hostname:
        raise ValueError("A2A endpoint must be an exact HTTPS URL")
    endpoint_base = f"{parsed_endpoint.scheme}://{parsed_endpoint.netloc}"
    skills = tuple(
        AgentSkillContract(
            skill_id=skill.value,
            name=skill.value.replace("-", " ").title(),
            description_digest=digest_value(f"aegis-a2a:{skill.value}:v1"),
            capability_id=f"a2a-{skill.value}",
            input_modes=("application/json", "text/plain"),
            output_modes=("application/json", "text/plain"),
            risk=(
                RiskLevel.HIGH
                if skill is A2ASkillName.PROPOSE
                else RiskLevel.MEDIUM
                if skill is A2ASkillName.INVESTIGATE
                else RiskLevel.LOW
            ),
        )
        for skill in A2ASkillName
    )
    unsigned: dict[str, object] = {
        "auth_schemes": ["mutual-tls", "oauth2"],
        "card_version": 1,
        "description_digest": digest_value(
            "Aegis bounded external investigation agent"
        ),
        "endpoint_origin_digest": digest_value(endpoint_base),
        "interface_origin_digests": [digest_value(endpoint_base)],
        "interface_endpoint_digests": [digest_value(endpoint_origin)],
        "expires_at": expires_at,
        "extensions": ["aegis-provenance-v1"],
        "issued_at": issued_at,
        "key_digest": key_digest,
        "name": "Aegis investigation gateway",
        "peer_id": peer_id,
        "protocol_version": protocol_version,
        "schema_version": 1,
        "skills": [skill.model_dump(mode="json") for skill in skills],
        "transports": [
            TransportKind.JSON_RPC_HTTP,
            TransportKind.STREAMABLE_HTTP,
        ],
    }
    card_digest = digest_value(unsigned)
    signature_digest = signer.sign_card_digest(
        key_ref=key_ref,
        card_digest=card_digest,
    )
    return AgentCardContract(
        **unsigned,
        card_digest=card_digest,
        signature_digest=signature_digest,
    )


def _status(
    state: TaskState,
    progress: int,
    sequence: int,
    occurred_at: datetime,
) -> StatusContract:
    material = {
        "occurred_at": occurred_at.isoformat(),
        "progress_percent": progress,
        "retry_after_seconds": None,
        "schema_version": 1,
        "sequence": sequence,
        "state": state,
    }
    return StatusContract(
        state=state,
        progress_percent=progress,
        sequence=sequence,
        status_digest=digest_value(material),
        occurred_at=occurred_at,
    )
