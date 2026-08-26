"""Application-owned MCP policy surface with protocol types kept in adapters."""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from threading import BoundedSemaphore
from typing import Annotated, Literal, Protocol, Self

from pydantic import AwareDatetime, Field, JsonValue, field_validator, model_validator

from aegis_framework.domain import Identifier, OpaqueReference, RiskLevel, StrictModel
from aegis_framework.errors import PayloadRejected, PolicyDenied
from aegis_framework.interoperability import (
    MAX_PROTOCOL_DOCUMENT_BYTES,
    CapabilityContract,
    CitationContract,
    MessagePart,
    PrincipalContract,
    ProtocolKind,
    ResourceContract,
    ToolContract,
    TransportKind,
    TrustEntry,
    TrustTier,
    canonical_json,
    digest_value,
    require_trusted_peer,
    validate_untrusted_text,
)

_RISK_ORDER = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
}


class McpToolName(StrEnum):
    INCIDENT_READ = "aegis.incident.read"
    EVIDENCE_LIST = "aegis.evidence.list"
    MEMORY_SEARCH = "aegis.memory.search"
    RUNBOOK_READ = "aegis.runbook.read"
    STATUS_READ = "aegis.status.read"
    INVESTIGATION_SUBMIT = "aegis.investigation.submit"
    PROPOSAL_SUBMIT = "aegis.proposal.submit"


class McpOperationKind(StrEnum):
    LIST_TOOLS = "list-tools"
    LIST_RESOURCES = "list-resources"
    READ_RESOURCE = "read-resource"
    CALL_TOOL = "call-tool"
    CANCEL = "cancel"


class McpInitialization(StrictModel):
    schema_version: Literal[1] = 1
    negotiated_protocol_version: Identifier
    client_name_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    client_version_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    capabilities: tuple[Identifier, ...] = Field(max_length=32)
    session_ref: OpaqueReference
    initialized_at: AwareDatetime

    @field_validator("capabilities")
    @classmethod
    def normalize_capabilities(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(value)))


class McpCursor(StrictModel):
    cursor_ref: OpaqueReference
    tenant_ref: OpaqueReference
    peer_id: Identifier
    operation: McpOperationKind
    position: int = Field(ge=0, le=10_000)
    page_size: int = Field(ge=1, le=100)
    query_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    expires_at: AwareDatetime
    cursor_digest: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def validate_cursor_digest(self) -> Self:
        if (
            digest_value(self.model_dump(mode="json", exclude={"cursor_digest"}))
            != self.cursor_digest
        ):
            raise ValueError("MCP cursor digest is invalid")
        return self


class McpCallRequest(StrictModel):
    schema_version: Literal[1] = 1
    call_id: Identifier
    tool_name: McpToolName
    arguments: dict[str, JsonValue] = Field(max_length=32)
    idempotency_key: Identifier
    progress_token_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    cursor: McpCursor | None = None

    @model_validator(mode="after")
    def validate_arguments(self) -> Self:
        encoded = canonical_json(self.arguments)
        if len(encoded) > 32_768:
            raise ValueError("MCP arguments exceed the bound")
        forbidden = {
            "approval",
            "authorization",
            "command",
            "executable",
            "roles",
            "shell",
            "tenant",
            "tenant_id",
        }
        if forbidden.intersection(key.lower() for key in self.arguments):
            raise ValueError("MCP arguments contain an authority or executable field")
        return self


class McpCallResult(StrictModel):
    schema_version: Literal[1] = 1
    call_id: Identifier
    status: Literal["completed", "failed", "cancelled", "quarantined"]
    resources: tuple[ResourceContract, ...] = Field(default=(), max_length=100)
    content: tuple[MessagePart, ...] = Field(default=(), max_length=32)
    citations: tuple[CitationContract, ...] = Field(default=(), max_length=64)
    next_cursor: McpCursor | None = None
    proposal_ref: OpaqueReference | None = None
    result_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    redaction_count: int = Field(ge=0, le=10_000)

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        material = self.model_dump(mode="json", exclude={"result_digest"})
        if digest_value(material) != self.result_digest:
            raise ValueError("MCP result digest is invalid")
        if self.proposal_ref is not None and self.status != "completed":
            raise ValueError("failed MCP calls cannot return a proposal reference")
        return self


class McpPage(StrictModel):
    items: tuple[ResourceContract | ToolContract, ...] = Field(max_length=100)
    next_cursor: McpCursor | None
    total_is_exact: Literal[False] = False


class McpReadRequest(StrictModel):
    resource_ref: OpaqueReference
    cursor: McpCursor | None = None
    limit: int = Field(default=50, ge=1, le=100)


class ProposalSubmission(StrictModel):
    title: Annotated[str, Field(min_length=1, max_length=200)]
    summary: Annotated[str, Field(min_length=1, max_length=2_000)]
    risk: RiskLevel
    citations: tuple[CitationContract, ...] = Field(min_length=1, max_length=64)
    requested_action_kind: Identifier

    @field_validator("title", "summary")
    @classmethod
    def validate_submission_text(cls, value: str) -> str:
        return validate_untrusted_text(value)


class ProposalReceipt(StrictModel):
    proposal_ref: OpaqueReference
    proposal_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    status: Literal["layer7-proposal-recorded"]
    approval_opened: Literal[False] = False
    effect_executed: Literal[False] = False


class McpApplicationPort(Protocol):
    """Explicit application data port; MCP cannot read repositories directly."""

    def read_incident(
        self,
        *,
        principal: PrincipalContract,
        incident_ref: str,
    ) -> tuple[
        ResourceContract, tuple[MessagePart, ...], tuple[CitationContract, ...]
    ]: ...

    def list_evidence(
        self,
        *,
        principal: PrincipalContract,
        incident_ref: str,
        offset: int,
        limit: int,
    ) -> tuple[tuple[ResourceContract, ...], bool]: ...

    def search_memory(
        self,
        *,
        principal: PrincipalContract,
        query_digest: str,
        incident_ref: str,
        limit: int,
    ) -> tuple[tuple[ResourceContract, ...], tuple[CitationContract, ...]]: ...

    def read_runbook(
        self,
        *,
        principal: PrincipalContract,
        runbook_ref: str,
    ) -> tuple[
        ResourceContract, tuple[MessagePart, ...], tuple[CitationContract, ...]
    ]: ...

    def read_status(
        self,
        *,
        principal: PrincipalContract,
        run_ref: str,
    ) -> tuple[ResourceContract, tuple[MessagePart, ...]]: ...

    def submit_investigation(
        self,
        *,
        principal: PrincipalContract,
        incident_ref: str,
        request_digest: str,
        idempotency_key: str,
    ) -> OpaqueReference: ...

    def submit_layer7_proposal(
        self,
        *,
        principal: PrincipalContract,
        submission: ProposalSubmission,
        idempotency_key: str,
    ) -> ProposalReceipt: ...


class McpServerAuthorizationPort(Protocol):
    def authorize(
        self,
        *,
        principal: PrincipalContract,
        tool: ToolContract,
        resource_ref: str,
    ) -> bool: ...


class CuratedMcpServer:
    """Least-privilege MCP facade over redacted application-owned ports."""

    def __init__(
        self,
        *,
        application: McpApplicationPort,
        authorization: McpServerAuthorizationPort,
        tools: Sequence[ToolContract],
        now: Callable[[], datetime],
    ) -> None:
        self._application = application
        self._authorization = authorization
        self._tools = {tool.name: tool for tool in tools}
        self._now = now
        expected = {item.value for item in McpToolName}
        if set(self._tools) != expected:
            raise ValueError("MCP server must expose exactly the curated tool set")
        if any(tool.destructive for tool in self._tools.values()):
            raise ValueError("MCP server cannot expose destructive tools")

    def list_tools(self, *, principal: PrincipalContract) -> tuple[ToolContract, ...]:
        del principal
        return tuple(self._tools[name] for name in sorted(self._tools))

    def call(
        self,
        *,
        principal: PrincipalContract,
        request: McpCallRequest,
        cancelled: Callable[[], bool],
    ) -> McpCallResult:
        if cancelled():
            return self._result(
                request=request,
                status="cancelled",
                resources=(),
                content=(),
                citations=(),
            )
        tool = self._tools[request.tool_name.value]
        resource_ref = _required_identifier(request.arguments, "resource_ref")
        if not self._authorization.authorize(
            principal=principal,
            tool=tool,
            resource_ref=resource_ref,
        ):
            raise PolicyDenied("application policy denied the MCP call")
        if request.tool_name is McpToolName.INCIDENT_READ:
            resource, content, citations = self._application.read_incident(
                principal=principal,
                incident_ref=resource_ref,
            )
            return self._result(
                request=request,
                status="completed",
                resources=(resource,),
                content=content,
                citations=citations,
            )
        if request.tool_name is McpToolName.EVIDENCE_LIST:
            limit = _bounded_int(
                request.arguments, "limit", default=50, minimum=1, maximum=100
            )
            offset = request.cursor.position if request.cursor is not None else 0
            resources, has_more = self._application.list_evidence(
                principal=principal,
                incident_ref=resource_ref,
                offset=offset,
                limit=limit,
            )
            cursor = (
                self._cursor(
                    principal=principal,
                    peer_id="aegis-mcp-server",
                    operation=McpOperationKind.CALL_TOOL,
                    position=offset + len(resources),
                    page_size=limit,
                    query_digest=digest_value(request.arguments),
                )
                if has_more
                else None
            )
            return self._result(
                request=request,
                status="completed",
                resources=resources,
                content=(),
                citations=(),
                next_cursor=cursor,
            )
        if request.tool_name is McpToolName.MEMORY_SEARCH:
            query = _required_text(request.arguments, "query")
            resources, citations = self._application.search_memory(
                principal=principal,
                query_digest=digest_value(query),
                incident_ref=resource_ref,
                limit=_bounded_int(
                    request.arguments,
                    "limit",
                    default=8,
                    minimum=1,
                    maximum=20,
                ),
            )
            return self._result(
                request=request,
                status="completed",
                resources=resources,
                content=(),
                citations=citations,
            )
        if request.tool_name is McpToolName.RUNBOOK_READ:
            resource, content, citations = self._application.read_runbook(
                principal=principal,
                runbook_ref=resource_ref,
            )
            return self._result(
                request=request,
                status="completed",
                resources=(resource,),
                content=content,
                citations=citations,
            )
        if request.tool_name is McpToolName.STATUS_READ:
            resource, content = self._application.read_status(
                principal=principal,
                run_ref=resource_ref,
            )
            return self._result(
                request=request,
                status="completed",
                resources=(resource,),
                content=content,
                citations=(),
            )
        if request.tool_name is McpToolName.INVESTIGATION_SUBMIT:
            request_digest = digest_value(request.arguments)
            investigation_ref = self._application.submit_investigation(
                principal=principal,
                incident_ref=resource_ref,
                request_digest=request_digest,
                idempotency_key=request.idempotency_key,
            )
            content = (
                MessagePart(
                    part_id="investigation-reference",
                    kind="resource-ref",
                    media_type="application/vnd.aegis.reference",
                    resource_ref=investigation_ref,
                    content_digest=digest_value(investigation_ref),
                ),
            )
            return self._result(
                request=request,
                status="completed",
                resources=(),
                content=content,
                citations=(),
            )
        if request.tool_name is McpToolName.PROPOSAL_SUBMIT:
            submission = ProposalSubmission.model_validate(
                request.arguments.get("proposal")
            )
            receipt = self._application.submit_layer7_proposal(
                principal=principal,
                submission=submission,
                idempotency_key=request.idempotency_key,
            )
            return self._result(
                request=request,
                status="completed",
                resources=(),
                content=(),
                citations=submission.citations,
                proposal_ref=receipt.proposal_ref,
            )
        raise PayloadRejected("unsupported MCP tool")

    def _result(
        self,
        *,
        request: McpCallRequest,
        status: Literal["completed", "failed", "cancelled", "quarantined"],
        resources: Sequence[ResourceContract],
        content: Sequence[MessagePart],
        citations: Sequence[CitationContract],
        next_cursor: McpCursor | None = None,
        proposal_ref: str | None = None,
    ) -> McpCallResult:
        material: dict[str, object] = {
            "call_id": request.call_id,
            "citations": [citation.model_dump(mode="json") for citation in citations],
            "content": [part.model_dump(mode="json") for part in content],
            "next_cursor": (
                next_cursor.model_dump(mode="json") if next_cursor is not None else None
            ),
            "proposal_ref": proposal_ref,
            "redaction_count": sum(part.redacted for part in content),
            "resources": [resource.model_dump(mode="json") for resource in resources],
            "schema_version": 1,
            "status": status,
        }
        if len(canonical_json(material)) > MAX_PROTOCOL_DOCUMENT_BYTES:
            raise PayloadRejected("MCP result exceeds the document bound")
        return McpCallResult(**material, result_digest=digest_value(material))

    def _cursor(
        self,
        *,
        principal: PrincipalContract,
        peer_id: str,
        operation: McpOperationKind,
        position: int,
        page_size: int,
        query_digest: str,
    ) -> McpCursor:
        now = self._now()
        cursor_hash = digest_value([peer_id, query_digest, position])[:32]
        material: dict[str, object] = {
            "cursor_ref": f"mcp-cursor-{cursor_hash}",
            "expires_at": principal.expires_at,
            "operation": operation,
            "page_size": page_size,
            "peer_id": peer_id,
            "position": position,
            "query_digest": query_digest,
            "tenant_ref": principal.tenant_ref,
        }
        if principal.expires_at <= now:
            raise PolicyDenied("principal expired before cursor issuance")
        return McpCursor(**material, cursor_digest=digest_value(material))


class FixedStdioRegistration(StrictModel):
    transport: Literal[TransportKind.STDIO] = TransportKind.STDIO
    executable: Annotated[str, Field(min_length=1, max_length=512)]
    arguments: tuple[Annotated[str, Field(max_length=512)], ...] = Field(max_length=32)
    executable_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    working_directory: Annotated[str, Field(min_length=1, max_length=512)]
    environment_names: tuple[Identifier, ...] = Field(default=(), max_length=16)

    @model_validator(mode="after")
    def validate_fixed_command(self) -> Self:
        executable = PurePosixPath(self.executable)
        working_directory = PurePosixPath(self.working_directory)
        if not executable.is_absolute() or not working_directory.is_absolute():
            raise ValueError("stdio executable and working directory must be absolute")
        if any(
            "\x00" in item or "\n" in item or "\r" in item for item in self.arguments
        ):
            raise ValueError("stdio arguments contain control characters")
        return self


class NetworkMcpRegistration(StrictModel):
    transport: Literal[TransportKind.STREAMABLE_HTTP] = TransportKind.STREAMABLE_HTTP
    endpoint_origin: Annotated[
        str,
        Field(pattern=r"^https://[a-zA-Z0-9][a-zA-Z0-9.-]*(?::[0-9]+)?$"),
    ]
    endpoint_path: Annotated[
        str, Field(min_length=1, max_length=256, pattern=r"^/[a-zA-Z0-9._~/-]+$")
    ]
    secret_reference: Identifier
    secret_version: int = Field(ge=1)
    certificate_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    server_name: Annotated[
        str, Field(min_length=1, max_length=253, pattern=r"^[a-zA-Z0-9.-]+$")
    ]
    allowed_cidrs: tuple[Annotated[str, Field(max_length=64)], ...] = Field(
        default=(), max_length=16
    )
    timeout_seconds: float = Field(gt=0, le=120)
    maximum_redirects: Literal[0] = 0
    inherit_environment_proxy: Literal[False] = False


class McpClientRegistration(StrictModel):
    schema_version: Literal[1] = 1
    registration_id: Identifier
    tenant_ref: OpaqueReference
    peer_id: Identifier
    required_peer_environment: Literal["development", "test", "staging", "production"]
    minimum_trust_tier: TrustTier
    supported_protocol_versions: tuple[Identifier, ...] = Field(
        min_length=1, max_length=8
    )
    required_capabilities: tuple[Identifier, ...] = Field(max_length=32)
    allowed_tools: tuple[Annotated[str, Field(pattern=r"^[a-z0-9._-]+$")], ...] = Field(
        max_length=64
    )
    allowed_resources: tuple[Identifier, ...] = Field(max_length=64)
    schema_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    risk_ceiling: RiskLevel
    maximum_calls_per_minute: int = Field(ge=1, le=10_000)
    maximum_cost_units_per_hour: int = Field(ge=0, le=1_000_000)
    maximum_concurrency: int = Field(ge=1, le=32)
    maximum_response_bytes: int = Field(ge=1_024, le=MAX_PROTOCOL_DOCUMENT_BYTES)
    retry_attempts: Literal[1] = 1
    transport: FixedStdioRegistration | NetworkMcpRegistration

    @field_validator(
        "supported_protocol_versions",
        "required_capabilities",
        "allowed_tools",
        "allowed_resources",
    )
    @classmethod
    def normalize_registration_sets(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(value)))


class McpSdkClientPort(Protocol):
    """Neutral facade implemented only by the official SDK adapter module."""

    def initialize(
        self,
        *,
        registration: McpClientRegistration,
        peer: TrustEntry,
    ) -> McpInitialization: ...

    def list_tools(
        self,
        *,
        registration: McpClientRegistration,
        initialization: McpInitialization,
        cursor: str | None,
    ) -> tuple[tuple[ToolContract, ...], str | None]: ...

    def call_tool(
        self,
        *,
        registration: McpClientRegistration,
        initialization: McpInitialization,
        name: str,
        arguments: Mapping[str, JsonValue],
        timeout_seconds: float,
        cancelled: Callable[[], bool],
    ) -> McpCallResult: ...

    def close(
        self,
        *,
        registration: McpClientRegistration,
        initialization: McpInitialization,
    ) -> None: ...


class HardenedMcpClient:
    """Registry-bound client that treats all remote descriptions/content as data."""

    def __init__(
        self,
        *,
        registration: McpClientRegistration,
        peer: TrustEntry,
        sdk: McpSdkClientPort,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            peer.protocol is not ProtocolKind.MCP
            or peer.peer_id != registration.peer_id
        ):
            raise ValueError("MCP registration does not match trust entry")
        if registration.schema_digest != peer.schema_digest:
            raise ValueError("MCP schema pin does not match trust entry")
        if registration.transport.transport not in peer.allowed_transports:
            raise ValueError("MCP transport is not trusted")
        if isinstance(registration.transport, NetworkMcpRegistration) and (
            registration.transport.endpoint_origin not in peer.egress_origins
            or registration.transport.certificate_digest != peer.certificate_digest
        ):
            raise ValueError("MCP network origin or certificate pin is not trusted")
        self._registration = registration
        self._peer = peer
        self._sdk = sdk
        self._now = now or (lambda: datetime.now(UTC))
        self._initialization: McpInitialization | None = None
        self._concurrency = BoundedSemaphore(registration.maximum_concurrency)

    def initialize(self) -> McpInitialization:
        require_trusted_peer(
            self._peer,
            protocol=ProtocolKind.MCP,
            now=self._now(),
            expected_environment=self._registration.required_peer_environment,
            minimum_trust_tier=self._registration.minimum_trust_tier,
        )
        result = self._sdk.initialize(
            registration=self._registration,
            peer=self._peer,
        )
        try:
            if result.negotiated_protocol_version not in (
                self._registration.supported_protocol_versions
            ):
                raise PolicyDenied(
                    "MCP protocol negotiation selected an unsupported version"
                )
            if not set(self._registration.required_capabilities).issubset(
                result.capabilities
            ):
                raise PolicyDenied("MCP server capabilities are insufficient")
        except PolicyDenied:
            # Close the SDK session immediately so it is not left open while
            # the caller handles the policy denial.
            with contextlib.suppress(BaseException):
                self._sdk.close(registration=self._registration, initialization=result)
            raise
        self._initialization = result
        return result

    def discover_tools(self) -> tuple[ToolContract, ...]:
        require_trusted_peer(
            self._peer,
            protocol=ProtocolKind.MCP,
            now=self._now(),
            expected_environment=self._registration.required_peer_environment,
            minimum_trust_tier=self._registration.minimum_trust_tier,
        )
        initialization = self._require_initialization()
        cursor: str | None = None
        observed_cursors: set[str] = set()
        tools: dict[str, ToolContract] = {}
        for _ in range(100):
            page, cursor = self._sdk.list_tools(
                registration=self._registration,
                initialization=initialization,
                cursor=cursor,
            )
            for tool in page:
                if (
                    tool.name not in self._registration.allowed_tools
                    or _RISK_ORDER[tool.risk]
                    > _RISK_ORDER[self._registration.risk_ceiling]
                    or tool.destructive
                ):
                    raise PolicyDenied("MCP server advertised an untrusted tool")
                existing = tools.get(tool.name)
                if existing is not None and existing != tool:
                    raise PayloadRejected(
                        "MCP tool definition changed during pagination"
                    )
                tools[tool.name] = tool
            if cursor is None:
                return tuple(tools[name] for name in sorted(tools))
            if cursor in observed_cursors:
                raise PayloadRejected("MCP pagination cursor loop detected")
            observed_cursors.add(cursor)
        raise PayloadRejected("MCP pagination exceeded the page bound")

    def call(
        self,
        *,
        name: str,
        arguments: Mapping[str, JsonValue],
        timeout_seconds: float,
        cancelled: Callable[[], bool],
    ) -> McpCallResult:
        require_trusted_peer(
            self._peer,
            protocol=ProtocolKind.MCP,
            now=self._now(),
            expected_environment=self._registration.required_peer_environment,
            minimum_trust_tier=self._registration.minimum_trust_tier,
        )
        if name not in self._registration.allowed_tools:
            raise PolicyDenied("MCP tool is not allowlisted")
        # Enforce resource allowlist: the middle segment of the tool name
        # identifies its resource kind (e.g. "aegis.status.read" → "status").
        # If allowed_resources is non-empty, the tool's resource kind must appear in it.
        name_parts = name.split(".")
        if (
            len(name_parts) >= 3
            and self._registration.allowed_resources
            and name_parts[1] not in self._registration.allowed_resources
        ):
            raise PolicyDenied("MCP tool resource kind is not allowlisted")
        if cancelled():
            raise PolicyDenied("MCP call was cancelled before dispatch")
        with self._concurrency:
            result = self._sdk.call_tool(
                registration=self._registration,
                initialization=self._require_initialization(),
                name=name,
                arguments=arguments,
                timeout_seconds=timeout_seconds,
                cancelled=cancelled,
            )
        if len(canonical_json(result.model_dump(mode="json"))) > (
            self._registration.maximum_response_bytes
        ):
            raise PayloadRejected("MCP result exceeds the registration bound")
        if result.proposal_ref is not None and name != McpToolName.PROPOSAL_SUBMIT:
            raise PayloadRejected("MCP result forged a proposal reference")
        return result

    def close(self) -> None:
        initialization = self._require_initialization()
        self._sdk.close(
            registration=self._registration,
            initialization=initialization,
        )
        self._initialization = None

    def _require_initialization(self) -> McpInitialization:
        if self._initialization is None:
            raise PolicyDenied("MCP session is not initialized")
        return self._initialization


def curated_tools() -> tuple[ToolContract, ...]:
    """Return deterministic declarations; descriptions remain digest-only."""

    risk = {
        McpToolName.INCIDENT_READ: RiskLevel.LOW,
        McpToolName.EVIDENCE_LIST: RiskLevel.LOW,
        McpToolName.MEMORY_SEARCH: RiskLevel.MEDIUM,
        McpToolName.RUNBOOK_READ: RiskLevel.LOW,
        McpToolName.STATUS_READ: RiskLevel.LOW,
        McpToolName.INVESTIGATION_SUBMIT: RiskLevel.MEDIUM,
        McpToolName.PROPOSAL_SUBMIT: RiskLevel.HIGH,
    }
    return tuple(
        ToolContract(
            tool_id=f"tool-{name.value.replace('.', '-')}",
            capability_id=f"mcp-{name.value.replace('.', '-')}",
            name=name.value,
            description_digest=digest_value(f"curated:{name.value}:v1"),
            input_schema_digest=digest_value(f"input:{name.value}:v1"),
            output_schema_digest=digest_value(f"output:{name.value}:v1"),
            risk=risk[name],
            idempotent=True,
        )
        for name in McpToolName
    )


def curated_capabilities() -> tuple[CapabilityContract, ...]:
    return tuple(
        CapabilityContract(
            capability_id=tool.capability_id,
            protocol=ProtocolKind.MCP,
            operation=(
                "propose"
                if tool.name == McpToolName.PROPOSAL_SUBMIT
                else "investigate"
                if tool.name == McpToolName.INVESTIGATION_SUBMIT
                else "status"
                if tool.name == McpToolName.STATUS_READ
                else "read"
            ),
            resource_kind=tool.name.split(".")[1],
            risk=tool.risk,
            input_schema_digest=tool.input_schema_digest,
            output_schema_digest=tool.output_schema_digest,
            maximum_input_bytes=32_768,
            maximum_output_bytes=MAX_PROTOCOL_DOCUMENT_BYTES,
        )
        for tool in curated_tools()
    )


def _required_identifier(arguments: Mapping[str, JsonValue], key: str) -> str:
    value = arguments.get(key)
    if not isinstance(value, str) or not value or len(value) > 512:
        raise PayloadRejected(f"MCP argument {key} is invalid")
    return value


def _required_text(arguments: Mapping[str, JsonValue], key: str) -> str:
    value = arguments.get(key)
    if not isinstance(value, str) or not value:
        raise PayloadRejected(f"MCP argument {key} is invalid")
    return validate_untrusted_text(value)


def _bounded_int(
    arguments: Mapping[str, JsonValue],
    key: str,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    value = arguments.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool):
        raise PayloadRejected(f"MCP argument {key} is invalid")
    if value < minimum or value > maximum:
        raise PayloadRejected(f"MCP argument {key} is outside the bound")
    return value
