"""Provider-neutral model contracts and application-owned gateway controls."""

from __future__ import annotations

import json
from collections import defaultdict, deque
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from decimal import ROUND_CEILING, Decimal
from enum import StrEnum
from hashlib import sha256
from threading import BoundedSemaphore, Lock
from typing import Protocol, TypeVar
from urllib.parse import urlsplit

from pydantic import (
    AwareDatetime,
    BaseModel,
    Field,
    JsonValue,
    TypeAdapter,
    ValidationError,
    field_validator,
)

from aegis_framework.domain import Identifier, RiskLevel, StrictModel
from aegis_framework.errors import IntegrityFailure, ModelProviderError, PolicyDenied

_MAX_MESSAGE_BYTES = 32_768
_MAX_CONTEXT_BYTES = 131_072
_MAX_MESSAGES = 64
_MAX_TOOLS = 16
_MAX_ROUTES = 8
_MONEY_SCALE = Decimal("1000000")
_OutputT = TypeVar("_OutputT", bound=BaseModel)


class ModelProvider(StrEnum):
    FAKE = "fake"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class ModelRole(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class DataClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class ModelCapability(StrEnum):
    JSON_SCHEMA = "json_schema"
    TOOLS = "tools"
    VISION = "vision"


class ModelFinishReason(StrEnum):
    STOP = "stop"
    TOOL_CALL = "tool_call"
    LENGTH = "length"
    CONTENT_FILTER = "content_filter"


class BillingDisposition(StrEnum):
    NOT_BILLED = "not_billed"
    BILLED = "billed"
    AMBIGUOUS = "ambiguous"


class ModelErrorCode(StrEnum):
    AUTHENTICATION = "authentication"
    BAD_REQUEST = "bad_request"
    CANCELLED = "cancelled"
    CAPABILITY = "capability"
    CIRCUIT_OPEN = "circuit_open"
    CONTENT_FILTER = "content_filter"
    MALFORMED_RESPONSE = "malformed_response"
    POLICY_DENIED = "policy_denied"
    PRICING_UNKNOWN = "pricing_unknown"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    TRANSIENT = "transient"
    UNAVAILABLE = "unavailable"
    USAGE_EXCEEDED = "usage_exceeded"


class TextContent(StrictModel):
    type: str = Field(default="text", pattern=r"^text$")
    text: str = Field(min_length=1, max_length=_MAX_MESSAGE_BYTES)


class JsonContent(StrictModel):
    type: str = Field(default="json", pattern=r"^json$")
    value: dict[str, JsonValue] = Field(max_length=64)


type MessageContent = TextContent | JsonContent


class ModelMessage(StrictModel):
    role: ModelRole
    content: tuple[MessageContent, ...] = Field(min_length=1, max_length=16)
    name: Identifier | None = None
    tool_call_id: Identifier | None = None

    @field_validator("content")
    @classmethod
    def bound_content(
        cls, value: tuple[MessageContent, ...]
    ) -> tuple[MessageContent, ...]:
        if len(_canonical_json([item.model_dump(mode="json") for item in value])) > (
            _MAX_MESSAGE_BYTES
        ):
            raise ValueError("message content exceeds the byte bound")
        return value


class ToolDefinition(StrictModel):
    name: Identifier
    description: str = Field(min_length=1, max_length=512)
    input_schema: dict[str, JsonValue] = Field(max_length=64)

    @field_validator("input_schema")
    @classmethod
    def require_object_schema(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        if value.get("type") != "object":
            raise ValueError("tool input schema must describe an object")
        if len(_canonical_json(value)) > 16_384:
            raise ValueError("tool input schema exceeds the byte bound")
        return dict(sorted(value.items()))


class StructuredOutputDefinition(StrictModel):
    name: Identifier
    json_schema: dict[str, JsonValue] = Field(max_length=128)
    strict: bool = True

    @field_validator("json_schema")
    @classmethod
    def require_object_schema(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        if value.get("type") != "object":
            raise ValueError("structured output schema must describe an object")
        if len(_canonical_json(value)) > 32_768:
            raise ValueError("structured output schema exceeds the byte bound")
        return dict(sorted(value.items()))


class ModelCallBinding(StrictModel):
    tenant_id: Identifier
    run_id: Identifier
    call_id: Identifier
    purpose: Identifier
    data_classification: DataClassification
    risk: RiskLevel


class ModelRequest(StrictModel):
    binding: ModelCallBinding
    messages: tuple[ModelMessage, ...] = Field(min_length=1, max_length=_MAX_MESSAGES)
    max_output_tokens: int = Field(ge=1, le=32_768)
    temperature_milli: int = Field(default=0, ge=0, le=2_000)
    tools: tuple[ToolDefinition, ...] = Field(default=(), max_length=_MAX_TOOLS)
    allowed_tool_names: tuple[Identifier, ...] = Field(
        default=(), max_length=_MAX_TOOLS
    )
    structured_output: StructuredOutputDefinition

    @field_validator("allowed_tool_names")
    @classmethod
    def normalize_tools(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(value)))

    @field_validator("tools")
    @classmethod
    def require_unique_tool_names(
        cls, value: tuple[ToolDefinition, ...]
    ) -> tuple[ToolDefinition, ...]:
        names = [tool.name for tool in value]
        if len(names) != len(set(names)):
            raise ValueError("tool definitions must use unique names")
        return value

    @field_validator("messages")
    @classmethod
    def bound_context(cls, value: tuple[ModelMessage, ...]) -> tuple[ModelMessage, ...]:
        encoded = _canonical_json(
            [message.model_dump(mode="json") for message in value]
        )
        if len(encoded) > _MAX_CONTEXT_BYTES:
            raise ValueError("model context exceeds the byte bound")
        return value

    def canonical_digest(self) -> str:
        return _digest(self.model_dump(mode="json"))


class ModelUsage(StrictModel):
    input_tokens: int = Field(ge=0, le=10_000_000)
    output_tokens: int = Field(ge=0, le=10_000_000)
    cache_read_tokens: int = Field(default=0, ge=0, le=10_000_000)
    cache_write_tokens: int = Field(default=0, ge=0, le=10_000_000)
    provider_reported: bool

    @property
    def total_tokens(self) -> int:
        return (
            self.input_tokens
            + self.output_tokens
            + self.cache_read_tokens
            + self.cache_write_tokens
        )


class SafetyAssessment(StrictModel):
    blocked: bool
    categories: tuple[Identifier, ...] = ()
    provider_reported: bool = False

    @field_validator("categories")
    @classmethod
    def normalize_categories(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(value)))


class ProviderResult(StrictModel):
    structured_output: dict[str, JsonValue] = Field(max_length=128)
    usage: ModelUsage
    finish_reason: ModelFinishReason
    safety: SafetyAssessment
    provider_request_ref: Identifier | None = None


class ModelPrice(StrictModel):
    version: Identifier
    currency: str = Field(pattern=r"^USD$")
    input_microunits_per_million_tokens: int = Field(ge=0, le=10**12)
    output_microunits_per_million_tokens: int = Field(ge=0, le=10**12)
    cache_read_microunits_per_million_tokens: int = Field(default=0, ge=0, le=10**12)
    cache_write_microunits_per_million_tokens: int = Field(default=0, ge=0, le=10**12)

    def maximum_cost_microunits(self, *, input_tokens: int, output_tokens: int) -> int:
        return _round_cost(
            input_tokens * self.input_microunits_per_million_tokens
            + output_tokens * self.output_microunits_per_million_tokens
            + input_tokens * self.cache_read_microunits_per_million_tokens
            + input_tokens * self.cache_write_microunits_per_million_tokens
        )

    def actual_cost_microunits(self, usage: ModelUsage) -> int:
        return _round_cost(
            usage.input_tokens * self.input_microunits_per_million_tokens
            + usage.output_tokens * self.output_microunits_per_million_tokens
            + usage.cache_read_tokens * self.cache_read_microunits_per_million_tokens
            + usage.cache_write_tokens * self.cache_write_microunits_per_million_tokens
        )


class CredentialReference(StrictModel):
    reference: Identifier
    version: int = Field(ge=1)


class ModelCatalogEntry(StrictModel):
    tenant_id: Identifier
    provider: ModelProvider
    model: Identifier
    region: Identifier
    capabilities: frozenset[ModelCapability]
    context_tokens: int = Field(ge=1, le=10_000_000)
    maximum_output_tokens: int = Field(ge=1, le=1_000_000)
    tokenizer: Identifier | None
    tokenizer_limitations: str = Field(min_length=1, max_length=512)
    usage_limitations: str = Field(min_length=1, max_length=512)
    price: ModelPrice
    credential: CredentialReference
    enabled: bool = True

    @field_validator("model", "region")
    @classmethod
    def reserve_catalog_separator(cls, value: str) -> str:
        if ":" in value:
            raise ValueError("model catalog components cannot contain ':'")
        return value

    @property
    def key(self) -> str:
        return f"{self.provider.value}:{self.model}:{self.region}"


class ModelRoute(StrictModel):
    provider: ModelProvider
    model: Identifier
    region: Identifier
    priority: int = Field(ge=1, le=_MAX_ROUTES)

    @property
    def catalog_key(self) -> str:
        return f"{self.provider.value}:{self.model}:{self.region}"


class TenantModelPolicy(StrictModel):
    tenant_id: Identifier
    policy_id: Identifier
    revision: int = Field(ge=1)
    allowed_providers: frozenset[ModelProvider]
    allowed_models: frozenset[Identifier]
    allowed_regions: frozenset[Identifier]
    allowed_data_classifications: frozenset[DataClassification]
    allowed_purposes: frozenset[Identifier]
    required_capabilities: frozenset[ModelCapability]
    risk_ceiling: RiskLevel
    routes: tuple[ModelRoute, ...] = Field(min_length=1, max_length=_MAX_ROUTES)
    maximum_input_tokens: int = Field(ge=1, le=10_000_000)
    maximum_output_tokens: int = Field(ge=1, le=1_000_000)
    maximum_cost_microunits: int = Field(ge=1, le=10**12)
    maximum_calls_per_run: int = Field(ge=1, le=1_000)
    repair_attempts: int = Field(default=1, ge=0, le=2)
    fallback_on_ambiguous_billing: bool = False

    def canonical_digest(self) -> str:
        document = self.model_dump(mode="json")
        document.update(
            {
                "allowed_providers": sorted(
                    provider.value for provider in self.allowed_providers
                ),
                "allowed_models": sorted(self.allowed_models),
                "allowed_regions": sorted(self.allowed_regions),
                "allowed_data_classifications": sorted(
                    value.value for value in self.allowed_data_classifications
                ),
                "allowed_purposes": sorted(self.allowed_purposes),
                "required_capabilities": sorted(
                    capability.value for capability in self.required_capabilities
                ),
            }
        )
        return _digest(document)

    @field_validator("routes")
    @classmethod
    def normalize_routes(cls, value: tuple[ModelRoute, ...]) -> tuple[ModelRoute, ...]:
        priorities = [route.priority for route in value]
        if len(priorities) != len(set(priorities)):
            raise ValueError("model route priorities must be unique")
        return tuple(
            sorted(
                value,
                key=lambda route: (
                    route.priority,
                    route.provider.value,
                    route.model,
                    route.region,
                ),
            )
        )


class ModelReservation(StrictModel):
    tenant_id: Identifier
    run_id: Identifier
    reservation_id: Identifier
    requested_input_tokens: int = Field(ge=0)
    requested_output_tokens: int = Field(ge=1)
    reserved_cost_microunits: int = Field(ge=0)
    policy_id: Identifier
    policy_revision: int = Field(ge=1)
    policy_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: AwareDatetime


class ModelCallRecord(StrictModel):
    tenant_id: Identifier
    run_id: Identifier
    call_id: Identifier
    attempt_id: Identifier
    request_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    catalog_key: Identifier
    price_version: Identifier
    policy_revision: int = Field(ge=1)
    requested_at: AwareDatetime
    completed_at: AwareDatetime | None = None
    outcome: Identifier
    billing: BillingDisposition
    usage: ModelUsage | None = None
    cost_microunits: int | None = Field(default=None, ge=0)
    error_code: ModelErrorCode | None = None


class ModelUsageView(StrictModel):
    run_id: Identifier
    reserved_cost_microunits: int = Field(ge=0)
    reconciled_cost_microunits: int = Field(ge=0)
    ambiguous_cost_microunits: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    call_count: int = Field(ge=0)


class ProviderHealthView(StrictModel):
    provider: ModelProvider
    model: Identifier
    region: Identifier
    status: str = Field(pattern=r"^(healthy|degraded|open|unknown)$")
    observed_calls: int = Field(ge=0)
    failure_count: int = Field(ge=0)


class ProviderInvocationError(ModelProviderError):
    """Typed provider failure with explicit retry and billing semantics."""

    def __init__(
        self,
        code: ModelErrorCode,
        *,
        retryable: bool,
        billing: BillingDisposition,
    ) -> None:
        super().__init__(code.value)
        self.code = code
        self.retryable = retryable
        self.billing = billing


class ModelProviderAdapter(Protocol):
    provider: ModelProvider

    def invoke(
        self,
        *,
        entry: ModelCatalogEntry,
        request: ModelRequest,
        credential_reference: CredentialReference,
    ) -> ProviderResult: ...


class ModelGatewayPort(Protocol):
    def generate(
        self, request: ModelRequest, output_type: type[_OutputT]
    ) -> _OutputT: ...


class ModelControlStore(Protocol):
    def current_policy(self, *, tenant_id: str) -> TenantModelPolicy | None: ...

    def catalog_entry(
        self, *, tenant_id: str, key: str
    ) -> ModelCatalogEntry | None: ...

    def reserve(
        self,
        *,
        request: ModelRequest,
        policy: TenantModelPolicy,
        maximum_input_tokens: int,
        maximum_cost_microunits: int,
        now: datetime,
    ) -> ModelReservation: ...

    def append_requested(
        self,
        *,
        reservation: ModelReservation,
        request: ModelRequest,
        entry: ModelCatalogEntry,
        attempt_id: str,
        now: datetime,
    ) -> ModelCallRecord: ...

    def reconcile(
        self,
        *,
        tenant_id: str,
        attempt_id: str,
        outcome: str,
        billing: BillingDisposition,
        usage: ModelUsage | None,
        cost_microunits: int | None,
        error_code: ModelErrorCode | None,
        now: datetime,
    ) -> ModelCallRecord: ...

    def finalize(
        self,
        *,
        reservation: ModelReservation,
        now: datetime,
    ) -> None: ...

    def usage(self, *, tenant_id: str, run_id: str) -> ModelUsageView: ...

    def health(self, *, tenant_id: str) -> Sequence[ProviderHealthView]: ...

    def catalog(self, *, tenant_id: str) -> Sequence[ModelCatalogEntry]: ...


class InMemoryModelControlStore:
    """Deterministic application-owned policy, reservation, and usage ledger."""

    def __init__(
        self,
        *,
        policies: Sequence[TenantModelPolicy],
        catalog: Sequence[ModelCatalogEntry],
        tenant_cost_limits: Mapping[str, int],
    ) -> None:
        self._policies = {policy.tenant_id: policy for policy in policies}
        self._catalog = {(entry.tenant_id, entry.key): entry for entry in catalog}
        self._limits = dict(tenant_cost_limits)
        self._reservations: dict[tuple[str, str], ModelReservation] = {}
        self._records: dict[tuple[str, str], ModelCallRecord] = {}
        self._finalized: dict[tuple[str, str], bool] = {}
        self._lock = Lock()

    def current_policy(self, *, tenant_id: str) -> TenantModelPolicy | None:
        return self._policies.get(tenant_id)

    def replace_policy(self, policy: TenantModelPolicy) -> None:
        self._policies[policy.tenant_id] = policy

    def catalog_entry(self, *, tenant_id: str, key: str) -> ModelCatalogEntry | None:
        return self._catalog.get((tenant_id, key))

    def reserve(
        self,
        *,
        request: ModelRequest,
        policy: TenantModelPolicy,
        maximum_input_tokens: int,
        maximum_cost_microunits: int,
        now: datetime,
    ) -> ModelReservation:
        key = (request.binding.tenant_id, request.binding.call_id)
        with self._lock:
            existing = self._reservations.get(key)
            if existing is not None:
                if (
                    existing.requested_input_tokens != maximum_input_tokens
                    or existing.requested_output_tokens != request.max_output_tokens
                    or existing.policy_id != policy.policy_id
                    or existing.policy_revision != policy.revision
                    or existing.policy_digest != policy.canonical_digest()
                ):
                    raise PolicyDenied("model reservation parameters changed")
                return existing
            tenant_consumed = sum(
                self._consumed_cost(reservation)
                for reservation in self._reservations.values()
                if reservation.tenant_id == request.binding.tenant_id
            )
            if maximum_cost_microunits > policy.maximum_cost_microunits:
                raise PolicyDenied("model call exceeds policy cost ceiling")
            if tenant_consumed + maximum_cost_microunits > self._limits.get(
                request.binding.tenant_id, 0
            ):
                raise PolicyDenied("tenant model budget exhausted")
            run_calls = sum(
                1
                for candidate in self._reservations.values()
                if candidate.tenant_id == request.binding.tenant_id
                and candidate.run_id == request.binding.run_id
            )
            if run_calls >= policy.maximum_calls_per_run:
                raise PolicyDenied("model run call limit exhausted")
            reservation = ModelReservation(
                tenant_id=request.binding.tenant_id,
                run_id=request.binding.run_id,
                reservation_id=request.binding.call_id,
                requested_input_tokens=maximum_input_tokens,
                requested_output_tokens=request.max_output_tokens,
                reserved_cost_microunits=maximum_cost_microunits,
                policy_id=policy.policy_id,
                policy_revision=policy.revision,
                policy_digest=policy.canonical_digest(),
                created_at=now,
            )
            self._reservations[key] = reservation
            return reservation

    def append_requested(
        self,
        *,
        reservation: ModelReservation,
        request: ModelRequest,
        entry: ModelCatalogEntry,
        attempt_id: str,
        now: datetime,
    ) -> ModelCallRecord:
        with self._lock:
            key = (request.binding.tenant_id, attempt_id)
            existing = self._records.get(key)
            if existing is not None:
                if existing.request_digest != request.canonical_digest():
                    raise PolicyDenied(
                        "model attempt id was reused with different input"
                    )
                raise PolicyDenied(
                    "model attempt already has durable intent; reconcile before retry"
                )
            record = ModelCallRecord(
                tenant_id=request.binding.tenant_id,
                run_id=request.binding.run_id,
                call_id=request.binding.call_id,
                attempt_id=attempt_id,
                request_digest=request.canonical_digest(),
                catalog_key=entry.key,
                price_version=entry.price.version,
                policy_revision=reservation.policy_revision,
                requested_at=now,
                outcome="requested",
                billing=BillingDisposition.AMBIGUOUS,
            )
            self._records[key] = record
            return record

    def reconcile(
        self,
        *,
        tenant_id: str,
        attempt_id: str,
        outcome: str,
        billing: BillingDisposition,
        usage: ModelUsage | None,
        cost_microunits: int | None,
        error_code: ModelErrorCode | None,
        now: datetime,
    ) -> ModelCallRecord:
        if billing is BillingDisposition.BILLED and (
            usage is None or cost_microunits is None
        ):
            raise IntegrityFailure("billed model outcome requires usage and cost")
        with self._lock:
            key = (tenant_id, attempt_id)
            current = self._records.get(key)
            if current is None:
                raise PolicyDenied("model attempt intent is unavailable")
            if current.completed_at is not None:
                if (
                    current.billing is BillingDisposition.AMBIGUOUS
                    and billing is not BillingDisposition.AMBIGUOUS
                ):
                    corrected = current.model_copy(
                        update={
                            "completed_at": now,
                            "outcome": outcome,
                            "billing": billing,
                            "usage": usage,
                            "cost_microunits": cost_microunits,
                            "error_code": error_code,
                        }
                    )
                    self._records[key] = corrected
                    call_key = (tenant_id, current.call_id)
                    if call_key in self._finalized:
                        self._finalized[call_key] = any(
                            record.tenant_id == tenant_id
                            and record.call_id == current.call_id
                            and record.billing is BillingDisposition.AMBIGUOUS
                            for record in self._records.values()
                        )
                    return corrected
                return current
            updated = current.model_copy(
                update={
                    "completed_at": now,
                    "outcome": outcome,
                    "billing": billing,
                    "usage": usage,
                    "cost_microunits": cost_microunits,
                    "error_code": error_code,
                }
            )
            self._records[key] = updated
            return updated

    def finalize(
        self,
        *,
        reservation: ModelReservation,
        now: datetime,
    ) -> None:
        del now
        key = (reservation.tenant_id, reservation.reservation_id)
        with self._lock:
            if key in self._finalized:
                return
            records = tuple(
                record
                for record in self._records.values()
                if record.tenant_id == reservation.tenant_id
                and record.call_id == reservation.reservation_id
            )
            self._finalized[key] = any(
                record.billing is BillingDisposition.AMBIGUOUS for record in records
            )

    def usage(self, *, tenant_id: str, run_id: str) -> ModelUsageView:
        reservations = tuple(
            reservation
            for reservation in self._reservations.values()
            if reservation.tenant_id == tenant_id and reservation.run_id == run_id
        )
        records = tuple(
            record
            for record in self._records.values()
            if record.tenant_id == tenant_id and record.run_id == run_id
        )
        return ModelUsageView(
            run_id=run_id,
            reserved_cost_microunits=sum(
                reservation.reserved_cost_microunits for reservation in reservations
            ),
            reconciled_cost_microunits=sum(
                record.cost_microunits or 0
                for record in records
                if record.billing is BillingDisposition.BILLED
            ),
            ambiguous_cost_microunits=sum(
                reservation.reserved_cost_microunits
                for reservation in reservations
                if any(
                    record.call_id == reservation.reservation_id
                    and (
                        record.billing is BillingDisposition.AMBIGUOUS
                        or record.completed_at is None
                    )
                    for record in records
                )
            ),
            input_tokens=sum(
                record.usage.input_tokens
                for record in records
                if record.usage is not None
            ),
            output_tokens=sum(
                record.usage.output_tokens
                for record in records
                if record.usage is not None
            ),
            call_count=len(records),
        )

    def _consumed_cost(self, reservation: ModelReservation) -> int:
        key = (reservation.tenant_id, reservation.reservation_id)
        ambiguous = self._finalized.get(key)
        if ambiguous is None or ambiguous:
            return reservation.reserved_cost_microunits
        return sum(
            record.cost_microunits or 0
            for record in self._records.values()
            if record.tenant_id == reservation.tenant_id
            and record.call_id == reservation.reservation_id
            and record.billing is BillingDisposition.BILLED
        )

    def health(self, *, tenant_id: str) -> Sequence[ProviderHealthView]:
        policy = self._policies.get(tenant_id)
        if policy is None:
            return ()
        views: list[ProviderHealthView] = []
        for route in policy.routes:
            records = tuple(
                record
                for record in self._records.values()
                if record.tenant_id == tenant_id
                and record.catalog_key == route.catalog_key
            )
            failures = sum(record.error_code is not None for record in records)
            views.append(
                ProviderHealthView(
                    provider=route.provider,
                    model=route.model,
                    region=route.region,
                    status=(
                        "unknown"
                        if not records
                        else "degraded"
                        if failures
                        else "healthy"
                    ),
                    observed_calls=len(records),
                    failure_count=failures,
                )
            )
        return tuple(views)

    def catalog(self, *, tenant_id: str) -> Sequence[ModelCatalogEntry]:
        policy = self._policies.get(tenant_id)
        if policy is None:
            return ()
        return tuple(
            entry
            for route in policy.routes
            if (entry := self._catalog.get((tenant_id, route.catalog_key))) is not None
        )


class GatewayClock(Protocol):
    def now(self) -> datetime: ...


class SystemGatewayClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class ModelGateway:
    """Routes one structured call under explicit application policy and accounting."""

    def __init__(
        self,
        *,
        store: ModelControlStore,
        adapters: Sequence[ModelProviderAdapter],
        clock: GatewayClock | None = None,
        cancellation_requested: Callable[[], bool] | None = None,
        maximum_concurrency: int = 8,
        rate_limit_per_minute: int = 60,
        circuit_failure_threshold: int = 3,
        circuit_open_seconds: int = 30,
    ) -> None:
        if maximum_concurrency < 1 or maximum_concurrency > 1_000:
            raise ValueError("model concurrency bound is invalid")
        if rate_limit_per_minute < 1 or rate_limit_per_minute > 100_000:
            raise ValueError("model rate bound is invalid")
        self._store = store
        self._adapters = {adapter.provider: adapter for adapter in adapters}
        self._clock = clock or SystemGatewayClock()
        self._cancelled = cancellation_requested or (lambda: False)
        self._concurrency = BoundedSemaphore(maximum_concurrency)
        self._rate_limit = rate_limit_per_minute
        self._rate_windows: defaultdict[str, deque[datetime]] = defaultdict(deque)
        self._circuit_failures: defaultdict[str, int] = defaultdict(int)
        self._circuit_opened: dict[str, datetime] = {}
        self._circuit_threshold = circuit_failure_threshold
        self._circuit_duration = timedelta(seconds=circuit_open_seconds)
        self._state_lock = Lock()

    def generate(self, request: ModelRequest, output_type: type[_OutputT]) -> _OutputT:
        if self._cancelled():
            raise ProviderInvocationError(
                ModelErrorCode.CANCELLED,
                retryable=False,
                billing=BillingDisposition.NOT_BILLED,
            )
        if not self._concurrency.acquire(blocking=False):
            raise ProviderInvocationError(
                ModelErrorCode.RATE_LIMITED,
                retryable=True,
                billing=BillingDisposition.NOT_BILLED,
            )
        try:
            return self._generate_admitted(request, output_type)
        finally:
            self._concurrency.release()

    def _generate_admitted(
        self, request: ModelRequest, output_type: type[_OutputT]
    ) -> _OutputT:
        policy = self._require_policy(request)
        circuit_entries = self._eligible_entries(request, policy)
        entries = tuple(
            entry
            for entry in circuit_entries
            if not self._circuit_is_open(
                request.binding.tenant_id,
                entry.key,
            )
        )
        if not entries:
            raise ProviderInvocationError(
                ModelErrorCode.CIRCUIT_OPEN,
                retryable=True,
                billing=BillingDisposition.NOT_BILLED,
            )
        self._check_rate(request.binding.tenant_id)
        input_tokens = _conservative_tokens(request)
        maximum_cost = (
            max(
                entry.price.maximum_cost_microunits(
                    input_tokens=input_tokens,
                    output_tokens=request.max_output_tokens,
                )
                for entry in entries
            )
            * len(entries)
            * (1 + policy.repair_attempts)
        )
        reservation = self._store.reserve(
            request=request,
            policy=policy,
            maximum_input_tokens=input_tokens,
            maximum_cost_microunits=maximum_cost,
            now=self._clock.now(),
        )
        failures: list[ProviderInvocationError] = []
        for route_index, entry in enumerate(entries, start=1):
            if self._cancelled():
                self._store.finalize(
                    reservation=reservation,
                    now=self._clock.now(),
                )
                raise ProviderInvocationError(
                    ModelErrorCode.CANCELLED,
                    retryable=False,
                    billing=BillingDisposition.NOT_BILLED,
                )
            attempts = 1 + policy.repair_attempts
            for repair_index in range(attempts):
                current_policy = self._store.current_policy(
                    tenant_id=request.binding.tenant_id
                )
                if (
                    current_policy is None
                    or current_policy.policy_id != reservation.policy_id
                    or current_policy.revision != reservation.policy_revision
                    or current_policy.canonical_digest() != reservation.policy_digest
                    or self._cancelled()
                ):
                    self._store.finalize(
                        reservation=reservation,
                        now=self._clock.now(),
                    )
                    raise ProviderInvocationError(
                        (
                            ModelErrorCode.CANCELLED
                            if self._cancelled()
                            else ModelErrorCode.POLICY_DENIED
                        ),
                        retryable=False,
                        billing=BillingDisposition.NOT_BILLED,
                    )
                attempt_id = (
                    f"{request.binding.call_id}:r{route_index}:a{repair_index + 1}"
                )
                self._store.append_requested(
                    reservation=reservation,
                    request=request,
                    entry=entry,
                    attempt_id=attempt_id,
                    now=self._clock.now(),
                )
                result: ProviderResult | None = None
                try:
                    result = self._invoke(entry, request)
                    current_policy = self._store.current_policy(
                        tenant_id=request.binding.tenant_id
                    )
                    if (
                        current_policy is None
                        or current_policy.policy_id != reservation.policy_id
                        or current_policy.revision != reservation.policy_revision
                        or current_policy.canonical_digest()
                        != reservation.policy_digest
                        or self._cancelled()
                    ):
                        cost = entry.price.actual_cost_microunits(result.usage)
                        code = (
                            ModelErrorCode.CANCELLED
                            if self._cancelled()
                            else ModelErrorCode.POLICY_DENIED
                        )
                        self._store.reconcile(
                            tenant_id=request.binding.tenant_id,
                            attempt_id=attempt_id,
                            outcome="stale",
                            billing=BillingDisposition.BILLED,
                            usage=result.usage,
                            cost_microunits=cost,
                            error_code=code,
                            now=self._clock.now(),
                        )
                        raise ProviderInvocationError(
                            code,
                            retryable=False,
                            billing=BillingDisposition.BILLED,
                        )
                    cost = entry.price.actual_cost_microunits(result.usage)
                    if (
                        result.usage.output_tokens > request.max_output_tokens
                        or (
                            result.usage.input_tokens
                            + result.usage.cache_read_tokens
                            + result.usage.cache_write_tokens
                        )
                        > reservation.requested_input_tokens
                        or result.usage.total_tokens > entry.context_tokens
                        or cost > reservation.reserved_cost_microunits
                    ):
                        raise ProviderInvocationError(
                            ModelErrorCode.USAGE_EXCEEDED,
                            retryable=False,
                            billing=BillingDisposition.BILLED,
                        )
                    if result.safety.blocked:
                        raise ProviderInvocationError(
                            ModelErrorCode.CONTENT_FILTER,
                            retryable=False,
                            billing=BillingDisposition.BILLED,
                        )
                    if result.finish_reason is not ModelFinishReason.STOP:
                        raise ProviderInvocationError(
                            ModelErrorCode.CAPABILITY,
                            retryable=False,
                            billing=BillingDisposition.BILLED,
                        )
                    parsed = TypeAdapter(output_type).validate_python(
                        result.structured_output
                    )
                except ValidationError:
                    error = ProviderInvocationError(
                        ModelErrorCode.MALFORMED_RESPONSE,
                        retryable=repair_index + 1 < attempts,
                        billing=BillingDisposition.BILLED,
                    )
                    self._record_failure(
                        request.binding.tenant_id,
                        attempt_id,
                        error,
                        entry,
                        usage=result.usage if result is not None else None,
                    )
                    failures.append(error)
                    if error.retryable:
                        continue
                    self._store.finalize(
                        reservation=reservation,
                        now=self._clock.now(),
                    )
                    raise error from None
                except ProviderInvocationError as error:
                    self._record_failure(
                        request.binding.tenant_id,
                        attempt_id,
                        error,
                        entry,
                        usage=result.usage if result is not None else None,
                    )
                    failures.append(error)
                    if error.code in {
                        ModelErrorCode.RATE_LIMITED,
                        ModelErrorCode.TIMEOUT,
                        ModelErrorCode.TRANSIENT,
                        ModelErrorCode.UNAVAILABLE,
                    }:
                        self._mark_failure(request.binding.tenant_id, entry.key)
                    if error.billing is BillingDisposition.AMBIGUOUS and (
                        not policy.fallback_on_ambiguous_billing
                    ):
                        self._store.finalize(
                            reservation=reservation,
                            now=self._clock.now(),
                        )
                        raise error
                    if not error.retryable or error.code not in {
                        ModelErrorCode.RATE_LIMITED,
                        ModelErrorCode.TIMEOUT,
                        ModelErrorCode.TRANSIENT,
                        ModelErrorCode.UNAVAILABLE,
                    }:
                        self._store.finalize(
                            reservation=reservation,
                            now=self._clock.now(),
                        )
                        raise error
                    break
                cost = entry.price.actual_cost_microunits(result.usage)
                self._store.reconcile(
                    tenant_id=request.binding.tenant_id,
                    attempt_id=attempt_id,
                    outcome="completed",
                    billing=BillingDisposition.BILLED,
                    usage=result.usage,
                    cost_microunits=cost,
                    error_code=None,
                    now=self._clock.now(),
                )
                self._mark_success(request.binding.tenant_id, entry.key)
                self._store.finalize(
                    reservation=reservation,
                    now=self._clock.now(),
                )
                return parsed
        self._store.finalize(
            reservation=reservation,
            now=self._clock.now(),
        )
        if failures:
            raise failures[-1]
        raise ProviderInvocationError(
            ModelErrorCode.UNAVAILABLE,
            retryable=False,
            billing=BillingDisposition.NOT_BILLED,
        )

    def _invoke(
        self, entry: ModelCatalogEntry, request: ModelRequest
    ) -> ProviderResult:
        adapter = self._adapters.get(entry.provider)
        if adapter is None:
            raise ProviderInvocationError(
                ModelErrorCode.UNAVAILABLE,
                retryable=False,
                billing=BillingDisposition.NOT_BILLED,
            )
        try:
            return adapter.invoke(
                entry=entry,
                request=request,
                credential_reference=entry.credential,
            )
        except ProviderInvocationError:
            raise
        except Exception as exc:
            # An unexpected adapter failure (e.g. secret-resolver RuntimeError,
            # non-SDK client exception) that escapes after append_requested()
            # would leave the attempt reservation permanently pending and block
            # retries.  Wrap it in a typed ambiguous-billing failure so the
            # gateway reconciles the attempt record correctly.
            raise ProviderInvocationError(
                ModelErrorCode.UNAVAILABLE,
                retryable=False,
                billing=BillingDisposition.AMBIGUOUS,
            ) from exc

    def _require_policy(self, request: ModelRequest) -> TenantModelPolicy:
        policy = self._store.current_policy(tenant_id=request.binding.tenant_id)
        if policy is None:
            raise PolicyDenied("no tenant model policy")
        if request.binding.purpose not in policy.allowed_purposes:
            raise PolicyDenied("model purpose is not allowed")
        if (
            request.binding.data_classification
            not in policy.allowed_data_classifications
        ):
            raise PolicyDenied("model data classification is not allowed")
        risk_order = {RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3}
        if risk_order[request.binding.risk] > risk_order[policy.risk_ceiling]:
            raise PolicyDenied("model risk exceeds policy")
        if request.max_output_tokens > policy.maximum_output_tokens:
            raise PolicyDenied("model output token request exceeds policy")
        tool_names = {tool.name for tool in request.tools}
        if set(request.allowed_tool_names) != tool_names:
            raise PolicyDenied("model tool allowlist does not match definitions")
        if any(message.role is ModelRole.TOOL for message in request.messages):
            raise PolicyDenied(
                "tool result messages are not supported by these adapters"
            )
        return policy

    def _eligible_entries(
        self, request: ModelRequest, policy: TenantModelPolicy
    ) -> tuple[ModelCatalogEntry, ...]:
        required = set(policy.required_capabilities)
        required.add(ModelCapability.JSON_SCHEMA)
        if request.tools:
            required.add(ModelCapability.TOOLS)
        input_tokens = _conservative_tokens(request)
        if input_tokens > policy.maximum_input_tokens:
            raise PolicyDenied("model input token estimate exceeds policy")
        entries: list[ModelCatalogEntry] = []
        for route in policy.routes:
            entry = self._store.catalog_entry(
                tenant_id=request.binding.tenant_id,
                key=route.catalog_key,
            )
            if (
                entry is None
                or entry.tenant_id != request.binding.tenant_id
                or entry.key != route.catalog_key
                or not entry.enabled
                or entry.provider not in policy.allowed_providers
                or entry.model not in policy.allowed_models
                or entry.region not in policy.allowed_regions
                or not required.issubset(entry.capabilities)
                or input_tokens + request.max_output_tokens > entry.context_tokens
                or request.max_output_tokens > entry.maximum_output_tokens
            ):
                continue
            entries.append(entry)
        if not entries:
            raise PolicyDenied("no policy-eligible model route")
        return tuple(entries)

    def _check_rate(self, tenant_id: str) -> None:
        now = self._clock.now()
        threshold = now - timedelta(minutes=1)
        with self._state_lock:
            window = self._rate_windows[tenant_id]
            while window and window[0] <= threshold:
                window.popleft()
            if len(window) >= self._rate_limit:
                raise ProviderInvocationError(
                    ModelErrorCode.RATE_LIMITED,
                    retryable=True,
                    billing=BillingDisposition.NOT_BILLED,
                )
            window.append(now)

    def _circuit_is_open(self, tenant_id: str, key: str) -> bool:
        circuit_key = f"{tenant_id}\x00{key}"
        with self._state_lock:
            opened = self._circuit_opened.get(circuit_key)
            if opened is None:
                return False
            if self._clock.now() - opened >= self._circuit_duration:
                self._circuit_opened.pop(circuit_key, None)
                self._circuit_failures[circuit_key] = 0
                return False
            return True

    def _mark_failure(self, tenant_id: str, key: str) -> None:
        circuit_key = f"{tenant_id}\x00{key}"
        with self._state_lock:
            self._circuit_failures[circuit_key] += 1
            if self._circuit_failures[circuit_key] >= self._circuit_threshold:
                self._circuit_opened[circuit_key] = self._clock.now()

    def _mark_success(self, tenant_id: str, key: str) -> None:
        circuit_key = f"{tenant_id}\x00{key}"
        with self._state_lock:
            self._circuit_failures[circuit_key] = 0
            self._circuit_opened.pop(circuit_key, None)

    def _record_failure(
        self,
        tenant_id: str,
        attempt_id: str,
        error: ProviderInvocationError,
        entry: ModelCatalogEntry,
        *,
        usage: ModelUsage | None,
    ) -> None:
        cost = entry.price.actual_cost_microunits(usage) if usage is not None else None
        self._store.reconcile(
            tenant_id=tenant_id,
            attempt_id=attempt_id,
            outcome="failed",
            billing=error.billing,
            usage=usage,
            cost_microunits=cost,
            error_code=error.code,
            now=self._clock.now(),
        )


class FakeModelProvider:
    """Network-free scripted provider used by tests and deterministic evals."""

    provider = ModelProvider.FAKE

    def __init__(
        self,
        outcomes: Sequence[ProviderResult | ProviderInvocationError],
    ) -> None:
        self._outcomes = deque(outcomes)
        self.calls: list[tuple[str, str]] = []

    def invoke(
        self,
        *,
        entry: ModelCatalogEntry,
        request: ModelRequest,
        credential_reference: CredentialReference,
    ) -> ProviderResult:
        self.calls.append((entry.key, credential_reference.reference))
        if not self._outcomes:
            raise ProviderInvocationError(
                ModelErrorCode.UNAVAILABLE,
                retryable=False,
                billing=BillingDisposition.NOT_BILLED,
            )
        outcome = self._outcomes.popleft()
        if isinstance(outcome, ProviderInvocationError):
            raise outcome
        return outcome


def _conservative_tokens(request: ModelRequest) -> int:
    """Portable upper estimate; provider tokenizers remain catalog limitations."""

    encoded = _canonical_json(
        {
            "messages": [
                message.model_dump(mode="json") for message in request.messages
            ],
            "tools": [tool.model_dump(mode="json") for tool in request.tools],
            "structured_output": request.structured_output.model_dump(mode="json"),
        }
    )
    return max(1, (len(encoded) + 2) // 3)


def _round_cost(token_microunit_product: int) -> int:
    return int(
        (Decimal(token_microunit_product) / _MONEY_SCALE).to_integral_value(
            rounding=ROUND_CEILING
        )
    )


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=True,
    ).encode()


def _digest(value: object) -> str:
    return sha256(_canonical_json(value)).hexdigest()


def validate_provider_base_url(
    value: str,
    *,
    provider: str,
    default_host: str,
    default_path_prefix: str,
) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https":
        raise ValueError(f"{provider} base URL must use https")
    if (
        not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{provider} base URL is invalid")
    if parsed.hostname != default_host:
        raise ValueError(f"{provider} base URL host is not allowlisted")
    path = parsed.path.rstrip("/")
    if path != default_path_prefix:
        raise ValueError(f"{provider} base URL path is not allowlisted")
    return f"https://{default_host}{default_path_prefix}"
