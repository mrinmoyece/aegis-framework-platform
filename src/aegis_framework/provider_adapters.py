"""Official provider SDK adapters isolated behind the neutral gateway contract."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from typing import Any, Protocol, cast

from anthropic import APIError as AnthropicAPIError
from openai import APIError as OpenAIAPIError
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aegis_framework.model_gateway import (
    BillingDisposition,
    CredentialReference,
    JsonContent,
    ModelCatalogEntry,
    ModelErrorCode,
    ModelFinishReason,
    ModelMessage,
    ModelProvider,
    ModelProviderAdapter,
    ModelRequest,
    ModelRole,
    ModelUsage,
    ProviderInvocationError,
    ProviderResult,
    SafetyAssessment,
    TextContent,
    validate_provider_base_url,
)

_OPENAI_BASE_URL = "https://api.openai.com/v1"
_ANTHROPIC_BASE_URL = "https://api.anthropic.com"


class SecretResolver(Protocol):
    def resolve(self, reference: CredentialReference) -> str: ...


class _SdkResponse(Protocol):
    def model_dump(self, *, mode: str = "python") -> dict[str, Any]: ...


class _OpenAIUsageObject(Protocol):
    input_tokens: int
    output_tokens: int


class _OpenAIResponseObject(_SdkResponse, Protocol):
    id: str
    output_text: str
    status: str
    usage: _OpenAIUsageObject | None


class _OpenAIResponses(Protocol):
    def create(self, **kwargs: Any) -> _OpenAIResponseObject: ...


class _OpenAIClient(Protocol):
    @property
    def responses(self) -> _OpenAIResponses: ...


class _AnthropicMessages(Protocol):
    def create(self, **kwargs: Any) -> _SdkResponse: ...


class _AnthropicClient(Protocol):
    @property
    def messages(self) -> _AnthropicMessages: ...


class _VendorModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class _AnthropicUsage(_VendorModel):
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    cache_read_input_tokens: int | None = Field(default=0, ge=0)
    cache_creation_input_tokens: int | None = Field(default=0, ge=0)


class _AnthropicTextBlock(_VendorModel):
    type: str
    text: str | None = None


class _AnthropicResponse(_VendorModel):
    id: str | None = None
    content: tuple[_AnthropicTextBlock, ...]
    stop_reason: str | None
    usage: _AnthropicUsage


class OpenAIProviderAdapter(ModelProviderAdapter):
    """OpenAI Responses API adapter with SDK retries disabled."""

    provider = ModelProvider.OPENAI

    def __init__(
        self, client_for: Callable[[CredentialReference], _OpenAIClient]
    ) -> None:
        self._client_for = client_for

    @classmethod
    def from_secret_resolver(
        cls,
        resolver: SecretResolver,
        *,
        timeout_seconds: float = 60.0,
        base_url: str = _OPENAI_BASE_URL,
    ) -> OpenAIProviderAdapter:
        if timeout_seconds <= 0 or timeout_seconds > 300:
            raise ValueError("OpenAI timeout bound is invalid")
        validated_base_url = validate_provider_base_url(
            base_url,
            provider="OpenAI",
            default_host="api.openai.com",
            default_path_prefix="/v1",
        )

        def factory(reference: CredentialReference) -> _OpenAIClient:
            from openai import DefaultHttpxClient, OpenAI

            return cast(
                _OpenAIClient,
                OpenAI(
                    api_key=resolver.resolve(reference),
                    max_retries=0,
                    timeout=timeout_seconds,
                    base_url=validated_base_url,
                    http_client=DefaultHttpxClient(trust_env=False),
                ),
            )

        return cls(factory)

    def invoke(
        self,
        *,
        entry: ModelCatalogEntry,
        request: ModelRequest,
        credential_reference: CredentialReference,
    ) -> ProviderResult:
        try:
            client = self._client_for(credential_reference)
            if request.structured_output is None:
                raise ProviderInvocationError(
                    ModelErrorCode.BAD_REQUEST,
                    retryable=False,
                    billing=BillingDisposition.NOT_BILLED,
                )
            response = client.responses.create(
                model=entry.model,
                input=_openai_messages(request.messages),
                max_output_tokens=request.max_output_tokens,
                temperature=request.temperature_milli / 1_000,
                tools=_openai_tools(request),
                text={
                    "format": {
                        "type": "json_schema",
                        "name": request.structured_output.name,
                        "schema": request.structured_output.json_schema,
                        "strict": request.structured_output.strict,
                    }
                },
            )
            structured = json.loads(response.output_text)
            if not isinstance(structured, dict):
                raise ValueError("OpenAI structured output was not an object")
            if response.usage is None:
                raise ProviderInvocationError(
                    ModelErrorCode.MALFORMED_RESPONSE,
                    retryable=False,
                    billing=BillingDisposition.AMBIGUOUS,
                )
            finish = (
                ModelFinishReason.STOP
                if response.status == "completed"
                else ModelFinishReason.LENGTH
            )
            details = getattr(response.usage, "input_tokens_details", None)
            cache_read = int(getattr(details, "cached_tokens", 0) or 0)
            cache_write = int(getattr(details, "cache_write_tokens", 0) or 0)
            uncached_input = max(
                response.usage.input_tokens - cache_read - cache_write,
                0,
            )
            return ProviderResult(
                structured_output=structured,
                usage=ModelUsage(
                    input_tokens=uncached_input,
                    output_tokens=response.usage.output_tokens,
                    cache_read_tokens=cache_read,
                    cache_write_tokens=cache_write,
                    provider_reported=True,
                ),
                finish_reason=finish,
                safety=SafetyAssessment(
                    blocked=response.status == "incomplete",
                    categories=(
                        ("provider_incomplete",)
                        if response.status == "incomplete"
                        else ()
                    ),
                    provider_reported=True,
                ),
                provider_request_ref=_safe_provider_ref(response.id),
            )
        except ProviderInvocationError:
            raise
        except (ValidationError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise ProviderInvocationError(
                ModelErrorCode.MALFORMED_RESPONSE,
                retryable=False,
                billing=BillingDisposition.AMBIGUOUS,
            ) from exc
        except OpenAIAPIError as exc:
            raise _classify_sdk_error(exc) from exc


class AnthropicProviderAdapter(ModelProviderAdapter):
    """Anthropic Messages adapter with SDK retries disabled."""

    provider = ModelProvider.ANTHROPIC

    def __init__(
        self, client_for: Callable[[CredentialReference], _AnthropicClient]
    ) -> None:
        self._client_for = client_for

    @classmethod
    def from_secret_resolver(
        cls,
        resolver: SecretResolver,
        *,
        timeout_seconds: float = 60.0,
        base_url: str = _ANTHROPIC_BASE_URL,
    ) -> AnthropicProviderAdapter:
        if timeout_seconds <= 0 or timeout_seconds > 300:
            raise ValueError("Anthropic timeout bound is invalid")
        validated_base_url = validate_provider_base_url(
            base_url,
            provider="Anthropic",
            default_host="api.anthropic.com",
            default_path_prefix="",
        )

        def factory(reference: CredentialReference) -> _AnthropicClient:
            from anthropic import Anthropic, DefaultHttpxClient

            return cast(
                _AnthropicClient,
                Anthropic(
                    api_key=resolver.resolve(reference),
                    max_retries=0,
                    timeout=timeout_seconds,
                    base_url=validated_base_url,
                    http_client=DefaultHttpxClient(trust_env=False),
                ),
            )

        return cls(factory)

    def invoke(
        self,
        *,
        entry: ModelCatalogEntry,
        request: ModelRequest,
        credential_reference: CredentialReference,
    ) -> ProviderResult:
        try:
            client = self._client_for(credential_reference)
            system, messages = _anthropic_messages(request.messages)
            if request.structured_output is None:
                raise ProviderInvocationError(
                    ModelErrorCode.BAD_REQUEST,
                    retryable=False,
                    billing=BillingDisposition.NOT_BILLED,
                )
            response = client.messages.create(
                model=entry.model,
                system=system,
                messages=messages,
                max_tokens=request.max_output_tokens,
                temperature=request.temperature_milli / 1_000,
                tools=_anthropic_tools(request),
                output_config={
                    "format": {
                        "type": "json_schema",
                        "schema": request.structured_output.json_schema,
                    }
                },
            )
            parsed = _AnthropicResponse.model_validate(
                response.model_dump(mode="python")
            )
            texts = tuple(
                block.text
                for block in parsed.content
                if block.type == "text" and block.text is not None
            )
            if len(texts) != 1:
                raise ValueError("Anthropic structured output block is invalid")
            structured = json.loads(texts[0])
            if not isinstance(structured, dict):
                raise ValueError("Anthropic structured output was not an object")
            finish_reason = _anthropic_finish(parsed.stop_reason)
            return ProviderResult(
                structured_output=structured,
                usage=ModelUsage(
                    input_tokens=parsed.usage.input_tokens,
                    output_tokens=parsed.usage.output_tokens,
                    cache_read_tokens=parsed.usage.cache_read_input_tokens or 0,
                    cache_write_tokens=parsed.usage.cache_creation_input_tokens or 0,
                    provider_reported=True,
                ),
                finish_reason=finish_reason,
                safety=SafetyAssessment(
                    blocked=finish_reason is ModelFinishReason.CONTENT_FILTER,
                    categories=(
                        ("provider_refusal",)
                        if finish_reason is ModelFinishReason.CONTENT_FILTER
                        else ()
                    ),
                    provider_reported=True,
                ),
                provider_request_ref=_safe_provider_ref(parsed.id),
            )
        except ProviderInvocationError:
            raise
        except (ValidationError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise ProviderInvocationError(
                ModelErrorCode.MALFORMED_RESPONSE,
                retryable=False,
                billing=BillingDisposition.AMBIGUOUS,
            ) from exc
        except AnthropicAPIError as exc:
            raise _classify_sdk_error(exc) from exc


def _openai_messages(messages: Sequence[ModelMessage]) -> list[dict[str, object]]:
    return [
        {
            "role": message.role.value,
            "content": _content_text(message),
        }
        for message in messages
    ]


def _openai_tools(request: ModelRequest) -> list[dict[str, object]]:
    return [
        {
            "type": "function",
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.input_schema,
            "strict": True,
        }
        for tool in request.tools
    ]


def _anthropic_messages(
    messages: Sequence[ModelMessage],
) -> tuple[str, list[dict[str, object]]]:
    system_parts = [
        _content_text(message)
        for message in messages
        if message.role is ModelRole.SYSTEM
    ]
    conversational: list[dict[str, object]] = [
        {"role": message.role.value, "content": _content_text(message)}
        for message in messages
        if message.role in {ModelRole.USER, ModelRole.ASSISTANT}
    ]
    return "\n".join(system_parts), conversational


def _anthropic_tools(request: ModelRequest) -> list[dict[str, object]]:
    return [
        {
            "name": tool.name,
            "description": tool.description,
            "input_schema": tool.input_schema,
        }
        for tool in request.tools
    ]


def _content_text(message: ModelMessage) -> str:
    parts: list[str] = []
    for content in message.content:
        if isinstance(content, TextContent):
            parts.append(content.text)
        elif isinstance(content, JsonContent):
            parts.append(
                json.dumps(content.value, separators=(",", ":"), sort_keys=True)
            )
    return "\n".join(parts)


def _anthropic_finish(reason: str | None) -> ModelFinishReason:
    if reason is None:
        return ModelFinishReason.CONTENT_FILTER
    return {
        "end_turn": ModelFinishReason.STOP,
        "stop_sequence": ModelFinishReason.STOP,
        "tool_use": ModelFinishReason.TOOL_CALL,
        "max_tokens": ModelFinishReason.LENGTH,
        "pause_turn": ModelFinishReason.LENGTH,
        "model_context_window_exceeded": ModelFinishReason.LENGTH,
        "refusal": ModelFinishReason.CONTENT_FILTER,
    }.get(reason, ModelFinishReason.CONTENT_FILTER)


def _safe_provider_ref(value: str | None) -> str | None:
    if value is None:
        return None
    digest = __import__("hashlib").sha256(value.encode()).hexdigest()[:32]
    return f"provider:{digest}"


def _classify_sdk_error(error: Exception) -> ProviderInvocationError:
    name = type(error).__name__.lower()
    status = getattr(error, "status_code", None)
    if status == 408:
        code = ModelErrorCode.TIMEOUT
        billing = BillingDisposition.AMBIGUOUS
    elif status in {401, 403}:
        code = ModelErrorCode.AUTHENTICATION
        billing = BillingDisposition.NOT_BILLED
    elif status == 429:
        code = ModelErrorCode.RATE_LIMITED
        billing = BillingDisposition.NOT_BILLED
    elif isinstance(status, int) and 400 <= status < 500:
        code = ModelErrorCode.BAD_REQUEST
        billing = BillingDisposition.NOT_BILLED
    elif isinstance(status, int) and status >= 500:
        code = ModelErrorCode.TRANSIENT
        billing = BillingDisposition.AMBIGUOUS
    elif "timeout" in name:
        code = ModelErrorCode.TIMEOUT
        billing = BillingDisposition.AMBIGUOUS
    elif "ratelimit" in name:
        code = ModelErrorCode.RATE_LIMITED
        billing = BillingDisposition.NOT_BILLED
    elif "authentication" in name or "permission" in name:
        code = ModelErrorCode.AUTHENTICATION
        billing = BillingDisposition.NOT_BILLED
    elif "badrequest" in name or "invalidrequest" in name:
        code = ModelErrorCode.BAD_REQUEST
        billing = BillingDisposition.NOT_BILLED
    else:
        code = ModelErrorCode.TRANSIENT
        billing = BillingDisposition.AMBIGUOUS
    return ProviderInvocationError(
        code,
        retryable=code
        in {
            ModelErrorCode.TIMEOUT,
            ModelErrorCode.RATE_LIMITED,
            ModelErrorCode.TRANSIENT,
        },
        billing=billing,
    )
