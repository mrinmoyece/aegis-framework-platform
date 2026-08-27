from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from threading import Event, Thread
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import Field, ValidationError

from aegis_framework.domain import (
    ModelEvidence,
    RiskLevel,
    Specialist,
    SpecialistFinding,
    SpecialistTask,
    StrictModel,
)
from aegis_framework.errors import PolicyDenied
from aegis_framework.fixtures import build_demo_bundle, demo_identity, demo_request
from aegis_framework.graph import LangGraphInvestigator
from aegis_framework.model import DeterministicStructuredModel, GatewayStructuredModel
from aegis_framework.model_gateway import (
    BillingDisposition,
    CredentialReference,
    DataClassification,
    FakeModelProvider,
    InMemoryModelControlStore,
    JsonContent,
    ModelCallBinding,
    ModelCapability,
    ModelCatalogEntry,
    ModelErrorCode,
    ModelFinishReason,
    ModelGateway,
    ModelMessage,
    ModelPrice,
    ModelProvider,
    ModelRequest,
    ModelRole,
    ModelRoute,
    ModelUsage,
    ProviderInvocationError,
    ProviderResult,
    SafetyAssessment,
    StructuredOutputDefinition,
    TenantModelPolicy,
    TextContent,
    ToolDefinition,
)
from aegis_framework.provider_adapters import (
    AnthropicProviderAdapter,
    OpenAIProviderAdapter,
    _classify_sdk_error,
)
from aegis_framework.safety import prepare_model_evidence

_NOW = datetime(2026, 8, 15, tzinfo=UTC)


class _Output(StrictModel):
    answer: str = Field(min_length=1, max_length=32)


class _Clock:
    def __init__(self) -> None:
        self.value = _NOW

    def now(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


class _DumpResponse:
    def __init__(self, value: dict[str, Any]) -> None:
        self._value = value
        self.id = str(value.get("id", "provider-response"))
        self.output_text = str(value.get("output_text", ""))
        self.status = str(value.get("status", "completed"))
        usage = value.get("usage", {})
        if usage is None:
            self.usage = None
            return
        details = usage.get("input_tokens_details", {})
        self.usage = SimpleNamespace(
            input_tokens=int(usage.get("input_tokens", 0)),
            output_tokens=int(usage.get("output_tokens", 0)),
            input_tokens_details=SimpleNamespace(
                cached_tokens=details.get("cached_tokens", 0),
                cache_write_tokens=details.get("cache_write_tokens", 0),
            ),
        )

    def model_dump(self, *, mode: str = "python") -> dict[str, Any]:
        assert mode == "python"
        return self._value


class _Responses:
    def __init__(self, value: dict[str, Any]) -> None:
        self.value = value
        self.kwargs: dict[str, Any] = {}

    def create(self, **kwargs: Any) -> _DumpResponse:
        self.kwargs = kwargs
        return _DumpResponse(self.value)


class _Messages(_Responses):
    pass


class _OpenAIClient:
    def __init__(self, value: dict[str, Any]) -> None:
        self.responses = _Responses(value)


class _AnthropicClient:
    def __init__(self, value: dict[str, Any]) -> None:
        self.messages = _Messages(value)


class _Secrets:
    def __init__(self) -> None:
        self.references: list[str] = []

    def resolve(self, reference: CredentialReference) -> str:
        self.references.append(reference.reference)
        return "unit-test-secret"


def _entry(
    *,
    tenant_id: str = "tenant-acme",
    model: str = "model-a",
    provider: ModelProvider = ModelProvider.FAKE,
    region: str = "eu-west-1",
    capabilities: frozenset[ModelCapability] | None = None,
    context_tokens: int = 8_192,
    enabled: bool = True,
) -> ModelCatalogEntry:
    return ModelCatalogEntry(
        tenant_id=tenant_id,
        provider=provider,
        model=model,
        region=region,
        capabilities=capabilities or frozenset({ModelCapability.JSON_SCHEMA}),
        context_tokens=context_tokens,
        maximum_output_tokens=1_024,
        tokenizer=None,
        tokenizer_limitations=(
            "Conservative portable estimate; exact tokenizer unavailable."
        ),
        usage_limitations=(
            "Provider-reported usage is authoritative only after settlement."
        ),
        price=ModelPrice(
            version=f"price-{model}-v1",
            currency="USD",
            input_microunits_per_million_tokens=2_000,
            output_microunits_per_million_tokens=4_000,
            cache_read_microunits_per_million_tokens=500,
            cache_write_microunits_per_million_tokens=1_000,
        ),
        credential=CredentialReference(
            reference=f"secret:{provider.value}-{model}",
            version=1,
        ),
        enabled=enabled,
    )


def _policy(
    entries: tuple[ModelCatalogEntry, ...],
    *,
    tenant_id: str = "tenant-acme",
    policy_id: str = "model-policy",
    revision: int = 1,
    repair_attempts: int = 1,
    fallback_on_ambiguous_billing: bool = False,
    maximum_input_tokens: int = 4_096,
    maximum_calls_per_run: int = 8,
) -> TenantModelPolicy:
    return TenantModelPolicy(
        tenant_id=tenant_id,
        policy_id=policy_id,
        revision=revision,
        allowed_providers=frozenset(entry.provider for entry in entries),
        allowed_models=frozenset(entry.model for entry in entries),
        allowed_regions=frozenset(entry.region for entry in entries),
        allowed_data_classifications=frozenset({DataClassification.INTERNAL}),
        allowed_purposes=frozenset({"incident-response"}),
        required_capabilities=frozenset({ModelCapability.JSON_SCHEMA}),
        risk_ceiling=RiskLevel.MEDIUM,
        routes=tuple(
            ModelRoute(
                provider=entry.provider,
                model=entry.model,
                region=entry.region,
                priority=index,
            )
            for index, entry in enumerate(entries, start=1)
        ),
        maximum_input_tokens=maximum_input_tokens,
        maximum_output_tokens=1_024,
        maximum_cost_microunits=100_000,
        maximum_calls_per_run=maximum_calls_per_run,
        repair_attempts=repair_attempts,
        fallback_on_ambiguous_billing=fallback_on_ambiguous_billing,
    )


def _request(
    *,
    call_id: str = "call:one",
    tenant_id: str = "tenant-acme",
    run_id: str = "run:one",
    purpose: str = "incident-response",
    classification: DataClassification = DataClassification.INTERNAL,
    risk: RiskLevel = RiskLevel.MEDIUM,
    tools: tuple[ToolDefinition, ...] = (),
    allowed_tools: tuple[str, ...] = (),
    text: str = "Analyze the framed evidence.",
) -> ModelRequest:
    return ModelRequest(
        binding=ModelCallBinding(
            tenant_id=tenant_id,
            run_id=run_id,
            call_id=call_id,
            purpose=purpose,
            data_classification=classification,
            risk=risk,
        ),
        messages=(
            ModelMessage(
                role=ModelRole.SYSTEM,
                content=(TextContent(text="Return only strict JSON."),),
            ),
            ModelMessage(
                role=ModelRole.USER,
                content=(
                    TextContent(text=text),
                    JsonContent(value={"evidence_id": "evidence:one"}),
                ),
            ),
        ),
        max_output_tokens=100,
        tools=tools,
        allowed_tool_names=allowed_tools,
        structured_output=StructuredOutputDefinition(
            name="test_output",
            json_schema=_Output.model_json_schema(),
        ),
    )


def _result(
    output: dict[str, Any] | None = None,
    *,
    blocked: bool = False,
) -> ProviderResult:
    return ProviderResult(
        structured_output=output or {"answer": "safe"},
        usage=ModelUsage(
            input_tokens=12,
            output_tokens=4,
            cache_read_tokens=2,
            cache_write_tokens=1,
            provider_reported=True,
        ),
        finish_reason=ModelFinishReason.STOP,
        safety=SafetyAssessment(
            blocked=blocked,
            categories=("provider_filter",) if blocked else (),
            provider_reported=True,
        ),
        provider_request_ref="provider:opaque",
    )


def _store(
    entries: tuple[ModelCatalogEntry, ...],
    *,
    policy: TenantModelPolicy | None = None,
    limit: int = 1_000_000,
) -> InMemoryModelControlStore:
    selected = policy or _policy(entries)
    return InMemoryModelControlStore(
        policies=(selected,),
        catalog=entries,
        tenant_cost_limits={selected.tenant_id: limit},
    )


def test_contract_bounds_digests_and_pricing_are_deterministic() -> None:
    request = _request()
    assert request.canonical_digest() == _request().canonical_digest()
    assert request.canonical_digest() != _request(text="different").canonical_digest()
    entries = (_entry(), _entry(model="model-b"))
    first_policy = _policy(entries)
    second_document = first_policy.model_dump(mode="json")
    second_document["allowed_models"] = list(
        reversed(sorted(first_policy.allowed_models))
    )
    assert (
        TenantModelPolicy.model_validate(second_document).canonical_digest()
        == first_policy.canonical_digest()
    )
    price = _entry().price
    assert (
        price.maximum_cost_microunits(
            input_tokens=1_000_000,
            output_tokens=500_000,
        )
        == 5_500
    )
    assert price.actual_cost_microunits(_result().usage) == 1

    with pytest.raises(ValidationError, match="message content exceeds"):
        ModelMessage(
            role=ModelRole.USER,
            content=(TextContent(text="x" * 32_768), TextContent(text="y")),
        )
    with pytest.raises(ValidationError, match="must describe an object"):
        ToolDefinition(
            name="bad",
            description="bad schema",
            input_schema={"type": "array"},
        )
    policy_data = _policy((_entry(), _entry(model="model-b"))).model_dump()
    policy_data["routes"] = (
        ModelRoute(
            provider=ModelProvider.FAKE,
            model="model-a",
            region="eu-west-1",
            priority=1,
        ),
        ModelRoute(
            provider=ModelProvider.FAKE,
            model="model-b",
            region="eu-west-1",
            priority=1,
        ),
    )
    with pytest.raises(ValidationError, match="priorities"):
        TenantModelPolicy.model_validate(policy_data)


def test_gateway_success_records_reservation_usage_and_health() -> None:
    entry = _entry()
    store = _store((entry,))
    fake = FakeModelProvider((_result(),))
    output = ModelGateway(store=store, adapters=(fake,)).generate(_request(), _Output)
    assert output.answer == "safe"
    assert fake.calls == [(entry.key, entry.credential.reference)]
    usage = store.usage(tenant_id="tenant-acme", run_id="run:one")
    assert usage.call_count == 1
    assert usage.input_tokens == 12
    assert usage.output_tokens == 4
    assert usage.reconciled_cost_microunits == 1
    assert usage.reserved_cost_microunits >= usage.reconciled_cost_microunits
    assert store.health(tenant_id="tenant-acme")[0].status == "healthy"
    assert store.catalog(tenant_id="tenant-acme") == (entry,)
    assert store.catalog(tenant_id="unknown") == ()


def test_zero_priced_catalog_reserves_and_settles_zero_cost() -> None:
    entry = _entry().model_copy(
        update={
            "price": ModelPrice(
                version="free-v1",
                currency="USD",
                input_microunits_per_million_tokens=0,
                output_microunits_per_million_tokens=0,
            )
        }
    )
    store = _store((entry,), limit=0)
    output = ModelGateway(
        store=store,
        adapters=(FakeModelProvider((_result(),)),),
    ).generate(_request(), _Output)
    assert output.answer == "safe"
    usage = store.usage(tenant_id="tenant-acme", run_id="run:one")
    assert usage.reserved_cost_microunits == 0
    assert usage.reconciled_cost_microunits == 0


def test_duplicate_attempt_is_suppressed_without_a_second_provider_call() -> None:
    entry = _entry()
    store = _store((entry,))
    gateway = ModelGateway(
        store=store,
        adapters=(FakeModelProvider((_result(),)),),
    )
    first = gateway.generate(_request(), _Output)
    assert first.answer == "safe"
    with pytest.raises(PolicyDenied, match="durable intent"):
        gateway.generate(_request(), _Output)
    usage = store.usage(tenant_id="tenant-acme", run_id="run:one")
    assert usage.call_count == 1
    fake = gateway._adapters[ModelProvider.FAKE]
    assert isinstance(fake, FakeModelProvider)
    assert len(fake.calls) == 1


def test_malformed_output_gets_one_bounded_repair() -> None:
    entry = _entry()
    store = _store((entry,))
    fake = FakeModelProvider((_result({"wrong": True}), _result()))
    output = ModelGateway(store=store, adapters=(fake,)).generate(_request(), _Output)
    assert output.answer == "safe"
    usage = store.usage(tenant_id="tenant-acme", run_id="run:one")
    assert usage.call_count == 2
    assert usage.input_tokens == 24
    assert usage.output_tokens == 8
    assert store.health(tenant_id="tenant-acme")[0].observed_calls == 2


def test_transient_not_billed_failure_falls_back_deterministically() -> None:
    first = _entry()
    second = _entry(model="model-b")
    store = _store((first, second), policy=_policy((first, second), repair_attempts=0))
    fake = FakeModelProvider(
        (
            ProviderInvocationError(
                ModelErrorCode.TRANSIENT,
                retryable=True,
                billing=BillingDisposition.NOT_BILLED,
            ),
            _result({"answer": "fallback"}),
        )
    )
    output = ModelGateway(store=store, adapters=(fake,)).generate(_request(), _Output)
    assert output.answer == "fallback"
    assert [call[0] for call in fake.calls] == [first.key, second.key]
    health = store.health(tenant_id="tenant-acme")
    assert [item.status for item in health] == ["degraded", "healthy"]


def test_ambiguous_billing_stops_fallback_by_default() -> None:
    first = _entry()
    second = _entry(model="model-b")
    store = _store((first, second), policy=_policy((first, second), repair_attempts=0))
    fake = FakeModelProvider(
        (
            ProviderInvocationError(
                ModelErrorCode.TIMEOUT,
                retryable=True,
                billing=BillingDisposition.AMBIGUOUS,
            ),
            _result(),
        )
    )
    with pytest.raises(ProviderInvocationError) as captured:
        ModelGateway(store=store, adapters=(fake,)).generate(_request(), _Output)
    assert captured.value.code is ModelErrorCode.TIMEOUT
    assert len(fake.calls) == 1
    usage = store.usage(tenant_id="tenant-acme", run_id="run:one")
    assert usage.ambiguous_cost_microunits == usage.reserved_cost_microunits


def test_policy_can_explicitly_allow_fallback_after_ambiguous_billing() -> None:
    first = _entry()
    second = _entry(model="model-b")
    policy = _policy(
        (first, second),
        repair_attempts=0,
        fallback_on_ambiguous_billing=True,
    )
    fake = FakeModelProvider(
        (
            ProviderInvocationError(
                ModelErrorCode.TIMEOUT,
                retryable=True,
                billing=BillingDisposition.AMBIGUOUS,
            ),
            _result({"answer": "explicit-fallback"}),
        )
    )
    store = _store((first, second), policy=policy)
    output = ModelGateway(
        store=store,
        adapters=(fake,),
    ).generate(_request(), _Output)
    assert output.answer == "explicit-fallback"
    usage = store.usage(tenant_id="tenant-acme", run_id="run:one")
    assert usage.ambiguous_cost_microunits == usage.reserved_cost_microunits


@pytest.mark.parametrize(
    ("request_factory", "reason"),
    [
        (lambda: _request(purpose="other"), "purpose"),
        (
            lambda: _request(classification=DataClassification.RESTRICTED),
            "classification",
        ),
        (lambda: _request(risk=RiskLevel.HIGH), "risk"),
    ],
)
def test_policy_dimensions_fail_closed(
    request_factory: Callable[[], ModelRequest],
    reason: str,
) -> None:
    entry = _entry()
    with pytest.raises(PolicyDenied, match=reason):
        ModelGateway(
            store=_store((entry,)),
            adapters=(FakeModelProvider((_result(),)),),
        ).generate(request_factory(), _Output)


def test_unknown_catalog_capability_context_and_tools_fail_closed() -> None:
    entry = _entry(capabilities=frozenset({ModelCapability.JSON_SCHEMA}))
    tool = ToolDefinition(
        name="lookup",
        description="Lookup an allowlisted fact.",
        input_schema={"type": "object", "properties": {}},
    )
    with pytest.raises(PolicyDenied, match="eligible"):
        ModelGateway(
            store=_store((entry,)),
            adapters=(FakeModelProvider((_result(),)),),
        ).generate(
            _request(tools=(tool,), allowed_tools=("lookup",)),
            _Output,
        )
    with pytest.raises(PolicyDenied, match="allowlist"):
        ModelGateway(
            store=_store((entry,)),
            adapters=(FakeModelProvider((_result(),)),),
        ).generate(_request(tools=(tool,)), _Output)
    with pytest.raises(PolicyDenied, match="tool result"):
        ModelGateway(
            store=_store((entry,)),
            adapters=(FakeModelProvider((_result(),)),),
        ).generate(
            _request().model_copy(
                update={
                    "messages": (
                        ModelMessage(
                            role=ModelRole.TOOL,
                            content=(TextContent(text="result"),),
                            tool_call_id="tool-call:one",
                        ),
                    )
                }
            ),
            _Output,
        )

    tiny = _entry(context_tokens=1)
    with pytest.raises(PolicyDenied, match="eligible"):
        ModelGateway(
            store=_store((tiny,)),
            adapters=(FakeModelProvider((_result(),)),),
        ).generate(_request(), _Output)


def test_budget_call_count_and_input_limits_fail_closed() -> None:
    entry = _entry()
    expensive_store = _store((entry,), limit=1)
    with pytest.raises(PolicyDenied, match="budget"):
        ModelGateway(
            store=expensive_store,
            adapters=(FakeModelProvider((_result(),)),),
        ).generate(_request(), _Output)

    input_policy = _policy((entry,), maximum_input_tokens=1)
    with pytest.raises(PolicyDenied, match="input token"):
        ModelGateway(
            store=_store((entry,), policy=input_policy),
            adapters=(FakeModelProvider((_result(),)),),
        ).generate(_request(), _Output)

    one_call_policy = _policy((entry,), maximum_calls_per_run=1)
    store = _store((entry,), policy=one_call_policy)
    gateway = ModelGateway(
        store=store,
        adapters=(FakeModelProvider((_result(), _result())),),
    )
    gateway.generate(_request(), _Output)
    with pytest.raises(PolicyDenied, match="call limit"):
        gateway.generate(_request(call_id="call:two"), _Output)

    releasing_store = _store((entry,), limit=10)
    releasing = ModelGateway(
        store=releasing_store,
        adapters=(FakeModelProvider((_result(), _result(), _result())),),
    )
    for index in range(3):
        releasing.generate(
            _request(call_id=f"call:release-{index}", run_id=f"run:{index}"),
            _Output,
        )


def test_cancellation_policy_revocation_and_content_filter_reject_stale_output() -> (
    None
):
    entry = _entry()
    store = _store((entry,))
    cancelled = Event()
    cancelled.set()
    with pytest.raises(ProviderInvocationError) as before:
        ModelGateway(
            store=store,
            adapters=(FakeModelProvider((_result(),)),),
            cancellation_requested=cancelled.is_set,
        ).generate(_request(), _Output)
    assert before.value.code is ModelErrorCode.CANCELLED

    class _RevokingProvider:
        provider = ModelProvider.FAKE

        def invoke(self, **kwargs: object) -> ProviderResult:
            del kwargs
            store.replace_policy(
                _policy(
                    (entry,),
                    revision=1,
                    policy_id="replacement-policy",
                )
            )
            return _result()

    with pytest.raises(ProviderInvocationError) as stale:
        ModelGateway(store=store, adapters=(_RevokingProvider(),)).generate(
            _request(call_id="call:revoked"),
            _Output,
        )
    assert stale.value.code is ModelErrorCode.POLICY_DENIED

    first = _entry()
    second = _entry(model="model-b")
    fallback_policy = _policy((first, second), repair_attempts=0)
    fallback_store = _store((first, second), policy=fallback_policy)

    class _RevokingFailureProvider:
        provider = ModelProvider.FAKE

        def __init__(self) -> None:
            self.calls = 0

        def invoke(self, **kwargs: object) -> ProviderResult:
            del kwargs
            self.calls += 1
            fallback_store.replace_policy(
                _policy(
                    (first, second),
                    revision=2,
                    repair_attempts=0,
                )
            )
            raise ProviderInvocationError(
                ModelErrorCode.TRANSIENT,
                retryable=True,
                billing=BillingDisposition.NOT_BILLED,
            )

    revoking_failure = _RevokingFailureProvider()
    with pytest.raises(ProviderInvocationError) as revoked_fallback:
        ModelGateway(
            store=fallback_store,
            adapters=(revoking_failure,),
        ).generate(_request(call_id="call:revoked-fallback"), _Output)
    assert revoked_fallback.value.code is ModelErrorCode.POLICY_DENIED
    assert revoking_failure.calls == 1

    filter_store = _store((entry,))
    with pytest.raises(ProviderInvocationError) as blocked:
        ModelGateway(
            store=filter_store,
            adapters=(FakeModelProvider((_result(blocked=True),)),),
        ).generate(_request(call_id="call:blocked"), _Output)
    assert blocked.value.code is ModelErrorCode.CONTENT_FILTER
    blocked_usage = filter_store.usage(
        tenant_id="tenant-acme",
        run_id="run:one",
    )
    assert blocked_usage.input_tokens == 12
    assert blocked_usage.reconciled_cost_microunits == 1

    fallback_entry = _entry(model="model-b")
    fallback_store = _store(
        (entry, fallback_entry),
        policy=_policy((entry, fallback_entry), repair_attempts=0),
    )
    blocked_fallback = FakeModelProvider((_result(blocked=True), _result()))
    with pytest.raises(ProviderInvocationError) as terminal:
        ModelGateway(
            store=fallback_store,
            adapters=(blocked_fallback,),
        ).generate(_request(call_id="call:blocked-fallback"), _Output)
    assert terminal.value.code is ModelErrorCode.CONTENT_FILTER
    assert len(blocked_fallback.calls) == 1

    circuit_store = _store((entry,))
    filtered_then_safe = ModelGateway(
        store=circuit_store,
        adapters=(FakeModelProvider((_result(blocked=True), _result())),),
        circuit_failure_threshold=1,
    )
    with pytest.raises(ProviderInvocationError):
        filtered_then_safe.generate(
            _request(call_id="call:filtered"),
            _Output,
        )
    assert (
        filtered_then_safe.generate(
            _request(call_id="call:after-filter"),
            _Output,
        ).answer
        == "safe"
    )


def test_provider_usage_above_reservation_is_settled_but_rejected() -> None:
    entry = _entry()
    store = _store((entry,), limit=100_000)
    excessive = _result().model_copy(
        update={
            "usage": ModelUsage(
                input_tokens=10,
                output_tokens=10_000,
                provider_reported=True,
            )
        }
    )
    with pytest.raises(ProviderInvocationError) as captured:
        ModelGateway(
            store=store,
            adapters=(FakeModelProvider((excessive,)),),
        ).generate(_request(), _Output)
    assert captured.value.code is ModelErrorCode.USAGE_EXCEEDED
    usage = store.usage(tenant_id="tenant-acme", run_id="run:one")
    assert usage.output_tokens == 10_000
    assert usage.reconciled_cost_microunits > usage.reserved_cost_microunits

    input_store = _store((entry,), limit=100_000)
    excessive_input = _result().model_copy(
        update={
            "usage": ModelUsage(
                input_tokens=10_000,
                output_tokens=1,
                cache_read_tokens=10_000,
                provider_reported=True,
            )
        }
    )
    with pytest.raises(ProviderInvocationError) as input_captured:
        ModelGateway(
            store=input_store,
            adapters=(FakeModelProvider((excessive_input,)),),
        ).generate(_request(call_id="call:excessive-input"), _Output)
    assert input_captured.value.code is ModelErrorCode.USAGE_EXCEEDED


def test_non_terminal_finish_reason_is_not_accepted_as_success() -> None:
    entry = _entry()
    length_result = _result().model_copy(
        update={"finish_reason": ModelFinishReason.LENGTH}
    )
    with pytest.raises(ProviderInvocationError) as captured:
        ModelGateway(
            store=_store((entry,)),
            adapters=(FakeModelProvider((length_result,)),),
        ).generate(_request(), _Output)
    assert captured.value.code is ModelErrorCode.CAPABILITY


def test_circuit_rate_and_concurrency_controls_are_bounded() -> None:
    entry = _entry()
    store = _store((entry,))
    clock = _Clock()
    fake = FakeModelProvider(
        (
            ProviderInvocationError(
                ModelErrorCode.TRANSIENT,
                retryable=True,
                billing=BillingDisposition.NOT_BILLED,
            ),
        )
    )
    gateway = ModelGateway(
        store=store,
        adapters=(fake,),
        clock=clock,
        circuit_failure_threshold=1,
        circuit_open_seconds=10,
    )
    with pytest.raises(ProviderInvocationError):
        gateway.generate(_request(), _Output)
    with pytest.raises(ProviderInvocationError) as opened:
        gateway.generate(_request(call_id="call:circuit"), _Output)
    assert opened.value.code is ModelErrorCode.CIRCUIT_OPEN
    clock.advance(11)

    rate_gateway = ModelGateway(
        store=_store((entry,)),
        adapters=(FakeModelProvider((_result(), _result())),),
        clock=clock,
        rate_limit_per_minute=1,
    )
    rate_gateway.generate(_request(call_id="call:rate-1"), _Output)
    with pytest.raises(ProviderInvocationError) as rate:
        rate_gateway.generate(_request(call_id="call:rate-2"), _Output)
    assert rate.value.code is ModelErrorCode.RATE_LIMITED
    assert (
        rate_gateway._store.usage(
            tenant_id="tenant-acme",
            run_id="run:one",
        ).reserved_cost_microunits
        == 4
    )
    clock.advance(61)
    assert (
        rate_gateway.generate(_request(call_id="call:rate-3"), _Output).answer == "safe"
    )

    entered = Event()
    release = Event()

    class _BlockingProvider:
        provider = ModelProvider.FAKE

        def invoke(self, **kwargs: object) -> ProviderResult:
            del kwargs
            entered.set()
            assert release.wait(timeout=2)
            return _result()

    concurrent_store = _store((entry,))
    concurrent = ModelGateway(
        store=concurrent_store,
        adapters=(_BlockingProvider(),),
        maximum_concurrency=1,
    )
    worker = Thread(
        target=lambda: concurrent.generate(
            _request(call_id="call:thread"),
            _Output,
        )
    )
    worker.start()
    assert entered.wait(timeout=2)
    with pytest.raises(ProviderInvocationError) as limited:
        concurrent.generate(_request(call_id="call:concurrent"), _Output)
    assert limited.value.code is ModelErrorCode.RATE_LIMITED
    release.set()
    worker.join(timeout=2)
    assert not worker.is_alive()


def test_circuit_state_is_tenant_scoped() -> None:
    entry = _entry()
    beta_entry = _entry(tenant_id="tenant-beta")
    policies = (
        _policy((entry,), tenant_id="tenant-acme", repair_attempts=0),
        _policy((beta_entry,), tenant_id="tenant-beta", repair_attempts=0),
    )
    store = InMemoryModelControlStore(
        policies=policies,
        catalog=(entry, beta_entry),
        tenant_cost_limits={"tenant-acme": 100, "tenant-beta": 100},
    )
    fake = FakeModelProvider(
        (
            ProviderInvocationError(
                ModelErrorCode.TRANSIENT,
                retryable=True,
                billing=BillingDisposition.NOT_BILLED,
            ),
            _result({"answer": "beta-safe"}),
        )
    )
    gateway = ModelGateway(
        store=store,
        adapters=(fake,),
        circuit_failure_threshold=1,
    )
    with pytest.raises(ProviderInvocationError):
        gateway.generate(_request(), _Output)
    beta = gateway.generate(
        _request(
            tenant_id="tenant-beta",
            call_id="call:beta-circuit",
            run_id="run:beta",
        ),
        _Output,
    )
    assert beta.answer == "beta-safe"
    assert fake.calls[-1][1] == beta_entry.credential.reference


def test_tenant_policy_and_usage_are_isolated() -> None:
    entry = _entry()
    store = _store((entry,))
    gateway = ModelGateway(
        store=store,
        adapters=(FakeModelProvider((_result(),)),),
    )
    gateway.generate(_request(), _Output)
    assert store.usage(tenant_id="tenant-beta", run_id="run:one").call_count == 0
    with pytest.raises(PolicyDenied, match="no tenant"):
        gateway.generate(
            _request(tenant_id="tenant-beta", call_id="call:beta"),
            _Output,
        )

    beta_entry = _entry(tenant_id="tenant-beta")
    shared_store = InMemoryModelControlStore(
        policies=(
            _policy((entry,), tenant_id="tenant-acme"),
            _policy((beta_entry,), tenant_id="tenant-beta"),
        ),
        catalog=(entry, beta_entry),
        tenant_cost_limits={"tenant-acme": 100, "tenant-beta": 100},
    )
    shared_gateway = ModelGateway(
        store=shared_store,
        adapters=(FakeModelProvider((_result(), _result())),),
    )
    shared_gateway.generate(_request(), _Output)
    beta = shared_gateway.generate(
        _request(tenant_id="tenant-beta"),
        _Output,
    )
    assert beta.answer == "safe"


def test_gateway_structured_generation_runs_inside_langgraph_nodes() -> None:
    entry = _entry()
    store = _store((entry,))
    bundle = build_demo_bundle()
    identity = demo_identity(request_id="gateway-graph")
    evidence = tuple(bundle.service._evidence.collect(identity, demo_request()))
    safe_evidence, _ = prepare_model_evidence(evidence)
    deterministic = DeterministicStructuredModel()
    outputs = {
        specialist: SpecialistFinding.model_validate(
            deterministic.analyze(
                SpecialistTask(
                    tenant_id=identity.tenant_id,
                    run_id=identity.request_id,
                    incident_id=demo_request().incident_id,
                    specialist=specialist,
                    evidence=tuple(
                        ModelEvidence.model_validate(item) for item in safe_evidence
                    ),
                )
            )
        ).model_dump(mode="json")
        for specialist in Specialist
    }

    class _SpecialistProvider:
        provider = ModelProvider.FAKE

        def invoke(
            self,
            *,
            entry: ModelCatalogEntry,
            request: ModelRequest,
            credential_reference: CredentialReference,
        ) -> ProviderResult:
            del entry, credential_reference
            prompt = request.messages[-1].content[0]
            assert isinstance(prompt, TextContent)
            specialist = next(
                item
                for item in Specialist
                if f"Specialist: {item.value}" in prompt.text
            )
            return _result(outputs[specialist])

    investigator = LangGraphInvestigator(
        GatewayStructuredModel(
            ModelGateway(store=store, adapters=(_SpecialistProvider(),))
        )
    )
    result = investigator.run(
        tenant_id=identity.tenant_id,
        request=demo_request(),
        request_id=identity.request_id,
        thread_ref="thread:gateway-integration",
        evidence=evidence,
    )
    assert result.status.value == "complete"
    assert result.critic.checked_citations == 8
    replay = investigator.run(
        tenant_id=identity.tenant_id,
        request=demo_request(),
        request_id=identity.request_id,
        thread_ref="thread:gateway-integration",
        evidence=evidence,
    )
    assert replay.replayed is True
    usage = store.usage(
        tenant_id=identity.tenant_id,
        run_id=identity.request_id,
    )
    assert usage.call_count == 2


def test_official_openai_adapter_maps_only_neutral_contracts() -> None:
    client = _OpenAIClient(
        {
            "id": "resp-sensitive",
            "output_text": '{"answer":"openai"}',
            "status": "completed",
            "usage": {"input_tokens": 10, "output_tokens": 3},
        }
    )
    adapter = OpenAIProviderAdapter(lambda reference: client)
    result = adapter.invoke(
        entry=_entry(provider=ModelProvider.OPENAI),
        request=_request(),
        credential_reference=CredentialReference(
            reference="secret:openai",
            version=1,
        ),
    )
    assert result.structured_output == {"answer": "openai"}
    assert result.usage.provider_reported is True
    assert result.provider_request_ref != "resp-sensitive"
    assert client.responses.kwargs["model"] == "model-a"
    assert client.responses.kwargs["text"]["format"]["strict"] is True

    cached_client = _OpenAIClient(
        {
            "id": "resp-cached",
            "output_text": '{"answer":"cached"}',
            "status": "completed",
            "usage": {
                "input_tokens": 10,
                "output_tokens": 3,
                "input_tokens_details": {
                    "cached_tokens": 4,
                    "cache_write_tokens": 1,
                },
            },
        }
    )
    cached = OpenAIProviderAdapter(lambda reference: cached_client).invoke(
        entry=_entry(provider=ModelProvider.OPENAI),
        request=_request(),
        credential_reference=CredentialReference(
            reference="secret:openai",
            version=1,
        ),
    )
    assert cached.usage.input_tokens == 5
    assert cached.usage.cache_read_tokens == 4
    assert cached.usage.cache_write_tokens == 1

    malformed = OpenAIProviderAdapter(
        lambda reference: _OpenAIClient(
            {
                "id": "resp",
                "output_text": "not-json",
                "status": "completed",
                "usage": {"input_tokens": 1, "output_tokens": 1},
            }
        )
    )
    with pytest.raises(ProviderInvocationError) as captured:
        malformed.invoke(
            entry=_entry(provider=ModelProvider.OPENAI),
            request=_request(),
            credential_reference=CredentialReference(
                reference="secret:openai",
                version=1,
            ),
        )
    assert captured.value.code is ModelErrorCode.MALFORMED_RESPONSE

    missing_usage = OpenAIProviderAdapter(
        lambda reference: _OpenAIClient(
            {
                "id": "resp-no-usage",
                "output_text": '{"answer":"unknown-usage"}',
                "status": "completed",
                "usage": None,
            }
        )
    )
    with pytest.raises(ProviderInvocationError) as absent:
        missing_usage.invoke(
            entry=_entry(provider=ModelProvider.OPENAI),
            request=_request(),
            credential_reference=CredentialReference(
                reference="secret:openai",
                version=1,
            ),
        )
    assert absent.value.billing is BillingDisposition.AMBIGUOUS


def test_official_anthropic_adapter_maps_usage_and_finish_reason() -> None:
    client = _AnthropicClient(
        {
            "id": "msg-sensitive",
            "content": [{"type": "text", "text": '{"answer":"anthropic"}'}],
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 9,
                "output_tokens": 2,
                "cache_read_input_tokens": 4,
                "cache_creation_input_tokens": 1,
            },
        }
    )
    result = AnthropicProviderAdapter(lambda reference: client).invoke(
        entry=_entry(provider=ModelProvider.ANTHROPIC),
        request=_request(),
        credential_reference=CredentialReference(
            reference="secret:anthropic",
            version=1,
        ),
    )
    assert result.structured_output == {"answer": "anthropic"}
    assert result.usage.cache_read_tokens == 4
    assert result.finish_reason is ModelFinishReason.STOP
    assert client.messages.kwargs["output_config"]["format"]["type"] == "json_schema"

    uncached = _AnthropicClient(
        {
            "id": "msg-uncached",
            "content": [{"type": "text", "text": '{"answer":"uncached"}'}],
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 9,
                "output_tokens": 2,
                "cache_read_input_tokens": None,
                "cache_creation_input_tokens": None,
            },
        }
    )
    uncached_result = AnthropicProviderAdapter(lambda reference: uncached).invoke(
        entry=_entry(provider=ModelProvider.ANTHROPIC),
        request=_request(),
        credential_reference=CredentialReference(
            reference="secret:anthropic",
            version=1,
        ),
    )
    assert uncached_result.usage.cache_read_tokens == 0

    refusal = _AnthropicClient(
        {
            "id": "msg-refusal",
            "content": [{"type": "text", "text": '{"answer":"refused"}'}],
            "stop_reason": "refusal",
            "usage": {"input_tokens": 9, "output_tokens": 2},
        }
    )
    refused = AnthropicProviderAdapter(lambda reference: refusal).invoke(
        entry=_entry(provider=ModelProvider.ANTHROPIC),
        request=_request(),
        credential_reference=CredentialReference(
            reference="secret:anthropic",
            version=1,
        ),
    )
    assert refused.finish_reason is ModelFinishReason.CONTENT_FILTER
    assert refused.safety.blocked is True
    assert refused.usage.input_tokens == 9


def test_sdk_http_status_classification_is_explicit() -> None:
    class _SdkError(Exception):
        def __init__(self, status_code: int) -> None:
            self.status_code = status_code

    not_found = _classify_sdk_error(_SdkError(404))
    assert not_found.code is ModelErrorCode.BAD_REQUEST
    assert not_found.billing is BillingDisposition.NOT_BILLED
    unavailable = _classify_sdk_error(_SdkError(503))
    assert unavailable.code is ModelErrorCode.TRANSIENT
    assert unavailable.billing is BillingDisposition.AMBIGUOUS
    too_large = _classify_sdk_error(_SdkError(413))
    assert too_large.code is ModelErrorCode.BAD_REQUEST
    assert too_large.billing is BillingDisposition.NOT_BILLED


def test_official_sdk_factories_resolve_references_without_network() -> None:
    secrets = _Secrets()
    openai_adapter = OpenAIProviderAdapter.from_secret_resolver(
        secrets,
        timeout_seconds=1,
    )
    anthropic_adapter = AnthropicProviderAdapter.from_secret_resolver(
        secrets,
        timeout_seconds=1,
    )
    openai_client = openai_adapter._client_for(
        CredentialReference(reference="secret:openai", version=1)
    )
    anthropic_client = anthropic_adapter._client_for(
        CredentialReference(reference="secret:anthropic", version=1)
    )
    assert openai_client.responses is not None
    assert anthropic_client.messages is not None
    assert secrets.references == ["secret:openai", "secret:anthropic"]
    with pytest.raises(ValueError, match="timeout"):
        OpenAIProviderAdapter.from_secret_resolver(secrets, timeout_seconds=0)
    with pytest.raises(ValueError, match="timeout"):
        AnthropicProviderAdapter.from_secret_resolver(secrets, timeout_seconds=301)
