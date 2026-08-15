"""Opt-in Langfuse tracing and evaluation publishing with minimized payloads."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from typing import Protocol, cast

from aegis_framework.ports import Observation
from aegis_framework.safety import (
    redact_value,
    safe_observability_attributes,
    tenant_bucket,
)


class _LangfuseObservation(Protocol):
    def update(
        self,
        *,
        output: object | None = None,
        metadata: object | None = None,
        level: str | None = None,
        status_message: str | None = None,
    ) -> object: ...


class _LangfuseClient(Protocol):
    def start_as_current_observation(
        self,
        *,
        name: str,
        as_type: str,
        input: object | None = None,
        metadata: object | None = None,
    ) -> AbstractContextManager[_LangfuseObservation]: ...

    def flush(self) -> None: ...


@dataclass
class _LangfuseRun:
    observation: _LangfuseObservation

    def finish(
        self,
        *,
        status: str,
        attributes: Mapping[str, str | int | bool],
    ) -> None:
        output = safe_observability_attributes({**attributes, "status": status})
        self.observation.update(
            output=output,
            level="ERROR" if status == "failed" else "DEFAULT",
            status_message=status,
        )


class LangfuseObservability:
    """Manual Langfuse integration; automatic graph-state capture stays disabled."""

    def __init__(self, client: _LangfuseClient) -> None:
        self._client = client

    def investigation(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        return self._run(tenant_id=tenant_id, attributes=attributes)

    @contextmanager
    def _run(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> Iterator[Observation]:
        safe = safe_observability_attributes(attributes)
        safe["operation"] = "checkout_investigation"
        safe["tenant_bucket"] = tenant_bucket(tenant_id)
        with self._client.start_as_current_observation(
            name="aegis.investigation",
            as_type="chain",
            input=safe,
            metadata={
                "capture_policy": "counts-and-status-only",
                "automatic_langgraph_capture": False,
            },
        ) as observation:
            yield _LangfuseRun(observation)

    def publish_evaluation(
        self,
        *,
        total: int,
        succeeded: int,
        passed: bool,
    ) -> None:
        with self._client.start_as_current_observation(
            name="aegis.layer1.eval",
            as_type="evaluator",
            input={"suite": "layer1", "case_count": total},
            metadata={"deterministic": True, "network_models": False},
        ) as observation:
            observation.update(
                output={
                    "passed": passed,
                    "total": total,
                    "succeeded": succeeded,
                },
                level="DEFAULT" if passed else "ERROR",
                status_message="passed" if passed else "failed",
            )
        self._client.flush()


def build_langfuse_observability() -> LangfuseObservability:
    """Build the optional SDK adapter from standard Langfuse environment keys."""

    from langfuse import Langfuse

    client = Langfuse(
        mask=_mask_langfuse_payload,
        blocked_instrumentation_scopes=[
            "anthropic",
            "langchain",
            "openai",
        ],
    )
    return LangfuseObservability(cast("_LangfuseClient", client))


def _mask_langfuse_payload(*, data: object, **kwargs: object) -> object:
    del kwargs
    return redact_value(data)
