"""Opt-in Langfuse tracing and evaluation publishing with minimized payloads."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, cast

from aegis_framework.errors import OptionalDependencyMissing
from aegis_framework.ports import Observation
from aegis_framework.safety import (
    redact_value,
    safe_observability_attributes,
)

if TYPE_CHECKING:
    from aegis_framework.evaluation import (
        CaseResult,
        DatasetContract,
        EvaluationReport,
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

    def evidence_query(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        return self._run(
            tenant_id=tenant_id,
            attributes={**attributes, "operation": "evidence_query"},
            name="aegis.evidence.query",
        )

    def graph_node(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        return self._run(
            tenant_id=tenant_id,
            attributes={**attributes, "operation": "graph_node"},
            name="aegis.graph.node",
        )

    def model_call(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        return self._run(
            tenant_id=tenant_id,
            attributes={**attributes, "operation": "model_call"},
            name="aegis.graph.model",
        )

    def sandbox(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        return self._run(
            tenant_id=tenant_id,
            attributes={**attributes, "operation": "sandbox_activity"},
            name="aegis.sandbox.activity",
        )

    def memory(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        return self._run(
            tenant_id=tenant_id,
            attributes={**attributes, "operation": "memory_activity"},
            name="aegis.memory.activity",
        )

    def interoperability(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
    ) -> AbstractContextManager[Observation]:
        protocol = attributes.get("protocol_kind")
        name = "aegis.a2a.task" if protocol == "a2a" else "aegis.mcp.call"
        return self._run(
            tenant_id=tenant_id,
            attributes={**attributes, "operation": "protocol_operation"},
            name=name,
        )

    @contextmanager
    def _run(
        self,
        *,
        tenant_id: str,
        attributes: Mapping[str, str | int | bool],
        name: str = "aegis.investigation",
    ) -> Iterator[Observation]:
        safe = safe_observability_attributes(attributes)
        safe.setdefault("operation", "checkout_investigation")
        del tenant_id
        with self._client.start_as_current_observation(
            name=name,
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
            name="aegis.layer3.eval",
            as_type="evaluator",
            input={"suite": "layer3", "case_count": total},
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

    def publish_case_result(self, result: CaseResult) -> None:
        """Publish a digest-only case result without sensitive payloads."""

        with self._client.start_as_current_observation(
            name="aegis.layer10.eval.case",
            as_type="evaluator",
            input={
                "case_digest": result.result_id,
                "suite_digest": result.suite_digest,
            },
            metadata={"sanitized": True, "deterministic": True},
        ) as observation:
            observation.update(
                output={
                    "passed": result.passed,
                    "metric_count": len(result.metrics),
                    "trace_ref_count": len(result.trace_refs),
                },
                level="DEFAULT" if result.passed else "ERROR",
                status_message="passed" if result.passed else "failed",
            )

    def publish_evaluation_report(self, report: EvaluationReport) -> None:
        """Publish sanitized aggregates; local comparison remains authority."""

        with self._client.start_as_current_observation(
            name="aegis.layer10.eval.report",
            as_type="evaluator",
            input={
                "report_digest": report.report_id,
                "suite": report.suite_id,
                "suite_version": report.suite_version,
            },
            metadata={
                "automatic_langgraph_capture": False,
                "deterministic": True,
                "sanitized": True,
            },
        ) as observation:
            observation.update(
                output={
                    "passed": report.passed,
                    "case_count": len(report.results),
                    "violation_count": len(report.comparison.violations),
                },
                level="DEFAULT" if report.passed else "ERROR",
                status_message="passed" if report.passed else "failed",
            )
        self._client.flush()

    def publish_dataset_manifest(self, dataset: DatasetContract) -> None:
        """Publish only governed dataset identity and counts, never fixture content."""

        with self._client.start_as_current_observation(
            name="aegis.layer10.eval.dataset",
            as_type="evaluator",
            input={
                "dataset_digest": dataset.canonical_digest,
                "dataset_version": dataset.version,
            },
            metadata={"sanitized": True, "synthetic": True},
        ) as observation:
            observation.update(
                output={
                    "active_case_count": len(dataset.case_ids),
                    "quarantined_case_count": len(dataset.quarantined_case_ids),
                    "deleted_case_count": len(dataset.deleted_case_ids),
                },
                level="DEFAULT",
                status_message="published",
            )


def build_langfuse_observability() -> LangfuseObservability:
    """Build the optional SDK adapter from standard Langfuse environment keys."""

    try:
        from langfuse import Langfuse
    except ModuleNotFoundError as exc:
        if exc.name != "langfuse":
            raise
        raise OptionalDependencyMissing(
            "langfuse support requires the framework-observability extra"
        ) from exc

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
