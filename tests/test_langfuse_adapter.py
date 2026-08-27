from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from aegis_framework.evals import load_cases
from aegis_framework.evaluation import (
    EvaluationRunner,
    load_baseline,
    load_dataset,
    load_suite,
)
from aegis_framework.langfuse_adapter import (
    LangfuseObservability,
    _mask_langfuse_payload,
    build_langfuse_observability,
)


@dataclass
class _FakeObservation:
    updates: list[dict[str, object]] = field(default_factory=list)

    def update(
        self,
        *,
        output: object | None = None,
        metadata: object | None = None,
        level: str | None = None,
        status_message: str | None = None,
    ) -> object:
        self.updates.append(
            {
                "output": output,
                "metadata": metadata,
                "level": level,
                "status_message": status_message,
            }
        )
        return self


@dataclass
class _FakeClient:
    starts: list[dict[str, object]] = field(default_factory=list)
    observations: list[_FakeObservation] = field(default_factory=list)
    flushes: int = 0

    @contextmanager
    def start_as_current_observation(
        self,
        *,
        name: str,
        as_type: str,
        input: object | None = None,
        metadata: object | None = None,
    ) -> Iterator[_FakeObservation]:
        self.starts.append(
            {
                "name": name,
                "as_type": as_type,
                "input": input,
                "metadata": metadata,
            }
        )
        observation = _FakeObservation()
        self.observations.append(observation)
        yield observation

    def flush(self) -> None:
        self.flushes += 1


def test_langfuse_investigation_never_receives_raw_data() -> None:
    client = _FakeClient()
    adapter = LangfuseObservability(client)
    with adapter.investigation(
        tenant_id="tenant-secret-name",
        attributes={
            "scenario": "success",
            "request_id": "request-secret",
            "prompt": "prompt-secret",
        },
    ) as observation:
        observation.finish(
            status="complete",
            attributes={
                "evidence_count": 3,
                "raw_evidence": "evidence-secret",
            },
        )
    rendered = repr((client.starts, client.observations))
    assert "tenant-secret-name" not in rendered
    assert "request-secret" not in rendered
    assert "prompt-secret" not in rendered
    assert "evidence-secret" not in rendered
    assert client.starts[0]["as_type"] == "chain"
    assert client.observations[0].updates[0]["output"] == {
        "evidence_count": 3,
        "status": "complete",
    }


def test_langfuse_evaluation_publishes_aggregates_only() -> None:
    client = _FakeClient()
    adapter = LangfuseObservability(client)
    adapter.publish_evaluation(total=5, succeeded=4, passed=False)
    assert client.starts[0]["as_type"] == "evaluator"
    assert client.observations[0].updates[0] == {
        "output": {"passed": False, "total": 5, "succeeded": 4},
        "metadata": None,
        "level": "ERROR",
        "status_message": "failed",
    }
    assert client.flushes == 1


def test_langfuse_layer10_publishes_only_sanitized_digests_and_counts() -> None:
    dataset = load_dataset(Path("evals/dataset.json"))
    report = EvaluationRunner(
        suite=load_suite(Path("evals/suite.json")),
        dataset=dataset,
        baseline=load_baseline(Path("evals/baseline.json")),
    ).run(load_cases(Path("evals/cases.json")), filters=("prompt-injection",))
    client = _FakeClient()
    adapter = LangfuseObservability(client)
    adapter.publish_dataset_manifest(dataset)
    adapter.publish_case_result(report.results[0])
    adapter.publish_evaluation_report(report)
    rendered = repr((client.starts, client.observations))
    assert "tenant-acme" not in rendered
    assert "ignore previous instructions" not in rendered
    assert [item["name"] for item in client.starts] == [
        "aegis.layer10.eval.dataset",
        "aegis.layer10.eval.case",
        "aegis.layer10.eval.report",
    ]
    assert client.flushes == 1


def test_langfuse_memory_observation_is_digest_and_count_only() -> None:
    client = _FakeClient()
    adapter = LangfuseObservability(client)
    with adapter.memory(
        tenant_id="tenant-secret-name",
        attributes={
            "memory_tier": "semantic",
            "candidate_count": 4,
            "query": "never-export",
        },
    ) as observation:
        observation.finish(
            status="complete",
            attributes={
                "chunk_count": 2,
                "content": "never-export",
            },
        )
    assert client.starts[0]["name"] == "aegis.memory.activity"
    rendered = repr((client.starts, client.observations))
    assert "tenant-secret-name" not in rendered
    assert "never-export" not in rendered
    assert client.observations[0].updates[0]["output"] == {
        "chunk_count": 2,
        "status": "complete",
    }


def test_langfuse_mask_is_defense_in_depth() -> None:
    assert _mask_langfuse_payload(
        data={"prompt": "secret", "safe": 1},
        ignored=True,
    ) == {"prompt": "[REDACTED]", "safe": 1}


def test_langfuse_builder_blocks_automatic_sensitive_instrumentation(
    monkeypatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_langfuse(**kwargs: object) -> _FakeClient:
        captured.update(kwargs)
        return _FakeClient()

    monkeypatch.setattr("langfuse.Langfuse", fake_langfuse)

    assert isinstance(build_langfuse_observability(), LangfuseObservability)
    assert captured["mask"] is _mask_langfuse_payload
    assert captured["blocked_instrumentation_scopes"] == [
        "anthropic",
        "langchain",
        "openai",
    ]
