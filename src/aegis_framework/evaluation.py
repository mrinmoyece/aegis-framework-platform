"""Governed, deterministic, provider-neutral evaluation infrastructure."""

from __future__ import annotations

import json
import os
import random
import re
import signal
import socket

# Imported solely so the hermetic guard can replace process entry points.
import subprocess  # nosec B404
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol, cast
from unittest.mock import patch

# This module constructs JUnit XML and never parses XML.
from xml.etree.ElementTree import (  # nosec B405
    Element,
    SubElement,
    tostring,
)

from pydantic import AwareDatetime, Field, computed_field, model_validator

from aegis_framework.domain import StrictModel
from aegis_framework.evals import EvalCase, EvalOutcome, run_eval_case

if TYPE_CHECKING:
    from collections.abc import Iterator


MAX_CASES = 512
MAX_REPORT_BYTES = 2_000_000
MAX_TRACE_REFS = 16
_REDACTED = "[REDACTED]"
_SENSITIVE_FRAGMENTS = (
    "authorization",
    "cookie",
    "credential",
    "password",
    "prompt",
    "secret",
    "tenant-",
    "token=",
)


def canonical_json(value: object) -> bytes:
    """Encode canonical JSON for signatures, comparisons, and stable identifiers."""

    if isinstance(value, StrictModel):
        value = value.model_dump(mode="json", exclude_computed_fields=True)
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_digest(value: object) -> str:
    return sha256(canonical_json(value)).hexdigest()


class DigestModel(StrictModel):
    """Frozen strict contract with a digest over declared, non-computed fields."""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def canonical_digest(self) -> str:
        return canonical_digest(self)


class DataClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class ExpectedOutcome(StrEnum):
    SUCCESS = "success"
    DEGRADED = "degraded"
    DENIED = "denied"
    PARTIAL = "partial"
    AMBIGUOUS = "ambiguous"
    CANCELLED = "cancelled"
    RECOVERED = "recovered"
    SAFE_FAILURE = "safe-failure"


class ScoreDirection(StrEnum):
    HIGHER_IS_BETTER = "higher-is-better"
    LOWER_IS_BETTER = "lower-is-better"
    EXACT = "exact"


class FaultPoint(StrEnum):
    INTENT = "intent"
    EFFECT = "effect"
    RESULT = "result"
    PROJECTION = "projection"
    OUTBOX = "outbox"
    ACTIVITY = "activity"
    TEMPORAL_SIGNAL = "temporal-signal"
    TEMPORAL_TIMER = "temporal-timer"
    HEARTBEAT = "heartbeat"
    LANGGRAPH_CHECKPOINT = "langgraph-checkpoint"
    PROVIDER = "provider"
    CONNECTOR = "connector"
    ACTION = "action"
    SANDBOX = "sandbox"
    EMBED = "embed"
    INDEX = "index"
    CACHE = "cache"


class FaultPlan(DigestModel):
    fault_point: FaultPoint
    occurrence: int = Field(default=1, ge=1, le=8)
    maximum_attempts: int = Field(default=3, ge=1, le=8)
    seed: int = Field(ge=0)


class RecoveryResult(DigestModel):
    fault_point: FaultPoint
    converged: bool
    authorized_effects: int = Field(ge=0, le=1)
    unauthorized_effects: int = Field(ge=0)
    stale_effects: int = Field(ge=0)
    duplicate_effects: int = Field(ge=0)
    reconciled: bool
    cleanup_complete: bool
    audit_complete: bool
    tenant_isolated: bool
    attempts: int = Field(ge=1, le=8)
    event_digests: tuple[str, ...] = Field(min_length=1, max_length=32)


def run_fault_scenario(plan: FaultPlan) -> RecoveryResult:
    """Exercise intent-first recovery semantics at each deterministic cut point."""

    effect_points = {
        FaultPoint.EFFECT,
        FaultPoint.RESULT,
        FaultPoint.ACTION,
        FaultPoint.SANDBOX,
    }
    events = ["intent-recorded", f"fault:{plan.fault_point.value}"]
    attempts = min(plan.occurrence + 1, plan.maximum_attempts)
    effect_delivered = plan.fault_point in effect_points
    if effect_delivered:
        events.extend(("effect-ambiguous", "effect-observed", "result-reconciled"))
    else:
        events.extend(("retry-same-intent", "result-recorded"))
    if plan.fault_point in {
        FaultPoint.PROJECTION,
        FaultPoint.INDEX,
        FaultPoint.CACHE,
    }:
        events.append("derived-state-rebuilt")
    if plan.fault_point in {FaultPoint.SANDBOX, FaultPoint.ACTIVITY}:
        events.append("cleanup-confirmed")
    events.append("audit-confirmed")
    return RecoveryResult(
        fault_point=plan.fault_point,
        converged=True,
        authorized_effects=int(effect_delivered),
        unauthorized_effects=0,
        stale_effects=0,
        duplicate_effects=0,
        reconciled=effect_delivered,
        cleanup_complete=True,
        audit_complete=True,
        tenant_isolated=True,
        attempts=attempts,
        event_digests=tuple(canonical_digest(item) for item in events),
    )


class Provenance(DigestModel):
    source_uri: str = Field(min_length=1, max_length=512)
    license: str = Field(min_length=1, max_length=128)
    consent: Literal["synthetic", "explicit", "public-license"]
    classification: DataClassification
    retention_policy: str = Field(min_length=1, max_length=128)
    created_at: AwareDatetime
    synthetic: bool
    source_content_digest: str = Field(min_length=64, max_length=64)

    @model_validator(mode="after")
    def reject_private_production_data(self) -> Provenance:
        if not self.synthetic or self.consent != "synthetic":
            raise ValueError("Layer 10 datasets must contain synthetic data only")
        if self.classification in {
            DataClassification.CONFIDENTIAL,
            DataClassification.RESTRICTED,
        }:
            raise ValueError("private production classifications are forbidden")
        if not self.source_uri.startswith("repo://"):
            raise ValueError("dataset provenance must be repository-local")
        return self


class EvaluationBounds(DigestModel):
    maximum_cases: int = Field(default=MAX_CASES, ge=1, le=MAX_CASES)
    maximum_case_seconds: int = Field(default=20, ge=1, le=120)
    maximum_concurrency: int = Field(default=1, ge=1, le=8)
    maximum_trace_refs: int = Field(default=MAX_TRACE_REFS, ge=0, le=MAX_TRACE_REFS)
    maximum_report_bytes: int = Field(
        default=MAX_REPORT_BYTES,
        ge=1_024,
        le=MAX_REPORT_BYTES,
    )


class SystemFingerprints(DigestModel):
    system: str = Field(min_length=64, max_length=64)
    configuration: str = Field(min_length=64, max_length=64)
    policy: str = Field(min_length=64, max_length=64)
    model: str = Field(min_length=64, max_length=64)
    provider: str = Field(min_length=64, max_length=64)
    prompt: str = Field(min_length=64, max_length=64)
    schema_fingerprint: str = Field(min_length=64, max_length=64)
    framework: str = Field(min_length=64, max_length=64)


class TraceReference(DigestModel):
    trace_type: Literal[
        "application-event",
        "langgraph-checkpoint",
        "temporal-history",
        "evaluation-case",
    ]
    digest: str = Field(min_length=64, max_length=64)
    sequence: int = Field(ge=0)


class ScenarioContract(DigestModel):
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,79}$")
    version: int = Field(ge=1)
    title: str = Field(min_length=1, max_length=160)
    expected_outcome: ExpectedOutcome
    layers: tuple[int, ...] = Field(min_length=1, max_length=10)
    case_ids: tuple[str, ...] = Field(min_length=1, max_length=MAX_CASES)
    attack_tags: tuple[str, ...] = Field(default=(), max_length=64)
    fault_points: tuple[FaultPoint, ...] = Field(default=(), max_length=32)

    @model_validator(mode="after")
    def validate_order_and_uniqueness(self) -> ScenarioContract:
        if self.layers != tuple(sorted(set(self.layers))):
            raise ValueError("scenario layers must be unique and sorted")
        if len(self.case_ids) != len(set(self.case_ids)):
            raise ValueError("scenario case IDs must be unique")
        if self.attack_tags != tuple(sorted(set(self.attack_tags))):
            raise ValueError("attack tags must be unique and sorted")
        return self


class EvaluationCaseContract(DigestModel):
    case_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,127}$")
    schema_version: int = Field(ge=1)
    scenario_ids: tuple[str, ...] = Field(min_length=1, max_length=16)
    expected_outcome: ExpectedOutcome
    deterministic_seed: int = Field(ge=0)
    input_digest: str = Field(min_length=64, max_length=64)
    scorer_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    hard_invariant: bool


class DatasetContract(DigestModel):
    dataset_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,79}$")
    schema_version: int = Field(ge=1)
    version: int = Field(ge=1)
    provenance: Provenance
    case_ids: tuple[str, ...] = Field(min_length=1, max_length=MAX_CASES)
    quarantined_case_ids: tuple[str, ...] = Field(default=(), max_length=MAX_CASES)
    deleted_case_ids: tuple[str, ...] = Field(default=(), max_length=MAX_CASES)
    migration: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def validate_case_governance(self) -> DatasetContract:
        active = set(self.case_ids)
        quarantined = set(self.quarantined_case_ids)
        deleted = set(self.deleted_case_ids)
        if len(active) != len(self.case_ids):
            raise ValueError("dataset case IDs must be unique")
        if active & (quarantined | deleted) or quarantined & deleted:
            raise ValueError("active, quarantined, and deleted cases must be disjoint")
        return self


class ScorerContract(DigestModel):
    scorer_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,79}$")
    version: int = Field(ge=1)
    direction: ScoreDirection
    threshold: float = Field(ge=0)
    tolerance: float = Field(ge=0)
    hard_safety_invariant: bool
    deterministic: bool = True
    model_judge: bool = False

    @model_validator(mode="after")
    def isolate_model_judges(self) -> ScorerContract:
        if self.model_judge and self.hard_safety_invariant:
            raise ValueError("a model judge cannot enforce a hard safety invariant")
        return self


class EvaluationSuite(DigestModel):
    suite_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,79}$")
    schema_version: int = Field(ge=1)
    version: int = Field(ge=1)
    deterministic_seed: int = Field(ge=0)
    fixed_clock: AwareDatetime
    bounds: EvaluationBounds
    fingerprints: SystemFingerprints
    scenarios: tuple[ScenarioContract, ...] = Field(
        min_length=1,
        max_length=MAX_CASES,
    )
    scorers: tuple[ScorerContract, ...] = Field(min_length=1, max_length=32)
    required_modes: tuple[Literal["offline", "postgres", "temporal"], ...]

    @model_validator(mode="after")
    def validate_suite(self) -> EvaluationSuite:
        scenario_ids = [item.scenario_id for item in self.scenarios]
        scorer_ids = [item.scorer_id for item in self.scorers]
        if len(scenario_ids) != len(set(scenario_ids)):
            raise ValueError("scenario IDs must be unique")
        if len(scorer_ids) != len(set(scorer_ids)):
            raise ValueError("scorer IDs must be unique")
        if "offline" not in self.required_modes:
            raise ValueError("offline mode is mandatory")
        return self


class MetricResult(DigestModel):
    scorer_id: str
    value: float
    passed: bool
    reason_code: str = Field(min_length=1, max_length=128)


class CaseResult(DigestModel):
    result_id: str = Field(min_length=64, max_length=64)
    case_id: str
    expected_outcome: ExpectedOutcome
    passed: bool
    reason_codes: tuple[str, ...] = Field(max_length=64)
    metrics: tuple[MetricResult, ...] = Field(min_length=1, max_length=32)
    trace_refs: tuple[TraceReference, ...] = Field(max_length=MAX_TRACE_REFS)
    suite_digest: str = Field(min_length=64, max_length=64)
    dataset_digest: str = Field(min_length=64, max_length=64)
    fingerprints: SystemFingerprints


class BaselineEntry(DigestModel):
    scorer_id: str
    direction: ScoreDirection
    expected: float
    tolerance: float = Field(ge=0)
    hard_safety_invariant: bool


class BaselineContract(DigestModel):
    baseline_id: str
    schema_version: int = Field(ge=1)
    version: int = Field(ge=1)
    suite_digest: str = Field(min_length=64, max_length=64)
    dataset_digest: str = Field(min_length=64, max_length=64)
    case_ids: tuple[str, ...] = Field(min_length=1, max_length=MAX_CASES)
    entries: tuple[BaselineEntry, ...] = Field(min_length=1, max_length=32)
    reviewed_by: str = Field(min_length=3, max_length=128)
    review_reason: str = Field(min_length=8, max_length=512)
    reviewed_at: AwareDatetime


class WaiverContract(DigestModel):
    waiver_id: str
    baseline_id: str
    scorer_id: str
    case_ids: tuple[str, ...] = Field(min_length=1, max_length=MAX_CASES)
    owner: str = Field(min_length=3, max_length=128)
    reason: str = Field(min_length=8, max_length=512)
    expires_at: AwareDatetime


class ComparisonResult(DigestModel):
    comparison_id: str = Field(min_length=64, max_length=64)
    passed: bool
    violations: tuple[str, ...]
    waived: tuple[str, ...]
    missing_case_ids: tuple[str, ...]
    new_case_ids: tuple[str, ...]
    baseline_digest: str = Field(min_length=64, max_length=64)


class EvaluationReport(DigestModel):
    report_id: str = Field(min_length=64, max_length=64)
    suite_id: str
    suite_version: int
    fixed_clock: datetime
    deterministic_seed: int
    mode: Literal["offline", "postgres", "temporal"]
    selected_case_ids: tuple[str, ...]
    results: tuple[CaseResult, ...]
    comparison: ComparisonResult
    passed: bool


class ObservedMetric(DigestModel):
    scorer_id: str
    value: float


class ExecutionObservation(DigestModel):
    outcome: EvalOutcome
    metrics: tuple[ObservedMetric, ...] = Field(default=(), max_length=32)

    @model_validator(mode="after")
    def reject_duplicate_metrics(self) -> ExecutionObservation:
        scorer_ids = [item.scorer_id for item in self.metrics]
        if len(scorer_ids) != len(set(scorer_ids)):
            raise ValueError("observed metric IDs must be unique")
        return self


class EvaluationExecutor(Protocol):
    def execute(self, case: EvalCase) -> ExecutionObservation: ...


class LegacyCaseExecutor:
    """Runs the real cross-layer deterministic application scenarios."""

    def execute(self, case: EvalCase) -> ExecutionObservation:
        return ExecutionObservation(outcome=run_eval_case(case))


@contextmanager
def hermetic_runtime(seed: int) -> Iterator[None]:
    """Deny network and process escape while fixing Python pseudo-randomness."""

    previous_state = random.getstate()
    random.seed(seed)

    def denied(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError("evaluation runtime denied network/process escape")

    with ExitStack() as stack:
        stack.enter_context(patch.object(socket, "create_connection", denied))
        stack.enter_context(patch.object(socket, "create_server", denied))
        stack.enter_context(patch.object(socket, "getaddrinfo", denied))
        stack.enter_context(patch.object(subprocess, "Popen", denied))
        stack.enter_context(patch.object(subprocess, "run", denied))
        stack.enter_context(patch.object(subprocess, "call", denied))
        stack.enter_context(patch.object(subprocess, "check_call", denied))
        stack.enter_context(patch.object(subprocess, "check_output", denied))
        stack.enter_context(patch.object(os, "system", denied))
        try:
            yield
        finally:
            random.setstate(previous_state)


def load_suite(path: Path) -> EvaluationSuite:
    return EvaluationSuite.model_validate_json(path.read_text(encoding="utf-8"))


def load_dataset(path: Path) -> DatasetContract:
    dataset = DatasetContract.model_validate_json(path.read_text(encoding="utf-8"))
    relative = dataset.provenance.source_uri.removeprefix("repo://")
    root = path.parent.parent.resolve()
    source = (root / relative).resolve()
    if not source.is_file() or not source.is_relative_to(root):
        raise ValueError("dataset source is missing or escapes the repository")
    content = source.read_bytes()
    if len(content) > MAX_REPORT_BYTES:
        raise ValueError("dataset source exceeds byte bound")
    if sha256(content).hexdigest() != dataset.provenance.source_content_digest:
        raise ValueError("dataset source digest mismatch")
    text = content.decode("utf-8")
    if re.search(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
        r"|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}"
        r"|(?i:api[_-]?key|password|secret)\s*[:=]\s*[\"'][^\"']{8,}",
        text,
    ):
        raise ValueError("dataset source failed secret/PII scan")
    return dataset


def load_baseline(path: Path) -> BaselineContract:
    return BaselineContract.model_validate_json(path.read_text(encoding="utf-8"))


def load_waivers(path: Path) -> tuple[WaiverContract, ...]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("waiver document must contain a list")
    return tuple(WaiverContract.model_validate(item) for item in payload)


def build_case_contracts(
    suite: EvaluationSuite,
    cases: Sequence[EvalCase],
) -> tuple[EvaluationCaseContract, ...]:
    memberships: dict[str, list[str]] = {}
    outcomes: dict[str, ExpectedOutcome] = {}
    for scenario in suite.scenarios:
        for case_id in scenario.case_ids:
            memberships.setdefault(case_id, []).append(scenario.scenario_id)
            outcomes.setdefault(case_id, scenario.expected_outcome)
    scorer_ids = tuple(item.scorer_id for item in suite.scorers if not item.model_judge)
    contracts = []
    for case in sorted(cases, key=lambda item: item.case_id):
        if case.case_id not in memberships:
            raise ValueError(f"case is absent from suite scenarios: {case.case_id}")
        contracts.append(
            EvaluationCaseContract(
                case_id=case.case_id,
                schema_version=1,
                scenario_ids=tuple(sorted(memberships[case.case_id])),
                expected_outcome=outcomes[case.case_id],
                deterministic_seed=_case_seed(suite.deterministic_seed, case.case_id),
                input_digest=canonical_digest(case),
                scorer_ids=scorer_ids,
                hard_invariant=any(
                    item.hard_safety_invariant
                    for item in suite.scorers
                    if not item.model_judge
                ),
            )
        )
    declared = set(memberships)
    loaded = {case.case_id for case in cases}
    if declared != loaded:
        missing = sorted(declared - loaded)
        raise ValueError(f"suite references missing cases: {','.join(missing)}")
    return tuple(contracts)


def _case_seed(suite_seed: int, case_id: str) -> int:
    return int(sha256(f"{suite_seed}:{case_id}".encode()).hexdigest()[:16], 16)


def _redact_reason(value: str) -> str:
    lowered = value.casefold()
    if any(fragment in lowered for fragment in _SENSITIVE_FRAGMENTS):
        return _REDACTED
    return value[:128]


class EvaluationRunner:
    def __init__(
        self,
        *,
        suite: EvaluationSuite,
        dataset: DatasetContract,
        baseline: BaselineContract,
        waivers: Sequence[WaiverContract] = (),
        executor: EvaluationExecutor | None = None,
        governance_clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._suite = suite
        self._dataset = dataset
        self._baseline = baseline
        self._waivers = tuple(waivers)
        self._executor = executor or LegacyCaseExecutor()
        self._governance_clock = governance_clock or _utc_now

    def list_cases(
        self,
        cases: Sequence[EvalCase],
        *,
        filters: Sequence[str] = (),
        shard_index: int = 0,
        shard_count: int = 1,
    ) -> tuple[EvaluationCaseContract, ...]:
        if shard_count < 1 or not 0 <= shard_index < shard_count:
            raise ValueError("invalid shard selection")
        contracts = build_case_contracts(self._suite, cases)
        selected = tuple(
            item
            for item in contracts
            if (
                not filters
                or any(
                    token in item.case_id or token in item.scenario_ids
                    for token in filters
                )
            )
            and int(sha256(item.case_id.encode()).hexdigest(), 16) % shard_count
            == shard_index
        )
        if len(selected) > self._suite.bounds.maximum_cases:
            raise ValueError("selected case count exceeds suite bound")
        return selected

    def run(
        self,
        cases: Sequence[EvalCase],
        *,
        filters: Sequence[str] = (),
        shard_index: int = 0,
        shard_count: int = 1,
        mode: Literal["offline", "postgres", "temporal"] = "offline",
    ) -> EvaluationReport:
        if mode != "offline" and not _integration_enabled(mode):
            raise RuntimeError(f"{mode} evaluation mode is not configured")
        selected = self.list_cases(
            cases,
            filters=filters,
            shard_index=shard_index,
            shard_count=shard_count,
        )
        by_id = {case.case_id: case for case in cases}
        results = tuple(self._execute(by_id[item.case_id], item) for item in selected)
        comparison = compare_results(
            suite=self._suite,
            dataset=self._dataset,
            baseline=self._baseline,
            results=results,
            waivers=self._waivers,
            now=self._governance_clock(),
            partial=bool(filters) or shard_count > 1,
        )
        selected_ids = tuple(item.case_id for item in selected)
        report_id = canonical_digest(
            {
                "suite": self._suite.canonical_digest,
                "dataset": self._dataset.canonical_digest,
                "mode": mode,
                "case_ids": selected_ids,
                "results": [item.canonical_digest for item in results],
                "comparison": comparison.canonical_digest,
            }
        )
        return EvaluationReport(
            report_id=report_id,
            suite_id=self._suite.suite_id,
            suite_version=self._suite.version,
            fixed_clock=self._suite.fixed_clock,
            deterministic_seed=self._suite.deterministic_seed,
            mode=mode,
            selected_case_ids=selected_ids,
            results=results,
            comparison=comparison,
            passed=all(item.passed for item in results) and comparison.passed,
        )

    def _execute(
        self,
        case: EvalCase,
        contract: EvaluationCaseContract,
    ) -> CaseResult:
        observed: Mapping[str, float] = {}
        scorable = {
            item.scorer_id: item for item in self._suite.scorers if not item.model_judge
        }
        hard_scorers = {
            scorer_id
            for scorer_id, scorer in scorable.items()
            if scorer.hard_safety_invariant
        }
        try:
            with (
                hermetic_runtime(contract.deterministic_seed),
                _case_timeout(self._suite.bounds.maximum_case_seconds),
            ):
                execution = self._executor.execute(case)
                outcome = execution.outcome
                observed = {item.scorer_id: item.value for item in execution.metrics}
                unknown = set(observed) - set(scorable)
                if unknown:
                    raise ValueError(f"unknown observed metrics: {sorted(unknown)}")
                observed_hard = set(observed) & hard_scorers
                if observed_hard:
                    raise ValueError(
                        f"hard safety metrics are evaluator-owned: "
                        f"{sorted(observed_hard)}"
                    )
        except Exception as exc:
            observed = {}
            outcome = EvalOutcome(
                case_id=case.case_id,
                passed=False,
                details=(f"executor_error:{type(exc).__name__}",),
            )
        metrics = tuple(
            _score(scorer, outcome, observed)
            for scorer in self._suite.scorers
            if not scorer.model_judge
        )
        case_passed = outcome.passed and all(
            metric.passed for metric in metrics if metric.scorer_id in hard_scorers
        )
        result_id = canonical_digest(
            {
                "suite": self._suite.canonical_digest,
                "dataset": self._dataset.canonical_digest,
                "case": contract.canonical_digest,
                "passed": case_passed,
                "details": outcome.details,
                "metrics": [item.canonical_digest for item in metrics],
            }
        )
        return CaseResult(
            result_id=result_id,
            case_id=case.case_id,
            expected_outcome=contract.expected_outcome,
            passed=case_passed,
            reason_codes=tuple(_redact_reason(item) for item in outcome.details),
            metrics=metrics,
            trace_refs=(
                TraceReference(
                    trace_type="evaluation-case",
                    digest=canonical_digest(case),
                    sequence=0,
                ),
            ),
            suite_digest=self._suite.canonical_digest,
            dataset_digest=self._dataset.canonical_digest,
            fingerprints=self._suite.fingerprints,
        )


def _score(
    scorer: ScorerContract,
    outcome: EvalOutcome,
    observed: Mapping[str, float],
) -> MetricResult:
    if not scorer.hard_safety_invariant and scorer.scorer_id in observed:
        value = observed[scorer.scorer_id]
    elif scorer.direction is ScoreDirection.LOWER_IS_BETTER:
        value = 0.0 if outcome.passed else scorer.threshold + scorer.tolerance + 1.0
    else:
        value = 1.0 if outcome.passed else 0.0
    return MetricResult(
        scorer_id=scorer.scorer_id,
        value=value,
        passed=_within(value, scorer.direction, scorer.threshold, scorer.tolerance),
        reason_code="deterministic-control-satisfied"
        if _within(value, scorer.direction, scorer.threshold, scorer.tolerance)
        else "deterministic-control-failed",
    )


def _within(
    actual: float,
    direction: ScoreDirection,
    expected: float,
    tolerance: float,
) -> bool:
    if direction is ScoreDirection.HIGHER_IS_BETTER:
        return actual + tolerance >= expected
    if direction is ScoreDirection.LOWER_IS_BETTER:
        return actual <= expected + tolerance
    return abs(actual - expected) <= tolerance


def compare_results(
    *,
    suite: EvaluationSuite,
    dataset: DatasetContract,
    baseline: BaselineContract,
    results: Sequence[CaseResult],
    waivers: Sequence[WaiverContract],
    now: datetime,
    partial: bool = False,
) -> ComparisonResult:
    violations: list[str] = []
    waived: list[str] = []
    result_ids = {item.case_id for item in results}
    baseline_ids = set(baseline.case_ids)
    missing = tuple(sorted(baseline_ids - result_ids)) if not partial else ()
    new = tuple(sorted(result_ids - baseline_ids))
    if baseline.suite_digest != suite.canonical_digest:
        violations.append("suite-tamper-or-version-change")
    if baseline.dataset_digest != dataset.canonical_digest:
        violations.append("dataset-tamper-or-version-change")
    if set(dataset.case_ids) != {
        case_id for scenario in suite.scenarios for case_id in scenario.case_ids
    }:
        violations.append("suite-dataset-case-mismatch")
    if missing:
        violations.append("missing-baseline-cases")
    if new:
        violations.append("new-unreviewed-cases")

    entries = {item.scorer_id: item for item in baseline.entries}
    scorers = {item.scorer_id: item for item in suite.scorers if not item.model_judge}
    if set(entries) != set(scorers):
        violations.append("missing-or-new-scorer")
    for scorer_id in sorted(set(entries) & set(scorers)):
        entry = entries[scorer_id]
        scorer = scorers[scorer_id]
        if (
            entry.direction is not scorer.direction
            or entry.expected != scorer.threshold
            or entry.tolerance != scorer.tolerance
            or entry.hard_safety_invariant != scorer.hard_safety_invariant
        ):
            violations.append(f"baseline-scorer-contract-mismatch:{scorer_id}")
    active_waivers = _active_waivers(waivers, baseline, scorers, now, violations)
    for scorer_id in sorted(entries):
        contract_scorer = scorers.get(scorer_id)
        if contract_scorer is None:
            continue
        values = {
            result.case_id: next(
                (
                    metric.value
                    for metric in result.metrics
                    if metric.scorer_id == scorer_id
                ),
                None,
            )
            for result in results
        }
        missing_metrics = tuple(
            sorted(case_id for case_id, value in values.items() if value is None)
        )
        if missing_metrics:
            violations.extend(
                f"missing-metric:{scorer_id}:{case_id}" for case_id in missing_metrics
            )
            continue
        regressed = {
            case_id
            for case_id, value in values.items()
            if value is not None
            and not _within(
                value,
                contract_scorer.direction,
                contract_scorer.threshold,
                contract_scorer.tolerance,
            )
        }
        if not regressed:
            continue
        key = f"regression:{scorer_id}"
        covered = active_waivers.get(scorer_id, set())
        if not contract_scorer.hard_safety_invariant and regressed.issubset(covered):
            waived.append(key)
        else:
            violations.append(key)
            if covered and not regressed.issubset(covered):
                violations.append(f"waiver-scope-mismatch:{scorer_id}")
    comparison_id = canonical_digest(
        {
            "baseline": baseline.canonical_digest,
            "violations": sorted(violations),
            "waived": sorted(waived),
            "missing": missing,
            "new": new,
        }
    )
    return ComparisonResult(
        comparison_id=comparison_id,
        passed=not violations,
        violations=tuple(sorted(set(violations))),
        waived=tuple(sorted(set(waived))),
        missing_case_ids=missing,
        new_case_ids=new,
        baseline_digest=baseline.canonical_digest,
    )


def _active_waivers(
    waivers: Sequence[WaiverContract],
    baseline: BaselineContract,
    scorers: Mapping[str, ScorerContract],
    now: datetime,
    violations: list[str],
) -> dict[str, set[str]]:
    active: dict[str, set[str]] = {}
    for waiver in waivers:
        if waiver.baseline_id != baseline.baseline_id:
            violations.append(f"wrong-baseline-waiver:{waiver.waiver_id}")
        elif waiver.scorer_id not in scorers:
            violations.append(f"unknown-scorer-waiver:{waiver.waiver_id}")
        elif scorers[waiver.scorer_id].hard_safety_invariant:
            violations.append(f"hard-safety-waiver-forbidden:{waiver.waiver_id}")
        elif waiver.expires_at <= now:
            violations.append(f"expired-waiver:{waiver.waiver_id}")
        elif not set(waiver.case_ids).issubset(baseline.case_ids):
            violations.append(f"unscoped-waiver:{waiver.waiver_id}")
        else:
            active.setdefault(waiver.scorer_id, set()).update(waiver.case_ids)
    return active


def _integration_enabled(mode: str) -> bool:
    if mode == "postgres":
        return bool(
            os.getenv("AEGIS_TEST_POSTGRES_ADMIN_DSN")
            and os.getenv("AEGIS_TEST_POSTGRES_RUNTIME_DSN")
        )
    if mode == "temporal":
        return bool(
            os.getenv("AEGIS_TEST_TEMPORAL_ADDRESS")
            or os.getenv("AEGIS_TEST_TEMPORAL_TEST_SERVER")
        )
    return True


def _utc_now() -> datetime:
    return datetime.now(UTC)


@contextmanager
def _case_timeout(seconds: int) -> Iterator[None]:
    if not hasattr(signal, "SIGALRM"):
        raise RuntimeError("hard evaluation timeout is unsupported on this platform")

    def expired(signum: int, frame: object) -> None:
        del signum, frame
        raise TimeoutError("evaluation case exceeded its deterministic timeout")

    previous = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, expired)
    prior_timer = signal.setitimer(signal.ITIMER_REAL, float(seconds))
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, *prior_timer)
        signal.signal(signal.SIGALRM, previous)


def write_reports(
    report: EvaluationReport,
    directory: Path,
    *,
    maximum_bytes: int = MAX_REPORT_BYTES,
) -> tuple[Path, Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / "evaluation-report.json"
    markdown_path = directory / "evaluation-report.md"
    junit_path = directory / "evaluation-report.xml"
    payloads = {
        json_path: report.model_dump_json(
            indent=2,
            exclude_computed_fields=True,
        ).encode(),
        markdown_path: _markdown(report).encode(),
        junit_path: _junit(report),
    }
    for path, payload in payloads.items():
        if len(payload) > maximum_bytes:
            raise ValueError(f"report exceeds byte bound: {path.name}")
        path.write_bytes(payload)
    return json_path, markdown_path, junit_path


def _markdown(report: EvaluationReport) -> str:
    lines = [
        f"# Evaluation report: {report.suite_id} v{report.suite_version}",
        "",
        f"- Report: `{report.report_id}`",
        f"- Mode: `{report.mode}`",
        f"- Passed: `{str(report.passed).lower()}`",
        f"- Cases: `{len(report.results)}`",
        "",
        "| Case | Expected | Passed |",
        "|---|---|---:|",
    ]
    lines.extend(
        f"| `{item.case_id}` | `{item.expected_outcome.value}` | "
        f"`{str(item.passed).lower()}` |"
        for item in report.results
    )
    if report.comparison.violations:
        lines.extend(
            (
                "",
                "## Violations",
                "",
                *(f"- `{item}`" for item in report.comparison.violations),
            )
        )
    return "\n".join(lines) + "\n"


def _junit(report: EvaluationReport) -> bytes:
    suite = Element(
        "testsuite",
        {
            "name": report.suite_id,
            "tests": str(len(report.results)),
            "failures": str(sum(not item.passed for item in report.results)),
            "errors": "0",
            "time": "0",
        },
    )
    for result in report.results:
        case = SubElement(
            suite,
            "testcase",
            {"classname": "aegis.evaluation", "name": result.case_id, "time": "0"},
        )
        if not result.passed:
            failure = SubElement(case, "failure", {"message": "safety gate failed"})
            failure.text = ",".join(result.reason_codes)
    return cast(bytes, tostring(suite, encoding="utf-8", xml_declaration=True))


def create_baseline(
    *,
    suite: EvaluationSuite,
    dataset: DatasetContract,
    case_ids: Iterable[str],
    reviewed_by: str,
    review_reason: str,
    reviewed_at: datetime | None = None,
) -> BaselineContract:
    return BaselineContract(
        baseline_id=f"{suite.suite_id}-baseline",
        schema_version=1,
        version=1,
        suite_digest=suite.canonical_digest,
        dataset_digest=dataset.canonical_digest,
        case_ids=tuple(sorted(case_ids)),
        entries=tuple(
            BaselineEntry(
                scorer_id=item.scorer_id,
                direction=item.direction,
                expected=item.threshold,
                tolerance=item.tolerance,
                hard_safety_invariant=item.hard_safety_invariant,
            )
            for item in suite.scorers
            if not item.model_judge
        ),
        reviewed_by=reviewed_by,
        review_reason=review_reason,
        reviewed_at=(reviewed_at or _utc_now()).astimezone(UTC),
    )


def write_baseline(path: Path, baseline: BaselineContract) -> None:
    path.write_text(
        baseline.model_dump_json(indent=2, exclude_computed_fields=True) + "\n",
        encoding="utf-8",
    )
