"""Deterministic structured model used by the executable Layer 1 slice."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum

from aegis_framework.domain import (
    Citation,
    EvidenceKind,
    ModelEvidence,
    Specialist,
    SpecialistFinding,
    SpecialistTask,
    stable_id,
)
from aegis_framework.errors import ModelProviderError


class ModelMode(StrEnum):
    NORMAL = "normal"
    MALFORMED = "malformed"
    ERROR = "error"


class DeterministicStructuredModel:
    """A network-free model double with provider-shaped structured output."""

    def __init__(
        self,
        modes: Mapping[Specialist, ModelMode] | None = None,
    ) -> None:
        self._modes = dict(modes or {})

    def analyze(self, task: SpecialistTask) -> object:
        mode = self._modes.get(task.specialist, ModelMode.NORMAL)
        if mode is ModelMode.ERROR:
            raise ModelProviderError(f"{task.specialist.value} model adapter failed")
        if mode is ModelMode.MALFORMED:
            return {"specialist": task.specialist.value, "unexpected": True}
        if task.specialist is Specialist.TELEMETRY:
            return self._telemetry_finding(task).model_dump(mode="python")
        return self._change_finding(task).model_dump(mode="python")

    @staticmethod
    def _telemetry_finding(task: SpecialistTask) -> SpecialistFinding:
        telemetry = next(
            (item for item in task.evidence if item.kind is EvidenceKind.TELEMETRY),
            None,
        )
        if telemetry is None:
            return _abstention(task, "telemetry_evidence_missing")

        value = telemetry.facts.get("value")
        threshold = telemetry.facts.get("threshold")
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not isinstance(threshold, (int, float))
            or isinstance(threshold, bool)
        ):
            return _abstention(task, "telemetry_signal_malformed")
        if value <= threshold:
            return _abstention(task, "failure_rate_below_threshold")

        change = next(
            (item for item in task.evidence if item.kind is EvidenceKind.CHANGE),
            None,
        )
        cause_code = (
            "post_deploy_regression"
            if change is not None and change.facts.get("status") == "deployed"
            else "traffic_or_dependency_anomaly"
        )
        citations = [_citation(telemetry)]
        if change is not None and change.facts.get("status") == "deployed":
            citations.append(_citation(change))
        return SpecialistFinding(
            finding_id=stable_id(
                "finding", task.incident_id, task.specialist.value, cause_code
            ),
            specialist=task.specialist,
            statement=(
                f"Checkout failures ({value:.3f}) exceed the configured threshold "
                f"({threshold:.3f})."
            ),
            cause_code=cause_code,
            confidence=0.91,
            citations=tuple(citations),
        )

    @staticmethod
    def _change_finding(task: SpecialistTask) -> SpecialistFinding:
        change = next(
            (item for item in task.evidence if item.kind is EvidenceKind.CHANGE),
            None,
        )
        if change is None:
            return _abstention(task, "change_evidence_missing")

        status = change.facts.get("status")
        minutes = change.facts.get("minutes_before_alert")
        if status != "deployed":
            return SpecialistFinding(
                finding_id=stable_id(
                    "finding",
                    task.incident_id,
                    task.specialist.value,
                    "no_recent_change",
                ),
                specialist=task.specialist,
                statement="No active deployment correlates with the alert window.",
                cause_code="no_recent_change",
                confidence=0.88,
                citations=(_citation(change),),
            )
        if (
            not isinstance(minutes, int)
            or isinstance(minutes, bool)
            or minutes < 0
            or minutes > 30
        ):
            return _abstention(task, "change_outside_correlation_window")

        telemetry = next(
            (item for item in task.evidence if item.kind is EvidenceKind.TELEMETRY),
            None,
        )
        citations = [_citation(change)]
        if telemetry is not None:
            citations.append(_citation(telemetry))
        return SpecialistFinding(
            finding_id=stable_id(
                "finding",
                task.incident_id,
                task.specialist.value,
                "post_deploy_regression",
            ),
            specialist=task.specialist,
            statement=(
                f"Deployment {change.facts.get('version', 'unknown')} preceded the "
                f"alert by {minutes} minutes."
            ),
            cause_code="post_deploy_regression",
            confidence=0.89,
            citations=tuple(citations),
        )


def _citation(item: ModelEvidence) -> Citation:
    return Citation(
        evidence_id=item.evidence_id,
        locator=item.locator,
        content_hash=item.content_hash,
    )


def _abstention(task: SpecialistTask, reason: str) -> SpecialistFinding:
    return SpecialistFinding(
        finding_id=stable_id(
            "finding", task.incident_id, task.specialist.value, reason
        ),
        specialist=task.specialist,
        statement=f"{task.specialist.value} specialist abstained: {reason}.",
        cause_code=None,
        confidence=0.0,
        citations=(),
        abstained=True,
        reason=reason,
    )
