"""Deterministic, non-causal evidence timeline and conflict correlation."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from datetime import timedelta

from aegis_framework.domain import (
    Citation,
    CorrelationContext,
    CorrelationStatus,
    Evidence,
    EvidenceConflict,
    EvidenceKind,
    EvidenceLink,
    TimelineEvidenceEvent,
    stable_id,
)

_REQUIRED_SOURCES = frozenset(
    {EvidenceKind.TELEMETRY, EvidenceKind.CHANGE, EvidenceKind.RUNBOOK}
)
_FRESHNESS = {
    EvidenceKind.TELEMETRY: timedelta(hours=1),
    EvidenceKind.CHANGE: timedelta(days=1),
    EvidenceKind.RUNBOOK: timedelta(days=30),
}
_SHARED_FACT_KEYS = frozenset({"region", "service", "status", "version"})
_CONFLICT_FACT_KEYS = frozenset(
    {"change_id", "error_code", "region", "service", "status", "version"}
)


def correlate_evidence(
    evidence: Sequence[Evidence],
    *,
    reference_time: object,
    required_sources: frozenset[EvidenceKind] = _REQUIRED_SOURCES,
    proximity: timedelta = timedelta(minutes=30),
) -> CorrelationContext:
    from datetime import datetime

    if not isinstance(reference_time, datetime) or reference_time.tzinfo is None:
        raise ValueError("correlation reference time must be timezone-aware")
    if proximity <= timedelta(0) or proximity > timedelta(days=7):
        raise ValueError("correlation proximity is outside the permitted bound")
    ordered = tuple(
        sorted(
            evidence,
            key=lambda item: (
                item.observed_at,
                item.kind.value,
                item.evidence_id,
            ),
        )
    )
    present = {item.kind for item in ordered}
    missing = tuple(sorted(required_sources - present, key=lambda item: item.value))
    # Freshness: a kind is stale only when its newest record is old.
    latest_per_kind: dict[EvidenceKind, object] = {}
    for item in ordered:
        if (
            item.kind not in latest_per_kind
            or item.observed_at > latest_per_kind[item.kind]  # type: ignore[operator]
        ):
            latest_per_kind[item.kind] = item.observed_at
    stale = tuple(
        sorted(
            {
                kind
                for kind, latest_at in latest_per_kind.items()
                if reference_time - latest_at > _FRESHNESS[kind]  # type: ignore[operator]
            },
            key=lambda item: item.value,
        )
    )
    timeline = tuple(
        TimelineEvidenceEvent(
            event_id=stable_id(
                "timeline",
                item.evidence_id,
                item.observed_at.isoformat(),
            ),
            occurred_at=item.observed_at,
            kind=item.kind,
            statement=f"{item.kind.value} evidence was observed.",
            citations=(_citation(item),),
        )
        for item in ordered
    )
    links = _links(ordered, proximity=proximity)
    conflicts = _conflicts(ordered)
    if conflicts:
        status = CorrelationStatus.CONFLICTED
    elif missing:
        status = CorrelationStatus.PARTIAL
    elif stale:
        status = CorrelationStatus.STALE
    else:
        status = CorrelationStatus.COMPLETE
    # CorrelationContext bounds: timeline ≤ 1,000 and links ≤ 2,000.
    # Cap deterministically to avoid Pydantic validation errors on large inputs.
    return CorrelationContext(
        status=status,
        timeline=timeline[:1_000],
        links=tuple(sorted(links, key=lambda lnk: lnk.link_id))[:2_000],
        conflicts=conflicts,
        missing_sources=missing,
        stale_sources=stale,
    )


def _links(
    evidence: Sequence[Evidence],
    *,
    proximity: timedelta,
) -> tuple[EvidenceLink, ...]:
    links: dict[str, EvidenceLink] = {}
    for index, left in enumerate(evidence):
        for right in evidence[index + 1 :]:
            if left.evidence_id == right.evidence_id:
                continue
            distance = abs(int((right.observed_at - left.observed_at).total_seconds()))
            if distance <= int(proximity.total_seconds()):
                link = EvidenceLink(
                    link_id=stable_id(
                        "link",
                        "temporal_proximity",
                        left.evidence_id,
                        right.evidence_id,
                    ),
                    relation="temporal_proximity",
                    left_evidence_id=left.evidence_id,
                    right_evidence_id=right.evidence_id,
                    distance_seconds=distance,
                )
                links[link.link_id] = link
            for key in sorted(set(left.facts) & set(right.facts) & _SHARED_FACT_KEYS):
                if (
                    left.facts[key] is None
                    or left.facts[key] != right.facts[key]
                    or isinstance(left.facts[key], (dict, list))
                ):
                    continue
                link = EvidenceLink(
                    link_id=stable_id(
                        "link",
                        "shared_fact",
                        key,
                        left.evidence_id,
                        right.evidence_id,
                    ),
                    relation="shared_fact",
                    left_evidence_id=left.evidence_id,
                    right_evidence_id=right.evidence_id,
                    fact_key=key,
                )
                links[link.link_id] = link
    return tuple(
        sorted(
            links.values(),
            key=lambda item: (
                item.relation,
                item.left_evidence_id,
                item.right_evidence_id,
                item.fact_key or "",
            ),
        )
    )


def _conflicts(evidence: Sequence[Evidence]) -> tuple[EvidenceConflict, ...]:
    grouped: dict[
        tuple[EvidenceKind, str],
        dict[str, list[Evidence]],
    ] = defaultdict(lambda: defaultdict(list))
    for item in evidence:
        for key, value in item.facts.items():
            if key not in _CONFLICT_FACT_KEYS or value is None:
                continue
            grouped[(item.kind, key)][_fact_text(value)].append(item)
    conflicts: list[EvidenceConflict] = []
    for (kind, key), values in sorted(
        grouped.items(),
        key=lambda item: (item[0][0].value, item[0][1]),
    ):
        if len(values) < 2:
            continue
        cited = {item.evidence_id: item for group in values.values() for item in group}
        conflicts.append(
            EvidenceConflict(
                conflict_id=stable_id("conflict", kind.value, key, *sorted(values)),
                fact_key=key,
                values=tuple(sorted(values)),
                citations=tuple(
                    _citation(cited[evidence_id]) for evidence_id in sorted(cited)
                ),
            )
        )
    return tuple(conflicts)


def _citation(item: Evidence) -> Citation:
    return Citation(
        evidence_id=item.evidence_id,
        locator=item.locator,
        content_hash=item.content_hash,
        provenance_digest=item.provenance_digest,
        source_id=item.source_id,
        query_id=item.query_id,
        page_number=item.page_number,
    )


def _fact_text(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return format(value, ".12g")
    return str(value)[:512]
