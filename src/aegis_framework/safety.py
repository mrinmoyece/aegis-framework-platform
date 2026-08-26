"""Evidence minimization, citation validation, and telemetry redaction."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from hashlib import sha256
from typing import Any

from aegis_framework.domain import Citation, Evidence, EvidenceKind, ModelEvidence

_INJECTION_PATTERNS = (
    re.compile(
        r"\bignore (?:all |any )?(?:prior|previous|system) instructions?\b", re.I
    ),
    re.compile(r"\bsystem prompt\b", re.I),
    re.compile(r"\bdeveloper message\b", re.I),
    re.compile(r"\btool call\b", re.I),
    re.compile(r"\bexfiltrat(?:e|ion)\b", re.I),
)

_ALLOWED_FACTS: dict[EvidenceKind, frozenset[str]] = {
    EvidenceKind.TELEMETRY: frozenset(
        {
            "metric",
            "value",
            "baseline",
            "threshold",
            "region",
            "error_code",
            "sample_count",
            "count",
            "involved_kind",
            "involved_name",
            "namespace",
            "reason",
            "timestamp",
            "type",
        }
    ),
    EvidenceKind.CHANGE: frozenset(
        {
            "service",
            "version",
            "minutes_before_alert",
            "change_id",
            "deployment",
            "environment",
            "sha",
            "status",
            "timestamp",
        }
    ),
    EvidenceKind.RUNBOOK: frozenset(
        {"action", "condition", "owner", "service", "title", "version"}
    ),
}

_SENSITIVE_KEY_PARTS = frozenset(
    {
        "authorization",
        "cookie",
        "credential",
        "evidence",
        "password",
        "prompt",
        "raw",
        "secret",
        "token",
        "untrusted",
    }
)

_SAFE_OBSERVABILITY_KEYS = frozenset(
    {
        "operation",
        "status",
        "scenario",
        "evidence_count",
        "finding_count",
        "citation_count",
        "injection_detected",
        "replayed",
        "error_code",
        "connector_kind",
        "page_count",
        "record_count",
        "quarantined_count",
        "rate_limited",
        "reconciliation_required",
        "stale_result",
        "node",
        "role",
        "artifact_count",
        "critic_decision",
        "action_kind",
        "approval_status",
        "effect_outcome",
        "verification_status",
        "rollback",
    }
)
_SAFE_AUDIT_KEYS = frozenset(
    {
        "approval_required",
        "attempt",
        "citation_count",
        "error_code",
        "evidence_count",
        "policy_id",
        "policy_revision",
        "reason",
        "request_ref",
    }
)


def contains_prompt_injection(evidence: Evidence) -> bool:
    material = "\n".join(
        (
            *(
                text
                for text in (evidence.summary, evidence.untrusted_text)
                if text is not None
            ),
            *(value for value in evidence.facts.values() if isinstance(value, str)),
        )
    )
    return any(pattern.search(material) is not None for pattern in _INJECTION_PATTERNS)


def prepare_model_evidence(
    evidence: Sequence[Evidence],
) -> tuple[tuple[ModelEvidence, ...], bool]:
    """Project untrusted evidence into a narrow, instruction-free model view."""

    injection_detected = False
    projected: list[ModelEvidence] = []
    for item in sorted(evidence, key=lambda candidate: candidate.evidence_id):
        injection_detected = injection_detected or contains_prompt_injection(item)
        allowed = _ALLOWED_FACTS[item.kind]
        safe_facts = {
            key: item.facts[key] for key in sorted(item.facts) if key in allowed
        }
        projected.append(
            ModelEvidence(
                evidence_id=item.evidence_id,
                kind=item.kind,
                locator=item.locator,
                content_hash=item.content_hash,
                facts=safe_facts,
                provenance_digest=item.provenance_digest,
                source_id=item.source_id,
                query_id=item.query_id,
                page_number=item.page_number,
            )
        )
    return tuple(projected), injection_detected


def citation_is_valid(citation: Citation, evidence: Sequence[Evidence]) -> bool:
    expected = {item.evidence_id: item for item in evidence}.get(citation.evidence_id)
    return (
        expected is not None
        and citation.locator == expected.locator
        and citation.content_hash == expected.content_hash
        and citation.provenance_digest == expected.provenance_digest
        and citation.source_id == expected.source_id
        and citation.query_id == expected.query_id
        and citation.page_number == expected.page_number
    )


def tenant_bucket(tenant_id: str, buckets: int = 64) -> str:
    value = int(sha256(tenant_id.encode()).hexdigest()[:8], 16) % buckets
    return f"{value:02d}"


def redact_value(value: Any) -> Any:
    """Recursively redact sensitive keys for local tests and explicit exporters."""

    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, child in value.items():
            normalized = str(key).lower()
            if any(part in normalized for part in _SENSITIVE_KEY_PARTS):
                redacted[str(key)] = "[REDACTED]"
            else:
                redacted[str(key)] = redact_value(child)
        return redacted
    if isinstance(value, (list, tuple)):
        return [redact_value(child) for child in value]
    return value


def safe_observability_attributes(
    attributes: Mapping[str, str | int | bool],
) -> dict[str, str | int | bool]:
    return {
        key: value
        for key, value in attributes.items()
        if key in _SAFE_OBSERVABILITY_KEYS
    }


def safe_audit_attributes(
    attributes: Mapping[str, str | int | bool],
) -> dict[str, str | int | bool]:
    safe: dict[str, str | int | bool] = {}
    for key, value in attributes.items():
        if key not in _SAFE_AUDIT_KEYS:
            continue
        if isinstance(value, str):
            safe[key] = value[:128]
        else:
            safe[key] = value
    return dict(sorted(safe.items()))
