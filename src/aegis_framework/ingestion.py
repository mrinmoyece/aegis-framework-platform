"""Bounded evidence canonicalization, scanning, redaction, and quarantine."""

from __future__ import annotations

import io
import json
import re
import unicodedata
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol

import yaml  # type: ignore[import-untyped]
from pydantic import JsonValue

from aegis_framework.domain import stable_id
from aegis_framework.errors import ConnectorRejected
from aegis_framework.evidence import (
    ConnectorRecord,
    DataClassification,
    EvidenceDisposition,
    EvidenceProvenance,
    EvidenceQuery,
    EvidenceSourceKind,
    NormalizedEvidence,
    QuarantineReason,
    ScannerFinding,
)

_SECRET_PATTERNS = (
    (
        "private-key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.I),
    ),
    ("github-token", re.compile(r"\b(?:gh[opsu]_[A-Za-z0-9]{20,255})\b")),
    (
        "cloud-access-key",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ),
    (
        "credential-assignment",
        re.compile(r"(?i)\b(?:api[_-]?key|password|secret|token)\s*[:=]\s*[^\s,;]{8,}"),
    ),
)
_PII_PATTERNS = (
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "ipv4",
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    ),
)
_INJECTION_PATTERNS = (
    (
        "ignore-instructions",
        re.compile(
            r"\bignore (?:all |any )?(?:prior|previous|system) instructions?\b",
            re.I,
        ),
    ),
    ("system-prompt", re.compile(r"\bsystem prompt\b", re.I)),
    ("developer-message", re.compile(r"\bdeveloper message\b", re.I)),
    ("tool-invocation", re.compile(r"\b(?:call|invoke|execute) (?:the )?tool\b", re.I)),
    ("data-exfiltration", re.compile(r"\bexfiltrat(?:e|ion)\b", re.I)),
)
_ALLOWED_FACTS: dict[EvidenceSourceKind, frozenset[str]] = {
    EvidenceSourceKind.DYNATRACE: frozenset(
        {
            "baseline",
            "error_code",
            "metric",
            "region",
            "sample_count",
            "threshold",
            "timestamp",
            "value",
        }
    ),
    EvidenceSourceKind.GITHUB: frozenset(
        {
            "change_id",
            "deployment",
            "environment",
            "minutes_before_alert",
            "service",
            "sha",
            "status",
            "timestamp",
            "version",
        }
    ),
    EvidenceSourceKind.KUBERNETES: frozenset(
        {
            "count",
            "involved_kind",
            "involved_name",
            "namespace",
            "reason",
            "timestamp",
            "type",
        }
    ),
    EvidenceSourceKind.RUNBOOK: frozenset(
        {"action", "condition", "owner", "service", "title", "version"}
    ),
}
_ACTIVE_EXTENSIONS = frozenset(
    {
        ".bat",
        ".cmd",
        ".com",
        ".exe",
        ".html",
        ".htm",
        ".js",
        ".msi",
        ".ps1",
        ".sh",
        ".svg",
        ".vbs",
    }
)
_TEXT_TYPES = frozenset(
    {
        "application/json",
        "application/yaml",
        "application/x-yaml",
        "text/markdown",
        "text/plain",
    }
)


class ContentScanner(Protocol):
    def scan(self, text: str) -> Sequence[ScannerFinding]: ...


class DuplicateIndex(Protocol):
    def find(
        self,
        *,
        tenant_id: str,
        incident_id: str,
        content_hash: str,
    ) -> str | None: ...

    def remember(
        self,
        *,
        tenant_id: str,
        incident_id: str,
        content_hash: str,
        evidence_id: str,
    ) -> None: ...


class InMemoryDuplicateIndex:
    def __init__(self) -> None:
        self._items: dict[tuple[str, str, str], str] = {}

    def find(
        self,
        *,
        tenant_id: str,
        incident_id: str,
        content_hash: str,
    ) -> str | None:
        return self._items.get((tenant_id, incident_id, content_hash))

    def remember(
        self,
        *,
        tenant_id: str,
        incident_id: str,
        content_hash: str,
        evidence_id: str,
    ) -> None:
        self._items.setdefault(
            (tenant_id, incident_id, content_hash),
            evidence_id,
        )


@dataclass(frozen=True)
class IngestionPolicy:
    retention_ref: str
    allowed_classifications: frozenset[DataClassification]
    maximum_text_chars: int = 65_536
    maximum_archive_members: int = 50
    maximum_archive_uncompressed_bytes: int = 4 * 1024 * 1024
    maximum_yaml_nodes: int = 2_000
    quarantine_injection: bool = True

    def __post_init__(self) -> None:
        if not self.retention_ref or len(self.retention_ref) > 128:
            raise ValueError("retention reference is invalid")
        if (
            self.maximum_text_chars < 1_024
            or self.maximum_text_chars > 65_536
            or self.maximum_archive_members < 1
            or self.maximum_archive_members > 100
            or self.maximum_archive_uncompressed_bytes < 1_024
            or self.maximum_archive_uncompressed_bytes > 16 * 1024 * 1024
            or self.maximum_yaml_nodes < 10
            or self.maximum_yaml_nodes > 10_000
        ):
            raise ValueError("ingestion bounds are invalid")


class EvidenceIngestor:
    def __init__(
        self,
        *,
        policy: IngestionPolicy,
        duplicates: DuplicateIndex,
        scanners: Sequence[ContentScanner] = (),
    ) -> None:
        self._policy = policy
        self._duplicates = duplicates
        self._scanners = tuple(scanners)

    def ingest_page(
        self,
        query: EvidenceQuery,
        records: Sequence[ConnectorRecord],
        *,
        page_number: int,
        retrieved_at: object,
    ) -> tuple[NormalizedEvidence, ...]:
        from datetime import datetime

        if not isinstance(retrieved_at, datetime) or retrieved_at.tzinfo is None:
            raise ValueError("ingestion retrieval time must be timezone-aware")
        return tuple(
            self.ingest(
                query,
                record,
                page_number=page_number,
                retrieved_at=retrieved_at,
            )
            for record in sorted(records, key=lambda item: item.record_id)
        )

    def ingest(
        self,
        query: EvidenceQuery,
        record: ConnectorRecord,
        *,
        page_number: int,
        retrieved_at: object,
    ) -> NormalizedEvidence:
        from datetime import datetime

        if not isinstance(retrieved_at, datetime) or retrieved_at.tzinfo is None:
            raise ValueError("ingestion retrieval time must be timezone-aware")
        raw_hash = sha256(record.payload).hexdigest()
        evidence_id = stable_id(
            "evidence",
            query.tenant_id,
            query.incident_id,
            query.source.source_id,
            raw_hash,
        )
        quarantine: QuarantineReason | None = None
        try:
            text, value = self._parse(record)
        except _Quarantine as exc:
            quarantine = exc.reason
            text = ""
            value = {}

        findings: list[ScannerFinding] = []
        redaction_count = 0
        if quarantine is None:
            text = _canonical_text(text, maximum_chars=self._policy.maximum_text_chars)
            text, secret_findings, secret_redactions = _scan_and_redact(
                text,
                _SECRET_PATTERNS,
                scanner="aegis-secret-v1",
                severity="blocking",
            )
            findings.extend(secret_findings)
            redaction_count += secret_redactions
            text, pii_findings, pii_redactions = _scan_and_redact(
                text,
                _PII_PATTERNS,
                scanner="aegis-pii-v1",
                severity="warning",
            )
            findings.extend(pii_findings)
            redaction_count += pii_redactions
            injection_findings = _scan(
                text,
                _INJECTION_PATTERNS,
                scanner="aegis-injection-v1",
                severity="blocking",
            )
            findings.extend(injection_findings)
            for scanner in self._scanners:
                findings.extend(scanner.scan(text))
            if secret_findings:
                quarantine = QuarantineReason.SECRET
            elif injection_findings and self._policy.quarantine_injection:
                quarantine = QuarantineReason.PROMPT_INJECTION
            elif any(item.severity == "blocking" for item in findings):
                quarantine = QuarantineReason.SCANNER_REJECTED
            elif (
                query.source.classification not in self._policy.allowed_classifications
            ):
                quarantine = QuarantineReason.CLASSIFICATION

        if quarantine is not None:
            text = ""
        content_hash = sha256(text.encode()).hexdigest()
        duplicate_of = None
        if quarantine is None:
            duplicate_of = self._duplicates.find(
                tenant_id=query.tenant_id,
                incident_id=query.incident_id,
                content_hash=content_hash,
            )
        if quarantine is not None:
            disposition = EvidenceDisposition.QUARANTINED
        elif duplicate_of is not None:
            disposition = EvidenceDisposition.DUPLICATE
        elif redaction_count:
            disposition = EvidenceDisposition.REDACTED
        else:
            disposition = EvidenceDisposition.ACCEPTED
        provenance = EvidenceProvenance(
            tenant_id=query.tenant_id,
            incident_id=query.incident_id,
            run_id=query.run_id,
            source_id=query.source.source_id,
            source_kind=query.source.kind,
            source_trust=query.source.trust,
            source_digest=query.source.digest,
            query_id=query.query_id,
            query_digest=query.digest,
            page_number=page_number,
            locator=record.locator,
            observed_at=record.observed_at,
            retrieved_at=retrieved_at,
            credential_version=query.source.credential_version,
            policy_revision=query.source.policy_revision,
            classification=query.source.classification,
            retention_ref=self._policy.retention_ref,
            raw_content_hash=raw_hash,
        )
        facts = (
            {}
            if quarantine is not None
            else _project_redacted_facts(query.source.kind, text, value)
        )
        result = NormalizedEvidence(
            evidence_id=evidence_id,
            tenant_id=query.tenant_id,
            incident_id=query.incident_id,
            kind=query.source.kind,
            summary=_summary(text, query.source.kind, disposition),
            facts=facts,
            canonical_text=text,
            content_hash=content_hash,
            provenance=provenance,
            disposition=disposition,
            redaction_count=redaction_count,
            scanner_findings=tuple(
                sorted(
                    findings,
                    key=lambda item: (item.scanner, item.rule_id, item.severity),
                )
            ),
            quarantine_reason=quarantine,
            duplicate_of=duplicate_of,
        )
        if disposition in {
            EvidenceDisposition.ACCEPTED,
            EvidenceDisposition.REDACTED,
        }:
            self._duplicates.remember(
                tenant_id=query.tenant_id,
                incident_id=query.incident_id,
                content_hash=content_hash,
                evidence_id=evidence_id,
            )
        return result

    def _parse(self, record: ConnectorRecord) -> tuple[str, JsonValue]:
        content_type = record.content_type.lower().split(";", maxsplit=1)[0].strip()
        if content_type == "application/zip":
            return self._parse_archive(record.payload)
        if content_type not in _TEXT_TYPES:
            raise _Quarantine(QuarantineReason.CONTENT_TYPE)
        try:
            text = record.payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise _Quarantine(QuarantineReason.MALFORMED) from exc
        if content_type == "application/json":
            try:
                value = json.loads(text)
            except (json.JSONDecodeError, RecursionError, ValueError) as exc:
                raise _Quarantine(QuarantineReason.MALFORMED) from exc
            _bound_structure(value, maximum_nodes=self._policy.maximum_yaml_nodes)
            return json.dumps(
                value,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ), value
        if content_type in {"application/yaml", "application/x-yaml"}:
            try:
                value = yaml.safe_load(text)
                _bound_structure(value, maximum_nodes=self._policy.maximum_yaml_nodes)
                normalized = json.dumps(
                    value,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            except (RecursionError, TypeError, ValueError, yaml.YAMLError) as exc:
                raise _Quarantine(QuarantineReason.MALFORMED) from exc
            return normalized, value
        return text, {}

    def _parse_archive(self, payload: bytes) -> tuple[str, JsonValue]:
        try:
            archive = zipfile.ZipFile(io.BytesIO(payload))
        except (zipfile.BadZipFile, OSError) as exc:
            raise _Quarantine(QuarantineReason.MALFORMED) from exc
        members = archive.infolist()
        if not members or len(members) > self._policy.maximum_archive_members:
            raise _Quarantine(QuarantineReason.ARCHIVE_BOUNDS)
        total = 0
        texts: list[str] = []
        for member in sorted(members, key=lambda item: item.filename):
            name = member.filename.replace("\\", "/")
            suffix = (
                "." + name.rsplit(".", maxsplit=1)[-1].lower() if "." in name else ""
            )
            if (
                member.is_dir()
                or name.startswith("/")
                or ".." in name.split("/")
                or suffix in _ACTIVE_EXTENSIONS
                or suffix not in {".json", ".md", ".txt", ".yaml", ".yml"}
                or (member.compress_size == 0 and member.file_size > 0)
            ):
                raise _Quarantine(QuarantineReason.ACTIVE_CONTENT)
            total += member.file_size
            if total > self._policy.maximum_archive_uncompressed_bytes:
                raise _Quarantine(QuarantineReason.ARCHIVE_BOUNDS)
            ratio = member.file_size / max(member.compress_size, 1)
            if ratio > 100:
                raise _Quarantine(QuarantineReason.ARCHIVE_BOUNDS)
            with archive.open(member, "r") as stream:
                content = stream.read(member.file_size + 1)
            if len(content) != member.file_size:
                raise _Quarantine(QuarantineReason.ARCHIVE_BOUNDS)
            try:
                texts.append(f"--- {name} ---\n{content.decode('utf-8')}")
            except UnicodeDecodeError as exc:
                raise _Quarantine(QuarantineReason.MALFORMED) from exc
        return "\n".join(texts), {}


class _Quarantine(Exception):
    def __init__(self, reason: QuarantineReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


def _canonical_text(value: str, *, maximum_chars: int) -> str:
    normalized = unicodedata.normalize("NFC", value)
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
    normalized = "".join(
        character
        for character in normalized
        if character in "\n\t" or ord(character) >= 32
    )
    normalized = "\n".join(line.rstrip() for line in normalized.splitlines()).strip()
    if len(normalized) > maximum_chars:
        raise ConnectorRejected("canonical evidence exceeds the text bound")
    return normalized


def _scan_and_redact(
    text: str,
    patterns: Sequence[tuple[str, re.Pattern[str]]],
    *,
    scanner: str,
    severity: str,
) -> tuple[str, list[ScannerFinding], int]:
    findings: list[ScannerFinding] = []
    count = 0
    redacted = text
    for rule_id, pattern in patterns:
        matches = len(pattern.findall(redacted))
        if matches:
            findings.append(
                ScannerFinding(
                    scanner=scanner,
                    rule_id=rule_id,
                    severity=severity,
                    count=matches,
                )
            )
            redacted, observed = pattern.subn("[REDACTED]", redacted)
            count += observed
    return redacted, findings, count


def _scan(
    text: str,
    patterns: Sequence[tuple[str, re.Pattern[str]]],
    *,
    scanner: str,
    severity: str,
) -> list[ScannerFinding]:
    findings: list[ScannerFinding] = []
    for rule_id, pattern in patterns:
        count = len(pattern.findall(text))
        if count:
            findings.append(
                ScannerFinding(
                    scanner=scanner,
                    rule_id=rule_id,
                    severity=severity,
                    count=count,
                )
            )
    return findings


def _bound_structure(value: object, *, maximum_nodes: int) -> None:
    seen: set[int] = set()
    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > maximum_nodes or depth > 32:
            raise _Quarantine(QuarantineReason.SIZE)
        if isinstance(item, Mapping):
            identity = id(item)
            if identity in seen:
                raise _Quarantine(QuarantineReason.MALFORMED)
            seen.add(identity)
            if len(item) > 256:
                raise _Quarantine(QuarantineReason.SIZE)
            if any(
                not isinstance(key, str) or not key or len(key) > 512 for key in item
            ):
                raise _Quarantine(QuarantineReason.MALFORMED)
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, (list, tuple)):
            identity = id(item)
            if identity in seen:
                raise _Quarantine(QuarantineReason.MALFORMED)
            seen.add(identity)
            if len(item) > 1_000:
                raise _Quarantine(QuarantineReason.SIZE)
            stack.extend((child, depth + 1) for child in item)
        elif not isinstance(item, (str, int, float, bool, type(None))):
            raise _Quarantine(QuarantineReason.MALFORMED)


def _project_facts(
    kind: EvidenceSourceKind,
    value: JsonValue,
) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        return {}
    allowed = _ALLOWED_FACTS[kind]
    return {
        str(key): child
        for key, child in sorted(value.items())
        if key in allowed
        and isinstance(child, (str, int, float, bool, type(None)))
        and (not isinstance(child, str) or len(child) <= 512)
    }


def _project_redacted_facts(
    kind: EvidenceSourceKind,
    text: str,
    original: JsonValue,
) -> dict[str, JsonValue]:
    if not isinstance(original, dict) or not original:
        return {}
    try:
        redacted = json.loads(text)
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ConnectorRejected(
            "redacted evidence could not be projected safely"
        ) from exc
    return _project_facts(kind, redacted)


def _summary(
    text: str,
    kind: EvidenceSourceKind,
    disposition: EvidenceDisposition,
) -> str:
    if disposition is EvidenceDisposition.QUARANTINED:
        return f"{kind.value} evidence quarantined by ingestion policy."
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    if not first:
        return f"{kind.value} evidence contained no descriptive text."
    return first[:512]
