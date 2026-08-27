"""Immutable Layer 8 sandbox contracts, policy, ledger, claims, and control service."""

from __future__ import annotations

import ipaddress
import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from datetime import datetime
from enum import StrEnum
from hashlib import sha256
from threading import Lock
from typing import Annotated, Literal, Protocol
from urllib.parse import urlsplit

from pydantic import AwareDatetime, Field, JsonValue, field_validator, model_validator

from aegis_framework.domain import (
    Identifier,
    IdentityContext,
    RiskLevel,
    Sha256Digest,
    StrictModel,
    stable_id,
)
from aegis_framework.errors import (
    ConcurrencyConflict,
    IdempotencyConflict,
    IntegrityFailure,
    PolicyDenied,
    SandboxRejected,
)
from aegis_framework.ports import Action, ClockPort, PolicyPort

_MAX_FACTS = 512
_OCI_IMAGE = re.compile(
    r"^(?P<registry>[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?)/"
    r"[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[a-f0-9]{64}$"
)
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_SECRET_NAME = re.compile(
    r"(?:TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|CREDENTIAL)", re.I
)
_SECRET_VALUE = re.compile(
    r"(?:-----BEGIN .*PRIVATE KEY-----|gh[opsu]_[A-Za-z0-9]{20,}|"
    r"(?:AKIA|ASIA)[A-Z0-9]{16}|"
    r"(?:api[_-]?key|password|secret|token)\s*[:=]\s*\S{8,})",
    re.I,
)
_SHELLS = frozenset(
    {
        "ash",
        "bash",
        "busybox",
        "cmd",
        "dash",
        "fish",
        "ksh",
        "powershell",
        "pwsh",
        "sh",
        "zsh",
    }
)
_SHELL_META = re.compile(r"(?:`|\$\(|\${|&&|\|\||[;\r\n\x00])")
_BIDI = frozenset(
    {
        "\u061c",
        "\u200e",
        "\u200f",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
    }
)
_DEVICE_NAMES = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{i}" for i in range(1, 10)),
        *(f"lpt{i}" for i in range(1, 10)),
    }
)


def canonical_digest(
    value: StrictModel | Mapping[str, object] | Sequence[object],
) -> str:
    """Canonical SHA-256 over a strict contract without self-referential digests."""

    if isinstance(value, StrictModel):
        digest_fields = {
            "ArtifactManifest": {"manifest_digest"},
            "ArtifactRecord": {"canonical_digest"},
            "SandboxAttestation": {"attestation_digest"},
            "SandboxExecutionRequest": {"request_digest"},
            "SandboxFact": {"canonical_digest"},
            "SandboxPolicy": {"policy_digest"},
            "SandboxResult": {"result_digest"},
            "SandboxSpec": {"spec_digest"},
        }
        material: object = value.model_dump(
            mode="json",
            exclude=digest_fields.get(type(value).__name__, set()),
        )
    else:
        material = value
    return sha256(
        json.dumps(
            material,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
            default=_canonical_default,
        ).encode()
    ).hexdigest()


def _canonical_default(value: object) -> object:
    if isinstance(value, datetime):
        encoded = value.isoformat()
        return encoded.replace("+00:00", "Z") if encoded.endswith("+00:00") else encoded
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, StrictModel):
        return value.model_dump(mode="json")
    raise TypeError(f"unsupported canonical value: {type(value).__name__}")


def _safe_text(value: str, *, label: str, maximum: int) -> str:
    if not value or len(value) > maximum:
        raise ValueError(f"{label} is outside its length bound")
    normalized = unicodedata.normalize("NFC", value)
    if normalized != value:
        raise ValueError(f"{label} must already be NFC-normalized")
    if any(
        character in _BIDI or unicodedata.category(character) in {"Cc", "Cf", "Cs"}
        for character in value
    ):
        raise ValueError(f"{label} contains control or bidirectional characters")
    return value


def validate_relative_path(value: str) -> str:
    """Validate a portable logical path; backends choose their own fixed root."""

    _safe_text(value, label="path", maximum=512)
    if (
        value.startswith(("/", "\\"))
        or "\\" in value
        or "//" in value
        or value.endswith("/")
    ):
        raise ValueError("path must be a normalized relative POSIX path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("path traversal is prohibited")
    if any(
        part.rstrip(" .").split(".", maxsplit=1)[0].lower() in _DEVICE_NAMES
        for part in parts
    ):
        raise ValueError("device paths are prohibited")
    if any(part != part.rstrip(" .") for part in parts):
        raise ValueError("ambiguous path suffix is prohibited")
    return value


class SandboxPurpose(StrEnum):
    ANALYSIS = "analysis"
    TESTING = "testing"
    PATCH_PREPARATION = "patch_preparation"


class NetworkMode(StrEnum):
    NONE = "none"
    EXACT_DESTINATIONS = "exact_destinations"


class SandboxOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    OOM_KILLED = "oom_killed"
    VIOLATION = "violation"
    CANCELLED = "cancelled"


class ArtifactDisposition(StrEnum):
    ACCEPTED = "accepted"
    REDACTED = "redacted"
    QUARANTINED = "quarantined"


class BackendObservationState(StrEnum):
    ABSENT = "absent"
    PROVISIONING = "provisioning"
    RUNNING = "running"
    TERMINAL = "terminal"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"


class SandboxStatus(StrEnum):
    REQUESTED = "requested"
    POLICY_APPROVED = "policy_approved"
    CLAIMED = "claimed"
    PROVISIONING = "provisioning"
    RUNNING = "running"
    CAPTURING = "capturing"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    OOM_KILLED = "oom_killed"
    VIOLATION = "violation"
    CANCELLED = "cancelled"
    ATTESTED = "attested"
    CLEANING = "cleaning"
    CLEANED = "cleaned"
    QUARANTINED = "quarantined"
    RECONCILING = "reconciling"


class ContentInput(StrictModel):
    tenant_id: Identifier
    logical_path: str
    content_hash: Sha256Digest
    size_bytes: int = Field(ge=0, le=64 * 1024 * 1024)
    media_type: Annotated[str, Field(min_length=3, max_length=128)]
    object_ref: Identifier

    @field_validator("logical_path")
    @classmethod
    def safe_path(cls, value: str) -> str:
        return validate_relative_path(value)


class MountReference(StrictModel):
    source_ref: Identifier
    target_path: str
    read_only: Literal[True] = True

    @field_validator("target_path")
    @classmethod
    def safe_path(cls, value: str) -> str:
        return validate_relative_path(value)


class SecretReference(StrictModel):
    reference: Identifier
    version: int = Field(ge=1)
    env_name: str

    @field_validator("env_name")
    @classmethod
    def safe_env_name(cls, value: str) -> str:
        if _ENV_NAME.fullmatch(value) is None:
            raise ValueError("secret environment name is invalid")
        return value


class EnvironmentVariable(StrictModel):
    name: str
    value: Annotated[str, Field(max_length=2_048)]

    @field_validator("name")
    @classmethod
    def safe_name(cls, value: str) -> str:
        if _ENV_NAME.fullmatch(value) is None:
            raise ValueError("environment variable name is invalid")
        if _SECRET_NAME.search(value):
            raise ValueError("secret-like environment names require a secret reference")
        return value

    @field_validator("value")
    @classmethod
    def safe_value(cls, value: str) -> str:
        _safe_text(value or "x", label="environment value", maximum=2_048)
        if _SECRET_VALUE.search(value):
            raise ValueError("secret literals are prohibited")
        return value


class EgressDestination(StrictModel):
    scheme: Literal["https"] = "https"
    host: str
    port: Literal[443] = 443

    @field_validator("host")
    @classmethod
    def exact_public_dns_name(cls, value: str) -> str:
        _safe_text(value, label="egress host", maximum=253)
        lowered = value.lower()
        if value != lowered or lowered.endswith(".") or "*" in lowered:
            raise ValueError("egress host must be an exact lowercase DNS name")
        try:
            ipaddress.ip_address(lowered)
        except ValueError:
            pass
        else:
            raise ValueError("literal IP egress destinations are prohibited")
        if (
            "." not in lowered
            or lowered == "localhost"
            or lowered.endswith((".local", ".internal", ".localhost"))
            or any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or re.fullmatch(r"[a-z0-9-]+", label) is None
                for label in lowered.split(".")
            )
        ):
            raise ValueError("egress host is not a public exact DNS name")
        return lowered


class SandboxNetworkPolicy(StrictModel):
    mode: NetworkMode = NetworkMode.NONE
    destinations: tuple[EgressDestination, ...] = Field(default=(), max_length=16)
    enforcement: Literal[
        "kubernetes-network-policy", "external-egress-proxy-required"
    ] = "kubernetes-network-policy"

    @model_validator(mode="after")
    def bind_destinations(self) -> SandboxNetworkPolicy:
        if self.mode is NetworkMode.NONE and self.destinations:
            raise ValueError("network-none policy cannot carry destinations")
        if self.mode is NetworkMode.EXACT_DESTINATIONS and not self.destinations:
            raise ValueError("exact-destination policy requires destinations")
        if len(set(self.destinations)) != len(self.destinations):
            raise ValueError("duplicate egress destinations are prohibited")
        return self


class SandboxResources(StrictModel):
    cpu_millicores: int = Field(ge=50, le=8_000)
    memory_mib: int = Field(ge=64, le=32_768)
    pid_limit: int = Field(ge=16, le=1_024)
    ephemeral_storage_mib: int = Field(ge=64, le=32_768)
    timeout_seconds: int = Field(ge=1, le=3_600)
    output_bytes: int = Field(ge=1_024, le=64 * 1024 * 1024)
    output_files: int = Field(ge=1, le=1_000)
    output_file_bytes: int = Field(ge=1, le=16 * 1024 * 1024)

    @model_validator(mode="after")
    def bind_output_bounds(self) -> SandboxResources:
        if self.output_file_bytes > self.output_bytes:
            raise ValueError("single output bound exceeds total output bound")
        return self


class SandboxSecurityContext(StrictModel):
    run_as_user: int = Field(ge=10_000, le=65_535)
    run_as_group: int = Field(ge=10_000, le=65_535)
    fs_group: int = Field(ge=10_000, le=65_535)
    run_as_non_root: Literal[True] = True
    read_only_root_filesystem: Literal[True] = True
    allow_privilege_escalation: Literal[False] = False
    privileged: Literal[False] = False
    capabilities_drop: tuple[Literal["ALL"], ...] = ("ALL",)
    seccomp_profile: Literal["RuntimeDefault"] = "RuntimeDefault"
    apparmor_profile: Identifier
    no_new_privileges: Literal[True] = True
    host_network: Literal[False] = False
    host_pid: Literal[False] = False
    host_ipc: Literal[False] = False
    automount_service_account_token: Literal[False] = False

    @model_validator(mode="after")
    def exact_capability_set(self) -> SandboxSecurityContext:
        if self.capabilities_drop != ("ALL",):
            raise ValueError("sandbox must drop all Linux capabilities")
        return self


class OutputExpectation(StrictModel):
    logical_path: str
    media_types: tuple[str, ...] = Field(min_length=1, max_length=8)
    required: bool = True

    @field_validator("logical_path")
    @classmethod
    def safe_path(cls, value: str) -> str:
        return validate_relative_path(value)

    @field_validator("media_types")
    @classmethod
    def safe_media_types(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(
            not item or len(item) > 128 or item != item.lower() or "/" not in item
            for item in value
        ):
            raise ValueError("output media type allowlist is invalid")
        return tuple(sorted(set(value)))


class RetryAndCleanup(StrictModel):
    retry_owner: Literal["temporal"] = "temporal"
    maximum_attempts: int = Field(ge=1, le=5)
    observe_before_create: Literal[True] = True
    stale_attempt_fencing: Literal[True] = True
    cleanup_required: Literal[True] = True
    cleanup_timeout_seconds: int = Field(ge=10, le=900)
    retain_failed_seconds: int = Field(ge=0, le=86_400)


class SandboxApprovalBinding(StrictModel):
    tenant_id: Identifier
    run_id: Identifier
    task_id: Identifier
    remediation_plan_id: Identifier
    remediation_action_id: Identifier
    remediation_plan_digest: Sha256Digest
    remediation_action_digest: Sha256Digest
    approval_id: Identifier
    approval_digest: Sha256Digest
    approval_policy_digest: Sha256Digest
    approval_expires_at: AwareDatetime


class SandboxSpec(StrictModel):
    schema_version: Literal[1] = 1
    spec_version: Identifier
    tenant_id: Identifier
    run_id: Identifier
    task_id: Identifier
    purpose: SandboxPurpose
    risk: RiskLevel
    approval: SandboxApprovalBinding
    image: str
    argv: tuple[str, ...] = Field(min_length=1, max_length=64)
    working_directory: Literal["workspace"] = "workspace"
    inputs: tuple[ContentInput, ...] = Field(default=(), max_length=256)
    mounts: tuple[MountReference, ...] = Field(default=(), max_length=32)
    environment: tuple[EnvironmentVariable, ...] = Field(default=(), max_length=64)
    secrets: tuple[SecretReference, ...] = Field(default=(), max_length=16)
    network: SandboxNetworkPolicy = Field(default_factory=SandboxNetworkPolicy)
    resources: SandboxResources
    security: SandboxSecurityContext
    required_runtime_class: Identifier
    required_admission_policies: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=16,
    )
    expected_outputs: tuple[OutputExpectation, ...] = Field(
        min_length=1,
        max_length=64,
    )
    retry: RetryAndCleanup
    spec_digest: Sha256Digest

    @field_validator("image")
    @classmethod
    def immutable_image(cls, value: str) -> str:
        if _OCI_IMAGE.fullmatch(value) is None:
            raise ValueError("image must use an immutable OCI sha256 digest")
        return value

    @field_validator("argv")
    @classmethod
    def argv_tokens_only(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for token in value:
            _safe_text(token, label="argv token", maximum=4_096)
            if _SHELL_META.search(token):
                raise ValueError("shell syntax and interpolation are prohibited")
        executable = value[0].rsplit("/", maxsplit=1)[-1].lower()
        if executable in _SHELLS:
            raise ValueError("shell executables are prohibited")
        if any(
            token in {"-c", "/c", "-command", "-encodedcommand"} for token in value[1:]
        ):
            raise ValueError("command-string interpreter flags are prohibited")
        return value

    @model_validator(mode="after")
    def exact_bindings_and_uniqueness(self) -> SandboxSpec:
        if (
            self.approval.tenant_id != self.tenant_id
            or self.approval.run_id != self.run_id
            or self.approval.task_id != self.task_id
        ):
            raise ValueError("sandbox approval scope does not match the spec")
        paths = [
            *(item.logical_path for item in self.inputs),
            *(item.target_path for item in self.mounts),
            *(item.logical_path for item in self.expected_outputs),
        ]
        if len(paths) != len(set(paths)):
            raise ValueError("duplicate or conflicting sandbox paths are prohibited")
        env_names = [
            *(item.name for item in self.environment),
            *(item.env_name for item in self.secrets),
        ]
        if len(env_names) != len(set(env_names)):
            raise ValueError("duplicate environment bindings are prohibited")
        if any(item.tenant_id != self.tenant_id for item in self.inputs):
            raise ValueError("sandbox input tenant mismatch")
        if len(set(self.required_admission_policies)) != len(
            self.required_admission_policies
        ):
            raise ValueError("duplicate admission policy requirements are prohibited")
        if sum(item.size_bytes for item in self.inputs) > 128 * 1024 * 1024:
            raise ValueError("sandbox inputs exceed the total byte bound")
        if self.spec_digest != canonical_digest(self):
            raise ValueError("sandbox spec digest mismatch")
        return self


class SandboxExecutionRequest(StrictModel):
    schema_version: Literal[1] = 1
    execution_id: Identifier
    tenant_id: Identifier
    run_id: Identifier
    task_id: Identifier
    spec: SandboxSpec
    spec_digest: Sha256Digest
    policy_digest: Sha256Digest
    approval_digest: Sha256Digest
    idempotency_key: Identifier
    attempt: int = Field(ge=1, le=16)
    fence_token: Identifier
    requested_at: AwareDatetime
    request_digest: Sha256Digest

    @model_validator(mode="after")
    def exact_binding(self) -> SandboxExecutionRequest:
        if (
            self.spec.tenant_id != self.tenant_id
            or self.spec.run_id != self.run_id
            or self.spec.task_id != self.task_id
            or self.spec.spec_digest != self.spec_digest
            or self.spec.approval.approval_digest != self.approval_digest
        ):
            raise ValueError("sandbox request binding does not match its spec")
        if self.request_digest != canonical_digest(self):
            raise ValueError("sandbox request digest mismatch")
        return self


class BackendObservation(StrictModel):
    execution_id: Identifier
    state: BackendObservationState
    provider_uid: Identifier | None = None
    attempt: int = Field(ge=1, le=16)
    fence_token: Identifier
    observed_at: AwareDatetime


class BackendExecution(StrictModel):
    execution_id: Identifier
    provider_ref: Identifier
    provider_uid: Identifier
    attempt: int = Field(ge=1, le=16)
    fence_token: Identifier
    provisioned_at: AwareDatetime


class ArtifactRecord(StrictModel):
    schema_version: Literal[1] = 1
    artifact_id: Identifier
    tenant_id: Identifier
    run_id: Identifier
    task_id: Identifier
    execution_id: Identifier
    logical_path: str
    media_type: str
    content_hash: Sha256Digest
    size_bytes: int = Field(ge=0, le=16 * 1024 * 1024)
    disposition: ArtifactDisposition
    redaction_count: int = Field(ge=0, le=10_000)
    scanner_codes: tuple[Identifier, ...] = Field(default=(), max_length=32)
    object_ref: Identifier | None = None
    retention_expires_at: AwareDatetime
    canonical_digest: Sha256Digest

    @field_validator("logical_path")
    @classmethod
    def safe_path(cls, value: str) -> str:
        return validate_relative_path(value)

    @model_validator(mode="after")
    def validate_artifact(self) -> ArtifactRecord:
        if self.disposition is ArtifactDisposition.QUARANTINED and self.object_ref:
            raise ValueError("quarantined artifacts cannot expose an object reference")
        if self.canonical_digest != canonical_digest(self):
            raise ValueError("artifact digest mismatch")
        return self


class ArtifactManifest(StrictModel):
    schema_version: Literal[1] = 1
    tenant_id: Identifier
    run_id: Identifier
    task_id: Identifier
    execution_id: Identifier
    artifacts: tuple[ArtifactRecord, ...] = Field(max_length=1_000)
    total_bytes: int = Field(ge=0, le=64 * 1024 * 1024)
    generated_at: AwareDatetime
    manifest_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_manifest(self) -> ArtifactManifest:
        if (
            tuple(sorted(self.artifacts, key=lambda item: item.logical_path))
            != self.artifacts
        ):
            raise ValueError("artifact manifest must be deterministically ordered")
        if self.total_bytes != sum(item.size_bytes for item in self.artifacts):
            raise ValueError("artifact manifest byte count mismatch")
        if any(
            item.tenant_id != self.tenant_id
            or item.run_id != self.run_id
            or item.task_id != self.task_id
            or item.execution_id != self.execution_id
            for item in self.artifacts
        ):
            raise ValueError("artifact manifest scope mismatch")
        if self.manifest_digest != canonical_digest(self):
            raise ValueError("artifact manifest digest mismatch")
        return self


class SandboxResult(StrictModel):
    schema_version: Literal[1] = 1
    tenant_id: Identifier
    run_id: Identifier
    task_id: Identifier
    execution_id: Identifier
    request_digest: Sha256Digest
    spec_digest: Sha256Digest
    policy_digest: Sha256Digest
    approval_digest: Sha256Digest
    provider_uid: Identifier
    attempt: int = Field(ge=1, le=16)
    fence_token: Identifier
    outcome: SandboxOutcome
    exit_code: int | None = Field(default=None, ge=0, le=255)
    output_bytes: int = Field(ge=0, le=64 * 1024 * 1024)
    output_files: int = Field(ge=0, le=1_000)
    started_at: AwareDatetime
    completed_at: AwareDatetime
    detail_code: Identifier
    manifest_digest: Sha256Digest | None = None
    result_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_result(self) -> SandboxResult:
        if self.completed_at < self.started_at:
            raise ValueError("sandbox completion precedes start")
        if self.outcome is SandboxOutcome.SUCCEEDED and self.exit_code != 0:
            raise ValueError("successful sandbox result requires exit code zero")
        if self.result_digest != canonical_digest(self):
            raise ValueError("sandbox result digest mismatch")
        return self


class SandboxAttestation(StrictModel):
    schema_version: Literal[1] = 1
    tenant_id: Identifier
    execution_id: Identifier
    request_digest: Sha256Digest
    result_digest: Sha256Digest
    spec_digest: Sha256Digest
    policy_digest: Sha256Digest
    approval_digest: Sha256Digest
    image_digest: Sha256Digest
    provider_uid: Identifier
    runtime_class: Identifier
    node_attestation_ref: Identifier
    admitted_policy_refs: tuple[Identifier, ...] = Field(min_length=1, max_length=16)
    attested_at: AwareDatetime
    attestation_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_attestation(self) -> SandboxAttestation:
        if self.attestation_digest != canonical_digest(self):
            raise ValueError("sandbox attestation digest mismatch")
        return self


class SandboxPolicy(StrictModel):
    schema_version: Literal[1] = 1
    tenant_id: Identifier
    policy_id: Identifier
    revision: int = Field(ge=1)
    enabled: bool = False
    allowed_image_digests: tuple[Sha256Digest, ...] = ()
    allowed_registries: tuple[str, ...] = ()
    allowed_commands: tuple[str, ...] = ()
    allowed_purposes: tuple[SandboxPurpose, ...] = ()
    allowed_mount_prefixes: tuple[str, ...] = ()
    allowed_secret_refs: tuple[Identifier, ...] = ()
    allowed_egress: tuple[EgressDestination, ...] = ()
    allowed_approval_policy_digests: tuple[Sha256Digest, ...] = ()
    maximum_resources: SandboxResources
    maximum_concurrency: int = Field(ge=0, le=100)
    maximum_lifetime_seconds: int = Field(ge=1, le=3_600)
    maximum_risk: RiskLevel
    require_runtime_class: Identifier
    require_admission_policies: tuple[Identifier, ...] = Field(
        min_length=1, max_length=16
    )
    policy_digest: Sha256Digest

    @field_validator("allowed_mount_prefixes")
    @classmethod
    def safe_prefixes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({validate_relative_path(item) for item in value}))

    @model_validator(mode="after")
    def validate_policy(self) -> SandboxPolicy:
        if self.policy_digest != canonical_digest(self):
            raise ValueError("sandbox policy digest mismatch")
        return self

    def authorize(
        self,
        spec: SandboxSpec,
        *,
        active_executions: int,
        now: datetime,
    ) -> None:
        if not self.enabled or self.tenant_id != spec.tenant_id:
            raise PolicyDenied("sandbox policy is disabled or tenant-mismatched")
        image = _OCI_IMAGE.fullmatch(spec.image)
        if image is None:
            raise PolicyDenied("sandbox image is not immutable")
        image_digest = spec.image.rsplit("@sha256:", maxsplit=1)[1]
        if (
            image_digest not in self.allowed_image_digests
            or image.group("registry") not in self.allowed_registries
            or spec.argv[0] not in self.allowed_commands
            or spec.purpose not in self.allowed_purposes
            or spec.approval.approval_policy_digest
            not in self.allowed_approval_policy_digests
            or spec.required_runtime_class != self.require_runtime_class
            or spec.required_admission_policies != self.require_admission_policies
            or spec.risk.value
            not in {
                RiskLevel.LOW.value,
                *(
                    (RiskLevel.MEDIUM.value,)
                    if self.maximum_risk in {RiskLevel.MEDIUM, RiskLevel.HIGH}
                    else ()
                ),
                *(
                    (RiskLevel.HIGH.value,)
                    if self.maximum_risk is RiskLevel.HIGH
                    else ()
                ),
            }
        ):
            raise PolicyDenied("sandbox request is not allowlisted")
        if now >= spec.approval.approval_expires_at:
            raise PolicyDenied("sandbox approval expired")
        if active_executions >= self.maximum_concurrency:
            raise PolicyDenied("sandbox concurrency quota exhausted")
        if spec.resources.timeout_seconds > self.maximum_lifetime_seconds:
            raise PolicyDenied("sandbox lifetime exceeds policy")
        ceilings = self.maximum_resources
        requested = spec.resources
        if any(
            (
                requested.cpu_millicores > ceilings.cpu_millicores,
                requested.memory_mib > ceilings.memory_mib,
                requested.pid_limit > ceilings.pid_limit,
                requested.ephemeral_storage_mib > ceilings.ephemeral_storage_mib,
                requested.timeout_seconds > ceilings.timeout_seconds,
                requested.output_bytes > ceilings.output_bytes,
                requested.output_files > ceilings.output_files,
                requested.output_file_bytes > ceilings.output_file_bytes,
            )
        ):
            raise PolicyDenied("sandbox resource request exceeds policy")
        if any(
            not any(
                mount.target_path == prefix
                or mount.target_path.startswith(prefix + "/")
                for prefix in self.allowed_mount_prefixes
            )
            for mount in spec.mounts
        ):
            raise PolicyDenied("sandbox mount is not allowlisted")
        if any(
            secret.reference not in self.allowed_secret_refs for secret in spec.secrets
        ):
            raise PolicyDenied("sandbox secret reference is not allowlisted")
        if spec.network.mode is NetworkMode.EXACT_DESTINATIONS and any(
            destination not in self.allowed_egress
            for destination in spec.network.destinations
        ):
            raise PolicyDenied("sandbox egress destination is not allowlisted")


class SandboxFactType(StrEnum):
    REQUEST_RECORDED = "sandbox.request_recorded"
    POLICY_DECIDED = "sandbox.policy_decided"
    APPROVAL_BOUND = "sandbox.approval_bound"
    CLAIMED = "sandbox.claimed"
    PROVISION_REQUESTED = "sandbox.provision_requested"
    PROVISIONED = "sandbox.provisioned"
    STARTED = "sandbox.started"
    OUTPUT_CAPTURE_REQUESTED = "sandbox.output_capture_requested"
    ARTIFACT_RECORDED = "sandbox.artifact_recorded"
    COMPLETED = "sandbox.completed"
    FAILED = "sandbox.failed"
    TIMED_OUT = "sandbox.timed_out"
    OOM_KILLED = "sandbox.oom_killed"
    VIOLATION = "sandbox.violation"
    CANCELLATION_REQUESTED = "sandbox.cancellation_requested"
    CANCELLED = "sandbox.cancelled"
    ATTESTED = "sandbox.attested"
    CLEANUP_REQUESTED = "sandbox.cleanup_requested"
    CLEANED = "sandbox.cleaned"
    QUARANTINED = "sandbox.quarantined"
    RECONCILIATION_STARTED = "sandbox.reconciliation_started"
    RECONCILIATION_RESOLVED = "sandbox.reconciliation_resolved"


class SandboxFact(StrictModel):
    schema_version: Literal[1] = 1
    tenant_id: Identifier
    execution_id: Identifier
    sequence: int = Field(ge=1)
    fact_id: Identifier
    fact_type: SandboxFactType
    command_id: Identifier
    actor_ref: Identifier
    recorded_at: AwareDatetime
    payload: dict[str, JsonValue] = Field(default_factory=dict, max_length=32)
    previous_digest: Sha256Digest
    canonical_digest: Sha256Digest


class SandboxProjection(StrictModel):
    tenant_id: Identifier
    execution_id: Identifier
    run_id: Identifier
    task_id: Identifier
    status: SandboxStatus
    version: int = Field(ge=1)
    request_digest: Sha256Digest
    spec_digest: Sha256Digest
    policy_digest: Sha256Digest
    approval_digest: Sha256Digest
    fence_token: Identifier
    provider_uid: Identifier | None = None
    result_digest: Sha256Digest | None = None
    manifest_digest: Sha256Digest | None = None
    attestation_digest: Sha256Digest | None = None
    cleanup_complete: bool = False
    last_fact_digest: Sha256Digest
    updated_at: AwareDatetime


_STATUS_BY_FACT = {
    SandboxFactType.REQUEST_RECORDED: SandboxStatus.REQUESTED,
    SandboxFactType.POLICY_DECIDED: SandboxStatus.POLICY_APPROVED,
    SandboxFactType.APPROVAL_BOUND: SandboxStatus.POLICY_APPROVED,
    SandboxFactType.CLAIMED: SandboxStatus.CLAIMED,
    SandboxFactType.PROVISION_REQUESTED: SandboxStatus.PROVISIONING,
    SandboxFactType.PROVISIONED: SandboxStatus.PROVISIONING,
    SandboxFactType.STARTED: SandboxStatus.RUNNING,
    SandboxFactType.OUTPUT_CAPTURE_REQUESTED: SandboxStatus.CAPTURING,
    SandboxFactType.ARTIFACT_RECORDED: SandboxStatus.CAPTURING,
    SandboxFactType.COMPLETED: SandboxStatus.COMPLETED,
    SandboxFactType.FAILED: SandboxStatus.FAILED,
    SandboxFactType.TIMED_OUT: SandboxStatus.TIMED_OUT,
    SandboxFactType.OOM_KILLED: SandboxStatus.OOM_KILLED,
    SandboxFactType.VIOLATION: SandboxStatus.VIOLATION,
    SandboxFactType.CANCELLATION_REQUESTED: SandboxStatus.CANCELLED,
    SandboxFactType.CANCELLED: SandboxStatus.CANCELLED,
    SandboxFactType.ATTESTED: SandboxStatus.ATTESTED,
    SandboxFactType.CLEANUP_REQUESTED: SandboxStatus.CLEANING,
    SandboxFactType.CLEANED: SandboxStatus.CLEANED,
    SandboxFactType.QUARANTINED: SandboxStatus.QUARANTINED,
    SandboxFactType.RECONCILIATION_STARTED: SandboxStatus.RECONCILING,
    SandboxFactType.RECONCILIATION_RESOLVED: SandboxStatus.RECONCILING,
}


def reduce_sandbox(
    current: SandboxProjection | None,
    fact: SandboxFact,
) -> SandboxProjection:
    """Replay application facts without Temporal or Kubernetes history."""

    if fact.canonical_digest != canonical_digest(
        fact.model_dump(mode="json", exclude={"canonical_digest"})
    ):
        raise IntegrityFailure("sandbox fact digest mismatch")
    if current is None:
        if fact.fact_type is not SandboxFactType.REQUEST_RECORDED or fact.sequence != 1:
            raise IntegrityFailure("sandbox aggregate must begin with a request")
        required = {
            "run_id",
            "task_id",
            "request_digest",
            "spec_digest",
            "policy_digest",
            "approval_digest",
            "fence_token",
        }
        if not required.issubset(fact.payload):
            raise IntegrityFailure("sandbox request fact is incomplete")
        return SandboxProjection(
            tenant_id=fact.tenant_id,
            execution_id=fact.execution_id,
            run_id=str(fact.payload["run_id"]),
            task_id=str(fact.payload["task_id"]),
            status=SandboxStatus.REQUESTED,
            version=1,
            request_digest=str(fact.payload["request_digest"]),
            spec_digest=str(fact.payload["spec_digest"]),
            policy_digest=str(fact.payload["policy_digest"]),
            approval_digest=str(fact.payload["approval_digest"]),
            fence_token=str(fact.payload["fence_token"]),
            last_fact_digest=fact.canonical_digest,
            updated_at=fact.recorded_at,
        )
    if (
        current.tenant_id != fact.tenant_id
        or current.execution_id != fact.execution_id
        or fact.sequence != current.version + 1
        or fact.previous_digest != current.last_fact_digest
    ):
        raise IntegrityFailure("sandbox fact chain is invalid")
    update: dict[str, object] = {
        "status": _STATUS_BY_FACT[fact.fact_type],
        "version": fact.sequence,
        "last_fact_digest": fact.canonical_digest,
        "updated_at": fact.recorded_at,
    }
    for key in (
        "provider_uid",
        "result_digest",
        "manifest_digest",
        "attestation_digest",
    ):
        if key in fact.payload:
            update[key] = str(fact.payload[key])
    if fact.fact_type is SandboxFactType.CLEANED:
        update["cleanup_complete"] = True
    return current.model_copy(update=update)


class SandboxLedger(Protocol):
    def append(
        self,
        *,
        tenant_id: str,
        execution_id: str,
        expected_version: int,
        fact_type: SandboxFactType,
        command_id: str,
        actor_ref: str,
        recorded_at: datetime,
        payload: Mapping[str, JsonValue],
    ) -> SandboxProjection: ...

    def projection(
        self,
        *,
        tenant_id: str,
        execution_id: str,
    ) -> SandboxProjection | None: ...

    def facts(
        self,
        *,
        tenant_id: str,
        execution_id: str,
    ) -> tuple[SandboxFact, ...]: ...


class InMemorySandboxLedger:
    def __init__(self) -> None:
        self._facts: dict[tuple[str, str], list[SandboxFact]] = {}
        self._projections: dict[tuple[str, str], SandboxProjection] = {}
        self._commands: dict[tuple[str, str], tuple[str, str]] = {}
        self._lock = Lock()

    def append(
        self,
        *,
        tenant_id: str,
        execution_id: str,
        expected_version: int,
        fact_type: SandboxFactType,
        command_id: str,
        actor_ref: str,
        recorded_at: datetime,
        payload: Mapping[str, JsonValue],
    ) -> SandboxProjection:
        key = (tenant_id, execution_id)
        fingerprint = canonical_digest(
            {"fact_type": fact_type.value, "payload": dict(payload)}
        )
        with self._lock:
            prior = self._commands.get((tenant_id, command_id))
            if prior is not None:
                if prior != (execution_id, fingerprint):
                    raise IdempotencyConflict("sandbox command replay changed input")
                return self._projections[key]
            facts = self._facts.setdefault(key, [])
            if len(facts) != expected_version:
                raise ConcurrencyConflict("sandbox aggregate version changed")
            if len(facts) >= _MAX_FACTS:
                raise IntegrityFailure("sandbox fact bound exceeded")
            sequence = len(facts) + 1
            previous = facts[-1].canonical_digest if facts else "0" * 64
            document = dict(sorted(payload.items()))
            material: dict[str, JsonValue] = {
                "schema_version": 1,
                "tenant_id": tenant_id,
                "execution_id": execution_id,
                "sequence": sequence,
                "fact_id": stable_id(
                    "sandbox-fact",
                    tenant_id,
                    execution_id,
                    str(sequence),
                    command_id,
                    length=32,
                ),
                "fact_type": fact_type.value,
                "command_id": command_id,
                "actor_ref": actor_ref,
                "recorded_at": recorded_at.isoformat().replace("+00:00", "Z"),
                "payload": document,
                "previous_digest": previous,
            }
            fact = SandboxFact(
                tenant_id=tenant_id,
                execution_id=execution_id,
                sequence=sequence,
                fact_id=str(material["fact_id"]),
                fact_type=fact_type,
                command_id=command_id,
                actor_ref=actor_ref,
                recorded_at=recorded_at,
                payload=document,
                previous_digest=previous,
                canonical_digest=canonical_digest(material),
            )
            projection = reduce_sandbox(self._projections.get(key), fact)
            facts.append(fact)
            self._commands[(tenant_id, command_id)] = (execution_id, fingerprint)
            self._projections[key] = projection
            return projection

    def projection(
        self,
        *,
        tenant_id: str,
        execution_id: str,
    ) -> SandboxProjection | None:
        with self._lock:
            return self._projections.get((tenant_id, execution_id))

    def facts(
        self,
        *,
        tenant_id: str,
        execution_id: str,
    ) -> tuple[SandboxFact, ...]:
        with self._lock:
            return tuple(self._facts.get((tenant_id, execution_id), ()))

    def rebuild(self, *, tenant_id: str, execution_id: str) -> SandboxProjection:
        projection: SandboxProjection | None = None
        for fact in self.facts(tenant_id=tenant_id, execution_id=execution_id):
            projection = reduce_sandbox(projection, fact)
        if projection is None:
            raise IntegrityFailure("cannot rebuild an unknown sandbox execution")
        return projection


class SandboxClaim(StrictModel):
    request_digest: Sha256Digest
    spec_digest: Sha256Digest
    policy_digest: Sha256Digest
    approval_digest: Sha256Digest
    attempt: int = Field(ge=1, le=16)
    fence_token: Identifier
    claim_token: Identifier
    claim_until: AwareDatetime
    worker_ref: Identifier
    result_digest: Sha256Digest | None = None


class SandboxQuotaDecision(StrictModel):
    allowed: bool
    reservation_id: Identifier
    units: int = Field(ge=1)
    reason: Identifier


class SandboxQuotaPort(Protocol):
    def reserve(
        self,
        *,
        tenant_id: str,
        execution_id: str,
        reservation_id: str,
        policy_digest: str,
        units: int,
        requested_at: datetime,
    ) -> SandboxQuotaDecision: ...


class InMemorySandboxQuota:
    def __init__(self, limits: Mapping[str, int]) -> None:
        self._remaining = dict(limits)
        self._reservations: dict[tuple[str, str], SandboxQuotaDecision] = {}
        self._lock = Lock()

    def reserve(
        self,
        *,
        tenant_id: str,
        execution_id: str,
        reservation_id: str,
        policy_digest: str,
        units: int,
        requested_at: datetime,
    ) -> SandboxQuotaDecision:
        del execution_id, policy_digest, requested_at
        if units < 1:
            raise ValueError("sandbox quota units must be positive")
        key = (tenant_id, reservation_id)
        with self._lock:
            existing = self._reservations.get(key)
            if existing is not None:
                return existing
            remaining = self._remaining.get(tenant_id, 0)
            allowed = remaining >= units
            decision = SandboxQuotaDecision(
                allowed=allowed,
                reservation_id=reservation_id,
                units=units,
                reason="reserved" if allowed else "sandbox_quota_exhausted",
            )
            self._reservations[key] = decision
            if allowed:
                self._remaining[tenant_id] = remaining - units
            return decision


class InMemorySandboxClaims:
    def __init__(self) -> None:
        self._claims: dict[tuple[str, str], SandboxClaim] = {}
        self._lock = Lock()

    def claim(
        self,
        request: SandboxExecutionRequest,
        *,
        worker_ref: str,
        now: datetime,
        claim_until: datetime,
    ) -> SandboxClaim:
        if claim_until <= now:
            raise ValueError("sandbox claim expiry must follow claim time")
        key = (request.tenant_id, request.execution_id)
        token = stable_id(
            "sandbox-claim",
            request.tenant_id,
            request.execution_id,
            worker_ref,
            str(request.attempt),
            request.fence_token,
            length=40,
        )
        with self._lock:
            current = self._claims.get(key)
            if current is not None:
                if (
                    current.spec_digest != request.spec_digest
                    or current.policy_digest != request.policy_digest
                    or current.approval_digest != request.approval_digest
                    or current.fence_token != request.fence_token
                ):
                    raise SandboxRejected("sandbox claim exact binding changed")
                if current.result_digest is not None:
                    return current
                if current.claim_until > now and current.claim_token != token:
                    raise ConcurrencyConflict("sandbox execution is actively claimed")
                if current.claim_until <= now and request.attempt <= current.attempt:
                    raise ConcurrencyConflict("sandbox retry attempt did not advance")
            claimed = SandboxClaim(
                request_digest=request.request_digest,
                spec_digest=request.spec_digest,
                policy_digest=request.policy_digest,
                approval_digest=request.approval_digest,
                attempt=request.attempt,
                fence_token=request.fence_token,
                claim_token=token,
                claim_until=claim_until,
                worker_ref=worker_ref,
            )
            self._claims[key] = claimed
            return claimed

    def complete(
        self,
        result: SandboxResult,
        *,
        claim_token: str,
        now: datetime,
    ) -> None:
        del now
        key = (result.tenant_id, result.execution_id)
        with self._lock:
            current = self._claims.get(key)
            if (
                current is None
                or current.claim_token != claim_token
                or current.fence_token != result.fence_token
                or current.attempt != result.attempt
            ):
                raise ConcurrencyConflict("stale sandbox completion rejected")
            if current.result_digest is not None:
                if current.result_digest != result.result_digest:
                    raise IdempotencyConflict("sandbox result changed on replay")
                return
            self._claims[key] = current.model_copy(
                update={"result_digest": result.result_digest}
            )


class SandboxReadPort(Protocol):
    def projection(
        self,
        *,
        tenant_id: str,
        execution_id: str,
    ) -> SandboxProjection | None: ...

    def artifacts(
        self,
        *,
        tenant_id: str,
        execution_id: str,
    ) -> tuple[ArtifactRecord, ...]: ...


class SandboxApprovalBindingPort(Protocol):
    def current(
        self,
        *,
        tenant_id: str,
        approval_id: str,
    ) -> SandboxApprovalBinding | None: ...


class SandboxControlService:
    """Authorize and record a sandbox request before any backend I/O."""

    def __init__(
        self,
        *,
        application_policy: PolicyPort,
        sandbox_policy: SandboxPolicy,
        approvals: SandboxApprovalBindingPort,
        quotas: SandboxQuotaPort,
        ledger: SandboxLedger,
        clock: ClockPort,
    ) -> None:
        self._application_policy = application_policy
        self._sandbox_policy = sandbox_policy
        self._approvals = approvals
        self._quotas = quotas
        self._ledger = ledger
        self._clock = clock

    def request(
        self,
        identity: IdentityContext,
        request: SandboxExecutionRequest,
        *,
        active_executions: int,
        command_id: str,
    ) -> SandboxProjection:
        if identity.tenant_id != request.tenant_id:
            raise PolicyDenied("sandbox tenant mismatch")
        decision = self._application_policy.authorize(
            identity,
            Action.SANDBOX_EXECUTE,
            resource_tenant_id=request.tenant_id,
            purpose="incident-response",
            risk=request.spec.risk,
        )
        if not decision.allowed:
            raise PolicyDenied("sandbox application authorization denied")
        if request.policy_digest != self._sandbox_policy.policy_digest:
            raise PolicyDenied("sandbox policy changed after request creation")
        current_approval = self._approvals.current(
            tenant_id=request.tenant_id,
            approval_id=request.spec.approval.approval_id,
        )
        if current_approval != request.spec.approval:
            raise PolicyDenied("sandbox approval binding changed")
        self._sandbox_policy.authorize(
            request.spec,
            active_executions=active_executions,
            now=self._clock.now(),
        )
        reservation = self._quotas.reserve(
            tenant_id=request.tenant_id,
            execution_id=request.execution_id,
            reservation_id=stable_id(
                "sandbox-quota",
                request.tenant_id,
                request.idempotency_key,
                length=40,
            ),
            policy_digest=request.policy_digest,
            units=1,
            requested_at=self._clock.now(),
        )
        if not reservation.allowed:
            raise PolicyDenied("sandbox execution quota exhausted")
        actor_ref = stable_id("actor", identity.issuer, identity.subject_id, length=32)
        projection = self._ledger.append(
            tenant_id=request.tenant_id,
            execution_id=request.execution_id,
            expected_version=0,
            fact_type=SandboxFactType.REQUEST_RECORDED,
            command_id=command_id,
            actor_ref=actor_ref,
            recorded_at=self._clock.now(),
            payload={
                "run_id": request.run_id,
                "task_id": request.task_id,
                "request_digest": request.request_digest,
                "spec_digest": request.spec_digest,
                "policy_digest": request.policy_digest,
                "approval_digest": request.approval_digest,
                "fence_token": request.fence_token,
            },
        )
        projection = self._ledger.append(
            tenant_id=request.tenant_id,
            execution_id=request.execution_id,
            expected_version=projection.version,
            fact_type=SandboxFactType.POLICY_DECIDED,
            command_id=f"{command_id}-policy",
            actor_ref=actor_ref,
            recorded_at=self._clock.now(),
            payload={
                "policy_id": self._sandbox_policy.policy_id,
                "policy_revision": self._sandbox_policy.revision,
                "policy_digest": self._sandbox_policy.policy_digest,
            },
        )
        return self._ledger.append(
            tenant_id=request.tenant_id,
            execution_id=request.execution_id,
            expected_version=projection.version,
            fact_type=SandboxFactType.APPROVAL_BOUND,
            command_id=f"{command_id}-approval",
            actor_ref=actor_ref,
            recorded_at=self._clock.now(),
            payload={
                "approval_id": request.spec.approval.approval_id,
                "approval_digest": request.approval_digest,
                "remediation_plan_digest": (
                    request.spec.approval.remediation_plan_digest
                ),
                "remediation_action_digest": (
                    request.spec.approval.remediation_action_digest
                ),
            },
        )


def parse_exact_destination(url: str) -> EgressDestination:
    """Parse policy configuration without performing DNS or network access."""

    parts = urlsplit(url)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
        or (parts.port or 443) != 443
    ):
        raise ValueError("egress destination must be an exact HTTPS origin")
    return EgressDestination(host=parts.hostname)
