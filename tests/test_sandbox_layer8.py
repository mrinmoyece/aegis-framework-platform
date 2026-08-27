from __future__ import annotations

import asyncio
import io
import re
import stat
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import aegis_framework.sandbox_adapters as sandbox_adapters
import aegis_framework.sandbox_temporal as sandbox_temporal
from aegis_framework.adapters import FixedClock
from aegis_framework.api import ApiRuntime, AppMode, create_app
from aegis_framework.authorization import RoleCatalog
from aegis_framework.domain import (
    GrantBinding,
    IdentityContext,
    PrincipalKind,
    RiskLevel,
)
from aegis_framework.errors import (
    ArtifactQuarantined,
    AuthenticationFailed,
    ConcurrencyConflict,
    IdempotencyConflict,
    IntegrityFailure,
    PolicyDenied,
    SandboxAmbiguous,
    SandboxRejected,
    SandboxUnavailable,
)
from aegis_framework.fixtures import build_demo_bundle
from aegis_framework.ports import Action, PolicyDecision
from aegis_framework.sandbox import (
    ArtifactDisposition,
    BackendObservationState,
    ContentInput,
    EgressDestination,
    EnvironmentVariable,
    InMemorySandboxClaims,
    InMemorySandboxLedger,
    InMemorySandboxQuota,
    MountReference,
    NetworkMode,
    OutputExpectation,
    RetryAndCleanup,
    SandboxApprovalBinding,
    SandboxControlService,
    SandboxExecutionRequest,
    SandboxFact,
    SandboxFactType,
    SandboxNetworkPolicy,
    SandboxOutcome,
    SandboxPolicy,
    SandboxPurpose,
    SandboxResources,
    SandboxSecurityContext,
    SandboxSpec,
    SandboxStatus,
    SecretReference,
    canonical_digest,
    parse_exact_destination,
    reduce_sandbox,
    validate_relative_path,
)
from aegis_framework.sandbox_adapters import (
    ArtifactProcessor,
    DeterministicSandboxBackend,
    KubernetesJobSandboxBackend,
    KubernetesSandboxConfig,
    build_kubernetes_job_sandbox_backend,
    safe_extract_zip,
)
from aegis_framework.sandbox_temporal import (
    SandboxActivityInput,
    SandboxActivityOutcome,
    TemporalSandboxActivities,
)

NOW = datetime(2026, 8, 17, 10, 0, tzinfo=UTC)
TENANT = "tenant-acme"
IMAGE_DIGEST = "a" * 64
APPROVAL_POLICY_DIGEST = "b" * 64
IMAGE = f"registry.example.invalid/aegis/runner@sha256:{IMAGE_DIGEST}"


class AllowingPolicy:
    def authorize(
        self,
        identity: IdentityContext,
        action: Action,
        *,
        resource_tenant_id: str,
        purpose: str,
        risk: RiskLevel,
    ) -> PolicyDecision:
        allowed = (
            identity.tenant_id == resource_tenant_id
            and action.value in identity.permissions
            and purpose in identity.purposes
        )
        return PolicyDecision(
            allowed=allowed,
            policy_id="application-policy",
            policy_revision=1,
            purpose=purpose,
            risk=risk,
            reason="allowed" if allowed else "denied",
        )


class ApprovalBindings:
    def __init__(self, approval: SandboxApprovalBinding | None) -> None:
        self.approval = approval

    def current(
        self,
        *,
        tenant_id: str,
        approval_id: str,
    ) -> SandboxApprovalBinding | None:
        if (
            self.approval is not None
            and self.approval.tenant_id == tenant_id
            and self.approval.approval_id == approval_id
        ):
            return self.approval
        return None


def _identity(
    *,
    tenant_id: str = TENANT,
    actions: tuple[Action, ...] = (Action.SANDBOX_EXECUTE,),
) -> IdentityContext:
    permissions = tuple(action.value for action in actions)
    return IdentityContext(
        tenant_id=tenant_id,
        issuer="https://identity.example.invalid",
        subject_id="sandbox-worker",
        principal_kind=PrincipalKind.WORKLOAD,
        roles=("sandbox-worker",),
        permissions=permissions,
        purposes=("incident-response",),
        grants=(
            GrantBinding(
                role="sandbox-worker",
                purpose="incident-response",
                permissions=permissions,
                risk_ceiling=RiskLevel.HIGH,
                expires_at=NOW + timedelta(hours=2),
            ),
        ),
        grant_version=1,
        authenticated_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=2),
        request_id="request-sandbox-001",
        trace_id="trace-sandbox-001",
    )


def _approval(**changes: object) -> SandboxApprovalBinding:
    values: dict[str, object] = {
        "tenant_id": TENANT,
        "run_id": "run-layer8-001",
        "task_id": "task-layer8-001",
        "remediation_plan_id": "plan-layer7-001",
        "remediation_action_id": "action-layer7-001",
        "remediation_plan_digest": "c" * 64,
        "remediation_action_digest": "d" * 64,
        "approval_id": "approval-layer7-001",
        "approval_digest": "e" * 64,
        "approval_policy_digest": APPROVAL_POLICY_DIGEST,
        "approval_expires_at": NOW + timedelta(hours=1),
    }
    values.update(changes)
    return SandboxApprovalBinding.model_validate(values)


def _resources(**changes: int) -> SandboxResources:
    values = {
        "cpu_millicores": 500,
        "memory_mib": 512,
        "pid_limit": 64,
        "ephemeral_storage_mib": 1024,
        "timeout_seconds": 300,
        "output_bytes": 1024 * 1024,
        "output_files": 16,
        "output_file_bytes": 256 * 1024,
    }
    values.update(changes)
    return SandboxResources(**values)


def _security() -> SandboxSecurityContext:
    return SandboxSecurityContext(
        run_as_user=10001,
        run_as_group=10001,
        fs_group=10001,
        apparmor_profile="aegis-sandbox-v1",
    )


def _spec(
    *,
    approval: SandboxApprovalBinding | None = None,
    image: str = IMAGE,
    argv: tuple[str, ...] = ("python", "-m", "pytest", "-q"),
    inputs: tuple[ContentInput, ...] = (),
    mounts: tuple[MountReference, ...] = (),
    environment: tuple[EnvironmentVariable, ...] = (),
    secrets: tuple[SecretReference, ...] = (),
    network: SandboxNetworkPolicy | None = None,
    resources: SandboxResources | None = None,
    outputs: tuple[OutputExpectation, ...] = (
        OutputExpectation(
            logical_path="reports/result.json",
            media_types=("application/json",),
        ),
    ),
) -> SandboxSpec:
    binding = approval or _approval()
    material = {
        "schema_version": 1,
        "spec_version": "sandbox-spec-v1",
        "tenant_id": TENANT,
        "run_id": binding.run_id,
        "task_id": binding.task_id,
        "purpose": SandboxPurpose.TESTING,
        "risk": RiskLevel.MEDIUM,
        "approval": binding,
        "image": image,
        "argv": argv,
        "working_directory": "workspace",
        "inputs": inputs,
        "mounts": mounts,
        "environment": environment,
        "secrets": secrets,
        "network": network or SandboxNetworkPolicy(),
        "resources": resources or _resources(),
        "security": _security(),
        "required_runtime_class": "kata-aegis",
        "required_admission_policies": (
            "aegis-sandbox-baseline",
            "aegis-sandbox-images",
        ),
        "expected_outputs": outputs,
        "retry": RetryAndCleanup(
            maximum_attempts=3,
            cleanup_timeout_seconds=120,
            retain_failed_seconds=600,
        ),
    }
    return SandboxSpec(**material, spec_digest=canonical_digest(material))


def _policy(
    *,
    enabled: bool = True,
    revision: int = 1,
    concurrency: int = 2,
    approval_digests: tuple[str, ...] = (APPROVAL_POLICY_DIGEST,),
    egress: tuple[EgressDestination, ...] = (),
) -> SandboxPolicy:
    material = {
        "schema_version": 1,
        "tenant_id": TENANT,
        "policy_id": "sandbox-policy",
        "revision": revision,
        "enabled": enabled,
        "allowed_image_digests": (IMAGE_DIGEST,),
        "allowed_registries": ("registry.example.invalid",),
        "allowed_commands": ("python",),
        "allowed_purposes": (SandboxPurpose.TESTING,),
        "allowed_mount_prefixes": ("inputs",),
        "allowed_secret_refs": ("sandbox-secret",),
        "allowed_egress": egress,
        "allowed_approval_policy_digests": approval_digests,
        "maximum_resources": _resources(
            cpu_millicores=2_000,
            memory_mib=4_096,
            pid_limit=256,
            ephemeral_storage_mib=8_192,
            timeout_seconds=900,
            output_bytes=8 * 1024 * 1024,
            output_files=128,
            output_file_bytes=2 * 1024 * 1024,
        ),
        "maximum_concurrency": concurrency,
        "maximum_lifetime_seconds": 900,
        "maximum_risk": RiskLevel.MEDIUM,
        "require_runtime_class": "kata-aegis",
        "require_admission_policies": (
            "aegis-sandbox-baseline",
            "aegis-sandbox-images",
        ),
    }
    return SandboxPolicy(**material, policy_digest=canonical_digest(material))


def _request(
    *,
    spec: SandboxSpec | None = None,
    policy: SandboxPolicy | None = None,
    attempt: int = 1,
) -> SandboxExecutionRequest:
    selected_spec = spec or _spec()
    selected_policy = policy or _policy()
    material = {
        "schema_version": 1,
        "execution_id": "sandbox-execution-001",
        "tenant_id": TENANT,
        "run_id": selected_spec.run_id,
        "task_id": selected_spec.task_id,
        "spec": selected_spec,
        "spec_digest": selected_spec.spec_digest,
        "policy_digest": selected_policy.policy_digest,
        "approval_digest": selected_spec.approval.approval_digest,
        "idempotency_key": "sandbox-idempotency-001",
        "attempt": attempt,
        "fence_token": "sandbox-fence-001",
        "requested_at": NOW,
    }
    return SandboxExecutionRequest(
        **material,
        request_digest=canonical_digest(material),
    )


def test_contracts_are_immutable_canonical_and_exactly_bound() -> None:
    request = _request()
    assert request.spec.image.endswith(IMAGE_DIGEST)
    assert request.request_digest == canonical_digest(request)
    with pytest.raises(ValidationError, match="frozen"):
        request.attempt = 2  # type: ignore[misc]

    changed = request.model_dump()
    changed["policy_digest"] = "f" * 64
    with pytest.raises(ValidationError, match="request digest mismatch"):
        SandboxExecutionRequest.model_validate(changed)

    mismatched = _approval(tenant_id="tenant-beta")
    with pytest.raises(ValidationError, match="approval scope"):
        _spec(approval=mismatched)


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "../escape",
        "safe/../escape",
        r"safe\escape",
        "safe//escape",
        "con",
        "safe/nul.txt",
        "safe/\u202etxt.exe",
        "safe/\x00name",
        "safe/name.",
    ],
)
def test_paths_reject_traversal_devices_absolute_unicode_and_controls(
    path: str,
) -> None:
    with pytest.raises(ValueError, match=r"path|control|device|ambiguous"):
        validate_relative_path(path)


@pytest.mark.parametrize(
    "argv",
    [
        ("sh", "-c", "echo ok"),
        ("bash", "script"),
        ("python", "-c", "print(1)"),
        ("python", "$(id)"),
        ("python", "`id`"),
        ("python", "ok && id"),
        ("python", "line\nbreak"),
        ("python", "\u202egpj.exe"),
    ],
)
def test_argv_rejects_shells_interpolation_controls_and_bidi(
    argv: tuple[str, ...],
) -> None:
    with pytest.raises(ValidationError):
        _spec(argv=argv)


@pytest.mark.parametrize(
    "image",
    [
        "registry.example.invalid/aegis/runner:latest",
        "registry.example.invalid/aegis/runner",
        f"registry.example.invalid/aegis/runner@sha512:{IMAGE_DIGEST}",
        f"UPPER.example.invalid/aegis/runner@sha256:{IMAGE_DIGEST}",
        f"runner@sha256:{IMAGE_DIGEST}",
    ],
)
def test_images_must_be_registry_qualified_immutable_digests(image: str) -> None:
    with pytest.raises(ValidationError, match="immutable OCI"):
        _spec(image=image)


def test_env_secret_refs_and_duplicate_paths_fail_closed() -> None:
    with pytest.raises(ValidationError, match="secret-like"):
        EnvironmentVariable(name="API_TOKEN", value="not-even-secret")
    with pytest.raises(ValidationError, match="secret literals"):
        EnvironmentVariable(name="CONFIG", value="token=abcdefghijk")
    with pytest.raises(ValidationError, match="duplicate environment"):
        _spec(
            environment=(EnvironmentVariable(name="MODE", value="test"),),
            secrets=(
                SecretReference(
                    reference="sandbox-secret",
                    version=1,
                    env_name="MODE",
                ),
            ),
        )
    duplicate = ContentInput(
        tenant_id=TENANT,
        logical_path="reports/result.json",
        content_hash="1" * 64,
        size_bytes=10,
        media_type="application/json",
        object_ref="input-object",
    )
    with pytest.raises(ValidationError, match="duplicate or conflicting"):
        _spec(inputs=(duplicate,))


def test_exact_egress_origin_rejects_private_ip_metadata_and_wildcards() -> None:
    assert (
        parse_exact_destination("https://packages.example.com").host
        == "packages.example.com"
    )
    for value in (
        "http://packages.example.com",
        "https://169.254.169.254",
        "https://10.0.0.1",
        "https://*.example.com",
        "https://localhost",
        "https://service.internal",
        "https://packages.example.com/path",
        "https://user:pass@packages.example.com",
    ):
        with pytest.raises(ValueError, match=r"egress|host|IP|DNS"):
            parse_exact_destination(value)


def test_policy_default_deny_approval_and_digest_invalidation() -> None:
    spec = _spec()
    disabled = _policy(enabled=False)
    with pytest.raises(PolicyDenied, match="disabled"):
        disabled.authorize(spec, active_executions=0, now=NOW)
    with pytest.raises(PolicyDenied, match="request is not allowlisted"):
        _policy(approval_digests=("9" * 64,)).authorize(
            spec,
            active_executions=0,
            now=NOW,
        )

    request = _request(spec=spec)
    service = SandboxControlService(
        application_policy=AllowingPolicy(),
        sandbox_policy=_policy(revision=2),
        approvals=ApprovalBindings(spec.approval),
        quotas=InMemorySandboxQuota({TENANT: 1}),
        ledger=InMemorySandboxLedger(),
        clock=FixedClock(NOW),
    )
    with pytest.raises(PolicyDenied, match="policy changed"):
        service.request(
            _identity(),
            request,
            active_executions=0,
            command_id="sandbox-submit",
        )


def test_policy_denies_tenant_approval_quota_resource_mount_secret_and_egress() -> None:
    destination = EgressDestination(host="packages.example.com")
    policy = _policy(concurrency=1, egress=(destination,))
    base = _spec()
    with pytest.raises(PolicyDenied, match="concurrency"):
        policy.authorize(base, active_executions=1, now=NOW)
    with pytest.raises(PolicyDenied, match="resource"):
        policy.authorize(
            _spec(resources=_resources(cpu_millicores=8_000)),
            active_executions=0,
            now=NOW,
        )
    with pytest.raises(PolicyDenied, match="mount"):
        policy.authorize(
            _spec(mounts=(MountReference(source_ref="object", target_path="other"),)),
            active_executions=0,
            now=NOW,
        )
    with pytest.raises(PolicyDenied, match="secret"):
        policy.authorize(
            _spec(
                secrets=(
                    SecretReference(
                        reference="unknown-secret",
                        version=1,
                        env_name="TOKEN",
                    ),
                )
            ),
            active_executions=0,
            now=NOW,
        )
    unlisted = SandboxNetworkPolicy(
        mode=NetworkMode.EXACT_DESTINATIONS,
        destinations=(EgressDestination(host="other.example.com"),),
        enforcement="external-egress-proxy-required",
    )
    with pytest.raises(PolicyDenied, match="egress"):
        policy.authorize(
            _spec(network=unlisted),
            active_executions=0,
            now=NOW,
        )

    request = _request(spec=base, policy=policy)
    service = SandboxControlService(
        application_policy=AllowingPolicy(),
        sandbox_policy=policy,
        approvals=ApprovalBindings(None),
        quotas=InMemorySandboxQuota({TENANT: 1}),
        ledger=InMemorySandboxLedger(),
        clock=FixedClock(NOW),
    )
    with pytest.raises(PolicyDenied, match="approval binding changed"):
        service.request(
            _identity(),
            request,
            active_executions=0,
            command_id="submit",
        )
    with pytest.raises(PolicyDenied, match="tenant mismatch"):
        service.request(
            _identity(tenant_id="tenant-beta"),
            request,
            active_executions=0,
            command_id="submit",
        )


def test_control_service_records_intent_policy_and_approval_before_io() -> None:
    request = _request()
    ledger = InMemorySandboxLedger()
    service = SandboxControlService(
        application_policy=AllowingPolicy(),
        sandbox_policy=_policy(),
        approvals=ApprovalBindings(request.spec.approval),
        quotas=InMemorySandboxQuota({TENANT: 1}),
        ledger=ledger,
        clock=FixedClock(NOW),
    )
    projection = service.request(
        _identity(),
        request,
        active_executions=0,
        command_id="submit-sandbox",
    )
    assert projection.status is SandboxStatus.POLICY_APPROVED
    assert projection.version == 3
    assert [
        fact.fact_type
        for fact in ledger.facts(
            tenant_id=TENANT,
            execution_id=request.execution_id,
        )
    ] == [
        SandboxFactType.REQUEST_RECORDED,
        SandboxFactType.POLICY_DECIDED,
        SandboxFactType.APPROVAL_BOUND,
    ]
    assert (
        ledger.rebuild(
            tenant_id=TENANT,
            execution_id=request.execution_id,
        )
        == projection
    )
    exhausted = SandboxControlService(
        application_policy=AllowingPolicy(),
        sandbox_policy=_policy(),
        approvals=ApprovalBindings(request.spec.approval),
        quotas=InMemorySandboxQuota({TENANT: 0}),
        ledger=InMemorySandboxLedger(),
        clock=FixedClock(NOW),
    )
    with pytest.raises(PolicyDenied, match="quota exhausted"):
        exhausted.request(
            _identity(),
            request,
            active_executions=0,
            command_id="quota-exhausted",
        )
    assert (
        service.request(
            _identity(),
            request,
            active_executions=0,
            command_id="submit-sandbox",
        )
        == projection
    )


def _append_lifecycle(
    ledger: InMemorySandboxLedger,
    request: SandboxExecutionRequest,
    types: tuple[SandboxFactType, ...],
) -> None:
    projection = ledger.projection(
        tenant_id=TENANT,
        execution_id=request.execution_id,
    )
    assert projection is not None
    for index, fact_type in enumerate(types, start=1):
        payload: dict[str, str | int | bool] = {}
        if fact_type is SandboxFactType.PROVISIONED:
            payload["provider_uid"] = "provider-uid"
        if fact_type in {
            SandboxFactType.COMPLETED,
            SandboxFactType.FAILED,
            SandboxFactType.TIMED_OUT,
            SandboxFactType.OOM_KILLED,
            SandboxFactType.VIOLATION,
            SandboxFactType.CANCELLED,
        }:
            payload["result_digest"] = "6" * 64
        if fact_type is SandboxFactType.ARTIFACT_RECORDED:
            payload["manifest_digest"] = "7" * 64
        if fact_type is SandboxFactType.ATTESTED:
            payload["attestation_digest"] = "8" * 64
        projection = ledger.append(
            tenant_id=TENANT,
            execution_id=request.execution_id,
            expected_version=projection.version,
            fact_type=fact_type,
            command_id=f"lifecycle-{index}-{fact_type.value}",
            actor_ref="sandbox-worker",
            recorded_at=NOW + timedelta(seconds=index),
            payload=payload,
        )


def test_ledger_replays_complete_additive_lifecycle_and_rejects_tampering() -> None:
    request = _request()
    ledger = InMemorySandboxLedger()
    SandboxControlService(
        application_policy=AllowingPolicy(),
        sandbox_policy=_policy(),
        approvals=ApprovalBindings(request.spec.approval),
        quotas=InMemorySandboxQuota({TENANT: 1}),
        ledger=ledger,
        clock=FixedClock(NOW),
    ).request(_identity(), request, active_executions=0, command_id="submit")
    _append_lifecycle(
        ledger,
        request,
        (
            SandboxFactType.CLAIMED,
            SandboxFactType.PROVISION_REQUESTED,
            SandboxFactType.PROVISIONED,
            SandboxFactType.STARTED,
            SandboxFactType.OUTPUT_CAPTURE_REQUESTED,
            SandboxFactType.ARTIFACT_RECORDED,
            SandboxFactType.COMPLETED,
            SandboxFactType.ATTESTED,
            SandboxFactType.CLEANUP_REQUESTED,
            SandboxFactType.CLEANED,
        ),
    )
    projection = ledger.projection(
        tenant_id=TENANT,
        execution_id=request.execution_id,
    )
    assert projection is not None
    assert projection.status is SandboxStatus.CLEANED
    assert projection.cleanup_complete
    assert projection.provider_uid == "provider-uid"
    assert projection.result_digest == "6" * 64
    assert projection.manifest_digest == "7" * 64
    assert projection.attestation_digest == "8" * 64
    assert (
        ledger.rebuild(
            tenant_id=TENANT,
            execution_id=request.execution_id,
        )
        == projection
    )

    first = ledger.facts(
        tenant_id=TENANT,
        execution_id=request.execution_id,
    )[0]
    with pytest.raises(IntegrityFailure, match="digest"):
        reduce_sandbox(
            None,
            first.model_copy(update={"canonical_digest": "9" * 64}),
        )
    with pytest.raises(IdempotencyConflict):
        ledger.append(
            tenant_id=TENANT,
            execution_id=request.execution_id,
            expected_version=projection.version,
            fact_type=SandboxFactType.FAILED,
            command_id="submit",
            actor_ref="sandbox-worker",
            recorded_at=NOW,
            payload={},
        )


@pytest.mark.parametrize(
    ("fact_type", "status"),
    [
        (SandboxFactType.FAILED, SandboxStatus.FAILED),
        (SandboxFactType.TIMED_OUT, SandboxStatus.TIMED_OUT),
        (SandboxFactType.OOM_KILLED, SandboxStatus.OOM_KILLED),
        (SandboxFactType.VIOLATION, SandboxStatus.VIOLATION),
        (SandboxFactType.CANCELLATION_REQUESTED, SandboxStatus.CANCELLED),
        (SandboxFactType.CANCELLED, SandboxStatus.CANCELLED),
        (SandboxFactType.QUARANTINED, SandboxStatus.QUARANTINED),
        (SandboxFactType.RECONCILIATION_STARTED, SandboxStatus.RECONCILING),
        (SandboxFactType.RECONCILIATION_RESOLVED, SandboxStatus.RECONCILING),
    ],
)
def test_failure_timeout_oom_cancel_quarantine_and_reconciliation_replay(
    fact_type: SandboxFactType,
    status: SandboxStatus,
) -> None:
    request = _request()
    ledger = InMemorySandboxLedger()
    SandboxControlService(
        application_policy=AllowingPolicy(),
        sandbox_policy=_policy(),
        approvals=ApprovalBindings(request.spec.approval),
        quotas=InMemorySandboxQuota({TENANT: 1}),
        ledger=ledger,
        clock=FixedClock(NOW),
    ).request(_identity(), request, active_executions=0, command_id="submit")
    _append_lifecycle(ledger, request, (fact_type,))
    projection = ledger.projection(
        tenant_id=TENANT,
        execution_id=request.execution_id,
    )
    assert projection is not None
    assert projection.status is status


def test_claims_fence_stale_attempts_duplicates_and_results() -> None:
    request = _request()
    claims = InMemorySandboxClaims()
    first = claims.claim(
        request,
        worker_ref="worker-one",
        now=NOW,
        claim_until=NOW + timedelta(minutes=1),
    )
    assert first.attempt == 1
    with pytest.raises(ConcurrencyConflict, match="actively"):
        claims.claim(
            request,
            worker_ref="worker-two",
            now=NOW,
            claim_until=NOW + timedelta(minutes=1),
        )
    with pytest.raises(ConcurrencyConflict, match="did not advance"):
        claims.claim(
            request,
            worker_ref="worker-two",
            now=NOW + timedelta(minutes=2),
            claim_until=NOW + timedelta(minutes=3),
        )
    retry = _request(attempt=2)
    advanced = claims.claim(
        retry,
        worker_ref="worker-two",
        now=NOW + timedelta(minutes=2),
        claim_until=NOW + timedelta(minutes=3),
    )
    backend = DeterministicSandboxBackend(clock=FixedClock(NOW))
    result = backend.wait(retry, backend.provision(retry))
    with pytest.raises(ConcurrencyConflict, match="stale"):
        claims.complete(result, claim_token=first.claim_token, now=NOW)
    claims.complete(result, claim_token=advanced.claim_token, now=NOW)
    claims.complete(result, claim_token=advanced.claim_token, now=NOW)
    changed = result.model_copy(update={"result_digest": "9" * 64})
    with pytest.raises(IdempotencyConflict, match="result changed"):
        claims.complete(changed, claim_token=advanced.claim_token, now=NOW)


@pytest.mark.parametrize(
    "outcome",
    [
        SandboxOutcome.SUCCEEDED,
        SandboxOutcome.FAILED,
        SandboxOutcome.TIMED_OUT,
        SandboxOutcome.OOM_KILLED,
        SandboxOutcome.VIOLATION,
    ],
)
def test_deterministic_backend_is_bounded_idempotent_and_observable(
    outcome: SandboxOutcome,
) -> None:
    request = _request()
    backend = DeterministicSandboxBackend(
        clock=FixedClock(NOW),
        outcomes=(outcome,),
    )
    assert backend.ready()
    assert backend.observe(request).state is BackendObservationState.ABSENT
    execution = backend.provision(request)
    assert backend.provision(request) == execution
    assert backend.observe(request).state is BackendObservationState.RUNNING
    result = backend.wait(request, execution)
    assert result.outcome is outcome
    backend.cleanup(request, execution)
    assert backend.observe(request).state is BackendObservationState.ABSENT


def test_deterministic_backend_cancel_and_request_conflict_fail_closed() -> None:
    request = _request()
    backend = DeterministicSandboxBackend(clock=FixedClock(NOW))
    execution = backend.provision(request)
    backend.cancel(request, execution)
    assert backend.wait(request, execution).outcome is SandboxOutcome.CANCELLED
    changed = request.model_copy(update={"request_digest": "9" * 64})
    assert backend.observe(changed).state is BackendObservationState.CONFLICT
    with pytest.raises(SandboxRejected):
        backend.provision(changed)


@dataclass
class Readiness:
    runtime: bool = True
    network: bool = True
    identity: bool = True
    admission: bool = True

    def admission_policy_ready(self, policy_ref: str) -> bool:
        del policy_ref
        return self.admission

    def runtime_class_ready(self, runtime_class: str) -> bool:
        del runtime_class
        return self.runtime

    def network_policy_ready(self, namespace: str) -> bool:
        del namespace
        return self.network

    def workload_identity_ready(self, namespace: str) -> bool:
        del namespace
        return self.identity


class _NotFound(Exception):
    status = 404


class FakeBatchApi:
    def __init__(self) -> None:
        self.job: object | None = None
        self.created: list[Mapping[str, object]] = []
        self.deleted: list[Mapping[str, object]] = []

    def read_namespaced_job(self, *, name: str, namespace: str) -> object:
        del name, namespace
        if self.job is None:
            raise _NotFound
        return self.job

    def create_namespaced_job(
        self,
        *,
        namespace: str,
        body: Mapping[str, object],
    ) -> object:
        del namespace
        self.created.append(body)
        labels = body["metadata"]["labels"]  # type: ignore[index]
        self.job = SimpleNamespace(
            metadata=SimpleNamespace(uid="job-uid-001", labels=labels),
            status=SimpleNamespace(active=1, succeeded=0, failed=0, conditions=[]),
        )
        return self.job

    def delete_namespaced_job(
        self,
        *,
        name: str,
        namespace: str,
        body: Mapping[str, object],
    ) -> object:
        del name, namespace
        self.deleted.append(body)
        self.job = None
        return {}


class FakeNetworkingApi:
    def __init__(self) -> None:
        self.policy: object | None = None
        self.created: list[Mapping[str, object]] = []
        self.deleted: list[Mapping[str, object]] = []

    def read_namespaced_network_policy(
        self,
        *,
        name: str,
        namespace: str,
    ) -> object:
        del name, namespace
        if self.policy is None:
            raise _NotFound
        return self.policy

    def create_namespaced_network_policy(
        self,
        *,
        namespace: str,
        body: Mapping[str, object],
    ) -> object:
        del namespace
        self.created.append(body)
        self.policy = SimpleNamespace(
            metadata=SimpleNamespace(labels=body["metadata"]["labels"])  # type: ignore[index]
        )
        return body

    def delete_namespaced_network_policy(
        self,
        *,
        name: str,
        namespace: str,
        body: Mapping[str, object],
    ) -> object:
        del name, namespace
        self.deleted.append(body)
        self.policy = None
        return {}


class FakeCoreApi:
    def __init__(self) -> None:
        self.reason: str | None = None
        self.exit_code: int | None = None
        self.owner_uid = "job-uid-001"

    def list_namespaced_pod(
        self,
        *,
        namespace: str,
        label_selector: str,
        limit: int,
    ) -> object:
        del namespace, label_selector, limit
        if self.reason is None and self.exit_code is None:
            return SimpleNamespace(items=[])
        return SimpleNamespace(
            items=[
                SimpleNamespace(
                    metadata=SimpleNamespace(
                        owner_references=[SimpleNamespace(uid=self.owner_uid)]
                    ),
                    status=SimpleNamespace(
                        container_statuses=[
                            SimpleNamespace(
                                state=SimpleNamespace(
                                    terminated=SimpleNamespace(
                                        reason=self.reason,
                                        exit_code=self.exit_code,
                                    )
                                )
                            )
                        ]
                    ),
                )
            ]
        )


def _kubernetes_backend(
    *,
    readiness: Readiness | None = None,
    proxy: bool = False,
) -> tuple[
    KubernetesJobSandboxBackend,
    FakeBatchApi,
    FakeNetworkingApi,
    FakeCoreApi,
]:
    batch = FakeBatchApi()
    networking = FakeNetworkingApi()
    core = FakeCoreApi()
    backend = KubernetesJobSandboxBackend(
        batch_api=batch,
        networking_api=networking,
        core_api=core,
        readiness=readiness or Readiness(),
        config=KubernetesSandboxConfig(
            namespace="aegis-sandboxes",
            runtime_class="kata-aegis",
            service_account_name="aegis-sandbox",
            input_csi_driver="inputs.aegis.invalid",
            output_csi_driver="outputs.aegis.invalid",
            apparmor_profile="aegis-sandbox-v1",
            admission_policy_refs=(
                "aegis-sandbox-baseline",
                "aegis-sandbox-images",
            ),
            enabled=True,
            external_egress_proxy_enforced=proxy,
            manage_network_policy=True,
        ),
        clock=FixedClock(NOW),
    )
    return backend, batch, networking, core


def test_kubernetes_manifest_is_nonroot_digest_pinned_and_host_isolated() -> None:
    input_item = ContentInput(
        tenant_id=TENANT,
        logical_path="source/input.json",
        content_hash="1" * 64,
        size_bytes=100,
        media_type="application/json",
        object_ref="input-object",
    )
    request = _request(
        spec=_spec(
            inputs=(input_item,),
            environment=(EnvironmentVariable(name="MODE", value="test"),),
            secrets=(
                SecretReference(
                    reference="sandbox-secret",
                    version=2,
                    env_name="ACCESS_TOKEN",
                ),
            ),
        )
    )
    backend, _, _, _ = _kubernetes_backend()
    manifest = backend.job_manifest(request)
    pod = manifest["spec"]["template"]["spec"]  # type: ignore[index]
    container = pod["containers"][0]
    assert pod["runtimeClassName"] == "kata-aegis"
    assert pod["automountServiceAccountToken"] is False
    assert pod["hostNetwork"] is False
    assert pod["hostPID"] is False
    assert pod["hostIPC"] is False
    assert pod["restartPolicy"] == "Never"
    assert manifest["spec"]["backoffLimit"] == 0  # type: ignore[index]
    assert container["image"] == IMAGE
    assert container["command"] == ["python"]
    assert container["args"] == ["-m", "pytest", "-q"]
    security = container["securityContext"]
    assert security["allowPrivilegeEscalation"] is False
    assert security["privileged"] is False
    assert security["readOnlyRootFilesystem"] is True
    assert security["capabilities"] == {"drop": ["ALL"], "add": []}
    assert security["seccompProfile"] == {"type": "RuntimeDefault"}
    assert security["appArmorProfile"] == {
        "type": "Localhost",
        "localhostProfile": "aegis-sandbox-v1",
    }
    assert (
        manifest["spec"]["template"]["metadata"]["annotations"][  # type: ignore[index]
            "container.apparmor.security.beta.kubernetes.io/sandbox"
        ]
        == "localhost/aegis-sandbox-v1"
    )
    assert all("hostPath" not in volume for volume in pod["volumes"])
    assert all("docker.sock" not in repr(volume) for volume in pod["volumes"])
    assert repr(manifest).find(TENANT) == -1
    assert ":" not in manifest["metadata"]["name"]  # type: ignore[index]
    assert len(manifest["metadata"]["name"]) <= 63  # type: ignore[index]
    for value in manifest["metadata"]["labels"].values():  # type: ignore[index]
        assert len(value) <= 63
        assert re.fullmatch(r"[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?", value)

    network = backend.network_policy_manifest(request)
    network_spec = network["spec"]  # type: ignore[index]
    assert network_spec["ingress"] == []
    assert network_spec["egress"] == []
    selector = network_spec["podSelector"]["matchLabels"]
    assert (
        selector["aegis.github.com/execution"]
        == manifest["metadata"]["labels"][  # type: ignore[index]
            "aegis.github.com/execution"
        ]
    )


def test_kubernetes_readiness_and_exact_egress_fail_closed_without_proxy() -> None:
    backend, _, _, _ = _kubernetes_backend(readiness=Readiness(runtime=False))
    assert not backend.ready()
    with pytest.raises(SandboxUnavailable, match="prerequisites"):
        backend.observe(_request())

    exact = SandboxNetworkPolicy(
        mode=NetworkMode.EXACT_DESTINATIONS,
        destinations=(EgressDestination(host="packages.example.com"),),
        enforcement="external-egress-proxy-required",
    )
    request = _request(spec=_spec(network=exact))
    backend, _, _, _ = _kubernetes_backend()
    with pytest.raises(SandboxRejected, match="not implemented"):
        backend.job_manifest(request)
    backend, _, _, _ = _kubernetes_backend(proxy=True)
    with pytest.raises(SandboxRejected, match="not implemented"):
        backend.network_policy_manifest(request)


def test_kubernetes_observe_before_create_uid_cleanup_and_terminal_states() -> None:
    request = _request()
    backend, batch, networking, _ = _kubernetes_backend()
    execution = backend.provision(request)
    assert len(batch.created) == 1
    assert len(networking.created) == 1
    assert backend.provision(request) == execution
    assert len(batch.created) == 1

    batch.job.status = SimpleNamespace(  # type: ignore[union-attr]
        active=0,
        succeeded=1,
        failed=0,
        conditions=[],
    )
    result = backend.wait(request, execution)
    assert result.outcome is SandboxOutcome.SUCCEEDED
    backend.cleanup(request, execution)
    assert batch.deleted[0]["preconditions"]["uid"] == execution.provider_uid
    assert len(networking.deleted) == 1


def test_kubernetes_conflicting_binding_and_uid_change_fail_closed() -> None:
    request = _request()
    backend, batch, _, _ = _kubernetes_backend()
    execution = backend.provision(request)
    batch.job.metadata.uid = "changed-uid"  # type: ignore[union-attr]
    with pytest.raises(SandboxRejected, match="UID changed"):
        backend.wait(request, execution)
    batch.job.metadata.labels["aegis.github.com/fence"] = "other"  # type: ignore[union-attr]
    assert backend.observe(request).state is BackendObservationState.CONFLICT
    with pytest.raises(SandboxRejected, match="conflicts"):
        backend.provision(request)


@pytest.mark.parametrize(
    ("failed", "reason", "pod_reason", "exit_code", "expected"),
    [
        (1, "DeadlineExceeded", None, None, SandboxOutcome.TIMED_OUT),
        (1, "BackoffLimitExceeded", "OOMKilled", 137, SandboxOutcome.OOM_KILLED),
        (1, "BackoffLimitExceeded", "Error", 42, SandboxOutcome.FAILED),
    ],
)
def test_kubernetes_terminal_timeout_oom_and_failure_mapping(
    failed: int,
    reason: str,
    pod_reason: str | None,
    exit_code: int | None,
    expected: SandboxOutcome,
) -> None:
    request = _request()
    backend, batch, _, core = _kubernetes_backend()
    execution = backend.provision(request)
    core.reason = pod_reason
    core.exit_code = exit_code
    batch.job.status = SimpleNamespace(  # type: ignore[union-attr]
        active=0,
        succeeded=0,
        failed=failed,
        conditions=[SimpleNamespace(reason=reason)],
    )
    result = backend.wait(request, execution)
    assert result.outcome is expected
    assert result.exit_code == exit_code


def test_kubernetes_provider_exceptions_and_malformed_create_fail_closed() -> None:
    class BrokenRead(FakeBatchApi):
        def read_namespaced_job(self, *, name: str, namespace: str) -> object:
            del name, namespace
            raise RuntimeError("sdk outage")

    backend, _, _, _ = _kubernetes_backend()
    backend._batch = BrokenRead()  # type: ignore[attr-defined]
    with pytest.raises(SandboxUnavailable, match="observation failed"):
        backend.observe(_request())

    class BrokenCreate(FakeBatchApi):
        def create_namespaced_job(
            self,
            *,
            namespace: str,
            body: Mapping[str, object],
        ) -> object:
            del namespace, body
            raise RuntimeError("ambiguous create")

    backend, _, _, _ = _kubernetes_backend()
    backend._batch = BrokenCreate()  # type: ignore[attr-defined]
    with pytest.raises(SandboxAmbiguous, match="ambiguous"):
        backend.provision(_request())

    class MissingUid(FakeBatchApi):
        def create_namespaced_job(
            self,
            *,
            namespace: str,
            body: Mapping[str, object],
        ) -> object:
            del namespace, body
            return SimpleNamespace(metadata=SimpleNamespace(uid=None))

    backend, _, _, _ = _kubernetes_backend()
    backend._batch = MissingUid()  # type: ignore[attr-defined]
    with pytest.raises(SandboxAmbiguous, match="no stable Job UID"):
        backend.provision(_request())


def test_kubernetes_cleanup_absence_config_and_static_builder_validation() -> None:
    request = _request()
    backend, batch, networking, _ = _kubernetes_backend()
    execution = backend.provision(request)
    batch.job = None
    backend.cleanup(request, execution)
    assert not batch.deleted
    assert len(networking.deleted) == 1

    with pytest.raises(ValueError, match="prerequisites"):
        KubernetesSandboxConfig(
            namespace="aegis",
            runtime_class="kata",
            service_account_name="sandbox",
            input_csi_driver="inputs",
            output_csi_driver="outputs",
            apparmor_profile="profile",
            admission_policy_refs=(),
        )
    with pytest.raises(ValueError, match="configuration"):
        KubernetesSandboxConfig(
            namespace="",
            runtime_class="kata",
            service_account_name="sandbox",
            input_csi_driver="inputs",
            output_csi_driver="outputs",
            apparmor_profile="profile",
            admission_policy_refs=("baseline",),
        )
    with pytest.raises(ValueError, match="static Kubernetes"):
        build_kubernetes_job_sandbox_backend(
            host="http://cluster.invalid",
            token="",
            ca_cert_path="relative.pem",
            readiness=Readiness(),
            config=KubernetesSandboxConfig(
                namespace="aegis",
                runtime_class="kata",
                service_account_name="sandbox",
                input_csi_driver="inputs",
                output_csi_driver="outputs",
                apparmor_profile="profile",
                admission_policy_refs=("baseline",),
            ),
            clock=FixedClock(NOW),
        )


def test_kubernetes_production_mode_uses_namespace_default_deny() -> None:
    backend, _, networking, _ = _kubernetes_backend()
    backend._config.manage_network_policy = False
    networking.policy = {
        "spec": {
            "podSelector": {},
            "policyTypes": ["Ingress", "Egress"],
        }
    }
    request = _request()
    execution = backend.provision(request)
    backend.cleanup(request, execution)
    assert networking.created == []
    assert networking.deleted == []
    networking.policy = {
        "spec": {
            "podSelector": {"matchLabels": {"unsafe": "true"}},
            "policyTypes": ["Ingress", "Egress"],
        }
    }
    with pytest.raises(SandboxRejected, match="incomplete"):
        backend.provision(request.model_copy(update={"execution_id": "execution:bad"}))
    networking.policy = None
    with pytest.raises(SandboxUnavailable, match="default-deny"):
        backend.provision(request.model_copy(update={"execution_id": "execution:two"}))


def test_kubernetes_rejects_unapproved_apparmor_and_delete_uid_change() -> None:
    request = _request()
    changed = request.spec.model_dump()
    changed["security"] = request.spec.security.model_copy(
        update={"apparmor_profile": "other-profile"}
    )
    changed["spec_digest"] = canonical_digest(
        {key: value for key, value in changed.items() if key != "spec_digest"}
    )
    changed_request = _request(spec=SandboxSpec.model_validate(changed))
    backend, _, _, _ = _kubernetes_backend()
    with pytest.raises(SandboxRejected, match="AppArmor"):
        backend.job_manifest(changed_request)

    backend, batch, _, _ = _kubernetes_backend()
    execution = backend.provision(request)
    batch.job.metadata.uid = "different-uid"  # type: ignore[union-attr]
    with pytest.raises(SandboxRejected, match="refusing to delete"):
        backend.cleanup(request, execution)


def test_kubernetes_network_policy_replay_mounts_and_runtime_binding() -> None:
    request = _request(
        spec=_spec(
            mounts=(
                MountReference(
                    source_ref="approved-readonly-reference",
                    target_path="inputs/reference",
                ),
            )
        )
    )
    backend, batch, networking, _ = _kubernetes_backend()
    execution = backend.provision(request)
    volumes = batch.created[0]["spec"]["template"]["spec"]["volumes"]  # type: ignore[index]
    mounts = batch.created[0]["spec"]["template"]["spec"]["containers"][0][  # type: ignore[index]
        "volumeMounts"
    ]
    assert any(
        volume.get("csi", {}).get("volumeAttributes", {}).get("sourceRef")
        == "approved-readonly-reference"
        for volume in volumes
    )
    assert any(
        mount.get("mountPath") == "/workspace/inputs/reference"
        and mount.get("readOnly") is True
        for mount in mounts
    )
    assert backend.provision(request) == execution
    assert len(networking.created) == 1

    bad_runtime = request.spec.model_dump()
    bad_runtime["required_runtime_class"] = "gvisor-aegis"
    bad_runtime["spec_digest"] = canonical_digest(
        {key: value for key, value in bad_runtime.items() if key != "spec_digest"}
    )
    with pytest.raises(SandboxRejected, match="RuntimeClass"):
        backend.job_manifest(_request(spec=SandboxSpec.model_validate(bad_runtime)))

    bad_admission = request.spec.model_dump()
    bad_admission["required_admission_policies"] = ("different-policy",)
    bad_admission["spec_digest"] = canonical_digest(
        {key: value for key, value in bad_admission.items() if key != "spec_digest"}
    )
    with pytest.raises(SandboxRejected, match="admission policy"):
        backend.job_manifest(_request(spec=SandboxSpec.model_validate(bad_admission)))


def test_kubernetes_ambiguous_job_create_reuses_matching_network_policy() -> None:
    class FailOnceBatch(FakeBatchApi):
        def __init__(self) -> None:
            super().__init__()
            self.fail = True

        def create_namespaced_job(
            self,
            *,
            namespace: str,
            body: Mapping[str, object],
        ) -> object:
            if self.fail:
                self.fail = False
                raise RuntimeError("timeout after network policy")
            return super().create_namespaced_job(namespace=namespace, body=body)

    request = _request()
    backend, _, networking, _ = _kubernetes_backend()
    batch = FailOnceBatch()
    backend._batch = batch  # type: ignore[attr-defined]
    with pytest.raises(SandboxAmbiguous):
        backend.provision(request)
    execution = backend.provision(request)
    assert execution.provider_uid == "job-uid-001"
    assert len(networking.created) == 1


def test_kubernetes_network_policy_and_pod_observation_fail_closed() -> None:
    request = _request()
    backend, batch, networking, core = _kubernetes_backend()
    execution = backend.provision(request)
    networking.policy.metadata.labels["aegis.github.com/fence"] = "wrong"  # type: ignore[union-attr]
    with pytest.raises(SandboxRejected, match="NetworkPolicy identity"):
        backend.provision(request)

    networking.policy.metadata.labels = backend._labels(request)  # type: ignore[union-attr,attr-defined]
    batch.job.status = SimpleNamespace(  # type: ignore[union-attr]
        active=0,
        succeeded=0,
        failed=1,
        conditions=[SimpleNamespace(reason="BackoffLimitExceeded")],
    )
    core.list_namespaced_pod = lambda **kwargs: SimpleNamespace(items="bad")  # type: ignore[method-assign]
    with pytest.raises(SandboxUnavailable, match="Pod response is malformed"):
        backend.wait(request, execution)


def test_kubernetes_official_builder_success_and_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Configuration:
        pass

    fake_module = SimpleNamespace(
        Configuration=Configuration,
        ApiClient=lambda configuration: configuration,
        BatchV1Api=lambda client: FakeBatchApi(),
        NetworkingV1Api=lambda client: FakeNetworkingApi(),
        CoreV1Api=lambda client: FakeCoreApi(),
    )
    monkeypatch.setattr(
        sandbox_adapters.importlib,
        "import_module",
        lambda name: fake_module,
    )
    config = KubernetesSandboxConfig(
        namespace="aegis",
        runtime_class="kata",
        service_account_name="sandbox",
        input_csi_driver="inputs",
        output_csi_driver="outputs",
        apparmor_profile="profile",
        admission_policy_refs=("baseline",),
    )
    assert isinstance(
        build_kubernetes_job_sandbox_backend(
            host="https://cluster.invalid",
            token="opaque-token",
            ca_cert_path="/etc/ssl/cluster.pem",
            readiness=Readiness(),
            config=config,
            clock=FixedClock(NOW),
        ),
        KubernetesJobSandboxBackend,
    )
    monkeypatch.setattr(
        sandbox_adapters.importlib,
        "import_module",
        lambda name: (_ for _ in ()).throw(ImportError(name)),
    )
    with pytest.raises(SandboxUnavailable, match="initialization failed"):
        build_kubernetes_job_sandbox_backend(
            host="https://cluster.invalid",
            token="opaque-token",
            ca_cert_path="/etc/ssl/cluster.pem",
            readiness=Readiness(),
            config=config,
            clock=FixedClock(NOW),
        )


def test_role_catalog_and_enterprise_policy_reach_sandbox_actions() -> None:
    permissions = set(RoleCatalog.permissions_for("incident-responder"))
    assert {
        Action.SANDBOX_EXECUTE.value,
        Action.SANDBOX_READ.value,
        Action.SANDBOX_ARTIFACT_READ.value,
    } <= permissions
    bundle = build_demo_bundle()
    identity = bundle.authenticator.authenticate(
        bearer_token="demo-responder-token",
        request_id="sandbox-enterprise-policy",
        trace_id="sandbox-enterprise-policy-trace",
    )
    assert bundle.policy.authorize(
        identity,
        Action.SANDBOX_EXECUTE,
        resource_tenant_id=TENANT,
        purpose="incident-response",
        risk=RiskLevel.MEDIUM,
    ).allowed
    assert not bundle.policy.authorize(
        identity,
        Action.SANDBOX_READ,
        resource_tenant_id="tenant-beta",
        purpose="incident-response",
        risk=RiskLevel.LOW,
    ).allowed


def _zip(entries: tuple[tuple[str, bytes, int | None], ...]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content, mode in entries:
            info = zipfile.ZipInfo(name)
            if mode is not None:
                info.external_attr = mode << 16
            archive.writestr(info, content)
    return stream.getvalue()


def test_safe_archive_extraction_is_atomic_bounded_and_content_preserving(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "workspace"
    extracted = safe_extract_zip(
        _zip(
            (
                ("source/input.txt", b"safe", None),
                ("reports/result.json", b"{}", None),
            )
        ),
        destination,
        maximum_members=5,
        maximum_uncompressed_bytes=1024,
        maximum_member_bytes=512,
    )
    assert [item.relative_to(destination).as_posix() for item in extracted] == [
        "source/input.txt",
        "reports/result.json",
    ]
    assert extracted[0].read_bytes() == b"safe"


@pytest.mark.parametrize(
    "payload",
    [
        _zip((("../escape", b"x", None),)),
        _zip((("/absolute", b"x", None),)),
        _zip(
            (
                ("same.txt", b"x", None),
                ("SAME.txt", b"y", None),
            )
        ),
        _zip((("link", b"target", stat.S_IFLNK | 0o777),)),
        _zip((("device", b"x", stat.S_IFCHR | 0o600),)),
        b"not-a-zip",
    ],
)
def test_archive_traversal_absolute_duplicate_symlink_device_and_malformed_denied(
    tmp_path: Path,
    payload: bytes,
) -> None:
    with pytest.raises((ArtifactQuarantined, ValueError, zipfile.BadZipFile)):
        safe_extract_zip(
            payload,
            tmp_path / "workspace",
            maximum_members=5,
            maximum_uncompressed_bytes=1024,
            maximum_member_bytes=512,
        )
    assert not (tmp_path / "workspace").exists()


def test_archive_bomb_and_oversized_member_are_quarantined(tmp_path: Path) -> None:
    bomb = _zip((("bomb.txt", b"0" * 50_000, None),))
    with pytest.raises(ArtifactQuarantined):
        safe_extract_zip(
            bomb,
            tmp_path / "workspace",
            maximum_members=2,
            maximum_uncompressed_bytes=10_000,
            maximum_member_bytes=10_000,
        )


def test_archive_empty_existing_destination_and_invalid_bounds_fail_closed(
    tmp_path: Path,
) -> None:
    empty = io.BytesIO()
    with zipfile.ZipFile(empty, "w"):
        pass
    with pytest.raises(ArtifactQuarantined, match="member count"):
        safe_extract_zip(
            empty.getvalue(),
            tmp_path / "empty",
            maximum_members=2,
            maximum_uncompressed_bytes=1_024,
            maximum_member_bytes=512,
        )
    destination = tmp_path / "existing"
    destination.mkdir()
    with pytest.raises(ArtifactQuarantined, match="already exists"):
        safe_extract_zip(
            _zip((("safe.txt", b"ok", None),)),
            destination,
            maximum_members=2,
            maximum_uncompressed_bytes=1_024,
            maximum_member_bytes=512,
        )
    with pytest.raises(ValueError, match="bounds"):
        safe_extract_zip(
            b"ignored",
            tmp_path / "invalid",
            maximum_members=0,
            maximum_uncompressed_bytes=1_024,
            maximum_member_bytes=512,
        )


def test_artifact_outputs_are_allowlisted_redacted_and_tenant_bound() -> None:
    request = _request()
    manifest = ArtifactProcessor(clock=FixedClock(NOW)).process(
        request,
        {
            "reports/result.json": (
                b'{"status":"ok","token":"ghp_abcdefghijklmnopqrstuvwxyz123456"}'
            )
        },
        {"reports/result.json": "application/json"},
    )
    assert manifest.tenant_id == TENANT
    assert manifest.manifest_digest == canonical_digest(manifest)
    assert len(manifest.artifacts) == 1
    artifact = manifest.artifacts[0]
    assert artifact.disposition is ArtifactDisposition.REDACTED
    assert artifact.redaction_count == 1
    assert artifact.object_ref is not None
    assert (
        artifact.content_hash
        != sha256(  # type: ignore[name-defined]
            b'{"status":"ok","token":"ghp_abcdefghijklmnopqrstuvwxyz123456"}'
        ).hexdigest()
    )


def test_artifact_unexpected_path_media_size_missing_and_invalid_utf8_fail_closed() -> (
    None
):
    request = _request()
    processor = ArtifactProcessor(clock=FixedClock(NOW))
    with pytest.raises(ArtifactQuarantined, match="unexpected"):
        processor.process(
            request,
            {"other.txt": b"x"},
            {"other.txt": "text/plain"},
        )
    with pytest.raises(ArtifactQuarantined, match="media type"):
        processor.process(
            request,
            {"reports/result.json": b"{}"},
            {"reports/result.json": "text/plain"},
        )
    with pytest.raises(ArtifactQuarantined, match="omitted"):
        processor.process(request, {}, {})

    optional = _request(
        spec=_spec(
            outputs=(
                OutputExpectation(
                    logical_path="reports/result.txt",
                    media_types=("text/plain",),
                    required=False,
                ),
            )
        )
    )
    manifest = processor.process(
        optional,
        {"reports/result.txt": b"\xff"},
        {"reports/result.txt": "text/plain"},
    )
    assert manifest.artifacts[0].disposition is ArtifactDisposition.QUARANTINED
    assert manifest.artifacts[0].object_ref is None

    tiny_request = _request(
        spec=_spec(
            resources=_resources(
                output_bytes=1_024,
                output_file_bytes=1_024,
            )
        )
    )
    with pytest.raises(ArtifactQuarantined, match="file exceeds"):
        processor.process(
            tiny_request,
            {"reports/result.json": b"x" * 1_025},
            {"reports/result.json": "application/json"},
        )


def test_fact_contract_requires_request_first_and_chain_order() -> None:
    material = {
        "schema_version": 1,
        "tenant_id": TENANT,
        "execution_id": "sandbox-execution-001",
        "sequence": 2,
        "fact_id": "fact-2",
        "fact_type": SandboxFactType.STARTED,
        "command_id": "started",
        "actor_ref": "worker",
        "recorded_at": NOW.isoformat().replace("+00:00", "Z"),
        "payload": {},
        "previous_digest": "0" * 64,
    }
    fact = SandboxFact(
        tenant_id=TENANT,
        execution_id="sandbox-execution-001",
        sequence=2,
        fact_id="fact-2",
        fact_type=SandboxFactType.STARTED,
        command_id="started",
        actor_ref="worker",
        recorded_at=NOW,
        payload={},
        previous_digest="0" * 64,
        canonical_digest=canonical_digest(material),
    )
    with pytest.raises(IntegrityFailure, match="begin with a request"):
        reduce_sandbox(None, fact)


def test_temporal_sandbox_activity_wrapper_heartbeats_and_cancels_pulse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    heartbeat_calls: list[object] = []
    pulse_cancelled = asyncio.Event()
    monkeypatch.setattr(
        sandbox_temporal.activity,
        "heartbeat",
        heartbeat_calls.append,
    )

    async def pulse(operation_id: str) -> None:
        assert operation_id == "sandbox-operation"
        try:
            await asyncio.Event().wait()
        finally:
            pulse_cancelled.set()

    monkeypatch.setattr(
        TemporalSandboxActivities,
        "_heartbeat",
        staticmethod(pulse),
    )

    async def operation(value: SandboxActivityInput) -> SandboxActivityOutcome:
        assert value.execution_id == "sandbox-execution-001"
        await asyncio.sleep(0)
        return SandboxActivityOutcome(outcome="recorded")

    value = SandboxActivityInput(
        tenant_ref="tenant:opaque",
        actor_ref="actor:opaque",
        request_ref="request:opaque",
        execution_id="sandbox-execution-001",
        operation_id="sandbox-operation",
        attempt=1,
    )
    result = asyncio.run(TemporalSandboxActivities._invoke(operation, value))
    assert result.outcome == "recorded"
    assert heartbeat_calls == [{"operation_id": "sandbox-operation"}]
    assert pulse_cancelled.is_set()


def test_authorized_sandbox_status_and_artifact_apis_are_redacted() -> None:
    request = _request()
    ledger = InMemorySandboxLedger()
    projection = SandboxControlService(
        application_policy=AllowingPolicy(),
        sandbox_policy=_policy(),
        approvals=ApprovalBindings(request.spec.approval),
        quotas=InMemorySandboxQuota({TENANT: 1}),
        ledger=ledger,
        clock=FixedClock(NOW),
    ).request(
        _identity(),
        request,
        active_executions=0,
        command_id="api-submit",
    )
    artifact = (
        ArtifactProcessor(clock=FixedClock(NOW))
        .process(
            request,
            {"reports/result.json": b'{"status":"ok"}'},
            {"reports/result.json": "application/json"},
        )
        .artifacts[0]
    )

    class Authenticator:
        def ready(self) -> bool:
            return True

        def authenticate(
            self,
            *,
            bearer_token: str,
            request_id: str,
            trace_id: str,
        ) -> IdentityContext:
            if bearer_token != "sandbox-token":
                raise AuthenticationFailed("invalid token")
            return _identity(
                actions=(Action.SANDBOX_READ, Action.SANDBOX_ARTIFACT_READ)
            ).model_copy(update={"request_id": request_id, "trace_id": trace_id})

    class Control:
        def projection(
            self,
            *,
            tenant_id: str,
            execution_id: str,
        ) -> object:
            if tenant_id == TENANT and execution_id == request.execution_id:
                return projection
            return None

        def artifacts(
            self,
            *,
            tenant_id: str,
            execution_id: str,
        ) -> tuple[object, ...]:
            if tenant_id == TENANT and execution_id == request.execution_id:
                return (artifact,)
            return ()

    bundle = build_demo_bundle()
    runtime = ApiRuntime(
        authenticator=Authenticator(),
        governance=bundle.governance,
        policy=AllowingPolicy(),
        service_for=lambda scenario: bundle.service,
        sandbox_control=Control(),  # type: ignore[arg-type]
    )
    client = TestClient(create_app(mode=AppMode.TEST, runtime=runtime))
    headers = {
        "Authorization": "Bearer sandbox-token",
        "X-Request-ID": "sandbox-api-read",
    }
    status = client.get(
        f"/v1/sandboxes/{request.execution_id}",
        headers=headers,
    )
    assert status.status_code == 200
    assert status.json()["status"] == projection.status.value
    assert "tenant_id" not in status.text
    assert "fence_token" not in status.text
    artifacts = client.get(
        f"/v1/sandboxes/{request.execution_id}/artifacts",
        headers=headers,
    )
    assert artifacts.status_code == 200
    assert artifacts.json()[0]["logical_path"] == "reports/result.json"
    assert "object_ref" not in artifacts.text
    assert "tenant_id" not in artifacts.text

    missing = client.get(
        "/v1/sandboxes/unknown-execution",
        headers={
            "Authorization": "Bearer sandbox-token",
            "X-Request-ID": "sandbox-api-missing",
        },
    )
    assert missing.status_code == 404
