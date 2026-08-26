"""Deterministic and hardened Kubernetes sandbox backend adapters."""

from __future__ import annotations

import importlib
import io
import os
import re
import shutil
import stat
import tempfile
import zipfile
from collections.abc import Mapping, Sequence
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Protocol, cast

from aegis_framework.domain import stable_id
from aegis_framework.errors import (
    ArtifactQuarantined,
    SandboxAmbiguous,
    SandboxRejected,
    SandboxUnavailable,
)
from aegis_framework.ports import ClockPort
from aegis_framework.sandbox import (
    ArtifactDisposition,
    ArtifactManifest,
    ArtifactRecord,
    BackendExecution,
    BackendObservation,
    BackendObservationState,
    NetworkMode,
    SandboxExecutionRequest,
    SandboxOutcome,
    SandboxResult,
    canonical_digest,
    validate_relative_path,
)

_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.I),
    re.compile(r"\bgh[opsu]_[A-Za-z0-9]{20,255}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"(?i)\b(?:api[_-]?key|password|secret|token)\s*[:=]\s*[^\s,;]{8,}"),
)
_CONTAINER_TMP = str(PurePosixPath("/") / "tmp")
_NORMALIZED_KEY = re.compile(r"[^a-z0-9]+")


class KubernetesBatchApi(Protocol):
    def read_namespaced_job(self, *, name: str, namespace: str) -> object: ...

    def create_namespaced_job(
        self,
        *,
        namespace: str,
        body: Mapping[str, object],
    ) -> object: ...

    def delete_namespaced_job(
        self,
        *,
        name: str,
        namespace: str,
        body: Mapping[str, object],
    ) -> object: ...


class KubernetesNetworkingApi(Protocol):
    def read_namespaced_network_policy(
        self,
        *,
        name: str,
        namespace: str,
    ) -> object: ...

    def create_namespaced_network_policy(
        self,
        *,
        namespace: str,
        body: Mapping[str, object],
    ) -> object: ...

    def delete_namespaced_network_policy(
        self,
        *,
        name: str,
        namespace: str,
        body: Mapping[str, object],
    ) -> object: ...


class KubernetesCoreApi(Protocol):
    def list_namespaced_pod(
        self,
        *,
        namespace: str,
        label_selector: str,
        limit: int,
    ) -> object: ...


class KubernetesReadinessProbe(Protocol):
    def admission_policy_ready(self, policy_ref: str) -> bool: ...

    def runtime_class_ready(self, runtime_class: str) -> bool: ...

    def network_policy_ready(self, namespace: str) -> bool: ...

    def workload_identity_ready(self, namespace: str) -> bool: ...


class KubernetesSandboxConfig:
    """Static trusted deployment configuration, never model-provided."""

    def __init__(
        self,
        *,
        namespace: str,
        runtime_class: str,
        service_account_name: str,
        input_csi_driver: str,
        output_csi_driver: str,
        apparmor_profile: str,
        admission_policy_refs: tuple[str, ...],
        enabled: bool = False,
        external_egress_proxy_enforced: bool = False,
    ) -> None:
        for value in (
            namespace,
            runtime_class,
            service_account_name,
            input_csi_driver,
            output_csi_driver,
            apparmor_profile,
            *admission_policy_refs,
        ):
            if not value or len(value) > 128:
                raise ValueError("Kubernetes sandbox configuration is invalid")
        if not admission_policy_refs:
            raise ValueError("admission policy prerequisites are required")
        self.namespace = namespace
        self.runtime_class = runtime_class
        self.service_account_name = service_account_name
        self.input_csi_driver = input_csi_driver
        self.output_csi_driver = output_csi_driver
        self.apparmor_profile = apparmor_profile
        self.admission_policy_refs = admission_policy_refs
        self.enabled = enabled
        self.external_egress_proxy_enforced = external_egress_proxy_enforced


def _get(value: object, *names: str) -> object | None:
    current: object | None = value
    for name in names:
        if current is None:
            return None
        current = (
            current.get(name)
            if isinstance(current, Mapping)
            else getattr(current, name, None)
        )
    return current


def _normalize_key(value: str) -> str:
    return _NORMALIZED_KEY.sub("", value.lower())


def _normalize_object(value: object) -> object:
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _normalize_object(value.to_dict())
    if isinstance(value, Mapping):
        return {
            _normalize_key(str(key)): _normalize_object(item)
            for key, item in value.items()
        }
    if hasattr(value, "__dict__") and not isinstance(value, type):
        return _normalize_object(vars(value))
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_normalize_object(item) for item in value]
    return value


def _normalized_get(value: object, *names: str) -> object | None:
    current: object | None = _normalize_object(value)
    for name in names:
        if not isinstance(current, Mapping):
            return None
        current = current.get(_normalize_key(name))
    return current


class KubernetesJobSandboxBackend:
    """Official-client Job adapter; cluster isolation still depends on deployment."""

    _MANAGED_BY = "aegis-sandbox-v1"

    def __init__(
        self,
        *,
        batch_api: KubernetesBatchApi,
        networking_api: KubernetesNetworkingApi,
        core_api: KubernetesCoreApi,
        readiness: KubernetesReadinessProbe,
        config: KubernetesSandboxConfig,
        clock: ClockPort,
    ) -> None:
        self._batch = batch_api
        self._networking = networking_api
        self._core = core_api
        self._readiness = readiness
        self._config = config
        self._clock = clock

    def ready(self) -> bool:
        return bool(
            self._config.enabled
            and self._readiness.runtime_class_ready(self._config.runtime_class)
            and self._readiness.network_policy_ready(self._config.namespace)
            and self._readiness.workload_identity_ready(self._config.namespace)
            and all(
                self._readiness.admission_policy_ready(policy)
                for policy in self._config.admission_policy_refs
            )
        )

    def observe(self, request: SandboxExecutionRequest) -> BackendObservation:
        self._require_ready(request)
        try:
            job = self._batch.read_namespaced_job(
                name=self._job_name(request),
                namespace=self._config.namespace,
            )
        except Exception as exc:
            if getattr(exc, "status", None) == 404:
                return BackendObservation(
                    execution_id=request.execution_id,
                    state=BackendObservationState.ABSENT,
                    attempt=request.attempt,
                    fence_token=request.fence_token,
                    observed_at=self._clock.now(),
                )
            raise SandboxUnavailable("Kubernetes Job observation failed") from exc
        metadata = _get(job, "metadata")
        labels = _get(metadata, "labels")
        uid = _get(metadata, "uid")
        if (
            not isinstance(labels, Mapping)
            or labels.get("app.kubernetes.io/managed-by") != self._MANAGED_BY
            or labels.get("aegis.github.com/tenant")
            != self._label_value("tenant", request.tenant_id)
            or labels.get("aegis.github.com/execution")
            != self._label_value("execution", request.execution_id)
            or labels.get("aegis.github.com/request-digest")
            != request.request_digest[:32]
            or labels.get("aegis.github.com/fence")
            != self._label_value("fence", request.fence_token)
            or not isinstance(uid, str)
            or not uid
            or not self._job_matches_request(job, request)
        ):
            return BackendObservation(
                execution_id=request.execution_id,
                state=BackendObservationState.CONFLICT,
                provider_uid=(uid if isinstance(uid, str) and uid else None),
                attempt=request.attempt,
                fence_token=request.fence_token,
                observed_at=self._clock.now(),
            )
        active = _get(job, "status", "active")
        succeeded = _get(job, "status", "succeeded")
        failed = _get(job, "status", "failed")
        if (isinstance(succeeded, int) and succeeded > 0) or (
            isinstance(failed, int) and failed
        ):
            state = BackendObservationState.TERMINAL
        elif isinstance(active, int) and active > 0:
            state = BackendObservationState.RUNNING
        else:
            state = BackendObservationState.PROVISIONING
        return BackendObservation(
            execution_id=request.execution_id,
            state=state,
            provider_uid=uid,
            attempt=request.attempt,
            fence_token=request.fence_token,
            observed_at=self._clock.now(),
        )

    def provision(self, request: SandboxExecutionRequest) -> BackendExecution:
        observation = self.observe(request)
        if observation.state is BackendObservationState.CONFLICT:
            raise SandboxRejected("Kubernetes Job identity binding conflicts")
        if observation.state is not BackendObservationState.ABSENT:
            if observation.provider_uid is None:
                raise SandboxAmbiguous("existing Kubernetes Job has no stable UID")
            self._require_network_policy(request)
            return BackendExecution(
                execution_id=request.execution_id,
                provider_ref=self._job_name(request),
                provider_uid=observation.provider_uid,
                attempt=request.attempt,
                fence_token=request.fence_token,
                provisioned_at=observation.observed_at,
            )
        try:
            self._ensure_network_policy(request)
            job = self._batch.create_namespaced_job(
                namespace=self._config.namespace,
                body=self.job_manifest(request),
            )
        except Exception as exc:
            if getattr(exc, "status", None) == 409:
                observation = self.observe(request)
                if observation.state is BackendObservationState.CONFLICT:
                    raise SandboxRejected(
                        "Kubernetes Job identity binding conflicts"
                    ) from exc
                if observation.state is not BackendObservationState.ABSENT:
                    if observation.provider_uid is None:
                        raise SandboxAmbiguous(
                            "existing Kubernetes Job has no stable UID"
                        ) from exc
                    self._require_network_policy(request)
                    return BackendExecution(
                        execution_id=request.execution_id,
                        provider_ref=self._job_name(request),
                        provider_uid=observation.provider_uid,
                        attempt=request.attempt,
                        fence_token=request.fence_token,
                        provisioned_at=observation.observed_at,
                    )
            raise SandboxAmbiguous(
                "Kubernetes create outcome is ambiguous; reconcile by identity"
            ) from exc
        uid = _get(job, "metadata", "uid")
        if not isinstance(uid, str) or not uid:
            raise SandboxAmbiguous("Kubernetes create returned no stable Job UID")
        return BackendExecution(
            execution_id=request.execution_id,
            provider_ref=self._job_name(request),
            provider_uid=uid,
            attempt=request.attempt,
            fence_token=request.fence_token,
            provisioned_at=self._clock.now(),
        )

    def wait(
        self,
        request: SandboxExecutionRequest,
        execution: BackendExecution,
    ) -> SandboxResult:
        observation = self.observe(request)
        if observation.provider_uid != execution.provider_uid:
            raise SandboxRejected("Kubernetes Job UID changed during execution")
        if observation.state is not BackendObservationState.TERMINAL:
            raise SandboxUnavailable("Kubernetes Job is not terminal")
        try:
            job = self._batch.read_namespaced_job(
                name=execution.provider_ref,
                namespace=self._config.namespace,
            )
        except Exception as exc:
            raise SandboxUnavailable("Kubernetes terminal Job read failed") from exc
        failed = _get(job, "status", "failed")
        succeeded = _get(job, "status", "succeeded")
        conditions = _get(job, "status", "conditions")
        reason = _terminal_reason(conditions)
        pod_reason, pod_exit_code = self._pod_termination(execution)
        if reason == "DeadlineExceeded":
            outcome, detail, exit_code = (
                SandboxOutcome.TIMED_OUT,
                "deadline_exceeded",
                None,
            )
        elif pod_reason == "OOMKilled":
            outcome, detail, exit_code = (
                SandboxOutcome.OOM_KILLED,
                "oom_killed",
                pod_exit_code,
            )
        elif isinstance(failed, int) and failed > 0:
            outcome, detail, exit_code = (
                SandboxOutcome.FAILED,
                "job_failed",
                pod_exit_code,
            )
        elif isinstance(succeeded, int) and succeeded > 0:
            outcome, detail, exit_code = (
                SandboxOutcome.SUCCEEDED,
                "job_succeeded",
                pod_exit_code if pod_exit_code is not None else 0,
            )
        else:
            raise SandboxUnavailable("Kubernetes terminal Job status is incomplete")
        material = {
            "schema_version": 1,
            "tenant_id": request.tenant_id,
            "run_id": request.run_id,
            "task_id": request.task_id,
            "execution_id": request.execution_id,
            "request_digest": request.request_digest,
            "spec_digest": request.spec_digest,
            "policy_digest": request.policy_digest,
            "approval_digest": request.approval_digest,
            "provider_uid": execution.provider_uid,
            "attempt": request.attempt,
            "fence_token": request.fence_token,
            "outcome": outcome,
            "exit_code": exit_code,
            "output_bytes": 0,
            "output_files": 0,
            "started_at": execution.provisioned_at,
            "completed_at": self._clock.now(),
            "detail_code": detail,
            "manifest_digest": None,
        }
        return SandboxResult(**material, result_digest=canonical_digest(material))

    def cancel(
        self,
        request: SandboxExecutionRequest,
        execution: BackendExecution,
    ) -> None:
        self._delete(request, execution)

    def cleanup(
        self,
        request: SandboxExecutionRequest,
        execution: BackendExecution,
    ) -> None:
        self._delete(request, execution)

    def _delete(
        self,
        request: SandboxExecutionRequest,
        execution: BackendExecution,
    ) -> None:
        observation = self.observe(request)
        if (
            observation.state is not BackendObservationState.ABSENT
            and observation.provider_uid != execution.provider_uid
        ):
            raise SandboxRejected("refusing to delete a different Kubernetes Job UID")
        preconditions = {"preconditions": {"uid": execution.provider_uid}}
        try:
            if observation.state is not BackendObservationState.ABSENT:
                try:
                    self._batch.delete_namespaced_job(
                        name=execution.provider_ref,
                        namespace=self._config.namespace,
                        body={
                            **preconditions,
                            "propagationPolicy": "Foreground",
                            "gracePeriodSeconds": 0,
                        },
                    )
                except Exception as exc:
                    if getattr(exc, "status", None) != 404:
                        raise
            # Only delete the NetworkPolicy after confirming the Job and its
            # Pods are no longer present. Foreground propagation has initiated
            # deletion above, but the Kubernetes API returns before Pods are
            # gone. Re-observe here; if any workload remains the cleanup
            # outcome will be "ambiguous" and the reconcile path will call
            # _delete_network_policy once absence is confirmed.
            post_observation = self.observe(request)
            if post_observation.state is BackendObservationState.ABSENT:
                self._delete_network_policy(request)
        except Exception as exc:
            raise SandboxAmbiguous(
                "Kubernetes delete outcome is ambiguous; reconcile by UID"
            ) from exc

    def _require_ready(self, request: SandboxExecutionRequest) -> None:
        if not self.ready():
            raise SandboxUnavailable(
                "sandbox admission/runtime/network/workload-identity prerequisites "
                "are not ready"
            )
        if request.spec.security.apparmor_profile != self._config.apparmor_profile:
            raise SandboxRejected("sandbox AppArmor profile is not deployment-approved")
        if request.spec.required_runtime_class != self._config.runtime_class:
            raise SandboxRejected("sandbox RuntimeClass requirement is not satisfied")
        if (
            request.spec.required_admission_policies
            != self._config.admission_policy_refs
        ):
            raise SandboxRejected(
                "sandbox admission policy requirements are not satisfied"
            )
        if request.spec.network.mode is NetworkMode.EXACT_DESTINATIONS:
            raise SandboxRejected(
                "exact DNS egress proxy policy registration is not implemented; "
                "standard Kubernetes NetworkPolicy cannot enforce FQDN destinations"
            )

    def job_manifest(self, request: SandboxExecutionRequest) -> Mapping[str, object]:
        self._require_ready(request)
        spec = request.spec
        labels = self._labels(request)
        input_volumes = [
            {
                "name": f"input-{index}",
                "csi": {
                    "driver": self._config.input_csi_driver,
                    "readOnly": True,
                    "volumeAttributes": {
                        "objectRef": item.object_ref,
                        "contentHash": item.content_hash,
                        "tenantBinding": stable_id(
                            "tenant", request.tenant_id, length=32
                        ),
                    },
                },
            }
            for index, item in enumerate(spec.inputs)
        ]
        input_mounts = [
            {
                "name": f"input-{index}",
                "mountPath": f"/workspace/inputs/{item.logical_path}",
                "readOnly": True,
                "subPath": item.logical_path.rsplit("/", maxsplit=1)[-1],
            }
            for index, item in enumerate(spec.inputs)
        ]
        reference_volumes = [
            {
                "name": f"mount-{index}",
                "csi": {
                    "driver": self._config.input_csi_driver,
                    "readOnly": True,
                    "volumeAttributes": {
                        "sourceRef": item.source_ref,
                        "tenantBinding": sha256(
                            f"tenant\x00{request.tenant_id}".encode()
                        ).hexdigest(),
                    },
                },
            }
            for index, item in enumerate(spec.mounts)
        ]
        reference_mounts = [
            {
                "name": f"mount-{index}",
                "mountPath": f"/workspace/{item.target_path}",
                "readOnly": True,
            }
            for index, item in enumerate(spec.mounts)
        ]
        secret_env = [
            {
                "name": item.env_name,
                "valueFrom": {
                    "secretKeyRef": {
                        "name": item.reference,
                        "key": f"v{item.version}",
                        "optional": False,
                    }
                },
            }
            for item in spec.secrets
        ]
        security = spec.security
        return {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": self._job_name(request),
                "namespace": self._config.namespace,
                "labels": labels,
            },
            "spec": {
                "backoffLimit": 0,
                "activeDeadlineSeconds": spec.resources.timeout_seconds,
                "template": {
                    "metadata": {
                        "labels": labels,
                        "annotations": {
                            "container.apparmor.security.beta.kubernetes.io/sandbox": (
                                f"localhost/{self._config.apparmor_profile}"
                            )
                        },
                    },
                    "spec": {
                        "restartPolicy": "Never",
                        "runtimeClassName": self._config.runtime_class,
                        "serviceAccountName": self._config.service_account_name,
                        "automountServiceAccountToken": False,
                        "enableServiceLinks": False,
                        "hostNetwork": False,
                        "hostPID": False,
                        "hostIPC": False,
                        "securityContext": {
                            "runAsNonRoot": True,
                            "runAsUser": security.run_as_user,
                            "runAsGroup": security.run_as_group,
                            "fsGroup": security.fs_group,
                            "seccompProfile": {"type": "RuntimeDefault"},
                            "supplementalGroups": [],
                        },
                        "containers": [
                            {
                                "name": "sandbox",
                                "image": spec.image,
                                "imagePullPolicy": "IfNotPresent",
                                "command": [spec.argv[0]],
                                "args": list(spec.argv[1:]),
                                "workingDir": "/workspace",
                                "env": [
                                    *(
                                        {"name": item.name, "value": item.value}
                                        for item in spec.environment
                                    ),
                                    *secret_env,
                                ],
                                "securityContext": {
                                    "allowPrivilegeEscalation": False,
                                    "privileged": False,
                                    "readOnlyRootFilesystem": True,
                                    "runAsNonRoot": True,
                                    "runAsUser": security.run_as_user,
                                    "runAsGroup": security.run_as_group,
                                    "capabilities": {"drop": ["ALL"], "add": []},
                                    "seccompProfile": {"type": "RuntimeDefault"},
                                    "appArmorProfile": {
                                        "type": "Localhost",
                                        "localhostProfile": (
                                            self._config.apparmor_profile
                                        ),
                                    },
                                },
                                "resources": {
                                    "requests": {
                                        "cpu": f"{spec.resources.cpu_millicores}m",
                                        "memory": f"{spec.resources.memory_mib}Mi",
                                        "ephemeral-storage": (
                                            f"{spec.resources.ephemeral_storage_mib}Mi"
                                        ),
                                    },
                                    "limits": {
                                        "cpu": f"{spec.resources.cpu_millicores}m",
                                        "memory": f"{spec.resources.memory_mib}Mi",
                                        "ephemeral-storage": (
                                            f"{spec.resources.ephemeral_storage_mib}Mi"
                                        ),
                                    },
                                },
                                "volumeMounts": [
                                    {
                                        "name": "workspace",
                                        "mountPath": "/workspace",
                                    },
                                    {
                                        "name": "tmp",
                                        "mountPath": _CONTAINER_TMP,
                                    },
                                    *input_mounts,
                                    *reference_mounts,
                                ],
                            }
                        ],
                        "volumes": [
                            {
                                "name": "workspace",
                                "csi": {
                                    "driver": self._config.output_csi_driver,
                                    "readOnly": False,
                                    "volumeAttributes": {
                                        "executionRef": request.execution_id,
                                        "requestDigest": request.request_digest,
                                        "tenantBinding": stable_id(
                                            "tenant", request.tenant_id, length=32
                                        ),
                                    },
                                },
                            },
                            {
                                "name": "tmp",
                                "emptyDir": {
                                    "medium": "Memory",
                                    "sizeLimit": "64Mi",
                                },
                            },
                            *input_volumes,
                            *reference_volumes,
                        ],
                    },
                },
            },
        }

    def network_policy_manifest(
        self,
        request: SandboxExecutionRequest,
    ) -> Mapping[str, object]:
        self._require_ready(request)
        return {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": self._network_policy_name(request),
                "namespace": self._config.namespace,
                "labels": self._labels(request),
            },
            "spec": {
                "podSelector": {
                    "matchLabels": {
                        "aegis.github.com/tenant": self._label_value(
                            "tenant",
                            request.tenant_id,
                        ),
                        "aegis.github.com/execution": self._label_value(
                            "execution",
                            request.execution_id,
                        ),
                    }
                },
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [],
                "egress": [],
            },
        }

    def _labels(self, request: SandboxExecutionRequest) -> dict[str, str]:
        return {
            "app.kubernetes.io/managed-by": self._MANAGED_BY,
            "aegis.github.com/tenant": self._label_value(
                "tenant",
                request.tenant_id,
            ),
            "aegis.github.com/execution": self._label_value(
                "execution",
                request.execution_id,
            ),
            "aegis.github.com/request-digest": request.request_digest[:32],
            "aegis.github.com/fence": self._label_value(
                "fence",
                request.fence_token,
            ),
            "aegis.github.com/attempt": str(request.attempt),
        }

    @staticmethod
    def _job_name(request: SandboxExecutionRequest) -> str:
        digest = sha256(
            f"job\x00{request.tenant_id}\x00{request.execution_id}".encode()
        ).hexdigest()[:32]
        return f"aegis-sandbox-job-{digest}"

    @staticmethod
    def _network_policy_name(request: SandboxExecutionRequest) -> str:
        digest = sha256(
            f"network\x00{request.tenant_id}\x00{request.execution_id}".encode()
        ).hexdigest()[:32]
        return f"aegis-sandbox-net-{digest}"

    @staticmethod
    def _label_value(kind: str, value: str) -> str:
        return sha256(f"{kind}\x00{value}".encode()).hexdigest()[:32]

    def _network_policy(self, request: SandboxExecutionRequest) -> object | None:
        try:
            return self._networking.read_namespaced_network_policy(
                name=self._network_policy_name(request),
                namespace=self._config.namespace,
            )
        except Exception as exc:
            if getattr(exc, "status", None) == 404:
                return None
            raise SandboxUnavailable(
                "Kubernetes NetworkPolicy observation failed"
            ) from exc

    def _require_network_policy(self, request: SandboxExecutionRequest) -> object:
        policy = self._network_policy(request)
        labels = _get(policy, "metadata", "labels")
        expected = self._labels(request)
        if (
            policy is None
            or not isinstance(labels, Mapping)
            or any(labels.get(key) != value for key, value in expected.items())
            or not self._network_policy_matches_request(policy, request)
        ):
            raise SandboxRejected("Kubernetes NetworkPolicy identity binding conflicts")
        return policy

    def _ensure_network_policy(self, request: SandboxExecutionRequest) -> None:
        existing = self._network_policy(request)
        if existing is not None:
            self._require_network_policy(request)
            return
        try:
            self._networking.create_namespaced_network_policy(
                namespace=self._config.namespace,
                body=self.network_policy_manifest(request),
            )
        except Exception as exc:
            if getattr(exc, "status", None) == 409:
                self._require_network_policy(request)
                return
            raise

    def _delete_network_policy(self, request: SandboxExecutionRequest) -> None:
        policy = self._network_policy(request)
        if policy is None:
            return
        self._require_network_policy(request)
        try:
            self._networking.delete_namespaced_network_policy(
                name=self._network_policy_name(request),
                namespace=self._config.namespace,
                body={},
            )
        except Exception as exc:
            if getattr(exc, "status", None) != 404:
                raise

    def _pod_termination(
        self,
        execution: BackendExecution,
    ) -> tuple[str | None, int | None]:
        try:
            response = self._core.list_namespaced_pod(
                namespace=self._config.namespace,
                label_selector=f"job-name={execution.provider_ref}",
                limit=4,
            )
        except Exception as exc:
            raise SandboxUnavailable("Kubernetes Job Pod observation failed") from exc
        items = _get(response, "items")
        if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
            raise SandboxUnavailable("Kubernetes Job Pod response is malformed")
        terminations: list[tuple[str | None, int | None]] = []
        for pod in items:
            owners = _get(pod, "metadata", "owner_references")
            if not isinstance(owners, Sequence) or isinstance(owners, (str, bytes)):
                continue
            if not any(
                _get(owner, "uid") == execution.provider_uid for owner in owners
            ):
                continue
            statuses = _get(pod, "status", "container_statuses")
            if not isinstance(statuses, Sequence) or isinstance(statuses, (str, bytes)):
                continue
            for status in statuses:
                terminated = _get(status, "state", "terminated")
                reason = _get(terminated, "reason")
                exit_code = _get(terminated, "exit_code")
                if terminated is not None:
                    terminations.append(
                        (
                            reason if isinstance(reason, str) else None,
                            exit_code if isinstance(exit_code, int) else None,
                        )
                    )
        if any(reason == "OOMKilled" for reason, _ in terminations):
            return next(item for item in terminations if item[0] == "OOMKilled")
        return terminations[-1] if terminations else (None, None)

    def _job_matches_request(
        self,
        job: object,
        request: SandboxExecutionRequest,
    ) -> bool:
        expected = _normalize_object(self.job_manifest(request))
        actual = _normalize_object(job)
        return bool(
            self._matches_paths(
                actual,
                expected,
                (
                    ("spec", "backoffLimit"),
                    ("spec", "activeDeadlineSeconds"),
                    ("spec", "template", "metadata", "annotations"),
                    ("spec", "template", "metadata", "labels"),
                    ("spec", "template", "spec", "restartPolicy"),
                    ("spec", "template", "spec", "runtimeClassName"),
                    ("spec", "template", "spec", "serviceAccountName"),
                    ("spec", "template", "spec", "automountServiceAccountToken"),
                    ("spec", "template", "spec", "enableServiceLinks"),
                    ("spec", "template", "spec", "hostNetwork"),
                    ("spec", "template", "spec", "hostPID"),
                    ("spec", "template", "spec", "hostIPC"),
                    ("spec", "template", "spec", "securityContext"),
                    ("spec", "template", "spec", "containers"),
                    ("spec", "template", "spec", "volumes"),
                ),
            )
            and not self._contains_host_path(job)
        )

    def _network_policy_matches_request(
        self,
        policy: object,
        request: SandboxExecutionRequest,
    ) -> bool:
        expected = _normalize_object(self.network_policy_manifest(request))
        actual = _normalize_object(policy)
        return self._matches_paths(
            actual,
            expected,
            (
                ("spec", "podSelector", "matchLabels"),
                ("spec", "policyTypes"),
                ("spec", "ingress"),
                ("spec", "egress"),
            ),
        )

    @staticmethod
    def _matches_paths(
        actual: object,
        expected: object,
        paths: Sequence[tuple[str, ...]],
    ) -> bool:
        return all(
            _normalized_get(actual, *path) == _normalized_get(expected, *path)
            for path in paths
        )

    @staticmethod
    def _contains_host_path(job: object) -> bool:
        volumes = _normalized_get(job, "spec", "template", "spec", "volumes")
        if not isinstance(volumes, Sequence) or isinstance(volumes, (str, bytes)):
            return False
        return any(
            isinstance(volume, Mapping) and "hostpath" in volume for volume in volumes
        )


def build_kubernetes_job_sandbox_backend(
    *,
    host: str,
    token: str,
    ca_cert_path: str,
    readiness: KubernetesReadinessProbe,
    config: KubernetesSandboxConfig,
    clock: ClockPort,
) -> KubernetesJobSandboxBackend:
    """Build with the official client and static TLS/token configuration only."""

    if (
        not host.startswith("https://")
        or not token
        or not ca_cert_path
        or not os.path.isabs(ca_cert_path)
    ):
        raise ValueError("static Kubernetes TLS configuration is required")
    try:
        client = importlib.import_module("kubernetes.client")
        configuration = client.Configuration()
        configuration.host = host
        configuration.api_key = {"authorization": token}
        configuration.api_key_prefix = {"authorization": "Bearer"}
        configuration.ssl_ca_cert = ca_cert_path
        configuration.verify_ssl = True
        configuration.proxy = None
        configuration.proxy_headers = None
        api_client = client.ApiClient(configuration=configuration)
        batch = client.BatchV1Api(api_client)
        networking = client.NetworkingV1Api(api_client)
        core = client.CoreV1Api(api_client)
    except Exception as exc:
        raise SandboxUnavailable(
            "official Kubernetes client initialization failed"
        ) from exc
    return KubernetesJobSandboxBackend(
        batch_api=cast(KubernetesBatchApi, batch),
        networking_api=cast(KubernetesNetworkingApi, networking),
        core_api=cast(KubernetesCoreApi, core),
        readiness=readiness,
        config=config,
        clock=clock,
    )


class DeterministicSandboxBackend:
    """Hermetic fake with observe-before-create, fencing, cancellation, and cleanup."""

    def __init__(
        self,
        *,
        clock: ClockPort,
        outcomes: Sequence[SandboxOutcome] = (SandboxOutcome.SUCCEEDED,),
    ) -> None:
        self._clock = clock
        self._outcomes = list(outcomes)
        self._executions: dict[tuple[str, str], BackendExecution] = {}
        self._requests: dict[tuple[str, str], str] = {}
        self._cancelled: set[tuple[str, str]] = set()
        self._cleaned: set[tuple[str, str]] = set()
        self.calls: list[str] = []

    def ready(self) -> bool:
        return True

    def observe(self, request: SandboxExecutionRequest) -> BackendObservation:
        self.calls.append("observe")
        key = (request.tenant_id, request.execution_id)
        execution = self._executions.get(key)
        prior = self._requests.get(key)
        if prior is not None and prior != request.request_digest:
            state = BackendObservationState.CONFLICT
        elif key in self._cleaned or execution is None:
            state = BackendObservationState.ABSENT
        else:
            state = BackendObservationState.RUNNING
        return BackendObservation(
            execution_id=request.execution_id,
            state=state,
            provider_uid=execution.provider_uid if execution else None,
            attempt=request.attempt,
            fence_token=request.fence_token,
            observed_at=self._clock.now(),
        )

    def provision(self, request: SandboxExecutionRequest) -> BackendExecution:
        self.calls.append("provision")
        observation = self.observe(request)
        if observation.state is BackendObservationState.CONFLICT:
            raise SandboxRejected("deterministic sandbox request binding changed")
        key = (request.tenant_id, request.execution_id)
        current = self._executions.get(key)
        if current is not None:
            return current
        execution = BackendExecution(
            execution_id=request.execution_id,
            provider_ref=f"fake-{request.execution_id}",
            provider_uid=stable_id(
                "fake-sandbox", request.tenant_id, request.execution_id, length=32
            ),
            attempt=request.attempt,
            fence_token=request.fence_token,
            provisioned_at=self._clock.now(),
        )
        self._requests[key] = request.request_digest
        self._executions[key] = execution
        return execution

    def wait(
        self,
        request: SandboxExecutionRequest,
        execution: BackendExecution,
    ) -> SandboxResult:
        self.calls.append("wait")
        key = (request.tenant_id, request.execution_id)
        if self._executions.get(key) != execution:
            raise SandboxRejected("stale deterministic execution fence")
        outcome = (
            SandboxOutcome.CANCELLED
            if key in self._cancelled
            else self._outcomes.pop(0)
            if self._outcomes
            else SandboxOutcome.SUCCEEDED
        )
        material = {
            "schema_version": 1,
            "tenant_id": request.tenant_id,
            "run_id": request.run_id,
            "task_id": request.task_id,
            "execution_id": request.execution_id,
            "request_digest": request.request_digest,
            "spec_digest": request.spec_digest,
            "policy_digest": request.policy_digest,
            "approval_digest": request.approval_digest,
            "provider_uid": execution.provider_uid,
            "attempt": request.attempt,
            "fence_token": request.fence_token,
            "outcome": outcome,
            "exit_code": 0 if outcome is SandboxOutcome.SUCCEEDED else None,
            "output_bytes": 0,
            "output_files": 0,
            "started_at": execution.provisioned_at,
            "completed_at": self._clock.now(),
            "detail_code": f"fake_{outcome.value}",
            "manifest_digest": None,
        }
        return SandboxResult(**material, result_digest=canonical_digest(material))

    def cancel(
        self,
        request: SandboxExecutionRequest,
        execution: BackendExecution,
    ) -> None:
        self.calls.append("cancel")
        if self._executions.get((request.tenant_id, request.execution_id)) != execution:
            raise SandboxRejected("stale deterministic cancellation")
        self._cancelled.add((request.tenant_id, request.execution_id))

    def cleanup(
        self,
        request: SandboxExecutionRequest,
        execution: BackendExecution,
    ) -> None:
        self.calls.append("cleanup")
        if self._executions.get((request.tenant_id, request.execution_id)) != execution:
            raise SandboxRejected("stale deterministic cleanup")
        self._cleaned.add((request.tenant_id, request.execution_id))


def safe_extract_zip(
    payload: bytes,
    destination: Path,
    *,
    maximum_members: int,
    maximum_uncompressed_bytes: int,
    maximum_member_bytes: int,
) -> tuple[Path, ...]:
    """Atomically extract a bounded archive without links, devices, or traversal."""

    if (
        maximum_members < 1
        or maximum_members > 1_000
        or maximum_uncompressed_bytes < 1
        or maximum_uncompressed_bytes > 128 * 1024 * 1024
        or maximum_member_bytes < 1
        or maximum_member_bytes > maximum_uncompressed_bytes
    ):
        raise ValueError("archive extraction bounds are invalid")
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent)
    )
    extracted: list[Path] = []
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            members = archive.infolist()
            if not members or len(members) > maximum_members:
                raise ArtifactQuarantined("archive member count is outside bounds")
            total = 0
            seen: set[str] = set()
            for member in members:
                if member.flag_bits & 0x1:
                    raise ArtifactQuarantined(
                        "encrypted archive members are prohibited"
                    )
                path = validate_relative_path(member.filename.rstrip("/"))
                folded = path.casefold()
                if folded in seen:
                    raise ArtifactQuarantined(
                        "duplicate or case-conflicting archive paths are prohibited"
                    )
                seen.add(folded)
                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                    raise ArtifactQuarantined(
                        "archive links and device entries are prohibited"
                    )
                if member.file_size > maximum_member_bytes:
                    raise ArtifactQuarantined("archive member exceeds its byte bound")
                total += member.file_size
                if total > maximum_uncompressed_bytes:
                    raise ArtifactQuarantined("archive expansion exceeds total bound")
                if member.compress_size == 0 and member.file_size > 0:
                    raise ArtifactQuarantined("archive compression ratio is invalid")
                if (
                    member.compress_size > 0
                    and member.file_size / member.compress_size > 100
                ):
                    raise ArtifactQuarantined("archive compression ratio exceeds bound")
                target = staging / path
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                observed = 0
                with archive.open(member, "r") as source, target.open("xb") as output:
                    while chunk := source.read(64 * 1024):
                        observed += len(chunk)
                        if (
                            observed > member.file_size
                            or observed > maximum_member_bytes
                        ):
                            raise ArtifactQuarantined(
                                "archive member changed size during extraction"
                            )
                        output.write(chunk)
                if observed != member.file_size:
                    raise ArtifactQuarantined("archive member size is inconsistent")
                extracted.append(target)
        if destination.exists():
            raise ArtifactQuarantined("atomic staging destination already exists")
        os.replace(staging, destination)
        return tuple(destination / item.relative_to(staging) for item in extracted)
    except ArtifactQuarantined:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    except (ValueError, zipfile.BadZipFile) as exc:
        shutil.rmtree(staging, ignore_errors=True)
        raise ArtifactQuarantined("archive is malformed or corrupted") from exc
    except Exception as exc:
        shutil.rmtree(staging, ignore_errors=True)
        raise ArtifactQuarantined("archive extraction failed closed") from exc


class ArtifactProcessor:
    """Canonical output allowlist, scanning, redaction, quarantine, and provenance."""

    def __init__(self, *, clock: ClockPort, retention_seconds: int = 86_400) -> None:
        if retention_seconds < 60 or retention_seconds > 31_536_000:
            raise ValueError("artifact retention is outside bounds")
        self._clock = clock
        self._retention_seconds = retention_seconds

    def process(
        self,
        request: SandboxExecutionRequest,
        outputs: Mapping[str, bytes],
        media_types: Mapping[str, str],
    ) -> ArtifactManifest:
        expected = {item.logical_path: item for item in request.spec.expected_outputs}
        if len(outputs) > request.spec.resources.output_files:
            raise ArtifactQuarantined("sandbox produced too many output files")
        records: list[ArtifactRecord] = []
        total = 0
        for path, payload in sorted(outputs.items()):
            path = validate_relative_path(path)
            expectation = expected.get(path)
            if expectation is None:
                raise ArtifactQuarantined("sandbox produced an unexpected output path")
            media_type = media_types.get(path, "")
            if media_type not in expectation.media_types:
                raise ArtifactQuarantined(
                    "sandbox output media type is not allowlisted"
                )
            if len(payload) > request.spec.resources.output_file_bytes:
                raise ArtifactQuarantined("sandbox output file exceeds its byte bound")
            total += len(payload)
            if total > request.spec.resources.output_bytes:
                raise ArtifactQuarantined("sandbox total output exceeds its byte bound")
            text: str | None = None
            redactions = 0
            scanner_codes: list[str] = []
            disposition = ArtifactDisposition.ACCEPTED
            stored = payload
            if media_type.startswith("text/") or media_type in {
                "application/json",
                "application/yaml",
            }:
                try:
                    text = payload.decode("utf-8")
                except UnicodeDecodeError:
                    disposition = ArtifactDisposition.QUARANTINED
                    scanner_codes.append("invalid_utf8")
                if text is not None:
                    for index, pattern in enumerate(_SECRET_PATTERNS):
                        text, count = pattern.subn("[REDACTED]", text)
                        if count:
                            redactions += count
                            scanner_codes.append(f"secret_{index + 1}")
                    if redactions:
                        disposition = ArtifactDisposition.REDACTED
                        stored = text.encode()
            object_ref = (
                stable_id(
                    "sandbox-artifact-object",
                    request.tenant_id,
                    request.execution_id,
                    path,
                    sha256(stored).hexdigest(),
                    length=48,
                )
                if disposition is not ArtifactDisposition.QUARANTINED
                else None
            )
            material = {
                "schema_version": 1,
                "artifact_id": stable_id(
                    "sandbox-artifact",
                    request.tenant_id,
                    request.execution_id,
                    path,
                    length=40,
                ),
                "tenant_id": request.tenant_id,
                "run_id": request.run_id,
                "task_id": request.task_id,
                "execution_id": request.execution_id,
                "logical_path": path,
                "media_type": media_type,
                "content_hash": sha256(stored).hexdigest(),
                "size_bytes": len(stored),
                "disposition": disposition,
                "redaction_count": redactions,
                "scanner_codes": tuple(scanner_codes),
                "object_ref": object_ref,
                "retention_expires_at": self._clock.now()
                + __import__("datetime").timedelta(seconds=self._retention_seconds),
            }
            records.append(
                ArtifactRecord(**material, canonical_digest=canonical_digest(material))
            )
        missing = {
            item.logical_path
            for item in request.spec.expected_outputs
            if item.required and item.logical_path not in outputs
        }
        if missing:
            raise ArtifactQuarantined("sandbox omitted required output files")
        generated_at = self._clock.now()
        material = {
            "schema_version": 1,
            "tenant_id": request.tenant_id,
            "run_id": request.run_id,
            "task_id": request.task_id,
            "execution_id": request.execution_id,
            "artifacts": tuple(records),
            "total_bytes": sum(record.size_bytes for record in records),
            "generated_at": generated_at,
        }
        return ArtifactManifest(**material, manifest_digest=canonical_digest(material))


def _terminal_reason(conditions: object) -> str | None:
    if not isinstance(conditions, Sequence) or isinstance(conditions, (str, bytes)):
        return None
    for condition in conditions:
        reason = _get(condition, "reason")
        if isinstance(reason, str) and reason in {
            "DeadlineExceeded",
            "OOMKilled",
            "BackoffLimitExceeded",
        }:
            return reason
    return None
