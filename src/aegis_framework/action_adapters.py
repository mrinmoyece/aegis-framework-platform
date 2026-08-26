"""Deterministic and fixed-shape Kubernetes action adapters."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from aegis_framework.errors import EffectConflict, EffectsDisabled
from aegis_framework.ports import ClockPort
from aegis_framework.remediation import (
    ActionIntent,
    ActionObservation,
    ActionReceipt,
    EffectOutcome,
    ObservationState,
    canonical_digest,
)


class DeterministicActionAdapter:
    """Hermetic at-least-once adapter used by demos, tests, and evaluations."""

    def __init__(
        self,
        *,
        clock: ClockPort,
        execute_outcomes: tuple[EffectOutcome, ...] = (EffectOutcome.SUCCEEDED,),
        verification_facts: Mapping[str, str | int | float | bool] | None = None,
        compensation_succeeds: bool = True,
    ) -> None:
        self._clock = clock
        self._execute_outcomes = list(execute_outcomes)
        self._verification_facts = dict(
            verification_facts
            or {
                "available_replicas": 3,
                "checkout_failure_rate_bps": 50,
            }
        )
        self._compensation_succeeds = compensation_succeeds
        self._receipts: dict[tuple[str, str], ActionReceipt] = {}
        self._target_fences: dict[tuple[str, str], str] = {}
        self._applied: set[tuple[str, str]] = set()
        self._compensated: set[tuple[str, str]] = set()
        self.calls: list[tuple[str, str]] = []

    def dry_run(self, intent: ActionIntent) -> ActionReceipt:
        self._validate(intent)
        self.calls.append(("dry_run", intent.operation_id))
        return self._receipt(
            intent,
            EffectOutcome.DRY_RUN_SUCCEEDED,
            "dry_run_valid",
        )

    def observe(self, intent: ActionIntent) -> ActionObservation:
        self._validate(intent)
        self.calls.append(("observe", intent.operation_id))
        key = (intent.tenant_id, intent.action.idempotency_key)
        if key in self._compensated:
            state = ObservationState.RECOVERED
            facts: dict[str, str | int | float | bool] = {
                "available_replicas": 3,
                "checkout_failure_rate_bps": 500,
            }
        elif key in self._applied:
            state = ObservationState.APPLIED
            facts = self._verification_facts
        else:
            state = ObservationState.BEFORE
            facts = {
                "available_replicas": 3,
                "checkout_failure_rate_bps": 500,
            }
        return ActionObservation(
            tenant_id=intent.tenant_id,
            plan_id=intent.plan_id,
            action_id=intent.action.action_id,
            operation_id=intent.operation_id,
            target_fingerprint=intent.action.target.resource_fingerprint,
            state=state,
            facts=facts,
            observed_at=self._clock.now(),
            provider_receipt_ref=(
                f"fake:{intent.action.idempotency_key}"
                if key in self._applied
                else None
            ),
            attempt_fence=intent.fence_token,
        )

    def execute(self, intent: ActionIntent) -> ActionReceipt:
        self._validate(intent)
        self.calls.append(("execute", intent.operation_id))
        key = (intent.tenant_id, intent.action.idempotency_key)
        existing = self._receipts.get(key)
        if existing is not None:
            if (
                existing.target_fingerprint != intent.action.target.resource_fingerprint
                or existing.fence_token != intent.fence_token
            ):
                return self._receipt(
                    intent,
                    EffectOutcome.CONFLICT,
                    "idempotency_or_fence_conflict",
                )
            return self._receipt(
                intent,
                EffectOutcome.DUPLICATE,
                "duplicate_suppressed",
                provider_receipt_ref=existing.provider_receipt_ref,
            )
        outcome = (
            self._execute_outcomes.pop(0)
            if self._execute_outcomes
            else EffectOutcome.SUCCEEDED
        )
        receipt = self._receipt(
            intent,
            outcome,
            {
                EffectOutcome.SUCCEEDED: "restart_accepted",
                EffectOutcome.AMBIGUOUS: "provider_timeout_after_request",
                EffectOutcome.FAILED: "provider_rejected",
                EffectOutcome.CONFLICT: "target_changed",
            }.get(outcome, "adapter_outcome"),
            provider_receipt_ref=(
                f"fake:{intent.action.idempotency_key}"
                if outcome in {EffectOutcome.SUCCEEDED, EffectOutcome.AMBIGUOUS}
                else None
            ),
        )
        self._receipts[key] = receipt
        if outcome is EffectOutcome.SUCCEEDED:
            self._applied.add(key)
        return receipt

    def settle_ambiguous_as_applied(
        self,
        *,
        tenant_id: str,
        idempotency_key: str,
    ) -> None:
        self._applied.add((tenant_id, idempotency_key))

    def compensate(self, intent: ActionIntent) -> ActionReceipt:
        self._validate(intent)
        self.calls.append(("compensate", intent.operation_id))
        outcome = (
            EffectOutcome.COMPENSATED
            if self._compensation_succeeds
            else EffectOutcome.FAILED
        )
        key = (intent.tenant_id, intent.action.idempotency_key)
        if outcome is EffectOutcome.COMPENSATED:
            self._compensated.add(key)
            self._applied.discard(key)
        return self._receipt(
            intent,
            outcome,
            "rollback_applied" if self._compensation_succeeds else "rollback_failed",
            provider_receipt_ref=f"fake:rollback:{intent.action.idempotency_key}",
        )

    def _validate(self, intent: ActionIntent) -> None:
        if intent.action.action_type != "kubernetes.rollout_restart":
            raise EffectConflict("deterministic adapter received unsupported action")
        target_key = (
            intent.action.target.cluster_ref,
            intent.action.target.resource_fingerprint,
        )
        existing = self._target_fences.get(target_key)
        if existing is not None and existing != intent.fence_token:
            raise EffectConflict("stale worker fence rejected")
        self._target_fences[target_key] = intent.fence_token

    def _receipt(
        self,
        intent: ActionIntent,
        outcome: EffectOutcome,
        detail_code: str,
        *,
        provider_receipt_ref: str | None = None,
    ) -> ActionReceipt:
        material = {
            "schema_version": 1,
            "tenant_id": intent.tenant_id,
            "plan_id": intent.plan_id,
            "action_id": intent.action.action_id,
            "operation_id": intent.operation_id,
            "idempotency_key": intent.action.idempotency_key,
            "fence_token": intent.fence_token,
            "attempt": intent.attempt,
            "outcome": outcome,
            "provider_receipt_ref": provider_receipt_ref,
            "target_fingerprint": intent.action.target.resource_fingerprint,
            "recorded_at": self._clock.now(),
            "detail_code": detail_code,
        }
        return ActionReceipt(
            **material,
            canonical_digest=canonical_digest(material),
        )


class KubernetesDeploymentApi(Protocol):
    def read_namespaced_deployment(
        self,
        *,
        name: str,
        namespace: str,
    ) -> object: ...

    def patch_namespaced_deployment(
        self,
        *,
        name: str,
        namespace: str,
        body: Mapping[str, object],
        dry_run: str | None = None,
        field_manager: str,
    ) -> object: ...


@dataclass(frozen=True)
class _DeploymentState:
    uid: str
    resource_version: str
    annotations: Mapping[str, str]
    available_replicas: int
    observed_generation: int


class KubernetesRolloutRestartAdapter:
    """One exact Deployment restart; no shell, arbitrary patch, or command surface."""

    _ANNOTATION = "aegis.github.com/rollout-operation"

    def __init__(
        self,
        *,
        api: KubernetesDeploymentApi,
        clock: ClockPort,
        enabled: bool = False,
    ) -> None:
        self._api = api
        self._clock = clock
        self._enabled = enabled

    def dry_run(self, intent: ActionIntent) -> ActionReceipt:
        self._validate_enabled(intent)
        state = self._read(intent)
        self._require_exact_target(intent, state)
        self._api.patch_namespaced_deployment(
            name=intent.action.target.name,
            namespace=intent.action.target.namespace,
            body=self._patch(intent),
            dry_run="All",
            field_manager="aegis-framework",
        )
        return self._receipt(intent, EffectOutcome.DRY_RUN_SUCCEEDED, "dry_run_valid")

    def observe(self, intent: ActionIntent) -> ActionObservation:
        self._validate_enabled(intent)
        state = self._read(intent)
        self._require_identity(intent, state)
        operation = state.annotations.get(self._ANNOTATION)
        if operation == intent.action.idempotency_key:
            observation = ObservationState.APPLIED
        elif state.resource_version == intent.action.target.resource_version:
            observation = ObservationState.BEFORE
        else:
            observation = ObservationState.CONFLICT
        return ActionObservation(
            tenant_id=intent.tenant_id,
            plan_id=intent.plan_id,
            action_id=intent.action.action_id,
            operation_id=intent.operation_id,
            target_fingerprint=intent.action.target.resource_fingerprint,
            state=observation,
            facts={
                "available_replicas": state.available_replicas,
                "observed_generation": state.observed_generation,
            },
            observed_at=self._clock.now(),
            provider_receipt_ref=(
                f"kubernetes:{state.uid}:{state.resource_version}"
                if observation is ObservationState.APPLIED
                else None
            ),
            attempt_fence=intent.fence_token,
        )

    def execute(self, intent: ActionIntent) -> ActionReceipt:
        self._validate_enabled(intent)
        state = self._read(intent)
        self._require_identity(intent, state)
        if state.annotations.get(self._ANNOTATION) == intent.action.idempotency_key:
            return self._receipt(
                intent,
                EffectOutcome.DUPLICATE,
                "duplicate_suppressed",
                provider_receipt_ref=f"kubernetes:{state.uid}:{state.resource_version}",
            )
        self._require_exact_target(intent, state)
        result = self._api.patch_namespaced_deployment(
            name=intent.action.target.name,
            namespace=intent.action.target.namespace,
            body=self._patch(intent),
            field_manager="aegis-framework",
        )
        updated = _deployment_state(result)
        self._require_identity(intent, updated)
        if updated.annotations.get(self._ANNOTATION) != intent.action.idempotency_key:
            raise EffectConflict("Kubernetes rollout patch was not committed")
        if updated.resource_version == state.resource_version:
            raise EffectConflict("Kubernetes rollout resourceVersion did not advance")
        return self._receipt(
            intent,
            EffectOutcome.SUCCEEDED,
            "rollout_restart_requested",
            provider_receipt_ref=f"kubernetes:{updated.uid}:{updated.resource_version}",
        )

    def compensate(self, intent: ActionIntent) -> ActionReceipt:
        self._validate_enabled(intent)
        if (
            not intent.action.compensation.enabled
            or intent.action.compensation.action != "rollback_revision"
        ):
            raise EffectConflict("rollback is not bound in the exact action")
        raise EffectConflict(
            "rollout restart has no safe inverse; rollback revision requires a "
            "separately approved fixed image action"
        )

    def _validate_enabled(self, intent: ActionIntent) -> None:
        if not self._enabled:
            raise EffectsDisabled("Kubernetes effects are disabled by default")
        if intent.action.action_type != "kubernetes.rollout_restart":
            raise EffectConflict("adapter supports only rollout restart")

    def _read(self, intent: ActionIntent) -> _DeploymentState:
        return _deployment_state(
            self._api.read_namespaced_deployment(
                name=intent.action.target.name,
                namespace=intent.action.target.namespace,
            )
        )

    @staticmethod
    def _require_identity(intent: ActionIntent, state: _DeploymentState) -> None:
        if state.uid != intent.action.target.uid:
            raise EffectConflict("Kubernetes target UID changed")

    def _require_exact_target(
        self,
        intent: ActionIntent,
        state: _DeploymentState,
    ) -> None:
        self._require_identity(intent, state)
        if state.resource_version != intent.action.target.resource_version:
            raise EffectConflict("Kubernetes target resourceVersion changed")

    def _patch(self, intent: ActionIntent) -> Mapping[str, object]:
        return {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": intent.action.target.name,
                "namespace": intent.action.target.namespace,
                "uid": intent.action.target.uid,
                "resourceVersion": intent.action.target.resource_version,
            },
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            self._ANNOTATION: intent.action.idempotency_key,
                            "aegis.github.com/requested-at": (
                                intent.requested_at.isoformat()
                            ),
                            "aegis.github.com/fence": intent.fence_token,
                        }
                    }
                }
            },
        }

    def _receipt(
        self,
        intent: ActionIntent,
        outcome: EffectOutcome,
        detail_code: str,
        *,
        provider_receipt_ref: str | None = None,
    ) -> ActionReceipt:
        material = {
            "schema_version": 1,
            "tenant_id": intent.tenant_id,
            "plan_id": intent.plan_id,
            "action_id": intent.action.action_id,
            "operation_id": intent.operation_id,
            "idempotency_key": intent.action.idempotency_key,
            "fence_token": intent.fence_token,
            "attempt": intent.attempt,
            "outcome": outcome,
            "provider_receipt_ref": provider_receipt_ref,
            "target_fingerprint": intent.action.target.resource_fingerprint,
            "recorded_at": self._clock.now(),
            "detail_code": detail_code,
        }
        return ActionReceipt(**material, canonical_digest=canonical_digest(material))


def build_kubernetes_rollout_restart_adapter(
    *,
    host: str,
    token: str,
    ca_cert_path: str,
    clock: ClockPort,
    enabled: bool = False,
) -> KubernetesRolloutRestartAdapter:
    """Construct the official client without kubeconfig or executable plugins."""

    if not host.startswith("https://") or not token or not ca_cert_path:
        raise ValueError("static Kubernetes TLS configuration is required")
    try:
        from kubernetes import client  # type: ignore[import-untyped]
    except ImportError as exc:
        raise RuntimeError(
            "install the connectors extra for Kubernetes actions"
        ) from exc
    configuration = client.Configuration()
    configuration.host = host
    configuration.ssl_ca_cert = ca_cert_path
    configuration.verify_ssl = True
    configuration.api_key = {"authorization": token}
    configuration.api_key_prefix = {"authorization": "Bearer"}
    configuration.proxy = None
    api = client.AppsV1Api(client.ApiClient(configuration=configuration))
    return KubernetesRolloutRestartAdapter(
        api=cast(KubernetesDeploymentApi, api),
        clock=clock,
        enabled=enabled,
    )


def _deployment_state(value: object) -> _DeploymentState:
    metadata = getattr(value, "metadata", None)
    status = getattr(value, "status", None)
    uid = getattr(metadata, "uid", None)
    resource_version = getattr(metadata, "resource_version", None)
    annotations = getattr(metadata, "annotations", None) or {}
    available = getattr(status, "available_replicas", None)
    observed = getattr(status, "observed_generation", None)
    if (
        not isinstance(uid, str)
        or not isinstance(resource_version, str)
        or not isinstance(annotations, Mapping)
        or not isinstance(available, int)
        or not isinstance(observed, int)
    ):
        raise EffectConflict("Kubernetes deployment response shape is invalid")
    normalized_annotations: dict[str, str] = {}
    for key, item in annotations.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise EffectConflict("Kubernetes annotations are invalid")
        normalized_annotations[key] = item
    return _DeploymentState(
        uid=uid,
        resource_version=resource_version,
        annotations=normalized_annotations,
        available_replicas=available,
        observed_generation=observed,
    )
