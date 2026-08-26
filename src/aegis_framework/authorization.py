"""Deny-by-default RBAC, purpose, tenant, risk, and policy evaluation."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import ClassVar

from aegis_framework.access import PolicyRecord, PolicyRepositoryPort
from aegis_framework.domain import IdentityContext, RiskLevel
from aegis_framework.ports import Action, ClockPort, PolicyDecision

_RISK_ORDER: Mapping[RiskLevel, int] = {
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
}


class RoleCatalog:
    """Immutable application role definitions; IdP role claims are never trusted."""

    DEFINITIONS: ClassVar[Mapping[str, frozenset[Action]]] = {
        "incident-responder": frozenset(
            {
                Action.INVESTIGATION_RUN,
                Action.INVESTIGATION_READ,
                Action.EVIDENCE_QUERY_READ,
                Action.EVIDENCE_CURSOR_READ,
                Action.MODEL_CATALOG_READ,
                Action.MODEL_HEALTH_READ,
                Action.MODEL_USAGE_READ,
                Action.ORCHESTRATION_ARTIFACT_READ,
                Action.REMEDIATION_PROPOSE,
                Action.REMEDIATION_READ,
                Action.APPROVAL_REQUEST,
                Action.EFFECT_READ,
                Action.SANDBOX_EXECUTE,
                Action.SANDBOX_READ,
                Action.SANDBOX_ARTIFACT_READ,
                Action.MEMORY_WRITE,
                Action.MEMORY_READ,
                Action.MEMORY_RETRIEVE,
                Action.OPERATIONS_READ,
                Action.SUPPORT_READ,
                Action.REPLAY_READ,
                Action.TENANT_READ,
                Action.POLICY_READ,
                Action.QUOTA_READ,
            }
        ),
        "incident-viewer": frozenset(
            {
                Action.INVESTIGATION_READ,
                Action.EVIDENCE_QUERY_READ,
                Action.EVIDENCE_CURSOR_READ,
                Action.MODEL_CATALOG_READ,
                Action.MODEL_HEALTH_READ,
                Action.MODEL_USAGE_READ,
                Action.ORCHESTRATION_ARTIFACT_READ,
                Action.REMEDIATION_READ,
                Action.EFFECT_READ,
                Action.SANDBOX_READ,
                Action.SANDBOX_ARTIFACT_READ,
                Action.MEMORY_READ,
                Action.MEMORY_RETRIEVE,
                Action.OPERATIONS_READ,
                Action.TENANT_READ,
                Action.POLICY_READ,
                Action.QUOTA_READ,
            }
        ),
        "tenant-admin": frozenset(
            {
                Action.TENANT_READ,
                Action.POLICY_READ,
                Action.POLICY_WRITE,
                Action.QUOTA_READ,
                Action.QUOTA_WRITE,
                Action.AUDIT_READ,
                Action.EVIDENCE_QUERY_READ,
                Action.EVIDENCE_CURSOR_READ,
                Action.MODEL_CATALOG_READ,
                Action.MODEL_HEALTH_READ,
                Action.MODEL_USAGE_READ,
                Action.ORCHESTRATION_ARTIFACT_READ,
                Action.REMEDIATION_READ,
                Action.APPROVAL_DECIDE,
                Action.APPROVAL_REVOKE,
                Action.EFFECT_READ,
                Action.SANDBOX_READ,
                Action.SANDBOX_ARTIFACT_READ,
                Action.MEMORY_WRITE,
                Action.MEMORY_READ,
                Action.MEMORY_RETRIEVE,
                Action.MEMORY_DELETE,
                Action.OPERATIONS_READ,
                Action.SUPPORT_READ,
                Action.REPLAY_READ,
                Action.PROJECTION_REBUILD,
            }
        ),
        "tenant-auditor": frozenset(
            {
                Action.TENANT_READ,
                Action.POLICY_READ,
                Action.QUOTA_READ,
                Action.AUDIT_READ,
                Action.EVIDENCE_QUERY_READ,
                Action.EVIDENCE_CURSOR_READ,
                Action.MODEL_CATALOG_READ,
                Action.MODEL_HEALTH_READ,
                Action.MODEL_USAGE_READ,
                Action.ORCHESTRATION_ARTIFACT_READ,
                Action.REMEDIATION_READ,
                Action.EFFECT_READ,
                Action.SANDBOX_READ,
                Action.SANDBOX_ARTIFACT_READ,
                Action.MEMORY_READ,
                Action.OPERATIONS_READ,
                Action.SUPPORT_READ,
                Action.REPLAY_READ,
            }
        ),
        "workload-investigator": frozenset(
            {
                Action.INVESTIGATION_RUN,
                Action.INVESTIGATION_READ,
                Action.MODEL_CATALOG_READ,
                Action.ORCHESTRATION_ARTIFACT_READ,
                Action.MODEL_HEALTH_READ,
                Action.MODEL_USAGE_READ,
                Action.QUOTA_READ,
                Action.SANDBOX_EXECUTE,
                Action.SANDBOX_READ,
                Action.SANDBOX_ARTIFACT_READ,
                Action.MEMORY_READ,
                Action.MEMORY_RETRIEVE,
            }
        ),
        "incident-commander": frozenset(
            {
                Action.REMEDIATION_READ,
                Action.APPROVAL_DECIDE,
                Action.APPROVAL_REVOKE,
                Action.EFFECT_READ,
            }
        ),
        "change-approver": frozenset(
            {
                Action.REMEDIATION_READ,
                Action.APPROVAL_DECIDE,
                Action.APPROVAL_REVOKE,
                Action.EFFECT_READ,
            }
        ),
        "effect-worker": frozenset(
            {
                Action.REMEDIATION_READ,
                Action.EFFECT_EXECUTE,
                Action.EFFECT_READ,
            }
        ),
    }

    @classmethod
    def permissions_for(cls, role: str) -> tuple[str, ...]:
        return tuple(sorted(action.value for action in cls.DEFINITIONS.get(role, ())))


class EnterprisePolicy:
    """Current application policy is evaluated on every operation."""

    def __init__(
        self,
        *,
        policies: PolicyRepositoryPort,
        clock: ClockPort,
    ) -> None:
        self._policies = policies
        self._clock = clock

    def authorize(
        self,
        identity: IdentityContext,
        action: Action,
        *,
        resource_tenant_id: str,
        purpose: str,
        risk: RiskLevel,
    ) -> PolicyDecision:
        # Reject cross-tenant access before any repository query to avoid
        # establishing a foreign tenant's RLS context.
        if identity.tenant_id != resource_tenant_id:
            return PolicyDecision(
                allowed=False,
                policy_id="deny-all:tenant-mismatch",
                policy_revision=0,
                purpose=purpose,
                risk=risk,
                reason="tenant_mismatch",
            )

        policy = self._policies.current_policy(tenant_id=resource_tenant_id)
        policy_id = policy.policy_id if policy is not None else "deny-all:no-policy"
        revision = policy.revision if policy is not None else 0

        reason = self._denial_reason(
            identity=identity,
            action=action,
            resource_tenant_id=resource_tenant_id,
            purpose=purpose,
            risk=risk,
            policy=policy,
            now=self._clock.now(),
        )
        return PolicyDecision(
            allowed=reason is None,
            policy_id=policy_id,
            policy_revision=revision,
            purpose=purpose,
            risk=risk,
            reason=reason or "explicit_current_grant",
        )

    @staticmethod
    def _denial_reason(
        *,
        identity: IdentityContext,
        action: Action,
        resource_tenant_id: str,
        purpose: str,
        risk: RiskLevel,
        policy: PolicyRecord | None,
        now: datetime,
    ) -> str | None:
        if identity.tenant_id != resource_tenant_id:
            return "tenant_mismatch"
        if identity.expires_at <= now:
            return "identity_expired"
        if policy is None:
            return "no_active_policy"
        if action.value not in policy.allowed_actions:
            return "action_disallowed_by_policy"
        if purpose not in policy.allowed_purposes:
            return "purpose_disallowed_by_policy"
        if _RISK_ORDER[risk] > _RISK_ORDER[policy.max_risk]:
            return "risk_exceeds_policy"

        binding = next(
            (
                grant
                for grant in identity.grants
                if grant.expires_at > now
                and grant.purpose == purpose
                and action.value in grant.permissions
                and _RISK_ORDER[risk] <= _RISK_ORDER[grant.risk_ceiling]
            ),
            None,
        )
        if binding is None:
            return "no_current_purpose_grant"
        return None
