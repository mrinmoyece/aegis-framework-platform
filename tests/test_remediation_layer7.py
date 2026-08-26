from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from aegis_framework.action_adapters import (
    DeterministicActionAdapter,
    KubernetesRolloutRestartAdapter,
    build_kubernetes_rollout_restart_adapter,
)
from aegis_framework.domain import (
    Citation,
    Evidence,
    EvidenceKind,
    GrantBinding,
    IdentityContext,
    PrincipalKind,
    RiskLevel,
    stable_id,
)
from aegis_framework.errors import (
    ApprovalExpired,
    ConcurrencyConflict,
    EffectAmbiguous,
    EffectConflict,
    EffectsDisabled,
    IdempotencyConflict,
    IntegrityFailure,
    PolicyDenied,
    VerificationFailed,
)
from aegis_framework.ports import Action, PolicyDecision
from aegis_framework.remediation import (
    ActionApprovalRequest,
    ActionDefinition,
    ActionPolicy,
    ApprovalDecision,
    ApprovalDisposition,
    ApprovalRequirement,
    ApprovalService,
    BlastRadius,
    CompensationContract,
    Condition,
    EffectOutcome,
    EffectService,
    InMemoryActionPolicyStore,
    InMemoryEffectClaims,
    InMemoryEffectQuota,
    InMemoryPostEffectEvidenceStore,
    InMemoryRemediationControlStore,
    InMemoryRemediationLedger,
    KubernetesTarget,
    ObservationState,
    RemediationFact,
    RemediationFactType,
    RemediationPlan,
    RemediationStatus,
    RetryContract,
    canonical_digest,
    reduce_remediation,
)

NOW = datetime(2026, 8, 16, 10, 0, tzinfo=UTC)
TENANT = "tenant-acme"
TARGET_FINGERPRINT = "a" * 64


@dataclass
class MutableClock:
    value: datetime = NOW

    def now(self) -> datetime:
        return self.value

    def advance(self, seconds: int = 1) -> None:
        self.value += timedelta(seconds=seconds)


class AllowingPolicy:
    def __init__(self, *, denied: frozenset[Action] = frozenset()) -> None:
        self.denied = denied

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
            and action not in self.denied
            and action.value in identity.permissions
            and purpose in identity.purposes
        )
        return PolicyDecision(
            allowed=allowed,
            policy_id="test-policy",
            policy_revision=1,
            purpose=purpose,
            risk=risk,
            reason="allowed" if allowed else "denied",
        )


def _identity(
    role: str,
    subject: str,
    *actions: Action,
    tenant_id: str = TENANT,
    principal_kind: PrincipalKind = PrincipalKind.HUMAN,
) -> IdentityContext:
    permissions = tuple(sorted(action.value for action in actions))
    grant = GrantBinding(
        role=role,
        purpose="incident-response",
        permissions=permissions,
        risk_ceiling=RiskLevel.HIGH,
        expires_at=NOW + timedelta(days=1),
    )
    return IdentityContext(
        tenant_id=tenant_id,
        issuer="https://identity.example.invalid",
        subject_id=subject,
        principal_kind=principal_kind,
        roles=(role,),
        permissions=permissions,
        purposes=("incident-response",),
        grants=(grant,),
        grant_version=1,
        authenticated_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(days=1),
        request_id=f"request-{subject}",
        trace_id=f"trace-{subject}",
    )


def _actor(identity: IdentityContext) -> str:
    return stable_id("actor", identity.issuer, identity.subject_id, length=32)


def _action_policy(
    *,
    enabled: bool = True,
    remaining_effects: int = 5,
    revision: int = 1,
    role_revision: int = 1,
    window_start: datetime = NOW - timedelta(hours=1),
    window_end: datetime = NOW + timedelta(hours=4),
    targets: tuple[str, ...] = (TARGET_FINGERPRINT,),
    actions: tuple[str, ...] = ("kubernetes.rollout_restart",),
    namespaces: tuple[str, ...] = ("checkout",),
) -> ActionPolicy:
    material = {
        "tenant_id": TENANT,
        "policy_id": "effect-policy",
        "revision": revision,
        "role_revision": role_revision,
        "quota_revision": 1,
        "enabled": enabled,
        "allowed_action_types": actions,
        "allowed_target_fingerprints": targets,
        "allowed_namespaces": namespaces,
        "maintenance_window_start": window_start,
        "maintenance_window_end": window_end,
        "max_risk": RiskLevel.HIGH,
        "max_blast_radius": BlastRadius.ONE_SERVICE,
        "remaining_effects": remaining_effects,
        "high_risk_quorum": 2,
        "normal_quorum": 1,
        "approver_roles": ("change-approver", "incident-commander"),
        "prohibit_self_approval": True,
        "require_accepted_critic": True,
    }
    return ActionPolicy(**material, policy_digest=canonical_digest(material))


def _action(
    *,
    target_fingerprint: str = TARGET_FINGERPRINT,
    compensation: bool = True,
) -> ActionDefinition:
    material = {
        "schema_version": 1,
        "action_id": "restart-checkout",
        "action_type": "kubernetes.rollout_restart",
        "target": KubernetesTarget(
            cluster_ref="cluster-production-eu",
            namespace="checkout",
            name="checkout-api",
            uid="deployment-uid-001",
            resource_version="1042",
            resource_fingerprint=target_fingerprint,
        ),
        "risk": RiskLevel.HIGH,
        "blast_radius": BlastRadius.ONE_SERVICE,
        "preconditions": (
            Condition(
                fact="available_replicas",
                operator="greater_than",
                expected=0,
            ),
        ),
        "postconditions": (
            Condition(
                fact="available_replicas",
                operator="greater_than",
                expected=0,
            ),
            Condition(
                fact="checkout_failure_rate_bps",
                operator="less_than",
                expected=100,
            ),
        ),
        "dry_run_required": True,
        "retry": RetryContract(
            maximum_attempts=3,
            attempt_timeout_seconds=300,
            schedule_timeout_seconds=900,
            heartbeat_timeout_seconds=30,
        ),
        "idempotency_key": "restart-checkout-incident-001",
        "compensation": CompensationContract(
            enabled=compensation,
            action="rollback_revision" if compensation else "observe_only",
            rollback_revision="checkout-v41" if compensation else None,
            requires_fresh_approval=False,
        ),
    }
    return ActionDefinition(**material, canonical_digest=canonical_digest(material))


def _plan(
    proposer: IdentityContext,
    policy: ActionPolicy,
    *,
    expires_at: datetime = NOW + timedelta(hours=2),
    action: ActionDefinition | None = None,
) -> RemediationPlan:
    selected_action = action or _action()
    material = {
        "schema_version": 1,
        "plan_id": "plan-checkout-001",
        "tenant_id": TENANT,
        "run_id": "run-checkout-001",
        "incident_id": "checkout-20260816-001",
        "proposer_ref": _actor(proposer),
        "target_fingerprint": TARGET_FINGERPRINT,
        "risk": RiskLevel.HIGH,
        "blast_radius": BlastRadius.ONE_SERVICE,
        "rationale": "Restart the exact checkout Deployment after regression evidence.",
        "actions": (selected_action,),
        "evidence": (
            Citation(
                evidence_id="evidence-change-001",
                locator="github:deployments/checkout-v42",
                content_hash="b" * 64,
            ),
        ),
        "critic_status": "accepted",
        "policy_snapshot": policy.snapshot(),
        "created_at": NOW,
        "expires_at": expires_at,
    }
    return RemediationPlan(**material, plan_digest=canonical_digest(material))


@dataclass
class Harness:
    clock: MutableClock
    policy: ActionPolicy
    policy_store: InMemoryActionPolicyStore
    ledger: InMemoryRemediationLedger
    store: InMemoryRemediationControlStore
    approvals: ApprovalService
    effects: EffectService
    adapter: DeterministicActionAdapter
    claims: InMemoryEffectClaims
    proposer: IdentityContext
    approver_one: IdentityContext
    approver_two: IdentityContext
    worker: IdentityContext
    plan: RemediationPlan
    evidence_store: InMemoryPostEffectEvidenceStore

    def post_effect_evidence(self) -> Evidence:
        """Add and return a post-effect evidence item using the current clock time."""
        item = Evidence(
            evidence_id=f"post-effect-{self.clock.now().timestamp():.0f}",
            tenant_id=TENANT,
            kind=EvidenceKind.TELEMETRY,
            source="test-harness",
            locator="test://post-effect",
            observed_at=self.clock.now(),
            summary="Post-effect verification evidence.",
            facts={"available_replicas": 3, "checkout_failure_rate_bps": 50},
            content_hash="d" * 64,
        )
        self.evidence_store.add(item)
        return item


def _harness(
    *,
    adapter_outcomes: tuple[EffectOutcome, ...] = (EffectOutcome.SUCCEEDED,),
    verification_facts: dict[str, str | int | float | bool] | None = None,
    compensation_succeeds: bool = True,
    policy: ActionPolicy | None = None,
    quota_limit: int = 1,
) -> Harness:
    clock = MutableClock()
    current = policy or _action_policy()
    policy_store = InMemoryActionPolicyStore((current,))
    ledger = InMemoryRemediationLedger()
    store = InMemoryRemediationControlStore()
    application_policy = AllowingPolicy()
    proposer = _identity(
        "incident-responder",
        "alice",
        Action.REMEDIATION_PROPOSE,
        Action.APPROVAL_REQUEST,
        Action.REMEDIATION_READ,
    )
    approver_one = _identity(
        "incident-commander",
        "bob",
        Action.APPROVAL_DECIDE,
        Action.APPROVAL_REVOKE,
        Action.REMEDIATION_READ,
    )
    approver_two = _identity(
        "change-approver",
        "carol",
        Action.APPROVAL_DECIDE,
        Action.APPROVAL_REVOKE,
        Action.REMEDIATION_READ,
    )
    worker = _identity(
        "effect-worker",
        "worker-one",
        Action.EFFECT_EXECUTE,
        Action.EFFECT_READ,
        principal_kind=PrincipalKind.WORKLOAD,
    )
    adapter = DeterministicActionAdapter(
        clock=clock,
        execute_outcomes=adapter_outcomes,
        verification_facts=verification_facts,
        compensation_succeeds=compensation_succeeds,
    )
    claims = InMemoryEffectClaims()
    evidence_store = InMemoryPostEffectEvidenceStore()
    approvals = ApprovalService(
        policy=application_policy,
        action_policies=policy_store,
        ledger=ledger,
        store=store,
        clock=clock,
    )
    effects = EffectService(
        policy=application_policy,
        action_policies=policy_store,
        ledger=ledger,
        store=store,
        actions=adapter,
        quotas=InMemoryEffectQuota({TENANT: quota_limit}),
        claims=claims,
        clock=clock,
        evidence=evidence_store,
    )
    plan = _plan(proposer, current)
    return Harness(
        clock=clock,
        policy=current,
        policy_store=policy_store,
        ledger=ledger,
        store=store,
        approvals=approvals,
        effects=effects,
        adapter=adapter,
        claims=claims,
        proposer=proposer,
        approver_one=approver_one,
        approver_two=approver_two,
        worker=worker,
        plan=plan,
        evidence_store=evidence_store,
    )


def _open_and_approve(harness: Harness) -> int:
    proposed = harness.approvals.propose(
        harness.proposer,
        harness.plan,
        command_id="command-propose",
    )
    assert proposed.version == 2
    pending = harness.approvals.request_approval(
        harness.proposer,
        plan_id=harness.plan.plan_id,
        expected_version=2,
        command_id="command-request-approval",
    )
    assert pending.status is RemediationStatus.APPROVAL_PENDING
    first = harness.approvals.decide(
        harness.approver_one,
        approval_id=pending.approval.approval_id,
        disposition=ApprovalDisposition.GRANT,
        rationale="Exact target and bounded restart are acceptable.",
        expected_version=3,
        command_id="command-grant-one",
        plan_digest=harness.plan.plan_digest,
        approval_digest=pending.approval.canonical_digest,
    )
    assert first.status is RemediationStatus.APPROVAL_PENDING
    second = harness.approvals.decide(
        harness.approver_two,
        approval_id=pending.approval.approval_id,
        disposition=ApprovalDisposition.GRANT,
        rationale="Independent change review confirms exact scope.",
        expected_version=4,
        command_id="command-grant-two",
        plan_digest=harness.plan.plan_digest,
        approval_digest=pending.approval.canonical_digest,
    )
    assert second.status is RemediationStatus.APPROVED
    assert second.grants == 2
    return second.version


def test_contract_digests_and_exact_target_binding_fail_closed() -> None:
    proposer = _identity(
        "incident-responder",
        "alice",
        Action.REMEDIATION_PROPOSE,
    )
    policy = _action_policy()
    with pytest.raises(ValidationError, match="digest"):
        ActionDefinition.model_validate(
            {
                **_action().model_dump(mode="json"),
                "canonical_digest": "0" * 64,
            }
        )

    wrong_target = _action(target_fingerprint="c" * 64)
    with pytest.raises(ValidationError, match="exact plan target"):
        _plan(proposer, policy, action=wrong_target)

    with pytest.raises(ValidationError, match="rollback revision"):
        CompensationContract(
            enabled=True,
            action="rollback_revision",
            requires_fresh_approval=True,
        )
    with pytest.raises(ValidationError, match="observe-only"):
        CompensationContract(
            enabled=False,
            action="rollback_revision",
            rollback_revision="old",
        )
    with pytest.raises(ValidationError, match="inverted"):
        ApprovalRequirement(
            quorum=1,
            required_roles=("approver",),
            rationale_min_length=100,
            rationale_max_length=50,
        )
    plan = _plan(proposer, policy)
    duplicate_material = plan.model_dump(mode="python", exclude={"plan_digest"})
    duplicate_material["actions"] = (plan.actions[0], plan.actions[0])
    with pytest.raises(ValidationError, match="unique"):
        RemediationPlan(
            **duplicate_material,
            plan_digest=canonical_digest(duplicate_material),
        )
    low_risk_material = plan.model_dump(mode="python", exclude={"plan_digest"})
    low_risk_material["risk"] = RiskLevel.LOW
    with pytest.raises(ValidationError, match="action risk"):
        RemediationPlan(
            **low_risk_material,
            plan_digest=canonical_digest(low_risk_material),
        )
    with pytest.raises(ValidationError, match="policy digest"):
        ActionPolicy.model_validate(
            {**policy.model_dump(mode="json"), "policy_digest": "0" * 64}
        )
    invalid_window = policy.model_dump(mode="python", exclude={"policy_digest"})
    invalid_window["maintenance_window_end"] = invalid_window[
        "maintenance_window_start"
    ]
    with pytest.raises(ValidationError, match="maintenance"):
        ActionPolicy(
            **invalid_window,
            policy_digest=canonical_digest(invalid_window),
        )
    with pytest.raises(TypeError, match="unsupported canonical"):
        canonical_digest({"unsupported": object()})


@pytest.mark.parametrize(
    ("policy", "reason"),
    [
        (_action_policy(enabled=False), "effects_disabled"),
        (_action_policy(remaining_effects=0), "effect_quota_exhausted"),
        (
            _action_policy(window_start=NOW + timedelta(hours=1)),
            "outside_maintenance_window",
        ),
        (_action_policy(targets=("d" * 64,)), "exact_target"),
        (_action_policy(actions=("kubernetes.scale",)), "exact_target"),
        (_action_policy(namespaces=("payments",)), "exact_target"),
    ],
)
def test_current_action_policy_is_deny_by_default(
    policy: ActionPolicy,
    reason: str,
) -> None:
    harness = _harness(policy=policy)
    if reason == "effect_quota_exhausted":
        harness.approvals.propose(
            harness.proposer,
            harness.plan,
            command_id="propose",
        )
        pending = harness.approvals.request_approval(
            harness.proposer,
            plan_id=harness.plan.plan_id,
            expected_version=2,
            command_id="request",
        )
        for index, approver in enumerate(
            (harness.approver_one, harness.approver_two),
            start=3,
        ):
            harness.approvals.decide(
                approver,
                approval_id=pending.approval.approval_id,
                disposition=ApprovalDisposition.GRANT,
                rationale="Independent exact-scope approval rationale.",
                expected_version=index,
                command_id=f"grant-{index}",
                plan_digest=harness.plan.plan_digest,
                approval_digest=pending.approval.canonical_digest,
            )
        with pytest.raises(PolicyDenied, match=reason):
            harness.effects.preflight(
                harness.worker,
                plan_id=harness.plan.plan_id,
                action_id="restart-checkout",
                expected_version=5,
                operation_id="preflight",
                attempt=1,
            )
        return
    with pytest.raises(PolicyDenied, match=reason):
        harness.approvals.propose(
            harness.proposer,
            harness.plan,
            command_id="propose",
        )


def test_two_person_approval_sod_races_and_replay_protection() -> None:
    harness = _harness()
    proposed = harness.approvals.propose(
        harness.proposer,
        harness.plan,
        command_id="propose",
    )
    replay = harness.approvals.propose(
        harness.proposer,
        harness.plan,
        command_id="propose",
    )
    assert replay == proposed
    with pytest.raises(IdempotencyConflict):
        harness.ledger.append(
            tenant_id=TENANT,
            plan_id=harness.plan.plan_id,
            expected_version=2,
            fact_type=RemediationFactType.APPROVAL_REQUESTED,
            command_id="propose",
            actor_ref=_actor(harness.proposer),
            recorded_at=NOW,
            payload={"changed": True},
        )
    pending = harness.approvals.request_approval(
        harness.proposer,
        plan_id=harness.plan.plan_id,
        expected_version=2,
        command_id="request",
    )
    with pytest.raises(ConcurrencyConflict):
        harness.approvals.request_approval(
            harness.proposer,
            plan_id=harness.plan.plan_id,
            expected_version=2,
            command_id="stale-request",
        )
    self_approver = _identity(
        "incident-commander",
        "alice",
        Action.APPROVAL_DECIDE,
    )
    with pytest.raises(PolicyDenied, match="self_approval"):
        harness.approvals.decide(
            self_approver,
            approval_id=pending.approval.approval_id,
            disposition=ApprovalDisposition.GRANT,
            rationale="Self approval must never be accepted.",
            expected_version=3,
            command_id="self",
            plan_digest=harness.plan.plan_digest,
            approval_digest=pending.approval.canonical_digest,
        )
    workload_approver = _identity(
        "incident-commander",
        "robot",
        Action.APPROVAL_DECIDE,
        principal_kind=PrincipalKind.WORKLOAD,
    )
    with pytest.raises(PolicyDenied, match="human"):
        harness.approvals.decide(
            workload_approver,
            approval_id=pending.approval.approval_id,
            disposition=ApprovalDisposition.GRANT,
            rationale="Workload approval must never be accepted.",
            expected_version=3,
            command_id="workload",
            plan_digest=harness.plan.plan_digest,
            approval_digest=pending.approval.canonical_digest,
        )
    wrong_role = _identity(
        "tenant-admin",
        "mallory",
        Action.APPROVAL_DECIDE,
    )
    with pytest.raises(PolicyDenied, match="role"):
        harness.approvals.decide(
            wrong_role,
            approval_id=pending.approval.approval_id,
            disposition=ApprovalDisposition.GRANT,
            rationale="This role is not an approved change role.",
            expected_version=3,
            command_id="wrong-role",
            plan_digest=harness.plan.plan_digest,
            approval_digest=pending.approval.canonical_digest,
        )
    with pytest.raises(PolicyDenied, match="rationale"):
        harness.approvals.decide(
            harness.approver_one,
            approval_id=pending.approval.approval_id,
            disposition=ApprovalDisposition.GRANT,
            rationale="short",
            expected_version=3,
            command_id="short",
            plan_digest=harness.plan.plan_digest,
            approval_digest=pending.approval.canonical_digest,
        )
    with pytest.raises(PolicyDenied, match="plan_digest"):
        harness.approvals.decide(
            harness.approver_one,
            approval_id=pending.approval.approval_id,
            disposition=ApprovalDisposition.GRANT,
            rationale="The supplied plan digest is intentionally forged.",
            expected_version=3,
            command_id="forged",
            plan_digest="0" * 64,
            approval_digest=pending.approval.canonical_digest,
        )
    first = harness.approvals.decide(
        harness.approver_one,
        approval_id=pending.approval.approval_id,
        disposition=ApprovalDisposition.GRANT,
        rationale="First independent exact-scope approval.",
        expected_version=3,
        command_id="grant-one",
        plan_digest=harness.plan.plan_digest,
        approval_digest=pending.approval.canonical_digest,
    )
    assert first.grants == 1
    with pytest.raises(IdempotencyConflict, match="already decided"):
        harness.approvals.decide(
            harness.approver_one,
            approval_id=pending.approval.approval_id,
            disposition=ApprovalDisposition.GRANT,
            rationale="A second decision by the same human is rejected.",
            expected_version=4,
            command_id="grant-again",
            plan_digest=harness.plan.plan_digest,
            approval_digest=pending.approval.canonical_digest,
        )
    decision = first.decisions[0]
    harness.store.add_decision(decision)
    changed = decision.model_dump(mode="python", exclude={"canonical_digest"})
    changed["rationale"] = "Changed replay content must be rejected."
    changed_decision = ApprovalDecision(
        **changed,
        canonical_digest=canonical_digest(changed),
    )
    with pytest.raises(IdempotencyConflict, match="replay changed"):
        harness.store.add_decision(changed_decision)
    conflicting_plan_material = harness.plan.model_dump(
        mode="python",
        exclude={"plan_digest"},
    )
    conflicting_plan_material["rationale"] = "Changed rationale under the same plan id."
    conflicting_plan = RemediationPlan(
        **conflicting_plan_material,
        plan_digest=canonical_digest(conflicting_plan_material),
    )
    with pytest.raises(IdempotencyConflict, match="plan id"):
        harness.store.put_plan(conflicting_plan)
    conflicting_approval_material = pending.approval.model_dump(
        mode="python",
        exclude={"canonical_digest"},
    )
    conflicting_approval_material["expires_at"] += timedelta(minutes=1)
    conflicting_approval = ActionApprovalRequest(
        **conflicting_approval_material,
        canonical_digest=canonical_digest(conflicting_approval_material),
    )
    with pytest.raises(IdempotencyConflict, match="approval id"):
        harness.store.put_approval(conflicting_approval)


def test_denial_expiry_revocation_and_policy_change_invalidate_approval() -> None:
    denied = _harness()
    denied.approvals.propose(denied.proposer, denied.plan, command_id="propose")
    pending = denied.approvals.request_approval(
        denied.proposer,
        plan_id=denied.plan.plan_id,
        expected_version=2,
        command_id="request",
    )
    result = denied.approvals.decide(
        denied.approver_one,
        approval_id=pending.approval.approval_id,
        disposition=ApprovalDisposition.DENY,
        rationale="The exact target is in an unsafe operational state.",
        expected_version=3,
        command_id="deny",
        plan_digest=denied.plan.plan_digest,
        approval_digest=pending.approval.canonical_digest,
    )
    assert result.status is RemediationStatus.DENIED

    expired = _harness()
    expired.plan = _plan(
        expired.proposer,
        expired.policy,
        expires_at=NOW + timedelta(minutes=1),
    )
    expired.approvals.propose(
        expired.proposer,
        expired.plan,
        command_id="propose",
    )
    pending = expired.approvals.request_approval(
        expired.proposer,
        plan_id=expired.plan.plan_id,
        expected_version=2,
        command_id="request",
    )
    expired.clock.advance(120)
    with pytest.raises(ApprovalExpired):
        expired.approvals.decide(
            expired.approver_one,
            approval_id=pending.approval.approval_id,
            disposition=ApprovalDisposition.GRANT,
            rationale="This otherwise valid approval arrived too late.",
            expected_version=3,
            command_id="late",
            plan_digest=expired.plan.plan_digest,
            approval_digest=pending.approval.canonical_digest,
        )
    assert (
        expired.ledger.projection(tenant_id=TENANT, plan_id=expired.plan.plan_id).status
        is RemediationStatus.EXPIRED
    )

    revoked = _harness()
    version = _open_and_approve(revoked)
    view = revoked.approvals.get(
        revoked.approver_one,
        approval_id=revoked.ledger.projection(
            tenant_id=TENANT,
            plan_id=revoked.plan.plan_id,
        ).approval_id,
    )
    assert view is not None
    projection = revoked.approvals.revoke(
        revoked.approver_one,
        approval_id=view.approval.approval_id,
        expected_version=version,
        command_id="revoke",
        rationale="Operational conditions changed after approval.",
    )
    assert projection.status is RemediationStatus.REVOKED

    changed = _harness()
    version = _open_and_approve(changed)
    updated = _action_policy(revision=2)
    changed.policy_store.replace(updated)
    with pytest.raises(ApprovalExpired, match="stale"):
        changed.effects.preflight(
            changed.worker,
            plan_id=changed.plan.plan_id,
            action_id="restart-checkout",
            expected_version=version,
            operation_id="preflight",
            attempt=1,
        )


def test_successful_effect_requires_dry_run_and_fresh_verification() -> None:
    harness = _harness()
    version = _open_and_approve(harness)
    dry_run = harness.effects.preflight(
        harness.worker,
        plan_id=harness.plan.plan_id,
        action_id="restart-checkout",
        expected_version=version,
        operation_id="preflight",
        attempt=1,
    )
    assert dry_run.outcome is EffectOutcome.DRY_RUN_SUCCEEDED
    receipt = harness.effects.execute(
        harness.worker,
        plan_id=harness.plan.plan_id,
        action_id="restart-checkout",
        expected_version=version + 2,
        operation_id="execute",
        attempt=1,
    )
    assert receipt.outcome is EffectOutcome.SUCCEEDED
    replayed_receipt = harness.effects.execute(
        harness.worker,
        plan_id=harness.plan.plan_id,
        action_id="restart-checkout",
        expected_version=version + 2,
        operation_id="execute",
        attempt=2,
    )
    assert replayed_receipt == receipt
    harness.clock.advance()
    harness.post_effect_evidence()
    verification = harness.effects.verify(
        harness.worker,
        plan_id=harness.plan.plan_id,
        action_id="restart-checkout",
        expected_version=version + 5,
        operation_id="verify",
        effect_receipt=receipt,
        fresh_evidence=(),
        attempt=1,
    )
    assert verification.postconditions_satisfied is True
    assert (
        harness.effects.verify(
            harness.worker,
            plan_id=harness.plan.plan_id,
            action_id="restart-checkout",
            expected_version=version + 5,
            operation_id="verify",
            effect_receipt=receipt,
            fresh_evidence=(),
            attempt=2,
        )
        == verification
    )
    projection = harness.ledger.rebuild(
        tenant_id=TENANT,
        plan_id=harness.plan.plan_id,
    )
    assert projection.status is RemediationStatus.VERIFIED
    assert projection.verification_digest == verification.canonical_digest
    assert [call[0] for call in harness.adapter.calls] == [
        "dry_run",
        "observe",
        "execute",
        "observe",
    ]
    direct_intent = harness.effects._intent(
        harness.plan,
        harness.store.approval(
            tenant_id=TENANT,
            approval_id=harness.ledger.projection(
                tenant_id=TENANT,
                plan_id=harness.plan.plan_id,
            ).approval_id,
        ),
        harness.policy,
        harness.ledger.projection(
            tenant_id=TENANT,
            plan_id=harness.plan.plan_id,
        ),
        action_id="restart-checkout",
        operation_id="execute",
        attempt=1,
        dry_run=False,
    )
    assert harness.adapter.execute(direct_intent).outcome is EffectOutcome.DUPLICATE


def test_ambiguous_effect_reconciles_only_after_observation() -> None:
    harness = _harness(adapter_outcomes=(EffectOutcome.AMBIGUOUS,))
    version = _open_and_approve(harness)
    harness.effects.preflight(
        harness.worker,
        plan_id=harness.plan.plan_id,
        action_id="restart-checkout",
        expected_version=version,
        operation_id="preflight",
        attempt=1,
    )
    with pytest.raises(EffectAmbiguous):
        harness.effects.execute(
            harness.worker,
            plan_id=harness.plan.plan_id,
            action_id="restart-checkout",
            expected_version=version + 2,
            operation_id="execute",
            attempt=1,
        )
    assert (
        harness.ledger.projection(tenant_id=TENANT, plan_id=harness.plan.plan_id).status
        is RemediationStatus.AMBIGUOUS
    )
    harness.adapter.settle_ambiguous_as_applied(
        tenant_id=TENANT,
        idempotency_key="restart-checkout-incident-001",
    )
    receipt = harness.effects.reconcile(
        harness.worker,
        plan_id=harness.plan.plan_id,
        action_id="restart-checkout",
        expected_version=version + 5,
        operation_id="reconcile",
        attempt=2,
    )
    assert receipt.detail_code == "reconciled_applied"
    assert (
        harness.effects.reconcile(
            harness.worker,
            plan_id=harness.plan.plan_id,
            action_id="restart-checkout",
            expected_version=version + 5,
            operation_id="reconcile",
            attempt=3,
        )
        == receipt
    )

    unresolved = _harness(adapter_outcomes=(EffectOutcome.AMBIGUOUS,))
    version = _open_and_approve(unresolved)
    unresolved.effects.preflight(
        unresolved.worker,
        plan_id=unresolved.plan.plan_id,
        action_id="restart-checkout",
        expected_version=version,
        operation_id="preflight",
        attempt=1,
    )
    with pytest.raises(EffectAmbiguous):
        unresolved.effects.execute(
            unresolved.worker,
            plan_id=unresolved.plan.plan_id,
            action_id="restart-checkout",
            expected_version=version + 2,
            operation_id="execute",
            attempt=1,
        )
    with pytest.raises(EffectAmbiguous, match="could not prove"):
        unresolved.effects.reconcile(
            unresolved.worker,
            plan_id=unresolved.plan.plan_id,
            action_id="restart-checkout",
            expected_version=version + 5,
            operation_id="reconcile",
            attempt=2,
        )
    assert (
        unresolved.ledger.projection(
            tenant_id=TENANT,
            plan_id=unresolved.plan.plan_id,
        ).status
        is RemediationStatus.ESCALATED
    )


def test_verification_failure_rolls_back_and_failed_rollback_escalates() -> None:
    harness = _harness(
        verification_facts={
            "available_replicas": 3,
            "checkout_failure_rate_bps": 500,
        }
    )
    version = _open_and_approve(harness)
    harness.effects.preflight(
        harness.worker,
        plan_id=harness.plan.plan_id,
        action_id="restart-checkout",
        expected_version=version,
        operation_id="preflight",
        attempt=1,
    )
    receipt = harness.effects.execute(
        harness.worker,
        plan_id=harness.plan.plan_id,
        action_id="restart-checkout",
        expected_version=version + 2,
        operation_id="execute",
        attempt=1,
    )
    harness.clock.advance()
    harness.post_effect_evidence()
    with pytest.raises(VerificationFailed):
        harness.effects.verify(
            harness.worker,
            plan_id=harness.plan.plan_id,
            action_id="restart-checkout",
            expected_version=version + 5,
            operation_id="verify",
            effect_receipt=receipt,
            fresh_evidence=(),
            attempt=1,
        )
    rollback = harness.effects.rollback(
        harness.worker,
        plan_id=harness.plan.plan_id,
        action_id="restart-checkout",
        expected_version=version + 7,
        operation_id="rollback",
        attempt=1,
    )
    assert rollback.outcome is EffectOutcome.COMPENSATED
    assert (
        harness.effects.rollback(
            harness.worker,
            plan_id=harness.plan.plan_id,
            action_id="restart-checkout",
            expected_version=version + 7,
            operation_id="rollback",
            attempt=2,
        )
        == rollback
    )

    failing = _harness(
        verification_facts={
            "available_replicas": 0,
            "checkout_failure_rate_bps": 500,
        },
        compensation_succeeds=False,
    )
    version = _open_and_approve(failing)
    failing.effects.preflight(
        failing.worker,
        plan_id=failing.plan.plan_id,
        action_id="restart-checkout",
        expected_version=version,
        operation_id="preflight",
        attempt=1,
    )
    receipt = failing.effects.execute(
        failing.worker,
        plan_id=failing.plan.plan_id,
        action_id="restart-checkout",
        expected_version=version + 2,
        operation_id="execute",
        attempt=1,
    )
    failing.clock.advance()
    failing.post_effect_evidence()
    with pytest.raises(VerificationFailed):
        failing.effects.verify(
            failing.worker,
            plan_id=failing.plan.plan_id,
            action_id="restart-checkout",
            expected_version=version + 5,
            operation_id="verify",
            effect_receipt=receipt,
            fresh_evidence=(),
            attempt=1,
        )
    with pytest.raises(EffectConflict, match="operator escalation"):
        failing.effects.rollback(
            failing.worker,
            plan_id=failing.plan.plan_id,
            action_id="restart-checkout",
            expected_version=version + 7,
            operation_id="rollback",
            attempt=1,
        )


def test_failed_effect_and_disabled_compensation_fail_closed() -> None:
    harness = _harness(adapter_outcomes=(EffectOutcome.FAILED,))
    version = _open_and_approve(harness)
    harness.effects.preflight(
        harness.worker,
        plan_id=harness.plan.plan_id,
        action_id="restart-checkout",
        expected_version=version,
        operation_id="preflight",
        attempt=1,
    )
    with pytest.raises(EffectConflict, match="failed safely"):
        harness.effects.execute(
            harness.worker,
            plan_id=harness.plan.plan_id,
            action_id="restart-checkout",
            expected_version=version + 2,
            operation_id="execute",
            attempt=1,
        )
    no_compensation = _harness()
    no_compensation.plan = _plan(
        no_compensation.proposer,
        no_compensation.policy,
        action=_action(compensation=False),
    )
    version = _open_and_approve(no_compensation)
    no_compensation.effects.preflight(
        no_compensation.worker,
        plan_id=no_compensation.plan.plan_id,
        action_id="restart-checkout",
        expected_version=version,
        operation_id="preflight",
        attempt=1,
    )
    receipt = no_compensation.effects.execute(
        no_compensation.worker,
        plan_id=no_compensation.plan.plan_id,
        action_id="restart-checkout",
        expected_version=version + 2,
        operation_id="execute",
        attempt=1,
    )
    no_compensation.clock.advance()
    no_compensation.post_effect_evidence()
    no_compensation.adapter._verification_facts["checkout_failure_rate_bps"] = 500
    with pytest.raises(VerificationFailed):
        no_compensation.effects.verify(
            no_compensation.worker,
            plan_id=no_compensation.plan.plan_id,
            action_id="restart-checkout",
            expected_version=version + 5,
            operation_id="verify",
            effect_receipt=receipt,
            fresh_evidence=(),
            attempt=1,
        )
    with pytest.raises(PolicyDenied, match="not_enabled"):
        no_compensation.effects.rollback(
            no_compensation.worker,
            plan_id=no_compensation.plan.plan_id,
            action_id="restart-checkout",
            expected_version=version + 7,
            operation_id="rollback",
            attempt=1,
        )


def test_effect_quota_is_reserved_once_before_adapter_work() -> None:
    harness = _harness(quota_limit=0)
    version = _open_and_approve(harness)
    with pytest.raises(PolicyDenied, match="quota"):
        harness.effects.preflight(
            harness.worker,
            plan_id=harness.plan.plan_id,
            action_id="restart-checkout",
            expected_version=version,
            operation_id="preflight",
            attempt=1,
        )
    assert harness.adapter.calls == []


def test_missing_postcondition_and_failed_precondition_fail_closed() -> None:
    missing_post = _action()
    post_material = missing_post.model_dump(
        mode="python",
        exclude={"canonical_digest"},
    )
    post_material["postconditions"] = (
        Condition(
            fact="missing_recovery_fact",
            operator="not_equals",
            expected="unhealthy",
        ),
    )
    post_action = ActionDefinition(
        **post_material,
        canonical_digest=canonical_digest(post_material),
    )
    harness = _harness()
    harness.plan = _plan(harness.proposer, harness.policy, action=post_action)
    version = _open_and_approve(harness)
    harness.effects.preflight(
        harness.worker,
        plan_id=harness.plan.plan_id,
        action_id="restart-checkout",
        expected_version=version,
        operation_id="preflight",
        attempt=1,
    )
    receipt = harness.effects.execute(
        harness.worker,
        plan_id=harness.plan.plan_id,
        action_id="restart-checkout",
        expected_version=version + 2,
        operation_id="execute",
        attempt=1,
    )
    harness.clock.advance()
    harness.post_effect_evidence()
    with pytest.raises(VerificationFailed):
        harness.effects.verify(
            harness.worker,
            plan_id=harness.plan.plan_id,
            action_id="restart-checkout",
            expected_version=version + 5,
            operation_id="verify",
            effect_receipt=receipt,
            fresh_evidence=(),
            attempt=1,
        )

    pre_material = _action().model_dump(
        mode="python",
        exclude={"canonical_digest"},
    )
    pre_material["preconditions"] = (
        Condition(
            fact="maintenance_lock_clear",
            operator="equals",
            expected=True,
        ),
    )
    pre_action = ActionDefinition(
        **pre_material,
        canonical_digest=canonical_digest(pre_material),
    )
    precondition = _harness()
    precondition.plan = _plan(
        precondition.proposer,
        precondition.policy,
        action=pre_action,
    )
    version = _open_and_approve(precondition)
    precondition.effects.preflight(
        precondition.worker,
        plan_id=precondition.plan.plan_id,
        action_id="restart-checkout",
        expected_version=version,
        operation_id="preflight",
        attempt=1,
    )
    with pytest.raises(EffectConflict, match="failed safely"):
        precondition.effects.execute(
            precondition.worker,
            plan_id=precondition.plan.plan_id,
            action_id="restart-checkout",
            expected_version=version + 2,
            operation_id="execute",
            attempt=1,
        )
    assert "execute" not in {name for name, _ in precondition.adapter.calls}


def test_effect_claims_reject_stale_workers_and_replay_receipts() -> None:
    harness = _harness()
    _open_and_approve(harness)
    projection = harness.ledger.projection(
        tenant_id=TENANT,
        plan_id=harness.plan.plan_id,
    )
    approval = harness.store.approval(
        tenant_id=TENANT,
        approval_id=projection.approval_id,
    )
    intent = harness.effects._intent(
        harness.plan,
        approval,
        harness.policy,
        projection,
        action_id="restart-checkout",
        operation_id="claim-test",
        attempt=1,
        dry_run=False,
    )
    claims = InMemoryEffectClaims()
    first = claims.claim(
        intent,
        worker_ref="worker-one",
        now=NOW,
        claim_until=NOW + timedelta(minutes=5),
    )
    with pytest.raises(ConcurrencyConflict, match="actively claimed"):
        claims.claim(
            intent,
            worker_ref="worker-two",
            now=NOW,
            claim_until=NOW + timedelta(minutes=5),
        )
    receipt = harness.adapter.execute(intent)
    claims.complete(receipt, claim_token=first.claim_token, now=NOW)
    replay = claims.claim(
        intent,
        worker_ref="worker-two",
        now=NOW,
        claim_until=NOW + timedelta(minutes=5),
    )
    assert replay.replayed is True
    assert replay.receipt == receipt
    with pytest.raises(ConcurrencyConflict, match="stale"):
        claims.complete(receipt, claim_token="claim-stale", now=NOW)
    changed = intent.model_copy(update={"fence_token": "fence-changed"})
    with pytest.raises(EffectConflict, match="binding"):
        claims.claim(
            changed,
            worker_ref="worker-two",
            now=NOW + timedelta(minutes=6),
            claim_until=NOW + timedelta(minutes=10),
        )
    expiring_intent = intent.model_copy(update={"operation_id": "claim-expiry-test"})
    expiring = InMemoryEffectClaims()
    expiring.claim(
        expiring_intent,
        worker_ref="worker-one",
        now=NOW,
        claim_until=NOW + timedelta(minutes=1),
    )
    retry_intent = expiring_intent.model_copy(update={"attempt": 2})
    reclaimed = expiring.claim(
        retry_intent,
        worker_ref="worker-two",
        now=NOW + timedelta(minutes=2),
        claim_until=NOW + timedelta(minutes=7),
    )
    assert reclaimed.attempt == 2
    stale_attempt = InMemoryEffectClaims()
    stale_attempt.claim(
        expiring_intent,
        worker_ref="worker-one",
        now=NOW,
        claim_until=NOW + timedelta(minutes=1),
    )
    with pytest.raises(ConcurrencyConflict, match="did not advance"):
        stale_attempt.claim(
            expiring_intent,
            worker_ref="worker-two",
            now=NOW + timedelta(minutes=2),
            claim_until=NOW + timedelta(minutes=7),
        )


def test_effect_service_reclaims_expired_midflight_attempt() -> None:
    harness = _harness()
    version = _open_and_approve(harness)
    harness.effects.preflight(
        harness.worker,
        plan_id=harness.plan.plan_id,
        action_id="restart-checkout",
        expected_version=version,
        operation_id="preflight",
        attempt=1,
    )
    projection = harness.ledger.projection(
        tenant_id=TENANT,
        plan_id=harness.plan.plan_id,
    )
    approval = harness.store.approval(
        tenant_id=TENANT,
        approval_id=projection.approval_id,
    )
    intent = harness.effects._intent(
        harness.plan,
        approval,
        harness.policy,
        projection,
        action_id="restart-checkout",
        operation_id="execute-retry",
        attempt=1,
        dry_run=False,
    )
    requested = harness.ledger.append(
        tenant_id=TENANT,
        plan_id=harness.plan.plan_id,
        expected_version=version + 2,
        fact_type=RemediationFactType.EXECUTION_REQUESTED,
        command_id="execute-retry:intent",
        actor_ref=_actor(harness.worker),
        recorded_at=harness.clock.now(),
        payload={
            "action_id": "restart-checkout",
            "idempotency_key": intent.action.idempotency_key,
            "fence_token": projection.fence_token,
        },
    )
    started = harness.ledger.append(
        tenant_id=TENANT,
        plan_id=harness.plan.plan_id,
        expected_version=requested.version,
        fact_type=RemediationFactType.EXECUTION_STARTED,
        command_id="execute-retry:started:1",
        actor_ref=_actor(harness.worker),
        recorded_at=harness.clock.now(),
        payload={"attempt": 1},
    )
    harness.claims.claim(
        intent,
        worker_ref=_actor(harness.worker),
        now=harness.clock.now(),
        claim_until=harness.clock.now() + timedelta(seconds=300),
    )
    harness.clock.advance(301)
    receipt = harness.effects.execute(
        harness.worker,
        plan_id=harness.plan.plan_id,
        action_id="restart-checkout",
        expected_version=started.version,
        operation_id="execute-retry",
        attempt=2,
    )
    assert receipt.outcome is EffectOutcome.SUCCEEDED
    assert (
        harness.ledger.projection(
            tenant_id=TENANT,
            plan_id=harness.plan.plan_id,
        ).status
        is RemediationStatus.SUCCEEDED
    )


def test_verification_rejects_unrecorded_receipt() -> None:
    harness = _harness()
    version = _open_and_approve(harness)
    harness.effects.preflight(
        harness.worker,
        plan_id=harness.plan.plan_id,
        action_id="restart-checkout",
        expected_version=version,
        operation_id="preflight",
        attempt=1,
    )
    receipt = harness.effects.execute(
        harness.worker,
        plan_id=harness.plan.plan_id,
        action_id="restart-checkout",
        expected_version=version + 2,
        operation_id="execute",
        attempt=1,
    )
    forged_material = receipt.model_dump(
        mode="python",
        exclude={"canonical_digest"},
    )
    forged_material["detail_code"] = "forged"
    forged = type(receipt)(
        **forged_material,
        canonical_digest=canonical_digest(forged_material),
    )
    with pytest.raises(IntegrityFailure, match="receipt binding"):
        harness.effects.verify(
            harness.worker,
            plan_id=harness.plan.plan_id,
            action_id="restart-checkout",
            expected_version=version + 5,
            operation_id="verify",
            effect_receipt=forged,
            fresh_evidence=(),
            attempt=1,
        )


def test_pure_replay_rejects_tampering_and_illegal_transitions() -> None:
    harness = _harness()
    _open_and_approve(harness)
    facts = harness.ledger.facts(tenant_id=TENANT, plan_id=harness.plan.plan_id)
    projection = None
    for fact in facts:
        projection = reduce_remediation(projection, fact)
    assert projection is not None
    assert projection.status is RemediationStatus.APPROVED

    tampered = facts[-1].model_copy(update={"previous_digest": "0" * 64})
    before_tampered = None
    for fact in facts[:-1]:
        before_tampered = reduce_remediation(before_tampered, fact)
    with pytest.raises(IntegrityFailure, match="chain"):
        reduce_remediation(before_tampered, tampered)
    denied = RemediationFact(
        tenant_id=TENANT,
        plan_id=harness.plan.plan_id,
        sequence=projection.version + 1,
        fact_id="fact-illegal",
        fact_type=RemediationFactType.APPROVAL_DENIED,
        command_id="illegal",
        actor_ref="actor-illegal",
        recorded_at=NOW,
        previous_digest=projection.last_fact_digest,
        canonical_digest="e" * 64,
    )
    with pytest.raises(IntegrityFailure, match="illegal remediation"):
        reduce_remediation(projection, denied)
    with pytest.raises(IntegrityFailure, match="start with proposal"):
        reduce_remediation(None, denied.model_copy(update={"sequence": 1}))
    with pytest.raises(IntegrityFailure, match="unknown"):
        InMemoryRemediationLedger().rebuild(
            tenant_id=TENANT,
            plan_id="missing",
        )
    terminal = projection.model_copy(update={"status": RemediationStatus.DENIED})
    with pytest.raises(IntegrityFailure, match="terminal"):
        reduce_remediation(
            terminal,
            denied.model_copy(
                update={
                    "sequence": terminal.version + 1,
                    "previous_digest": terminal.last_fact_digest,
                }
            ),
        )


class FakeKubernetesApi:
    def __init__(self) -> None:
        self.annotations: dict[str, str] = {}
        self.resource_version = "1042"
        self.uid = "deployment-uid-001"
        self.patches: list[dict[str, object]] = []

    def deployment(self) -> object:
        return SimpleNamespace(
            metadata=SimpleNamespace(
                uid=self.uid,
                resource_version=self.resource_version,
                annotations=self.annotations,
            ),
            status=SimpleNamespace(
                available_replicas=3,
                observed_generation=42,
            ),
        )

    def read_namespaced_deployment(self, *, name: str, namespace: str) -> object:
        assert name == "checkout-api"
        assert namespace == "checkout"
        return self.deployment()

    def patch_namespaced_deployment(
        self,
        *,
        name: str,
        namespace: str,
        body: dict[str, object],
        dry_run: str | None = None,
        field_manager: str,
    ) -> object:
        assert name == "checkout-api"
        assert namespace == "checkout"
        assert field_manager == "aegis-framework"
        self.patches.append({"body": body, "dry_run": dry_run})
        annotations = body["spec"]["template"]["metadata"]["annotations"]
        if dry_run is None:
            self.annotations.update(annotations)
            self.resource_version = "1043"
        return self.deployment()


def test_kubernetes_adapter_is_fixed_shape_dry_run_gated_and_exact_targeted() -> None:
    harness = _harness()
    _open_and_approve(harness)
    projection = harness.ledger.projection(
        tenant_id=TENANT,
        plan_id=harness.plan.plan_id,
    )
    approval = harness.store.approval(
        tenant_id=TENANT,
        approval_id=projection.approval_id,
    )
    intent = harness.effects._intent(
        harness.plan,
        approval,
        harness.policy,
        projection,
        action_id="restart-checkout",
        operation_id="execute-k8s",
        attempt=1,
        dry_run=False,
    )
    api = FakeKubernetesApi()
    disabled = KubernetesRolloutRestartAdapter(
        api=api,
        clock=harness.clock,
    )
    with pytest.raises(EffectsDisabled):
        disabled.dry_run(intent)

    adapter = KubernetesRolloutRestartAdapter(
        api=api,
        clock=harness.clock,
        enabled=True,
    )
    dry_run = adapter.dry_run(intent.model_copy(update={"dry_run": True}))
    assert dry_run.outcome is EffectOutcome.DRY_RUN_SUCCEEDED
    assert api.patches[0]["dry_run"] == "All"
    patch = api.patches[0]["body"]
    assert patch["kind"] == "Deployment"
    assert "command" not in str(patch).lower()
    before = adapter.observe(intent)
    assert before.state is ObservationState.BEFORE
    receipt = adapter.execute(intent)
    assert receipt.outcome is EffectOutcome.SUCCEEDED
    assert adapter.observe(intent).state is ObservationState.APPLIED
    assert adapter.execute(intent).outcome is EffectOutcome.DUPLICATE
    with pytest.raises(EffectConflict, match="no safe inverse"):
        adapter.compensate(intent)

    api.resource_version = "9999"
    with pytest.raises(EffectConflict, match="resourceVersion"):
        adapter.dry_run(intent)
    assert adapter.observe(intent).state is ObservationState.APPLIED
    api.annotations.clear()
    assert adapter.observe(intent).state is ObservationState.CONFLICT
    api.uid = "other-deployment"
    with pytest.raises(EffectConflict, match="UID"):
        adapter.observe(intent)
    with pytest.raises(ValueError, match="static Kubernetes"):
        build_kubernetes_rollout_restart_adapter(
            host="http://cluster.invalid",
            token="token",
            ca_cert_path="/etc/ssl/aegis-ca.crt",
            clock=harness.clock,
        )
    built = build_kubernetes_rollout_restart_adapter(
        host="https://cluster.invalid",
        token="token",
        ca_cert_path="/etc/ssl/aegis-ca.crt",
        clock=harness.clock,
    )
    assert isinstance(built, KubernetesRolloutRestartAdapter)


def test_kubernetes_adapter_rejects_malformed_provider_shapes() -> None:
    harness = _harness()
    _open_and_approve(harness)
    projection = harness.ledger.projection(
        tenant_id=TENANT,
        plan_id=harness.plan.plan_id,
    )
    approval = harness.store.approval(
        tenant_id=TENANT,
        approval_id=projection.approval_id,
    )
    intent = harness.effects._intent(
        harness.plan,
        approval,
        harness.policy,
        projection,
        action_id="restart-checkout",
        operation_id="malformed",
        attempt=1,
        dry_run=False,
    )

    class MalformedApi(FakeKubernetesApi):
        def deployment(self) -> object:
            return SimpleNamespace(metadata=None, status=None)

    adapter = KubernetesRolloutRestartAdapter(
        api=MalformedApi(),
        clock=harness.clock,
        enabled=True,
    )
    with pytest.raises(EffectConflict, match="shape"):
        adapter.observe(intent)

    api = FakeKubernetesApi()
    api.annotations = {"bad": 1}  # type: ignore[dict-item]
    adapter = KubernetesRolloutRestartAdapter(
        api=api,
        clock=harness.clock,
        enabled=True,
    )
    with pytest.raises(EffectConflict, match="annotations"):
        adapter.observe(intent)


def test_kubernetes_adapter_rejects_uncommitted_restart_patch() -> None:
    harness = _harness()
    _open_and_approve(harness)
    projection = harness.ledger.projection(
        tenant_id=TENANT,
        plan_id=harness.plan.plan_id,
    )
    approval = harness.store.approval(
        tenant_id=TENANT,
        approval_id=projection.approval_id,
    )
    intent = harness.effects._intent(
        harness.plan,
        approval,
        harness.policy,
        projection,
        action_id="restart-checkout",
        operation_id="execute-k8s-uncommitted",
        attempt=1,
        dry_run=False,
    )

    class NonCommittingApi(FakeKubernetesApi):
        def patch_namespaced_deployment(
            self,
            *,
            name: str,
            namespace: str,
            body: dict[str, object],
            dry_run: str | None = None,
            field_manager: str,
        ) -> object:
            super().patch_namespaced_deployment(
                name=name,
                namespace=namespace,
                body=body,
                dry_run=dry_run,
                field_manager=field_manager,
            )
            self.annotations.clear()
            self.resource_version = "1042"
            return self.deployment()

    adapter = KubernetesRolloutRestartAdapter(
        api=NonCommittingApi(),
        clock=harness.clock,
        enabled=True,
    )
    with pytest.raises(EffectConflict, match=r"not committed|did not advance"):
        adapter.execute(intent)
