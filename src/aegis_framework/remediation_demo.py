"""Deterministic redacted Layer 7 approval/effect demonstration."""

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from pydantic import Field

from aegis_framework.action_adapters import DeterministicActionAdapter
from aegis_framework.domain import (
    Citation,
    Evidence,
    EvidenceKind,
    GrantBinding,
    IdentityContext,
    PrincipalKind,
    RiskLevel,
    StrictModel,
    stable_id,
)
from aegis_framework.errors import ApprovalExpired, EffectAmbiguous, VerificationFailed
from aegis_framework.ports import Action, PolicyDecision
from aegis_framework.remediation import (
    ActionDefinition,
    ActionPolicy,
    ApprovalDisposition,
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
    RemediationPlan,
    RemediationStatus,
    RetryContract,
    canonical_digest,
)

DEMO_TIME = datetime(2026, 8, 16, 10, 0, tzinfo=UTC)


class RemediationDemoScenario(StrEnum):
    SUCCESS = "success"
    DENIAL = "denial"
    EXPIRY = "expiry"
    AMBIGUITY = "ambiguity"
    VERIFICATION_FAILURE = "verification_failure"
    ROLLBACK = "rollback"


class RemediationDemoResult(StrictModel):
    scenario: RemediationDemoScenario
    plan_ref: str
    action_ref: str
    status: RemediationStatus
    approval_count: int = Field(ge=0)
    fact_count: int = Field(ge=1)
    effect_outcome: EffectOutcome | None = None
    reconciled: bool = False
    verification_satisfied: bool | None = None
    rollback_outcome: EffectOutcome | None = None
    authority: str = "application-ledger"
    workflow: str = "temporal"
    agent_authority: str = "proposal-only"


@dataclass
class _Clock:
    value: datetime = DEMO_TIME

    def now(self) -> datetime:
        return self.value

    def advance(self, seconds: int = 1) -> None:
        self.value += timedelta(seconds=seconds)


class _Policy:
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
            policy_id="demo-application-policy",
            policy_revision=1,
            purpose=purpose,
            risk=risk,
            reason="explicit_demo_grant" if allowed else "denied",
        )


@dataclass
class _Demo:
    clock: _Clock
    policy: ActionPolicy
    ledger: InMemoryRemediationLedger
    store: InMemoryRemediationControlStore
    approvals: ApprovalService
    effects: EffectService
    adapter: DeterministicActionAdapter
    proposer: IdentityContext
    approvers: tuple[IdentityContext, IdentityContext]
    worker: IdentityContext
    plan: RemediationPlan
    evidence_store: InMemoryPostEffectEvidenceStore


@dataclass(frozen=True)
class RemediationApiDemo:
    approvals: ApprovalService
    approval_id: str


def build_remediation_api_demo() -> RemediationApiDemo:
    demo = _build_demo(RemediationDemoScenario.SUCCESS)
    proposed = demo.approvals.propose(
        demo.proposer,
        demo.plan,
        command_id="api-demo-propose",
    )
    pending = demo.approvals.request_approval(
        demo.proposer,
        plan_id=demo.plan.plan_id,
        expected_version=proposed.version,
        command_id="api-demo-request",
    )
    return RemediationApiDemo(
        approvals=demo.approvals,
        approval_id=pending.approval.approval_id,
    )


def run_remediation_demo(
    scenario: RemediationDemoScenario,
) -> RemediationDemoResult:
    demo = _build_demo(scenario)
    proposed = demo.approvals.propose(
        demo.proposer,
        demo.plan,
        command_id=f"demo-{scenario.value}-propose",
    )
    pending = demo.approvals.request_approval(
        demo.proposer,
        plan_id=demo.plan.plan_id,
        expected_version=proposed.version,
        command_id=f"demo-{scenario.value}-approval",
    )
    if scenario is RemediationDemoScenario.EXPIRY:
        demo.clock.advance(120)
        with suppress(ApprovalExpired):
            demo.approvals.decide(
                demo.approvers[0],
                approval_id=pending.approval.approval_id,
                disposition=ApprovalDisposition.GRANT,
                rationale="This decision intentionally arrives after expiry.",
                expected_version=pending.version,
                command_id="demo-expired-decision",
                plan_digest=demo.plan.plan_digest,
                approval_digest=pending.approval.canonical_digest,
            )
        return _result(demo, scenario, approval_count=0)

    if scenario is RemediationDemoScenario.DENIAL:
        demo.approvals.decide(
            demo.approvers[0],
            approval_id=pending.approval.approval_id,
            disposition=ApprovalDisposition.DENY,
            rationale="Independent exact-scope human denial for the checkout restart.",
            expected_version=pending.version,
            command_id=f"demo-{scenario.value}-decision-one",
            plan_digest=demo.plan.plan_digest,
            approval_digest=pending.approval.canonical_digest,
        )
        return _result(demo, scenario, approval_count=0)
    first = demo.approvals.decide(
        demo.approvers[0],
        approval_id=pending.approval.approval_id,
        disposition=ApprovalDisposition.GRANT,
        rationale="Independent exact-scope human decision for the checkout restart.",
        expected_version=pending.version,
        command_id=f"demo-{scenario.value}-decision-one",
        plan_digest=demo.plan.plan_digest,
        approval_digest=pending.approval.canonical_digest,
    )
    approved = demo.approvals.decide(
        demo.approvers[1],
        approval_id=pending.approval.approval_id,
        disposition=ApprovalDisposition.GRANT,
        rationale="Second distinct approver confirms target, digest, and risk.",
        expected_version=first.version,
        command_id=f"demo-{scenario.value}-decision-two",
        plan_digest=demo.plan.plan_digest,
        approval_digest=pending.approval.canonical_digest,
    )
    dry_run = demo.effects.preflight(
        demo.worker,
        plan_id=demo.plan.plan_id,
        action_id="restart-checkout",
        expected_version=approved.version,
        operation_id=f"demo-{scenario.value}-preflight",
        attempt=1,
    )
    effect: EffectOutcome | None = dry_run.outcome
    reconciled = False
    try:
        receipt = demo.effects.execute(
            demo.worker,
            plan_id=demo.plan.plan_id,
            action_id="restart-checkout",
            expected_version=approved.version + 2,
            operation_id=f"demo-{scenario.value}-execute",
            attempt=1,
        )
        effect = receipt.outcome
    except EffectAmbiguous:
        effect = EffectOutcome.AMBIGUOUS
        demo.adapter.settle_ambiguous_as_applied(
            tenant_id=demo.plan.tenant_id,
            idempotency_key=demo.plan.actions[0].idempotency_key,
        )
        receipt = demo.effects.reconcile(
            demo.worker,
            plan_id=demo.plan.plan_id,
            action_id="restart-checkout",
            expected_version=approved.version + 5,
            operation_id="demo-ambiguity-reconcile",
            attempt=2,
        )
        reconciled = True
    demo.clock.advance()
    # Register post-effect evidence so EffectService.verify() can confirm freshness.
    demo.evidence_store.add(
        Evidence(
            evidence_id="checkout-post-effect-demo",
            tenant_id=demo.plan.tenant_id,
            kind=EvidenceKind.CHANGE,
            source="demo-k8s-watch",
            locator="github:deployments/checkout-v42",
            observed_at=demo.clock.now(),
            summary="Checkout deployment restarted successfully.",
            facts={"available_replicas": 3, "checkout_failure_rate_bps": 42},
            content_hash="c" * 64,
        )
    )
    try:
        verification = demo.effects.verify(
            demo.worker,
            plan_id=demo.plan.plan_id,
            action_id="restart-checkout",
            expected_version=(
                approved.version + 7 if reconciled else approved.version + 5
            ),
            operation_id=f"demo-{scenario.value}-verify",
            effect_receipt=receipt,
            fresh_evidence=(),
            attempt=1,
        )
    except VerificationFailed:
        if scenario is RemediationDemoScenario.ROLLBACK:
            rollback = demo.effects.rollback(
                demo.worker,
                plan_id=demo.plan.plan_id,
                action_id="restart-checkout",
                expected_version=(
                    approved.version + 9 if reconciled else approved.version + 7
                ),
                operation_id="demo-rollback",
                attempt=1,
            )
            return _result(
                demo,
                scenario,
                approval_count=2,
                effect_outcome=effect,
                reconciled=reconciled,
                verification_satisfied=False,
                rollback_outcome=rollback.outcome,
            )
        return _result(
            demo,
            scenario,
            approval_count=2,
            effect_outcome=effect,
            reconciled=reconciled,
            verification_satisfied=False,
        )
    return _result(
        demo,
        scenario,
        approval_count=2,
        effect_outcome=effect,
        reconciled=reconciled,
        verification_satisfied=verification.postconditions_satisfied,
    )


def _build_demo(scenario: RemediationDemoScenario) -> _Demo:
    clock = _Clock()
    policy = _action_policy()
    policy_store = InMemoryActionPolicyStore((policy,))
    ledger = InMemoryRemediationLedger()
    store = InMemoryRemediationControlStore()
    application_policy = _Policy()
    proposer = _identity(
        role="incident-responder",
        subject="alice",
        actions=(
            Action.REMEDIATION_PROPOSE,
            Action.APPROVAL_REQUEST,
            Action.REMEDIATION_READ,
        ),
    )
    approvers = (
        _identity(
            role="incident-commander",
            subject="bob",
            actions=(Action.APPROVAL_DECIDE, Action.REMEDIATION_READ),
        ),
        _identity(
            role="change-approver",
            subject="carol",
            actions=(Action.APPROVAL_DECIDE, Action.REMEDIATION_READ),
        ),
    )
    worker = _identity(
        role="effect-worker",
        subject="worker",
        actions=(Action.EFFECT_EXECUTE, Action.EFFECT_READ),
        principal_kind=PrincipalKind.WORKLOAD,
    )
    verification_facts = (
        {
            "available_replicas": 3,
            "checkout_failure_rate_bps": 500,
        }
        if scenario
        in {
            RemediationDemoScenario.VERIFICATION_FAILURE,
            RemediationDemoScenario.ROLLBACK,
        }
        else None
    )
    adapter = DeterministicActionAdapter(
        clock=clock,
        execute_outcomes=(
            (EffectOutcome.AMBIGUOUS,)
            if scenario is RemediationDemoScenario.AMBIGUITY
            else (EffectOutcome.SUCCEEDED,)
        ),
        verification_facts=verification_facts,
    )
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
        quotas=InMemoryEffectQuota({"tenant-acme": 1}),
        claims=InMemoryEffectClaims(),
        clock=clock,
        evidence=evidence_store,
    )
    return _Demo(
        clock=clock,
        policy=policy,
        ledger=ledger,
        store=store,
        approvals=approvals,
        effects=effects,
        adapter=adapter,
        proposer=proposer,
        approvers=approvers,
        worker=worker,
        plan=_plan(
            proposer,
            policy,
            expires_at=(
                DEMO_TIME + timedelta(minutes=1)
                if scenario is RemediationDemoScenario.EXPIRY
                else DEMO_TIME + timedelta(hours=2)
            ),
        ),
        evidence_store=evidence_store,
    )


def _identity(
    *,
    role: str,
    subject: str,
    actions: tuple[Action, ...],
    principal_kind: PrincipalKind = PrincipalKind.HUMAN,
) -> IdentityContext:
    permissions = tuple(sorted(action.value for action in actions))
    grant = GrantBinding(
        role=role,
        purpose="incident-response",
        permissions=permissions,
        risk_ceiling=RiskLevel.HIGH,
        expires_at=DEMO_TIME + timedelta(days=1),
    )
    return IdentityContext(
        tenant_id="tenant-acme",
        issuer="https://demo.aegis.invalid",
        subject_id=subject,
        principal_kind=principal_kind,
        roles=(role,),
        permissions=permissions,
        purposes=("incident-response",),
        grants=(grant,),
        grant_version=1,
        authenticated_at=DEMO_TIME - timedelta(minutes=1),
        expires_at=DEMO_TIME + timedelta(days=1),
        request_id=f"demo-{subject}",
        trace_id=f"trace-{subject}",
    )


def _action_policy() -> ActionPolicy:
    material = {
        "tenant_id": "tenant-acme",
        "policy_id": "checkout-effect-policy",
        "revision": 1,
        "role_revision": 1,
        "quota_revision": 1,
        "enabled": True,
        "allowed_action_types": ("kubernetes.rollout_restart",),
        "allowed_target_fingerprints": ("a" * 64,),
        "allowed_namespaces": ("checkout",),
        "maintenance_window_start": DEMO_TIME - timedelta(hours=1),
        "maintenance_window_end": DEMO_TIME + timedelta(hours=4),
        "max_risk": RiskLevel.HIGH,
        "max_blast_radius": BlastRadius.ONE_SERVICE,
        "remaining_effects": 5,
        "high_risk_quorum": 2,
        "normal_quorum": 1,
        "approver_roles": ("change-approver", "incident-commander"),
        "prohibit_self_approval": True,
        "require_accepted_critic": True,
    }
    return ActionPolicy(**material, policy_digest=canonical_digest(material))


def _plan(
    proposer: IdentityContext,
    policy: ActionPolicy,
    *,
    expires_at: datetime,
) -> RemediationPlan:
    action_material = {
        "schema_version": 1,
        "action_id": "restart-checkout",
        "action_type": "kubernetes.rollout_restart",
        "target": KubernetesTarget(
            cluster_ref="cluster-production-eu",
            namespace="checkout",
            name="checkout-api",
            uid="deployment-uid-001",
            resource_version="1042",
            resource_fingerprint="a" * 64,
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
        "idempotency_key": "checkout-restart-demo",
        "compensation": CompensationContract(
            enabled=True,
            action="rollback_revision",
            rollback_revision="checkout-v41",
            requires_fresh_approval=False,
        ),
    }
    action = ActionDefinition(
        **action_material,
        canonical_digest=canonical_digest(action_material),
    )
    plan_material = {
        "schema_version": 1,
        "plan_id": "checkout-remediation-demo",
        "tenant_id": "tenant-acme",
        "run_id": "checkout-run-demo",
        "incident_id": "checkout-20260816-demo",
        "proposer_ref": stable_id(
            "actor",
            proposer.issuer,
            proposer.subject_id,
            length=32,
        ),
        "target_fingerprint": "a" * 64,
        "risk": RiskLevel.HIGH,
        "blast_radius": BlastRadius.ONE_SERVICE,
        "rationale": "Restart the exact checkout Deployment after cited regression.",
        "actions": (action,),
        "evidence": (
            Citation(
                evidence_id="checkout-change-demo",
                locator="github:deployments/checkout-v42",
                content_hash="b" * 64,
            ),
        ),
        "critic_status": "accepted",
        "policy_snapshot": policy.snapshot(),
        "created_at": DEMO_TIME,
        "expires_at": expires_at,
    }
    return RemediationPlan(
        **plan_material,
        plan_digest=canonical_digest(plan_material),
    )


def _result(
    demo: _Demo,
    scenario: RemediationDemoScenario,
    *,
    approval_count: int,
    effect_outcome: EffectOutcome | None = None,
    reconciled: bool = False,
    verification_satisfied: bool | None = None,
    rollback_outcome: EffectOutcome | None = None,
) -> RemediationDemoResult:
    projection = demo.ledger.projection(
        tenant_id=demo.plan.tenant_id,
        plan_id=demo.plan.plan_id,
    )
    if projection is None:
        raise RuntimeError("demo remediation projection is missing")
    return RemediationDemoResult(
        scenario=scenario,
        plan_ref=stable_id("plan", demo.plan.plan_id, length=20),
        action_ref=stable_id("action", demo.plan.actions[0].action_id, length=20),
        status=projection.status,
        approval_count=approval_count,
        fact_count=len(
            demo.ledger.facts(
                tenant_id=demo.plan.tenant_id,
                plan_id=demo.plan.plan_id,
            )
        ),
        effect_outcome=effect_outcome,
        reconciled=reconciled,
        verification_satisfied=verification_satisfied,
        rollback_outcome=rollback_outcome,
    )
