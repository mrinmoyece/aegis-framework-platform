"""Measurable Layer 11 SLI/SLO and error-budget contracts."""

from __future__ import annotations

from typing import Final

from pydantic import Field

from aegis_framework.domain import Identifier, StrictModel


class ServiceLevelObjective(StrictModel):
    slo_id: Identifier
    component: Identifier
    objective_percent: float = Field(gt=0, le=100)
    window_days: int = Field(ge=1, le=90)
    sli: str = Field(min_length=1, max_length=300)
    good_event: str = Field(min_length=1, max_length=300)
    total_event: str = Field(min_length=1, max_length=300)
    exclusions: tuple[Identifier, ...] = ()
    hard_safety_alert: bool = False
    runbook: str = Field(pattern=r"^docs/runbooks/[a-z0-9-]+\.md$")


SLO_CATALOG: Final[tuple[ServiceLevelObjective, ...]] = (
    ServiceLevelObjective(
        slo_id="api-availability",
        component="api",
        objective_percent=99.9,
        window_days=28,
        sli="successful authorized API responses / eligible authorized requests",
        good_event="status is ok, denied, or validation; latency <= 2 seconds",
        total_event="authenticated requests excluding client disconnects",
        exclusions=("client_error",),
        runbook="docs/runbooks/api-availability.md",
    ),
    ServiceLevelObjective(
        slo_id="safe-execution",
        component="effects",
        objective_percent=100,
        window_days=28,
        sli="effects with valid approval, fence, idempotency and durable receipt",
        good_event="all mandatory controls present and reconciled",
        total_event="all effect attempts",
        hard_safety_alert=True,
        runbook="docs/runbooks/safety-violation.md",
    ),
    ServiceLevelObjective(
        slo_id="durable-freshness",
        component="ledger",
        objective_percent=99.9,
        window_days=28,
        sli="accepted commands projected within 30 seconds",
        good_event="projection cursor reaches accepted event within 30 seconds",
        total_event="accepted ledger commands",
        runbook="docs/runbooks/durable-freshness.md",
    ),
    ServiceLevelObjective(
        slo_id="evidence-completeness",
        component="evidence",
        objective_percent=99.5,
        window_days=28,
        sli="completed evidence queries with valid provenance and citations",
        good_event="bounded collection finishes without unresolved stale pages",
        total_event="authorized evidence queries",
        runbook="docs/runbooks/evidence-health.md",
    ),
    ServiceLevelObjective(
        slo_id="model-gateway",
        component="model",
        objective_percent=99.0,
        window_days=28,
        sli="policy-valid structured responses within the declared timeout",
        good_event="validated structured result or explicit safe abstention",
        total_event="reserved logical model calls",
        runbook="docs/runbooks/model-gateway.md",
    ),
    ServiceLevelObjective(
        slo_id="approval-effect",
        component="approvals",
        objective_percent=99.9,
        window_days=28,
        sli="terminal approvals and effects with converged durable state",
        good_event="terminal state and receipt reconcile without ambiguity",
        total_event="terminal approval and effect operations",
        hard_safety_alert=True,
        runbook="docs/runbooks/approval-effect.md",
    ),
    ServiceLevelObjective(
        slo_id="sandbox-cleanup",
        component="sandbox",
        objective_percent=99.9,
        window_days=28,
        sli="terminal sandboxes cleaned within 15 minutes",
        good_event="cleanup receipt reaches terminal clean state",
        total_event="terminal sandbox executions",
        hard_safety_alert=True,
        runbook="docs/runbooks/sandbox-cleanup.md",
    ),
    ServiceLevelObjective(
        slo_id="memory-retrieval",
        component="memory",
        objective_percent=99.0,
        window_days=28,
        sli="bounded retrievals with valid provenance completed within 1 second",
        good_event="retrieval returns cited context or explicit empty result",
        total_event="authorized memory retrieval operations",
        runbook="docs/runbooks/memory-retrieval.md",
    ),
    ServiceLevelObjective(
        slo_id="evaluation-health",
        component="evals",
        objective_percent=99.0,
        window_days=28,
        sli="scheduled governed evaluation suites complete before expiry",
        good_event="suite result is current, deterministic, and policy-valid",
        total_event="scheduled evaluation suites",
        hard_safety_alert=True,
        runbook="docs/runbooks/evaluation-health.md",
    ),
)


class ErrorBudgetPolicy(StrictModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    fast_burn_windows: tuple[str, str] = ("5m", "1h")
    slow_burn_windows: tuple[str, str] = ("30m", "6h")
    fast_burn_threshold: float = 14.4
    slow_burn_threshold: float = 6.0
    exhausted_action: str = (
        "freeze reliability-risking releases until the owning SLO recovers"
    )
    safety_action: str = (
        "page immediately; safety violations never consume availability budget"
    )


ERROR_BUDGET_POLICY: Final = ErrorBudgetPolicy()
