"""Explicit failures surfaced at application and adapter boundaries."""


class AegisFrameworkError(Exception):
    """Base class for expected application failures."""


class PolicyDenied(AegisFrameworkError):
    pass


class AuthenticationFailed(AegisFrameworkError):
    pass


class IdentityUnavailable(AegisFrameworkError):
    pass


class BudgetExhausted(AegisFrameworkError):
    pass


class EvidenceIsolationViolation(AegisFrameworkError):
    pass


class EvidenceUnavailable(AegisFrameworkError):
    pass


class ConnectorDisabled(AegisFrameworkError):
    pass


class ConnectorRejected(AegisFrameworkError):
    pass


class ConnectorRateLimited(AegisFrameworkError):
    pass


class ReconciliationRequired(AegisFrameworkError):
    pass


class ModelProviderError(AegisFrameworkError):
    pass


class OrchestrationFailure(AegisFrameworkError):
    pass


class ApprovalBoundaryFailure(AegisFrameworkError):
    pass


class EffectsDisabled(AegisFrameworkError):
    pass


class IdempotencyConflict(AegisFrameworkError):
    pass


class InvestigationInProgress(AegisFrameworkError):
    pass


class OptionalDependencyMissing(AegisFrameworkError):
    pass


class ConcurrencyConflict(AegisFrameworkError):
    pass


class RepositoryUnavailable(AegisFrameworkError):
    pass


class AuditFailure(AegisFrameworkError):
    pass


class MigrationFailure(AegisFrameworkError):
    pass


class IntegrityFailure(AegisFrameworkError):
    pass


class MessageClaimConflict(AegisFrameworkError):
    pass


class PayloadRejected(AegisFrameworkError):
    pass
