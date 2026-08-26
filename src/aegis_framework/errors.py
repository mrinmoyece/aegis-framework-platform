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


class ApprovalDenied(AegisFrameworkError):
    pass


class ApprovalExpired(AegisFrameworkError):
    pass


class ApprovalRevoked(AegisFrameworkError):
    pass


class EffectConflict(AegisFrameworkError):
    pass


class EffectAmbiguous(AegisFrameworkError):
    pass


class VerificationFailed(AegisFrameworkError):
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


class SandboxRejected(AegisFrameworkError):
    pass


class SandboxUnavailable(AegisFrameworkError):
    pass


class SandboxAmbiguous(AegisFrameworkError):
    pass


class ArtifactQuarantined(AegisFrameworkError):
    pass


class AmbiguousTransportError(AegisFrameworkError):
    """Network delivery may have reached the external peer."""
