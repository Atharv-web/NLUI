"""Stable, non-sensitive safety-core errors."""


class SafetyError(RuntimeError):
    """Base safety error safe for control flow."""


class PolicyDeniedError(SafetyError):
    """Deterministic policy denied the proposed action."""


class ApprovalRequiredError(SafetyError):
    """A trusted, scoped approval is required."""


class AuthorizationError(SafetyError):
    """Approval or capability authorization is invalid."""


class GatewayUnavailableError(SafetyError):
    """The gateway could not establish its durable safety boundary."""
