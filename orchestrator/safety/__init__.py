"""Milestone 4 deterministic safety boundary."""

from .adapters import CallableToolAdapter, ToolAdapter, ToolAdapterRegistry
from .approvals import ApprovalService
from .capabilities import CapabilityIssuer
from .contracts import (
    AdapterExecution,
    ExecutionRequest,
    GatewayDisposition,
    GatewayResult,
    PolicyEvaluation,
)
from .errors import (
    ApprovalRequiredError,
    AuthorizationError,
    GatewayUnavailableError,
    PolicyDeniedError,
    SafetyError,
)
from .gateway import ExecutionGateway
from .legacy import LegacyToolIntake
from .policy import (
    PolicyEngine,
    derive_exact_target,
    exact_target_hash,
    normalized_arguments_hash,
)

__all__ = [
    "AdapterExecution",
    "ApprovalRequiredError",
    "ApprovalService",
    "AuthorizationError",
    "CallableToolAdapter",
    "CapabilityIssuer",
    "ExecutionGateway",
    "ExecutionRequest",
    "GatewayDisposition",
    "GatewayResult",
    "GatewayUnavailableError",
    "LegacyToolIntake",
    "PolicyDeniedError",
    "PolicyEngine",
    "PolicyEvaluation",
    "SafetyError",
    "ToolAdapter",
    "ToolAdapterRegistry",
    "derive_exact_target",
    "exact_target_hash",
    "normalized_arguments_hash",
]
