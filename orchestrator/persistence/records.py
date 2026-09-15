"""Typed rows accepted and returned by the durability layer."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import Field, field_validator

from ..contracts import (
    ApprovalDecision,
    PolicyDisposition,
    RiskLevel,
    StrictContract,
    TaskMode,
    TaskStatus,
    _require_aware,
)


class InvocationStatus(str, Enum):
    REQUESTED = "requested"
    AUTHORIZED = "authorized"
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    OUTCOME_UNKNOWN = "outcome_unknown"
    CANCELLED = "cancelled"


class SideEffectMarker(str, Enum):
    NONE = "none"
    POSSIBLE = "possible"
    OCCURRED = "occurred"
    OUTCOME_UNKNOWN = "outcome_unknown"


class TaskRecord(StrictContract):
    task_id: str
    session_id: str
    trace_id: str
    goal_artifact_id: str
    goal_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    mode: TaskMode
    status: TaskStatus
    workspace: str | None = None
    owner: str | None = None
    cancellation_requested: bool = False
    created_at: datetime
    updated_at: datetime

    _aware_created = field_validator("created_at")(_require_aware)
    _aware_updated = field_validator("updated_at")(_require_aware)


class ToolInvocationRecord(StrictContract):
    invocation_id: str
    task_id: str
    step_id: str
    attempt_id: str
    idempotency_key: str
    tool_name: str
    normalized_arguments_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: InvocationStatus
    side_effect_marker: SideEffectMarker
    result_reference: str | None = None
    error_code: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    policy_decision_id: str | None = None
    capability_grant_id: str | None = None
    approval_id: str | None = None

    _aware_started = field_validator("started_at")(
        lambda value: _require_aware(value) if value is not None else value
    )
    _aware_completed = field_validator("completed_at")(
        lambda value: _require_aware(value) if value is not None else value
    )
    _aware_invocation_created = field_validator("created_at")(_require_aware)
    _aware_invocation_updated = field_validator("updated_at")(_require_aware)


class ApprovalRecord(StrictContract):
    approval_id: str
    task_id: str
    step_id: str
    plan_id: str
    plan_version: int = Field(ge=1)
    risk: RiskLevel
    reason: str
    scope_hash: str = Field(min_length=32, max_length=256)
    decision: ApprovalDecision
    channel: str
    expires_at: datetime
    approver: str | None = None
    consumed_at: datetime | None = None
    created_at: datetime
    policy_decision_id: str | None = None
    tool_name: str | None = None
    normalized_arguments_hash: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    exact_target_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    revoked_at: datetime | None = None
    decision_channel: str | None = Field(default=None, max_length=64)

    _aware_approval_expires = field_validator("expires_at")(_require_aware)
    _aware_approval_consumed = field_validator("consumed_at")(
        lambda value: _require_aware(value) if value is not None else value
    )
    _aware_approval_created = field_validator("created_at")(_require_aware)
    _aware_approval_revoked = field_validator("revoked_at")(
        lambda value: _require_aware(value) if value is not None else value
    )


class CapabilityGrantStatus(str, Enum):
    ISSUED = "issued"
    CONSUMED = "consumed"
    REVOKED = "revoked"
    EXPIRED = "expired"


class PolicyDecisionRecord(StrictContract):
    decision_id: str
    task_id: str
    step_id: str
    plan_id: str
    plan_version: int = Field(ge=1)
    policy_version: str
    risk: RiskLevel
    disposition: PolicyDisposition
    reasons: tuple[str, ...]
    tool_name: str
    normalized_arguments_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    exact_target_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    scope_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    capability_constraints: tuple[str, ...] = ()
    evaluated_at: datetime

    _aware_policy_evaluated = field_validator("evaluated_at")(_require_aware)


class CapabilityGrantRecord(StrictContract):
    capability_grant_id: str
    policy_decision_id: str
    approval_id: str | None = None
    task_id: str
    step_id: str
    plan_id: str
    plan_version: int = Field(ge=1)
    tool_name: str
    normalized_arguments_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    exact_target_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    scope_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    risk: RiskLevel
    constraints: tuple[str, ...] = ()
    status: CapabilityGrantStatus
    expires_at: datetime
    consumed_at: datetime | None = None
    created_at: datetime

    _aware_capability_expires = field_validator("expires_at")(_require_aware)
    _aware_capability_consumed = field_validator("consumed_at")(
        lambda value: _require_aware(value) if value is not None else value
    )
    _aware_capability_created = field_validator("created_at")(_require_aware)


class StepSecurityRecord(StrictContract):
    step_id: str
    task_id: str
    plan_id: str
    plan_version: int = Field(ge=1)
    tool_name: str
    normalized_arguments_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    exact_target_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: str
    timeout_seconds: int = Field(ge=1, le=3600)
    risk: RiskLevel
    capability_scope: tuple[str, ...] = ()


class VerificationRecord(StrictContract):
    verification_id: str
    task_id: str
    step_id: str
    invocation_id: str | None = None
    verifier_type: str
    evidence_references: tuple[str, ...]
    result: str = Field(pattern=r"^(passed|failed)$")
    confidence: float | None = Field(default=None, ge=0, le=1)
    repair_count: int = Field(default=0, ge=0, le=2)
    created_at: datetime

    _aware_verification_created = field_validator("created_at")(_require_aware)


class ArtifactRecord(StrictContract):
    artifact_id: str
    task_id: str
    step_id: str | None = None
    kind: str
    storage_reference: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int | None = Field(default=None, ge=0)
    sensitivity_class: str
    retention_class: str
    encrypted: bool
    encryption_key_reference: str | None = None
    redaction_metadata: dict[str, str] = Field(default_factory=dict)
    created_at: datetime

    _aware_artifact_created = field_validator("created_at")(_require_aware)


class CheckpointRecord(StrictContract):
    checkpoint_id: str
    task_id: str
    step_id: str | None = None
    workspace: str
    state_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    metadata: dict[str, str] = Field(default_factory=dict)
    created_at: datetime

    _aware_checkpoint_created = field_validator("created_at")(_require_aware)


class OutboxRecord(StrictContract):
    outbox_id: str
    event_id: str
    topic: str
    partition_key: str
    payload_json: str
    attempts: int = Field(ge=0)
    available_at: datetime
    published_at: datetime | None = None
    delivery_transport: str | None = Field(default=None, max_length=32)
    published_reference: str | None = Field(default=None, max_length=256)
    last_error_code: str | None = None
    created_at: datetime

    _aware_available = field_validator("available_at")(_require_aware)
    _aware_published = field_validator("published_at")(
        lambda value: _require_aware(value) if value is not None else value
    )
    _aware_outbox_created = field_validator("created_at")(_require_aware)
