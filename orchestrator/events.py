"""Canonical event taxonomy and shared versioned event envelope."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import ConfigDict, Field, field_validator

from .contracts import RiskLevel, StrictContract, _require_aware
from .correlation import CorrelationContext


EVENT_SCHEMA_VERSION = "1.0"


class EventSeverity(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class EventType(str, Enum):
    INTENT_RECEIVED = "intent.received"
    INTENT_CLASSIFIED = "intent.classified"
    TASK_CREATED = "task.created"
    DISCOVERY_STARTED = "discovery.started"
    DISCOVERY_COMPLETED = "discovery.completed"
    PLAN_PROPOSED = "plan.proposed"
    PLAN_VERSIONED = "plan.versioned"
    PLAN_APPROVED = "plan.approved"
    PLAN_REJECTED = "plan.rejected"
    POLICY_EVALUATED = "policy.evaluated"
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_GRANTED = "approval.granted"
    APPROVAL_DENIED = "approval.denied"
    APPROVAL_EXPIRED = "approval.expired"
    APPROVAL_CONSUMED = "approval.consumed"
    CAPABILITY_ISSUED = "capability.issued"
    CAPABILITY_REJECTED = "capability.rejected"
    STEP_QUEUED = "step.queued"
    STEP_LEASED = "step.leased"
    STEP_STARTED = "step.started"
    STEP_HEARTBEAT = "step.heartbeat"
    STEP_CANCEL_REQUESTED = "step.cancel_requested"
    STEP_COMPLETED = "step.completed"
    STEP_FAILED = "step.failed"
    STEP_CANCELLED = "step.cancelled"
    TOOL_REQUESTED = "tool.requested"
    TOOL_AUTHORIZED = "tool.authorized"
    TOOL_STARTED = "tool.started"
    TOOL_SUCCEEDED = "tool.succeeded"
    TOOL_FAILED = "tool.failed"
    TOOL_OUTCOME_UNKNOWN = "tool.outcome_unknown"
    VERIFICATION_STARTED = "verification.started"
    VERIFICATION_PASSED = "verification.passed"
    VERIFICATION_FAILED = "verification.failed"
    REPAIR_STARTED = "repair.started"
    REPAIR_COMPLETED = "repair.completed"
    ROLLBACK_STARTED = "rollback.started"
    ROLLBACK_COMPLETED = "rollback.completed"
    # Read compatibility for historical audit rows only; no broker runtime exists.
    REDIS_DEGRADED = "redis.degraded"
    REDIS_RECOVERED = "redis.recovered"
    WORKER_STARTED = "worker.started"
    WORKER_LOST = "worker.lost"
    MODEL_CIRCUIT_OPENED = "model.circuit_opened"
    MODEL_CIRCUIT_CLOSED = "model.circuit_closed"
    AUDIT_INTEGRITY_FAILED = "audit.integrity_failed"
    TASK_COMPLETED = "task.completed"
    TASK_PAUSED = "task.paused"
    TASK_CANCELLED = "task.cancelled"
    TASK_FAILED = "task.failed"
    TASK_ROLLED_BACK = "task.rolled_back"


class EventEnvelope(StrictContract):
    """Flattened envelope shared by future durable audit and diagnostics layers."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    event_id: str = Field(min_length=1, max_length=128)
    schema_version: Literal["1.0"] = EVENT_SCHEMA_VERSION
    event_type: EventType
    occurred_at: datetime
    recorded_at: datetime
    severity: EventSeverity

    session_id: str = Field(min_length=1, max_length=128)
    trace_id: str = Field(min_length=1, max_length=128)
    task_id: str | None = Field(default=None, max_length=128)
    plan_id: str | None = Field(default=None, max_length=128)
    plan_version: int | None = Field(default=None, ge=1)
    step_id: str | None = Field(default=None, max_length=128)
    parent_step_id: str | None = Field(default=None, max_length=128)
    attempt_id: str | None = Field(default=None, max_length=128)
    invocation_id: str | None = Field(default=None, max_length=128)
    approval_id: str | None = Field(default=None, max_length=128)

    worker_id: str | None = Field(default=None, max_length=128)
    worker_type: str | None = Field(default=None, max_length=128)
    model_role: str | None = Field(default=None, max_length=64)
    model_name: str | None = Field(default=None, max_length=256)
    tool_name: str | None = Field(default=None, max_length=128)
    idempotency_key: str | None = Field(default=None, max_length=256)
    fencing_token: int | None = Field(default=None, ge=0)

    risk_level: RiskLevel | None = None
    policy_version: str | None = Field(default=None, max_length=128)
    approval_channel: str | None = Field(default=None, max_length=64)
    approval_scope_hash: str | None = Field(default=None, max_length=256)
    capability_grant_id: str | None = Field(default=None, max_length=128)

    previous_state: str | None = Field(default=None, max_length=128)
    new_state: str | None = Field(default=None, max_length=128)
    outcome: str | None = Field(default=None, max_length=128)
    duration_ms: float | None = Field(default=None, ge=0)
    retry_count: int | None = Field(default=None, ge=0)
    error_code: str | None = Field(default=None, max_length=128)
    recovery_disposition: str | None = Field(default=None, max_length=128)

    redaction_policy_version: str = Field(min_length=1, max_length=128)
    payload_reference: str | None = Field(default=None, max_length=4096)
    payload_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    sensitivity_class: str = Field(min_length=1, max_length=64)
    retention_class: str = Field(min_length=1, max_length=64)
    redacted_metadata: dict[str, Any] = Field(default_factory=dict)
    previous_event_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    event_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    _aware_occurred_at = field_validator("occurred_at")(_require_aware)
    _aware_recorded_at = field_validator("recorded_at")(_require_aware)

    @classmethod
    def correlation_fields(cls, context: CorrelationContext) -> dict[str, object]:
        return context.model_dump()
