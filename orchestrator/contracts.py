"""Strict, versioned orchestration contracts for Milestone 1."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


CONTRACT_SCHEMA_VERSION = "1.0"


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class RiskLevel(str, Enum):
    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"
    R4 = "R4"


class TaskMode(str, Enum):
    ROUTINE = "routine"
    CODING = "coding"
    COMPUTER_USE = "computer_use"


class TaskStatus(str, Enum):
    RECEIVED = "received"
    DISCOVERING = "discovering"
    PLANNED = "planned"
    AWAITING_PLAN_APPROVAL = "awaiting_plan_approval"
    READY = "ready"
    QUEUED = "queued"
    RUNNING = "running"
    AWAITING_STEP_APPROVAL = "awaiting_step_approval"
    VERIFYING = "verifying"
    REPAIRING = "repairing"
    COMPLETED = "completed"
    PAUSED = "paused"
    CANCELLED = "cancelled"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class PolicyDisposition(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class ApprovalDecision(str, Enum):
    PENDING = "pending"
    GRANTED = "granted"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"
    CONSUMED = "consumed"


class ToolOutcome(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    OUTCOME_UNKNOWN = "outcome_unknown"
    CANCELLED = "cancelled"


class EvidenceKind(str, Enum):
    FILE_HASH = "file_hash"
    PROCESS_STATE = "process_state"
    PROVIDER_RECEIPT = "provider_receipt"
    SCREENSHOT = "screenshot"
    STRUCTURED_RESULT = "structured_result"
    TEST_REPORT = "test_report"
    URL_STATE = "url_state"


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return value


class Intent(StrictContract):
    schema_version: Literal["1.0"] = CONTRACT_SCHEMA_VERSION
    intent_id: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=128)
    trace_id: str = Field(min_length=1, max_length=128)
    mode: TaskMode
    goal: str = Field(min_length=1, max_length=20_000)
    received_at: datetime
    workspace: str | None = Field(default=None, max_length=4096)

    _aware_received_at = field_validator("received_at")(_require_aware)


class StepDependency(StrictContract):
    step_id: str = Field(min_length=1, max_length=128)
    depends_on_step_id: str = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def no_self_dependency(self) -> "StepDependency":
        if self.step_id == self.depends_on_step_id:
            raise ValueError("a step cannot depend on itself")
        return self


class ToolProposal(StrictContract):
    tool_name: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any]
    exact_target: str | None = Field(default=None, max_length=4096)

    @field_validator("tool_name")
    @classmethod
    def registered_tool_only(cls, value: str) -> str:
        from .tool_registry import TOOL_REGISTRY

        if value not in TOOL_REGISTRY:
            raise ValueError(f"unknown tool: {value}")
        return value


class PlanStep(StrictContract):
    step_id: str = Field(min_length=1, max_length=128)
    action: str = Field(min_length=1, max_length=2000)
    expected_result: str = Field(min_length=1, max_length=4000)
    proposal: ToolProposal | None = None
    risk: RiskLevel
    attempt_limit: int = Field(default=1, ge=1, le=3)
    timeout_seconds: int = Field(ge=1, le=3600)
    capability_scope: tuple[str, ...] = ()


class Plan(StrictContract):
    schema_version: Literal["1.0"] = CONTRACT_SCHEMA_VERSION
    plan_id: str = Field(min_length=1, max_length=128)
    task_id: str = Field(min_length=1, max_length=128)
    trace_id: str = Field(min_length=1, max_length=128)
    version: int = Field(ge=1)
    model_name: str = Field(min_length=1, max_length=256)
    prompt_version: str = Field(min_length=1, max_length=128)
    summary: str = Field(min_length=1, max_length=10_000)
    risk_summary: str = Field(min_length=1, max_length=10_000)
    steps: tuple[PlanStep, ...] = Field(min_length=1, max_length=500)
    dependencies: tuple[StepDependency, ...] = ()

    @model_validator(mode="after")
    def validate_graph(self) -> "Plan":
        step_ids = [step.step_id for step in self.steps]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("plan step IDs must be unique")
        known = set(step_ids)
        graph: dict[str, set[str]] = {step_id: set() for step_id in step_ids}
        for edge in self.dependencies:
            if edge.step_id not in known or edge.depends_on_step_id not in known:
                raise ValueError("dependency references an unknown step")
            graph[edge.step_id].add(edge.depends_on_step_id)

        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(step_id: str) -> None:
            if step_id in visiting:
                raise ValueError("plan dependencies must be acyclic")
            if step_id in visited:
                return
            visiting.add(step_id)
            for dependency in graph[step_id]:
                visit(dependency)
            visiting.remove(step_id)
            visited.add(step_id)

        for step_id in step_ids:
            visit(step_id)
        return self


class PolicyDecision(StrictContract):
    decision_id: str = Field(min_length=1, max_length=128)
    task_id: str = Field(min_length=1, max_length=128)
    step_id: str = Field(min_length=1, max_length=128)
    policy_version: str = Field(min_length=1, max_length=128)
    risk: RiskLevel
    disposition: PolicyDisposition
    reasons: tuple[str, ...] = Field(min_length=1)
    evaluated_at: datetime

    _aware_evaluated_at = field_validator("evaluated_at")(_require_aware)


class Approval(StrictContract):
    approval_id: str = Field(min_length=1, max_length=128)
    task_id: str = Field(min_length=1, max_length=128)
    step_id: str = Field(min_length=1, max_length=128)
    plan_version: int = Field(ge=1)
    risk: RiskLevel
    scope_hash: str = Field(min_length=32, max_length=256)
    channel: str = Field(min_length=1, max_length=64)
    decision: ApprovalDecision
    expires_at: datetime
    approver: str | None = Field(default=None, max_length=256)

    _aware_expires_at = field_validator("expires_at")(_require_aware)


class Evidence(StrictContract):
    evidence_id: str = Field(min_length=1, max_length=128)
    kind: EvidenceKind
    reference: str = Field(min_length=1, max_length=4096)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    captured_at: datetime
    sensitivity_class: str = Field(min_length=1, max_length=64)

    _aware_captured_at = field_validator("captured_at")(_require_aware)


class ToolResult(StrictContract):
    invocation_id: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=1, max_length=256)
    outcome: ToolOutcome
    side_effect_occurred: bool
    started_at: datetime
    completed_at: datetime
    evidence: tuple[Evidence, ...] = ()
    result_reference: str | None = Field(default=None, max_length=4096)
    error_code: str | None = Field(default=None, max_length=128)

    _aware_started_at = field_validator("started_at")(_require_aware)
    _aware_completed_at = field_validator("completed_at")(_require_aware)

    @model_validator(mode="after")
    def valid_timing(self) -> "ToolResult":
        if self.completed_at < self.started_at:
            raise ValueError("completed_at cannot precede started_at")
        return self


class OrchestrationError(StrictContract):
    code: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=2000)
    retryable: bool
    safe_detail_reference: str | None = Field(default=None, max_length=4096)
