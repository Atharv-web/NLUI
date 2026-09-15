"""Strict contracts for deterministic policy and gateway execution."""

from __future__ import annotations

import json
import math
from enum import Enum
from typing import Any

from pydantic import Field, field_validator

from ..contracts import (
    PolicyDisposition,
    RiskLevel,
    StrictContract,
    TaskMode,
    ToolOutcome,
)


class GatewayDisposition(str, Enum):
    EXECUTED = "executed"
    APPROVAL_REQUIRED = "approval_required"
    DENIED = "denied"
    FAILED = "failed"
    OUTCOME_UNKNOWN = "outcome_unknown"
    REPLAYED = "replayed"


class ExecutionRequest(StrictContract):
    session_id: str = Field(min_length=1, max_length=128)
    trace_id: str = Field(min_length=1, max_length=128)
    task_id: str = Field(min_length=1, max_length=128)
    plan_id: str = Field(min_length=1, max_length=128)
    plan_version: int = Field(ge=1)
    step_id: str = Field(min_length=1, max_length=128)
    attempt_id: str = Field(min_length=1, max_length=128)
    invocation_id: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=1, max_length=256)
    task_mode: TaskMode
    tool_name: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any]
    exact_target: str | None = Field(default=None, max_length=4096)
    workspace: str | None = Field(default=None, max_length=4096)
    allowed_domains: tuple[str, ...] = ()
    data_sensitivity: tuple[str, ...] = ()
    approval_id: str | None = Field(default=None, max_length=128)

    @field_validator("tool_name")
    @classmethod
    def known_tool(cls, value: str) -> str:
        from ..tool_registry import TOOL_REGISTRY

        if value not in TOOL_REGISTRY:
            raise ValueError("tool is not registered")
        return value

    @field_validator("allowed_domains", "data_sensitivity", mode="before")
    @classmethod
    def tuple_from_json(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("arguments")
    @classmethod
    def bounded_json_arguments(cls, value: dict[str, Any]) -> dict[str, Any]:
        def validate(item: object, depth: int = 0) -> None:
            if depth > 8:
                raise ValueError("tool arguments exceed maximum nesting")
            if item is None or isinstance(item, (str, bool, int)):
                if isinstance(item, str) and len(item) > 20_000:
                    raise ValueError("tool argument string is too large")
                return
            if isinstance(item, float):
                if not math.isfinite(item):
                    raise ValueError("tool argument number must be finite")
                return
            if isinstance(item, list):
                if len(item) > 500:
                    raise ValueError("tool argument collection is too large")
                for child in item:
                    validate(child, depth + 1)
                return
            if isinstance(item, dict):
                if len(item) > 200 or any(
                    not isinstance(key, str) or len(key) > 128 for key in item
                ):
                    raise ValueError("tool argument object is invalid")
                for child in item.values():
                    validate(child, depth + 1)
                return
            raise ValueError("tool arguments must contain JSON values only")

        validate(value)
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        if len(encoded.encode("utf-8")) > 65_536:
            raise ValueError("tool arguments exceed maximum encoded size")
        return value


class PolicyEvaluation(StrictContract):
    decision_id: str
    policy_version: str = Field(min_length=1, max_length=128)
    risk: RiskLevel
    disposition: PolicyDisposition
    reasons: tuple[str, ...] = Field(min_length=1)
    normalized_arguments_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    exact_target_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    scope_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    capability_constraints: tuple[str, ...]


class AdapterExecution(StrictContract):
    output: Any = None
    side_effect_occurred: bool
    result_reference: str | None = Field(
        default=None,
        pattern=r"^(?:sha256:[0-9a-f]{64}|artifact:[A-Za-z0-9_-]{1,128})$",
    )


class GatewayResult(StrictContract):
    disposition: GatewayDisposition
    outcome: ToolOutcome | None = None
    output: Any = None
    approval_id: str | None = None
    invocation_id: str | None = None
    risk: RiskLevel | None = None
    reason_codes: tuple[str, ...] = ()
    audit_committed: bool = True
