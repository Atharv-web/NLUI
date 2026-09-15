"""Minimal one-step intake while the Milestone 5 state machine is not active."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

from ..contracts import Intent, Plan, PlanStep, RiskLevel, TaskMode, ToolProposal
from ..events import EventEnvelope, EventSeverity, EventType
from ..persistence import DurableStore
from ..persistence.hashing import canonical_json, sha256_text
from ..tool_registry import TOOL_REGISTRY
from .contracts import ExecutionRequest, GatewayResult
from .gateway import ExecutionGateway
from .policy import derive_exact_target


class LegacyToolIntake:
    """Create durable one-step work before delegating exclusively to the gateway."""

    def __init__(self, store: DurableStore, gateway: ExecutionGateway) -> None:
        self.store = store
        self.gateway = gateway
        self._dispatch_lock = asyncio.Lock()

    async def execute(
        self, *, session_id: str, trace_id: str, call_id: str,
        tool_name: str, arguments: dict[str, object],
        workspace: str | None = None,
    ) -> GatewayResult:
        # Desktop actions share state. Serialize until resource-aware workers exist.
        async with self._dispatch_lock:
            return await self._execute(
                session_id=session_id, trace_id=trace_id, call_id=call_id,
                tool_name=tool_name, arguments=arguments, workspace=workspace,
            )

    async def _execute(
        self,
        *,
        session_id: str,
        trace_id: str,
        call_id: str,
        tool_name: str,
        arguments: dict[str, object],
        workspace: str | None = None,
    ) -> GatewayResult:
        metadata = TOOL_REGISTRY[tool_name]
        idempotency_key = sha256_text(
            canonical_json(
                {
                    "session_id": session_id,
                    "call_id": call_id,
                    "tool_name": tool_name,
                    "arguments": arguments,
                }
            )
        )
        existing = self.store.get_invocation_by_idempotency_key(idempotency_key)
        if existing is not None:
            task = self.store.get_task(existing.task_id)
            step = self.store.get_step_security_context(existing.step_id)
            return await self.gateway.execute(ExecutionRequest(
                session_id=task.session_id, trace_id=task.trace_id,
                task_id=task.task_id, plan_id=step.plan_id,
                plan_version=step.plan_version, step_id=existing.step_id,
                attempt_id=existing.attempt_id, invocation_id=existing.invocation_id,
                idempotency_key=idempotency_key, task_mode=task.mode,
                tool_name=tool_name, arguments=dict(arguments),
                exact_target=derive_exact_target(tool_name, arguments),
                workspace=task.workspace,
            ))
        now = datetime.now(timezone.utc)
        task_id = uuid.uuid4().hex
        plan_id = uuid.uuid4().hex
        step_id = uuid.uuid4().hex
        attempt_id = uuid.uuid4().hex
        invocation_id = uuid.uuid4().hex
        target = derive_exact_target(tool_name, arguments)
        mode = _mode_for_tool(tool_name)
        intent = Intent(
            intent_id=uuid.uuid4().hex,
            session_id=session_id,
            trace_id=trace_id,
            mode=mode,
            goal=f"Execute registered tool {tool_name}",
            received_at=now,
            workspace=workspace,
        )
        self.store.create_task(
            intent,
            _event(
                EventType.TASK_CREATED,
                now,
                session_id=session_id,
                trace_id=trace_id,
                task_id=task_id,
            ),
        )
        plan = Plan(
            plan_id=plan_id,
            task_id=task_id,
            trace_id=trace_id,
            version=1,
            model_name="legacy-live-intake",
            prompt_version="legacy-one-step-v1",
            summary=f"One registered {tool_name} action",
            risk_summary=f"Registry risk floor {metadata.default_risk.value}",
            steps=(
                PlanStep(
                    step_id=step_id,
                    action=f"Execute registered tool {tool_name}",
                    expected_result="Return a normalized gateway result",
                    proposal=ToolProposal(
                        tool_name=tool_name,
                        arguments=dict(arguments),
                        exact_target=target,
                    ),
                    risk=metadata.default_risk,
                    attempt_limit=1,
                    timeout_seconds=metadata.default_timeout_seconds,
                    capability_scope=(f"tool:{tool_name}",),
                ),
            ),
        )
        self.store.save_plan(
            plan,
            _event(
                EventType.PLAN_PROPOSED,
                now,
                session_id=session_id,
                trace_id=trace_id,
                task_id=task_id,
                plan_id=plan_id,
                plan_version=1,
            ),
        )
        return await self.gateway.execute(
            ExecutionRequest(
                session_id=session_id,
                trace_id=trace_id,
                task_id=task_id,
                plan_id=plan_id,
                plan_version=1,
                step_id=step_id,
                attempt_id=attempt_id,
                invocation_id=invocation_id,
                idempotency_key=idempotency_key,
                task_mode=mode,
                tool_name=tool_name,
                arguments=dict(arguments),
                exact_target=target,
                workspace=workspace,
            )
        )


def _mode_for_tool(tool_name: str) -> TaskMode:
    if tool_name in {"code_helper", "dev_agent"}:
        return TaskMode.CODING
    if tool_name in {"computer_control", "screen_process"}:
        return TaskMode.COMPUTER_USE
    return TaskMode.ROUTINE


def _event(
    event_type: EventType,
    now: datetime,
    *,
    session_id: str,
    trace_id: str,
    task_id: str,
    plan_id: str | None = None,
    plan_version: int | None = None,
) -> EventEnvelope:
    return EventEnvelope(
        event_id=uuid.uuid4().hex,
        event_type=event_type,
        occurred_at=now,
        recorded_at=now,
        severity=EventSeverity.INFO,
        session_id=session_id,
        trace_id=trace_id,
        task_id=task_id,
        plan_id=plan_id,
        plan_version=plan_version,
        redaction_policy_version="1.0",
        sensitivity_class="operational_metadata",
        retention_class="audit",
    )
