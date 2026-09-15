"""Canonical safety event construction without raw arguments or results."""

from __future__ import annotations

import uuid
from datetime import datetime

from ..events import EventEnvelope, EventSeverity, EventType
from .contracts import ExecutionRequest, PolicyEvaluation


def safety_event(
    event_type: EventType,
    request: ExecutionRequest,
    now: datetime,
    *,
    evaluation: PolicyEvaluation | None = None,
    approval_id: str | None = None,
    capability_grant_id: str | None = None,
    severity: EventSeverity = EventSeverity.INFO,
    outcome: str | None = None,
    previous_state: str | None = None,
    new_state: str | None = None,
    error_code: str | None = None,
    duration_ms: float | None = None,
) -> EventEnvelope:
    return EventEnvelope(
        event_id=uuid.uuid4().hex,
        event_type=event_type,
        occurred_at=now,
        recorded_at=now,
        severity=severity,
        session_id=request.session_id,
        trace_id=request.trace_id,
        task_id=request.task_id,
        plan_id=request.plan_id,
        plan_version=request.plan_version,
        step_id=request.step_id,
        attempt_id=request.attempt_id,
        invocation_id=request.invocation_id,
        approval_id=approval_id,
        tool_name=request.tool_name,
        idempotency_key=request.idempotency_key,
        risk_level=evaluation.risk if evaluation is not None else None,
        policy_version=(evaluation.policy_version if evaluation is not None else None),
        approval_channel=None,
        approval_scope_hash=(
            evaluation.scope_hash if evaluation is not None else None
        ),
        capability_grant_id=capability_grant_id,
        previous_state=previous_state,
        new_state=new_state,
        outcome=outcome,
        duration_ms=duration_ms,
        error_code=error_code,
        redaction_policy_version="1.0",
        sensitivity_class="operational_metadata",
        retention_class="audit",
    )
