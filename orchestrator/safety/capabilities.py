"""One-time exact-scope capability issuance."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from ..config import SafetyConfig
from ..events import EventType
from ..persistence import (
    ApprovalRecord,
    CapabilityGrantRecord,
    CapabilityGrantStatus,
    DurableStore,
)
from .contracts import ExecutionRequest, PolicyEvaluation
from .events import safety_event


class CapabilityIssuer:
    def __init__(self, store: DurableStore, config: SafetyConfig) -> None:
        self.store = store
        self.config = config

    def issue(
        self,
        request: ExecutionRequest,
        evaluation: PolicyEvaluation,
        approval: ApprovalRecord | None,
        *,
        now: datetime | None = None,
    ) -> CapabilityGrantRecord:
        current = now or datetime.now(timezone.utc)
        record = CapabilityGrantRecord(
            capability_grant_id=uuid.uuid4().hex,
            policy_decision_id=evaluation.decision_id,
            approval_id=approval.approval_id if approval is not None else None,
            task_id=request.task_id,
            step_id=request.step_id,
            plan_id=request.plan_id,
            plan_version=request.plan_version,
            tool_name=request.tool_name,
            normalized_arguments_hash=evaluation.normalized_arguments_hash,
            exact_target_hash=evaluation.exact_target_hash,
            scope_hash=evaluation.scope_hash,
            risk=evaluation.risk,
            constraints=evaluation.capability_constraints,
            status=CapabilityGrantStatus.ISSUED,
            expires_at=current
            + timedelta(seconds=self.config.capability_ttl_seconds),
            created_at=current,
        )
        event = safety_event(
            EventType.CAPABILITY_ISSUED,
            request,
            current,
            evaluation=evaluation,
            approval_id=record.approval_id,
            capability_grant_id=record.capability_grant_id,
            outcome=CapabilityGrantStatus.ISSUED.value,
        )
        self.store.record_capability_grant(record, event)
        return record
