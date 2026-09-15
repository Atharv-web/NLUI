"""Exact-scope, expiring, revocable trusted approval lifecycle."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from ..config import SafetyConfig
from ..contracts import ApprovalDecision, PolicyDisposition, RiskLevel
from ..events import EventSeverity, EventType
from ..persistence import ApprovalRecord, DurableStore, RecordConflictError
from .contracts import ExecutionRequest, PolicyEvaluation
from .errors import AuthorizationError
from .events import safety_event


class ApprovalService:
    def __init__(self, store: DurableStore, config: SafetyConfig) -> None:
        self.store = store
        self.config = config

    def request(
        self,
        request: ExecutionRequest,
        evaluation: PolicyEvaluation,
        *,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        current = now or datetime.now(timezone.utc)
        ttl = (
            self.config.high_risk_approval_ttl_seconds
            if evaluation.risk is RiskLevel.R3
            else self.config.approval_ttl_seconds
        )
        record = ApprovalRecord(
            approval_id=uuid.uuid4().hex,
            task_id=request.task_id,
            step_id=request.step_id,
            plan_id=request.plan_id,
            plan_version=request.plan_version,
            risk=evaluation.risk,
            reason="trusted_approval_required",
            scope_hash=evaluation.scope_hash,
            decision=ApprovalDecision.PENDING,
            channel="trusted_desktop",
            expires_at=current + timedelta(seconds=ttl),
            created_at=current,
            policy_decision_id=evaluation.decision_id,
            tool_name=request.tool_name,
            normalized_arguments_hash=evaluation.normalized_arguments_hash,
            exact_target_hash=evaluation.exact_target_hash,
        )
        event = safety_event(
            EventType.APPROVAL_REQUESTED,
            request,
            current,
            evaluation=evaluation,
            approval_id=record.approval_id,
            outcome=ApprovalDecision.PENDING.value,
        )
        self.store.record_approval(record, event)
        return record

    def grant(
        self,
        approval_id: str,
        *,
        channel: str,
        approver: str,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        self._validate_trusted_actor(channel, approver)
        current = now or datetime.now(timezone.utc)
        record = self.store.get_approval(approval_id)
        request = _request_from_approval(self.store, record, approval_id)
        evaluation = _evaluation_from_approval(record, self.config.policy_version)
        event = safety_event(
            EventType.APPROVAL_GRANTED,
            request,
            current,
            evaluation=evaluation,
            approval_id=approval_id,
            outcome=ApprovalDecision.GRANTED.value,
        ).model_copy(update={"approval_channel": channel})
        try:
            return self.store.transition_approval_secure(
                approval_id,
                ApprovalDecision.PENDING,
                ApprovalDecision.GRANTED,
                event,
                now=current,
                approver=approver,
            )
        except RecordConflictError as exc:
            raise AuthorizationError("approval is expired or no longer pending") from exc

    def deny(
        self,
        approval_id: str,
        *,
        channel: str,
        approver: str,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        self._validate_trusted_actor(channel, approver)
        return self._transition(
            approval_id,
            ApprovalDecision.PENDING,
            ApprovalDecision.DENIED,
            EventType.APPROVAL_DENIED,
            channel=channel,
            approver=approver,
            now=now,
        )

    def revoke(
        self,
        approval_id: str,
        *,
        channel: str,
        approver: str,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        self._validate_trusted_actor(channel, approver)
        return self._transition(
            approval_id,
            ApprovalDecision.GRANTED,
            ApprovalDecision.REVOKED,
            EventType.APPROVAL_DENIED,
            channel=channel,
            approver=approver,
            now=now,
        )

    def validate(
        self,
        approval_id: str,
        request: ExecutionRequest,
        evaluation: PolicyEvaluation,
        *,
        now: datetime,
    ) -> ApprovalRecord:
        record = self.store.get_approval(approval_id)
        if record.expires_at <= now:
            if record.decision in {ApprovalDecision.PENDING, ApprovalDecision.GRANTED}:
                self._transition(
                    approval_id,
                    record.decision,
                    ApprovalDecision.EXPIRED,
                    EventType.APPROVAL_EXPIRED,
                    channel="system",
                    approver="system",
                    now=now,
                )
            raise AuthorizationError("approval has expired")
        if record.decision is not ApprovalDecision.GRANTED:
            raise AuthorizationError("approval is not granted")
        expected = (
            request.task_id,
            request.step_id,
            request.plan_id,
            request.plan_version,
            request.tool_name,
            evaluation.normalized_arguments_hash,
            evaluation.exact_target_hash,
            evaluation.scope_hash,
            evaluation.risk,
        )
        actual = (
            record.task_id,
            record.step_id,
            record.plan_id,
            record.plan_version,
            record.tool_name,
            record.normalized_arguments_hash,
            record.exact_target_hash,
            record.scope_hash,
            record.risk,
        )
        if actual != expected:
            raise AuthorizationError("approval scope does not match execution")
        return record

    def _transition(
        self,
        approval_id: str,
        expected: ApprovalDecision,
        decision: ApprovalDecision,
        event_type: EventType,
        *,
        channel: str,
        approver: str,
        now: datetime | None,
    ) -> ApprovalRecord:
        current = now or datetime.now(timezone.utc)
        record = self.store.get_approval(approval_id)
        request = _request_from_approval(self.store, record, approval_id)
        evaluation = _evaluation_from_approval(record, self.config.policy_version)
        event = safety_event(
            event_type,
            request,
            current,
            evaluation=evaluation,
            approval_id=approval_id,
            severity=(
                EventSeverity.WARNING
                if decision in {ApprovalDecision.DENIED, ApprovalDecision.REVOKED}
                else EventSeverity.INFO
            ),
            outcome=decision.value,
        ).model_copy(update={"approval_channel": channel})
        return self.store.transition_approval_secure(
            approval_id,
            expected,
            decision,
            event,
            now=current,
            approver=approver,
        )

    def _validate_trusted_actor(self, channel: str, approver: str) -> None:
        if channel not in self.config.trusted_approval_channels:
            raise AuthorizationError("approval channel is not trusted")
        identity = approver.strip().lower()
        if not identity or len(approver) > 256 or identity in {
            "model",
            "assistant",
            "voice_model",
        }:
            raise AuthorizationError("approval requires a trusted user identity")


def _request_from_approval(
    store: DurableStore, record: ApprovalRecord, approval_id: str
) -> ExecutionRequest:
    task = store.get_task(record.task_id)
    return ExecutionRequest(
        session_id=task.session_id,
        trace_id=task.trace_id,
        task_id=record.task_id,
        plan_id=record.plan_id,
        plan_version=record.plan_version,
        step_id=record.step_id,
        attempt_id="approval-lifecycle",
        invocation_id="approval-lifecycle",
        idempotency_key=f"approval:{approval_id}",
        task_mode=task.mode,
        tool_name=record.tool_name or "system_status",
        arguments={},
        approval_id=approval_id,
    )


def _evaluation_from_approval(
    record: ApprovalRecord, policy_version: str
) -> PolicyEvaluation:
    return PolicyEvaluation(
        decision_id=record.policy_decision_id or "legacy-policy-decision",
        policy_version=policy_version,
        risk=record.risk,
        disposition=PolicyDisposition.REQUIRE_APPROVAL,
        reasons=("approval_lifecycle",),
        normalized_arguments_hash=record.normalized_arguments_hash or "0" * 64,
        exact_target_hash=record.exact_target_hash or "0" * 64,
        scope_hash=record.scope_hash,
        capability_constraints=(),
    )
