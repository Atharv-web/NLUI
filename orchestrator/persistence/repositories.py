"""Narrow repository protocols used by later orchestration modules."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from ..contracts import ApprovalDecision, Intent, Plan, TaskStatus
from ..events import EventEnvelope
from .records import (
    ApprovalRecord,
    CapabilityGrantRecord,
    InvocationStatus,
    OutboxRecord,
    PolicyDecisionRecord,
    StepSecurityRecord,
    TaskRecord,
    ToolInvocationRecord,
)


class TaskRepository(Protocol):
    def create_task(
        self, intent: Intent, event: EventEnvelope, *, owner: str | None = None,
        outbox_topic: str = "jarvis:events",
    ) -> tuple[TaskRecord, EventEnvelope]: ...

    def get_task(self, task_id: str) -> TaskRecord: ...

    def transition_task(
        self, task_id: str, expected_status: TaskStatus, new_status: TaskStatus,
        event: EventEnvelope, *, outbox_topic: str = "jarvis:events",
    ) -> EventEnvelope: ...


class PlanRepository(Protocol):
    def save_plan(
        self, plan: Plan, event: EventEnvelope, *, outbox_topic: str = "jarvis:events"
    ) -> EventEnvelope: ...

    def get_plan(self, plan_id: str, version: int) -> Plan: ...

    def set_plan_acceptance(
        self, plan_id: str, version: int, expected: str | None, decision: str,
        event: EventEnvelope, *, outbox_topic: str = "jarvis:events",
    ) -> EventEnvelope: ...


class InvocationRepository(Protocol):
    def record_invocation(
        self, record: ToolInvocationRecord, event: EventEnvelope,
        *, outbox_topic: str = "jarvis:events",
    ) -> EventEnvelope: ...

    def get_invocation_by_idempotency_key(
        self, idempotency_key: str
    ) -> ToolInvocationRecord | None: ...

    def update_invocation(
        self, record: ToolInvocationRecord, expected_status: InvocationStatus,
        event: EventEnvelope, *, outbox_topic: str = "jarvis:events",
    ) -> EventEnvelope: ...


class AuditRepository(Protocol):
    def append_event(
        self, event: EventEnvelope, *, outbox_topic: str = "jarvis:events"
    ) -> EventEnvelope: ...

    def list_events(self, *, task_id: str | None = None) -> tuple[EventEnvelope, ...]: ...

    def verify_audit_chain(self) -> int: ...


class OutboxRepository(Protocol):
    def list_pending_outbox(
        self, limit: int = 100, *, available_before: datetime | None = None
    ) -> tuple[OutboxRecord, ...]: ...

    def mark_outbox_published(
        self, outbox_id: str, published_at: datetime, *,
        delivery_transport: str = "redis", published_reference: str | None = None,
    ) -> None: ...

    def mark_outbox_failed(
        self, outbox_id: str, *, error_code: str, available_at: datetime
    ) -> None: ...


class FencingRepository(Protocol):
    def next_fencing_token(self, resource: str) -> int: ...


class SafetyRepository(Protocol):
    def get_step_security_context(self, step_id: str) -> StepSecurityRecord: ...

    def record_policy_decision(
        self, record: PolicyDecisionRecord, event: EventEnvelope,
        *, outbox_topic: str = "jarvis:events",
    ) -> EventEnvelope: ...

    def get_policy_decision(self, decision_id: str) -> PolicyDecisionRecord: ...

    def record_approval(
        self, record: ApprovalRecord, event: EventEnvelope,
        *, outbox_topic: str = "jarvis:events",
    ) -> EventEnvelope: ...

    def get_approval(self, approval_id: str) -> ApprovalRecord: ...

    def transition_approval_secure(
        self, approval_id: str, expected: ApprovalDecision,
        decision: ApprovalDecision, event: EventEnvelope, *, now: datetime,
        approver: str | None = None, outbox_topic: str = "jarvis:events",
    ) -> ApprovalRecord: ...

    def record_capability_grant(
        self, record: CapabilityGrantRecord, event: EventEnvelope,
        *, outbox_topic: str = "jarvis:events",
    ) -> EventEnvelope: ...

    def get_capability_grant(self, grant_id: str) -> CapabilityGrantRecord: ...

    def consume_authorization(
        self, invocation_id: str, capability_grant_id: str,
        authorization_event: EventEnvelope, *, now: datetime,
        approval_consumed_event: EventEnvelope | None = None,
        outbox_topic: str = "jarvis:events",
    ) -> tuple[EventEnvelope, ...]: ...
