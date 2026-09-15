"""Atomic repositories for durable orchestration state, audit, and outbox."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from pydantic import ValidationError

from ..contracts import ApprovalDecision, Intent, Plan, RiskLevel, TaskMode, TaskStatus
from ..events import EventEnvelope, EventType
from .database import SQLiteDatabase
from .errors import (
    AuditIntegrityError,
    PersistenceError,
    RecordConflictError,
    RecordNotFoundError,
)
from .hashing import AuditHasher, canonical_json, sha256_text
from .records import (
    ApprovalRecord,
    ArtifactRecord,
    CapabilityGrantRecord,
    CapabilityGrantStatus,
    CheckpointRecord,
    OutboxRecord,
    PolicyDecisionRecord,
    StepSecurityRecord,
    TaskRecord,
    ToolInvocationRecord,
    VerificationRecord,
    InvocationStatus,
    SideEffectMarker,
)
from .schema import MigrationRunner
from .secrets import EncryptedPayloadStore, StoredPayload


_TASK_CREATION_EVENTS = {EventType.TASK_CREATED}
_PLAN_EVENTS = {EventType.PLAN_PROPOSED, EventType.PLAN_VERSIONED}


class DurableStore:
    """All authoritative mutations include an event and outbox row atomically."""

    def __init__(
        self,
        database: SQLiteDatabase,
        payload_store: EncryptedPayloadStore,
        *,
        audit_hasher: AuditHasher | None = None,
    ) -> None:
        self.database = database
        self.payload_store = payload_store
        self.audit_hasher = audit_hasher or AuditHasher()
        self.migrations = MigrationRunner(database)

    def initialize(self, *, verify_integrity: bool = True) -> int:
        self.payload_store.ensure_key()
        version = self.migrations.migrate()
        if verify_integrity:
            self.verify_database_integrity()
            self.verify_audit_chain()
            self.verify_artifact_integrity()
        return version

    def create_task(
        self,
        intent: Intent,
        event: EventEnvelope,
        *,
        owner: str | None = None,
        outbox_topic: str = "jarvis:events",
    ) -> tuple[TaskRecord, EventEnvelope]:
        self._validate_event(event, allowed=_TASK_CREATION_EVENTS)
        if event.task_id is None:
            raise ValueError("task.created event requires task_id")
        if event.session_id != intent.session_id or event.trace_id != intent.trace_id:
            raise ValueError("task event correlation does not match the intent")

        stored = self.payload_store.put(intent.goal.encode("utf-8"))
        record = TaskRecord(
            task_id=event.task_id,
            session_id=intent.session_id,
            trace_id=intent.trace_id,
            goal_artifact_id=stored.artifact_id,
            goal_hash=stored.sha256,
            mode=intent.mode,
            status=TaskStatus.RECEIVED,
            workspace=intent.workspace,
            owner=owner,
            created_at=event.recorded_at,
            updated_at=event.recorded_at,
        )
        try:
            with self.database.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO tasks(
                        task_id, session_id, trace_id, goal_artifact_id, goal_hash,
                        mode, status, workspace, owner, cancellation_requested,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                    """,
                    (
                        record.task_id,
                        record.session_id,
                        record.trace_id,
                        record.goal_artifact_id,
                        record.goal_hash,
                        record.mode.value,
                        record.status.value,
                        record.workspace,
                        record.owner,
                        _dt(record.created_at),
                        _dt(record.updated_at),
                    ),
                )
                self._insert_payload_artifact(
                    connection,
                    stored,
                    task_id=record.task_id,
                    kind="task_goal",
                    sensitivity_class="user_goal",
                    retention_class="task",
                    created_at=record.created_at,
                )
                sealed = self._append_event(connection, event)
                self._enqueue_event(connection, sealed, outbox_topic)
            return record, sealed
        except sqlite3.IntegrityError as exc:
            self.payload_store.delete(stored.storage_reference)
            raise RecordConflictError("task, artifact, or event already exists") from exc
        except Exception:
            self.payload_store.delete(stored.storage_reference)
            raise

    def get_task(self, task_id: str) -> TaskRecord:
        with self.database.read() as connection:
            row = connection.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
        if row is None:
            raise RecordNotFoundError("task does not exist")
        return _task_from_row(row)

    def load_task_goal(self, task_id: str) -> str:
        task = self.get_task(task_id)
        artifact = self.get_artifact(task.goal_artifact_id)
        payload = self.payload_store.get(_stored_payload(artifact))
        return payload.decode("utf-8")

    def transition_task(
        self,
        task_id: str,
        expected_status: TaskStatus,
        new_status: TaskStatus,
        event: EventEnvelope,
        *,
        outbox_topic: str = "jarvis:events",
    ) -> EventEnvelope:
        if event.task_id != task_id:
            raise ValueError("task event correlation does not match the mutation")
        if event.previous_state != expected_status.value or event.new_state != new_status.value:
            raise ValueError("task event states do not match the requested transition")
        with self.database.transaction() as connection:
            result = connection.execute(
                """
                UPDATE tasks SET status = ?, updated_at = ?
                WHERE task_id = ? AND status = ?
                """,
                (new_status.value, _dt(event.recorded_at), task_id, expected_status.value),
            )
            if result.rowcount != 1:
                exists = connection.execute(
                    "SELECT status FROM tasks WHERE task_id = ?", (task_id,)
                ).fetchone()
                if exists is None:
                    raise RecordNotFoundError("task does not exist")
                raise RecordConflictError("task status changed concurrently")
            sealed = self._append_event(connection, event)
            self._enqueue_event(connection, sealed, outbox_topic)
            return sealed

    def request_task_cancellation(
        self,
        task_id: str,
        event: EventEnvelope,
        *,
        outbox_topic: str = "jarvis:events",
    ) -> EventEnvelope:
        if event.task_id != task_id or event.event_type is not EventType.STEP_CANCEL_REQUESTED:
            raise ValueError("cancellation event does not match the task mutation")
        with self.database.transaction() as connection:
            result = connection.execute(
                """
                UPDATE tasks SET cancellation_requested = 1, updated_at = ?
                WHERE task_id = ? AND cancellation_requested = 0
                """,
                (_dt(event.recorded_at), task_id),
            )
            if result.rowcount != 1:
                raise RecordConflictError("task is missing or cancellation was already requested")
            sealed = self._append_event(connection, event)
            self._enqueue_event(connection, sealed, outbox_topic)
            return sealed

    def save_plan(
        self,
        plan: Plan,
        event: EventEnvelope,
        *,
        outbox_topic: str = "jarvis:events",
    ) -> EventEnvelope:
        self._validate_event(event, allowed=_PLAN_EVENTS)
        if (
            event.task_id != plan.task_id
            or event.plan_id != plan.plan_id
            or event.plan_version != plan.version
            or event.trace_id != plan.trace_id
        ):
            raise ValueError("plan event correlation does not match the plan")
        plan_json = plan.model_dump_json()
        stored = self.payload_store.put(plan_json.encode("utf-8"))
        try:
            with self.database.transaction() as connection:
                self._insert_payload_artifact(
                    connection,
                    stored,
                    task_id=plan.task_id,
                    kind="plan",
                    sensitivity_class="plan_content",
                    retention_class="task",
                    created_at=event.recorded_at,
                )
                connection.execute(
                    """
                    INSERT INTO plans(
                        plan_id, version, task_id, trace_id, model_name,
                        prompt_version, plan_artifact_id, plan_hash,
                        user_acceptance, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
                    """,
                    (
                        plan.plan_id,
                        plan.version,
                        plan.task_id,
                        plan.trace_id,
                        plan.model_name,
                        plan.prompt_version,
                        stored.artifact_id,
                        stored.sha256,
                        _dt(event.recorded_at),
                    ),
                )
                for step in plan.steps:
                    proposal = step.proposal
                    arguments_json = (
                        canonical_json(proposal.arguments) if proposal is not None else None
                    )
                    target = proposal.exact_target if proposal is not None else None
                    connection.execute(
                        """
                        INSERT INTO steps(
                            step_id, plan_id, plan_version, task_id, action_hash,
                            tool_name, arguments_artifact_id, normalized_arguments_hash,
                            target_artifact_id, exact_target_hash, expected_result_hash,
                            status, attempt_limit, timeout_seconds, risk,
                            capability_scope_json, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            step.step_id,
                            plan.plan_id,
                            plan.version,
                            plan.task_id,
                            sha256_text(step.action),
                            proposal.tool_name if proposal else None,
                            stored.artifact_id if arguments_json is not None else None,
                            sha256_text(arguments_json) if arguments_json is not None else None,
                            stored.artifact_id if target is not None else None,
                            sha256_text(target) if target is not None else None,
                            sha256_text(step.expected_result),
                            "planned",
                            step.attempt_limit,
                            step.timeout_seconds,
                            step.risk.value,
                            canonical_json(list(step.capability_scope)),
                            _dt(event.recorded_at),
                        ),
                    )
                for dependency in plan.dependencies:
                    connection.execute(
                        """
                        INSERT INTO step_dependencies(step_id, depends_on_step_id)
                        VALUES (?, ?)
                        """,
                        (dependency.step_id, dependency.depends_on_step_id),
                    )
                sealed = self._append_event(connection, event)
                self._enqueue_event(connection, sealed, outbox_topic)
            return sealed
        except sqlite3.IntegrityError as exc:
            self.payload_store.delete(stored.storage_reference)
            raise RecordConflictError("plan, step, artifact, or event already exists") from exc
        except Exception:
            self.payload_store.delete(stored.storage_reference)
            raise

    def get_plan(self, plan_id: str, version: int) -> Plan:
        with self.database.read() as connection:
            row = connection.execute(
                """
                SELECT a.* FROM plans p
                JOIN artifacts a ON a.artifact_id = p.plan_artifact_id
                WHERE p.plan_id = ? AND p.version = ?
                """,
                (plan_id, version),
            ).fetchone()
        if row is None:
            raise RecordNotFoundError("plan does not exist")
        artifact = _artifact_from_row(row)
        payload = self.payload_store.get(_stored_payload(artifact))
        try:
            return Plan.model_validate_json(payload)
        except ValidationError as exc:
            raise AuditIntegrityError("stored plan artifact is schema-invalid") from exc

    def get_step_security_context(self, step_id: str) -> StepSecurityRecord:
        with self.database.read() as connection:
            row = connection.execute(
                "SELECT * FROM steps WHERE step_id = ?", (step_id,)
            ).fetchone()
        if row is None:
            raise RecordNotFoundError("step does not exist")
        if row["tool_name"] is None or row["normalized_arguments_hash"] is None:
            raise AuditIntegrityError("step has no executable tool proposal")
        return StepSecurityRecord(
            step_id=row["step_id"],
            task_id=row["task_id"],
            plan_id=row["plan_id"],
            plan_version=row["plan_version"],
            tool_name=row["tool_name"],
            normalized_arguments_hash=row["normalized_arguments_hash"],
            exact_target_hash=(
                row["exact_target_hash"]
                if row["exact_target_hash"] is not None
                else sha256_text("null")
            ),
            status=row["status"],
            timeout_seconds=row["timeout_seconds"],
            risk=RiskLevel(row["risk"]),
            capability_scope=tuple(json.loads(row["capability_scope_json"])),
        )

    def set_plan_acceptance(
        self,
        plan_id: str,
        version: int,
        expected: str | None,
        decision: str,
        event: EventEnvelope,
        *,
        outbox_topic: str = "jarvis:events",
    ) -> EventEnvelope:
        if event.plan_id != plan_id or event.plan_version != version:
            raise ValueError("plan event correlation does not match the acceptance mutation")
        if event.event_type not in {EventType.PLAN_APPROVED, EventType.PLAN_REJECTED}:
            raise ValueError("plan acceptance requires an approved or rejected event")
        with self.database.transaction() as connection:
            if expected is None:
                result = connection.execute(
                    """
                    UPDATE plans SET user_acceptance = ?
                    WHERE plan_id = ? AND version = ? AND user_acceptance IS NULL
                    """,
                    (decision, plan_id, version),
                )
            else:
                result = connection.execute(
                    """
                    UPDATE plans SET user_acceptance = ?
                    WHERE plan_id = ? AND version = ? AND user_acceptance = ?
                    """,
                    (decision, plan_id, version, expected),
                )
            if result.rowcount != 1:
                raise RecordConflictError("plan acceptance changed concurrently")
            sealed = self._append_event(connection, event)
            self._enqueue_event(connection, sealed, outbox_topic)
            return sealed

    def transition_step(
        self,
        step_id: str,
        expected_status: str,
        new_status: str,
        event: EventEnvelope,
        *,
        outbox_topic: str = "jarvis:events",
    ) -> EventEnvelope:
        if event.step_id != step_id:
            raise ValueError("step event correlation does not match the mutation")
        if event.previous_state != expected_status or event.new_state != new_status:
            raise ValueError("step event states do not match the requested transition")
        with self.database.transaction() as connection:
            result = connection.execute(
                "UPDATE steps SET status = ? WHERE step_id = ? AND status = ?",
                (new_status, step_id, expected_status),
            )
            if result.rowcount != 1:
                exists = connection.execute(
                    "SELECT status FROM steps WHERE step_id = ?", (step_id,)
                ).fetchone()
                if exists is None:
                    raise RecordNotFoundError("step does not exist")
                raise RecordConflictError("step status changed concurrently")
            sealed = self._append_event(connection, event)
            self._enqueue_event(connection, sealed, outbox_topic)
            return sealed

    def record_invocation(
        self,
        record: ToolInvocationRecord,
        event: EventEnvelope,
        *,
        outbox_topic: str = "jarvis:events",
    ) -> EventEnvelope:
        if (
            event.task_id != record.task_id
            or event.step_id != record.step_id
            or event.invocation_id != record.invocation_id
        ):
            raise ValueError("invocation event correlation does not match the record")
        if record.policy_decision_id is not None and (
            event.tool_name != record.tool_name
            or event.attempt_id != record.attempt_id
            or event.idempotency_key != record.idempotency_key
            or event.capability_grant_id != record.capability_grant_id
            or event.approval_id != record.approval_id
        ):
            raise ValueError("authorized invocation event scope does not match")
        try:
            with self.database.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO tool_invocations(
                        invocation_id, task_id, step_id, attempt_id, idempotency_key,
                        tool_name, normalized_arguments_hash, status, result_reference,
                        error_code, side_effect_marker, started_at, completed_at,
                        created_at, updated_at, policy_decision_id,
                        capability_grant_id, approval_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.invocation_id, record.task_id, record.step_id,
                        record.attempt_id, record.idempotency_key, record.tool_name,
                        record.normalized_arguments_hash, record.status.value,
                        record.result_reference, record.error_code,
                        record.side_effect_marker.value, _optional_dt(record.started_at),
                        _optional_dt(record.completed_at), _dt(record.created_at),
                        _dt(record.updated_at), record.policy_decision_id,
                        record.capability_grant_id, record.approval_id,
                    ),
                )
                sealed = self._append_event(connection, event)
                self._enqueue_event(connection, sealed, outbox_topic)
                return sealed
        except sqlite3.IntegrityError as exc:
            raise RecordConflictError("invocation, idempotency key, or event already exists") from exc

    def get_invocation_by_idempotency_key(
        self, idempotency_key: str
    ) -> ToolInvocationRecord | None:
        with self.database.read() as connection:
            row = connection.execute(
                "SELECT * FROM tool_invocations WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
        return _invocation_from_row(row) if row is not None else None

    def update_invocation(
        self,
        record: ToolInvocationRecord,
        expected_status: InvocationStatus,
        event: EventEnvelope,
        *,
        outbox_topic: str = "jarvis:events",
    ) -> EventEnvelope:
        if event.invocation_id != record.invocation_id or event.step_id != record.step_id:
            raise ValueError("invocation event correlation does not match the update")
        if record.policy_decision_id is not None and (
            event.task_id != record.task_id
            or event.tool_name != record.tool_name
            or event.idempotency_key != record.idempotency_key
            or event.capability_grant_id != record.capability_grant_id
            or event.approval_id != record.approval_id
        ):
            raise ValueError("invocation update event scope does not match")
        with self.database.transaction() as connection:
            result = connection.execute(
                """
                UPDATE tool_invocations SET
                    status = ?, result_reference = ?, error_code = ?,
                    side_effect_marker = ?, started_at = ?, completed_at = ?, updated_at = ?
                WHERE invocation_id = ? AND status = ?
                """,
                (
                    record.status.value, record.result_reference, record.error_code,
                    record.side_effect_marker.value, _optional_dt(record.started_at),
                    _optional_dt(record.completed_at), _dt(record.updated_at),
                    record.invocation_id, expected_status.value,
                ),
            )
            if result.rowcount != 1:
                raise RecordConflictError("invocation status changed concurrently")
            sealed = self._append_event(connection, event)
            self._enqueue_event(connection, sealed, outbox_topic)
            return sealed

    def record_approval(
        self, record: ApprovalRecord, event: EventEnvelope, *, outbox_topic: str = "jarvis:events"
    ) -> EventEnvelope:
        if event.approval_id != record.approval_id or event.task_id != record.task_id:
            raise ValueError("approval event correlation does not match the record")
        if record.policy_decision_id is not None and (
            event.event_type is not EventType.APPROVAL_REQUESTED
            or event.step_id != record.step_id
            or event.plan_id != record.plan_id
            or event.plan_version != record.plan_version
            or event.risk_level != record.risk
            or event.approval_scope_hash != record.scope_hash
            or event.tool_name != record.tool_name
        ):
            raise ValueError("approval event scope does not match the record")
        values = (
            record.approval_id, record.task_id, record.step_id, record.plan_id,
            record.plan_version, record.risk.value, record.reason, record.scope_hash,
            record.decision.value, record.channel, _dt(record.expires_at), record.approver,
            _optional_dt(record.consumed_at), _dt(record.created_at),
            record.policy_decision_id, record.tool_name,
            record.normalized_arguments_hash, record.exact_target_hash,
            _optional_dt(record.revoked_at),
        )
        return self._insert_with_event(
            """
            INSERT INTO approvals(
                approval_id, task_id, step_id, plan_id, plan_version, risk, reason,
                scope_hash, decision, channel, expires_at, approver, consumed_at, created_at,
                policy_decision_id, tool_name, normalized_arguments_hash,
                exact_target_hash, revoked_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values, event, outbox_topic, "approval or event already exists",
        )

    def update_approval_decision(
        self,
        approval_id: str,
        expected: ApprovalDecision,
        decision: ApprovalDecision,
        event: EventEnvelope,
        *,
        approver: str | None = None,
        consumed_at: datetime | None = None,
        outbox_topic: str = "jarvis:events",
    ) -> EventEnvelope:
        if event.approval_id != approval_id:
            raise ValueError("approval event correlation does not match the update")
        with self.database.transaction() as connection:
            result = connection.execute(
                """
                UPDATE approvals SET decision = ?, approver = COALESCE(?, approver),
                    consumed_at = COALESCE(?, consumed_at)
                WHERE approval_id = ? AND decision = ?
                """,
                (
                    decision.value, approver, _optional_dt(consumed_at),
                    approval_id, expected.value,
                ),
            )
            if result.rowcount != 1:
                raise RecordConflictError("approval decision changed concurrently")
            sealed = self._append_event(connection, event)
            self._enqueue_event(connection, sealed, outbox_topic)
            return sealed

    def get_approval(self, approval_id: str) -> ApprovalRecord:
        with self.database.read() as connection:
            row = connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
        if row is None:
            raise RecordNotFoundError("approval does not exist")
        return _approval_from_row(row)

    def transition_approval_secure(
        self,
        approval_id: str,
        expected: ApprovalDecision,
        decision: ApprovalDecision,
        event: EventEnvelope,
        *,
        now: datetime,
        approver: str | None = None,
        outbox_topic: str = "jarvis:events",
    ) -> ApprovalRecord:
        if event.approval_id != approval_id:
            raise ValueError("approval event correlation does not match the update")
        allowed_events = {
            ApprovalDecision.GRANTED: EventType.APPROVAL_GRANTED,
            ApprovalDecision.DENIED: EventType.APPROVAL_DENIED,
            ApprovalDecision.EXPIRED: EventType.APPROVAL_EXPIRED,
        }
        expected_event = allowed_events.get(decision)
        if decision is ApprovalDecision.REVOKED:
            expected_event = EventType.APPROVAL_DENIED
        if expected_event is None or event.event_type is not expected_event:
            raise ValueError("approval decision event type is invalid")

        with self.database.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
            if row is None:
                raise RecordNotFoundError("approval does not exist")
            if row["decision"] != expected.value:
                raise RecordConflictError("approval decision changed concurrently")
            if (
                event.task_id != row["task_id"]
                or event.step_id != row["step_id"]
                or event.plan_id != row["plan_id"]
                or event.plan_version != row["plan_version"]
                or event.risk_level != RiskLevel(row["risk"])
                or event.approval_scope_hash != row["scope_hash"]
                or event.tool_name != row["tool_name"]
            ):
                raise ValueError("approval event scope does not match the record")
            expires_at = _parse_dt(row["expires_at"])
            if decision is ApprovalDecision.GRANTED and expires_at <= now:
                raise RecordConflictError("approval has expired")
            result = connection.execute(
                """
                UPDATE approvals SET decision = ?, approver = COALESCE(?, approver),
                    revoked_at = CASE WHEN ? = 'revoked' THEN ? ELSE revoked_at END,
                    decision_channel = COALESCE(?, decision_channel)
                WHERE approval_id = ? AND decision = ?
                """,
                (
                    decision.value,
                    approver,
                    decision.value,
                    _dt(now),
                    event.approval_channel,
                    approval_id,
                    expected.value,
                ),
            )
            if result.rowcount != 1:
                raise RecordConflictError("approval decision changed concurrently")
            sealed = self._append_event(connection, event)
            self._enqueue_event(connection, sealed, outbox_topic)
            updated = connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
        return _approval_from_row(updated)

    def record_policy_decision(
        self,
        record: PolicyDecisionRecord,
        event: EventEnvelope,
        *,
        outbox_topic: str = "jarvis:events",
    ) -> EventEnvelope:
        if event.event_type is not EventType.POLICY_EVALUATED:
            raise ValueError("policy decision requires policy.evaluated event")
        if (
            event.task_id != record.task_id
            or event.step_id != record.step_id
            or event.plan_id != record.plan_id
            or event.plan_version != record.plan_version
            or event.tool_name != record.tool_name
            or event.policy_version != record.policy_version
            or event.risk_level != record.risk
        ):
            raise ValueError("policy event correlation does not match the decision")
        return self._insert_with_event(
            """
            INSERT INTO policy_decisions(
                decision_id, task_id, step_id, plan_id, plan_version,
                policy_version, risk, disposition, reasons_json, tool_name,
                normalized_arguments_hash, exact_target_hash, scope_hash,
                capability_constraints_json, evaluated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.decision_id,
                record.task_id,
                record.step_id,
                record.plan_id,
                record.plan_version,
                record.policy_version,
                record.risk.value,
                record.disposition.value,
                canonical_json(list(record.reasons)),
                record.tool_name,
                record.normalized_arguments_hash,
                record.exact_target_hash,
                record.scope_hash,
                canonical_json(list(record.capability_constraints)),
                _dt(record.evaluated_at),
            ),
            event,
            outbox_topic,
            "policy decision or event already exists",
        )

    def get_policy_decision(self, decision_id: str) -> PolicyDecisionRecord:
        with self.database.read() as connection:
            row = connection.execute(
                "SELECT * FROM policy_decisions WHERE decision_id = ?", (decision_id,)
            ).fetchone()
        if row is None:
            raise RecordNotFoundError("policy decision does not exist")
        return _policy_decision_from_row(row)

    def record_capability_grant(
        self,
        record: CapabilityGrantRecord,
        event: EventEnvelope,
        *,
        outbox_topic: str = "jarvis:events",
    ) -> EventEnvelope:
        if event.event_type is not EventType.CAPABILITY_ISSUED:
            raise ValueError("capability grant requires capability.issued event")
        if (
            event.task_id != record.task_id
            or event.step_id != record.step_id
            or event.capability_grant_id != record.capability_grant_id
            or event.tool_name != record.tool_name
            or event.risk_level != record.risk
            or event.plan_id != record.plan_id
            or event.plan_version != record.plan_version
            or event.approval_id != record.approval_id
            or event.approval_scope_hash != record.scope_hash
        ):
            raise ValueError("capability event correlation does not match the grant")
        return self._insert_with_event(
            """
            INSERT INTO capability_grants(
                capability_grant_id, policy_decision_id, approval_id, task_id,
                step_id, plan_id, plan_version, tool_name,
                normalized_arguments_hash, exact_target_hash, scope_hash, risk,
                constraints_json, status, expires_at, consumed_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.capability_grant_id,
                record.policy_decision_id,
                record.approval_id,
                record.task_id,
                record.step_id,
                record.plan_id,
                record.plan_version,
                record.tool_name,
                record.normalized_arguments_hash,
                record.exact_target_hash,
                record.scope_hash,
                record.risk.value,
                canonical_json(list(record.constraints)),
                record.status.value,
                _dt(record.expires_at),
                _optional_dt(record.consumed_at),
                _dt(record.created_at),
            ),
            event,
            outbox_topic,
            "capability grant or event already exists",
        )

    def get_capability_grant(self, grant_id: str) -> CapabilityGrantRecord:
        with self.database.read() as connection:
            row = connection.execute(
                "SELECT * FROM capability_grants WHERE capability_grant_id = ?",
                (grant_id,),
            ).fetchone()
        if row is None:
            raise RecordNotFoundError("capability grant does not exist")
        return _capability_from_row(row)

    def consume_authorization(
        self,
        invocation_id: str,
        capability_grant_id: str,
        authorization_event: EventEnvelope,
        *,
        now: datetime,
        approval_consumed_event: EventEnvelope | None = None,
        outbox_topic: str = "jarvis:events",
    ) -> tuple[EventEnvelope, ...]:
        """Atomically consume exact approval/capability and authorize execution."""
        if authorization_event.event_type is not EventType.TOOL_AUTHORIZED:
            raise ValueError("authorization requires tool.authorized event")
        with self.database.transaction() as connection:
            invocation = connection.execute(
                "SELECT * FROM tool_invocations WHERE invocation_id = ?",
                (invocation_id,),
            ).fetchone()
            capability = connection.execute(
                "SELECT * FROM capability_grants WHERE capability_grant_id = ?",
                (capability_grant_id,),
            ).fetchone()
            if invocation is None or capability is None:
                raise RecordNotFoundError("invocation or capability does not exist")
            task = connection.execute(
                "SELECT status, cancellation_requested FROM tasks WHERE task_id = ?",
                (capability["task_id"],),
            ).fetchone()
            if task is None:
                raise RecordNotFoundError("task does not exist")
            if task["cancellation_requested"] or task["status"] in {
                TaskStatus.PAUSED.value,
                TaskStatus.COMPLETED.value,
                TaskStatus.CANCELLED.value,
                TaskStatus.FAILED.value,
                TaskStatus.ROLLED_BACK.value,
            }:
                raise RecordConflictError("task is not executable")
            if invocation["status"] != InvocationStatus.REQUESTED.value:
                raise RecordConflictError("invocation is not awaiting authorization")
            if capability["status"] != CapabilityGrantStatus.ISSUED.value:
                raise RecordConflictError("capability grant is not usable")
            if _parse_dt(capability["expires_at"]) <= now:
                raise RecordConflictError("capability grant has expired")
            decision = connection.execute(
                "SELECT * FROM policy_decisions WHERE decision_id = ?",
                (capability["policy_decision_id"],),
            ).fetchone()
            if decision is None:
                raise RecordNotFoundError("policy decision does not exist")
            for field in (
                "task_id", "step_id", "plan_id", "plan_version", "tool_name",
                "normalized_arguments_hash", "exact_target_hash", "scope_hash", "risk",
            ):
                if decision[field] != capability[field]:
                    raise RecordConflictError("capability does not match policy decision")
            if decision["disposition"] == "deny":
                raise RecordConflictError("policy denies execution")
            if (
                decision["risk"] in {"R2", "R3"}
                or decision["disposition"] == "require_approval"
            ) and capability["approval_id"] is None:
                raise RecordConflictError("policy requires an approval")
            for invocation_field, capability_field in (
                ("task_id", "task_id"),
                ("step_id", "step_id"),
                ("tool_name", "tool_name"),
                ("normalized_arguments_hash", "normalized_arguments_hash"),
                ("policy_decision_id", "policy_decision_id"),
                ("capability_grant_id", "capability_grant_id"),
                ("approval_id", "approval_id"),
            ):
                if invocation[invocation_field] != capability[capability_field]:
                    raise RecordConflictError("capability scope does not match invocation")
            if (
                authorization_event.task_id != capability["task_id"]
                or authorization_event.step_id != capability["step_id"]
                or authorization_event.plan_id != capability["plan_id"]
                or authorization_event.plan_version != capability["plan_version"]
                or authorization_event.invocation_id != invocation_id
                or authorization_event.tool_name != capability["tool_name"]
                or authorization_event.idempotency_key != invocation["idempotency_key"]
                or authorization_event.capability_grant_id != capability_grant_id
                or authorization_event.approval_id != capability["approval_id"]
                or authorization_event.risk_level != RiskLevel(capability["risk"])
                or authorization_event.policy_version != decision["policy_version"]
                or authorization_event.approval_scope_hash != capability["scope_hash"]
            ):
                raise ValueError("authorization event scope does not match capability")

            approval_id = capability["approval_id"]
            sealed: list[EventEnvelope] = []
            if approval_id is not None:
                approval = connection.execute(
                    "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
                ).fetchone()
                if approval is None:
                    raise RecordNotFoundError("approval does not exist")
                if approval_consumed_event is None:
                    raise ValueError("approval consumption requires an audit event")
                if (
                    approval_consumed_event.event_type
                    is not EventType.APPROVAL_CONSUMED
                    or approval_consumed_event.approval_id != approval_id
                    or approval_consumed_event.task_id != capability["task_id"]
                    or approval_consumed_event.step_id != capability["step_id"]
                    or approval_consumed_event.tool_name != capability["tool_name"]
                    or approval_consumed_event.capability_grant_id
                    != capability_grant_id
                    or approval_consumed_event.approval_scope_hash
                    != capability["scope_hash"]
                ):
                    raise ValueError("approval consumption event is invalid")
                if (
                    approval["decision"] != ApprovalDecision.GRANTED.value
                    or any(approval[field] != capability[field] for field in (
                        "task_id", "step_id", "plan_id", "plan_version", "risk"
                    ))
                    or _parse_dt(approval["expires_at"]) <= now
                    or approval["scope_hash"] != capability["scope_hash"]
                    or approval["tool_name"] != capability["tool_name"]
                    or approval["normalized_arguments_hash"]
                    != capability["normalized_arguments_hash"]
                    or approval["exact_target_hash"] != capability["exact_target_hash"]
                ):
                    raise RecordConflictError("approval is expired or scope-mismatched")
                result = connection.execute(
                    """
                    UPDATE approvals SET decision = 'consumed', consumed_at = ?
                    WHERE approval_id = ? AND decision = 'granted' AND expires_at > ?
                    """,
                    (_dt(now), approval_id, _dt(now)),
                )
                if result.rowcount != 1:
                    raise RecordConflictError("approval could not be consumed")
                approval_event = self._append_event(
                    connection, approval_consumed_event
                )
                self._enqueue_event(connection, approval_event, outbox_topic)
                sealed.append(approval_event)
            elif approval_consumed_event is not None:
                raise ValueError("unexpected approval consumption event")

            result = connection.execute(
                """
                UPDATE capability_grants SET status = 'consumed', consumed_at = ?
                WHERE capability_grant_id = ? AND status = 'issued' AND expires_at > ?
                """,
                (_dt(now), capability_grant_id, _dt(now)),
            )
            if result.rowcount != 1:
                raise RecordConflictError("capability could not be consumed")
            result = connection.execute(
                """
                UPDATE tool_invocations SET status = 'authorized', updated_at = ?
                WHERE invocation_id = ? AND status = 'requested'
                """,
                (_dt(now), invocation_id),
            )
            if result.rowcount != 1:
                raise RecordConflictError("invocation could not be authorized")
            authorized = self._append_event(connection, authorization_event)
            self._enqueue_event(connection, authorized, outbox_topic)
            sealed.append(authorized)
        return tuple(sealed)

    def record_verification(
        self, record: VerificationRecord, event: EventEnvelope, *, outbox_topic: str = "jarvis:events"
    ) -> EventEnvelope:
        if event.task_id != record.task_id or event.step_id != record.step_id:
            raise ValueError("verification event correlation does not match the record")
        return self._insert_with_event(
            """
            INSERT INTO verifications(
                verification_id, task_id, step_id, invocation_id, verifier_type,
                evidence_references_json, result, confidence, repair_count, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.verification_id, record.task_id, record.step_id,
                record.invocation_id, record.verifier_type,
                canonical_json(list(record.evidence_references)), record.result,
                record.confidence, record.repair_count, _dt(record.created_at),
            ),
            event, outbox_topic, "verification or event already exists",
        )

    def record_artifact(
        self, record: ArtifactRecord, event: EventEnvelope, *, outbox_topic: str = "jarvis:events"
    ) -> EventEnvelope:
        if event.task_id != record.task_id or (
            record.step_id is not None and event.step_id != record.step_id
        ):
            raise ValueError("artifact event correlation does not match the record")
        return self._insert_with_event(
            _ARTIFACT_INSERT_SQL,
            _artifact_values(record),
            event,
            outbox_topic,
            "artifact or event already exists",
        )

    def record_checkpoint(
        self, record: CheckpointRecord, event: EventEnvelope, *, outbox_topic: str = "jarvis:events"
    ) -> EventEnvelope:
        if event.task_id != record.task_id:
            raise ValueError("checkpoint event correlation does not match the record")
        return self._insert_with_event(
            """
            INSERT INTO checkpoints(
                checkpoint_id, task_id, step_id, workspace, state_hash,
                metadata_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.checkpoint_id, record.task_id, record.step_id, record.workspace,
                record.state_hash, canonical_json(record.metadata), _dt(record.created_at),
            ),
            event, outbox_topic, "checkpoint or event already exists",
        )

    def append_event(
        self, event: EventEnvelope, *, outbox_topic: str = "jarvis:events"
    ) -> EventEnvelope:
        with self.database.transaction() as connection:
            sealed = self._append_event(connection, event)
            self._enqueue_event(connection, sealed, outbox_topic)
            return sealed

    def list_events(self, *, task_id: str | None = None) -> tuple[EventEnvelope, ...]:
        sql = "SELECT envelope_json FROM events"
        params: tuple[object, ...] = ()
        if task_id is not None:
            sql += " WHERE task_id = ?"
            params = (task_id,)
        sql += " ORDER BY event_sequence"
        with self.database.read() as connection:
            rows = connection.execute(sql, params).fetchall()
        try:
            return tuple(EventEnvelope.model_validate_json(row["envelope_json"]) for row in rows)
        except ValidationError as exc:
            raise AuditIntegrityError("stored audit envelope is schema-invalid") from exc

    def list_pending_outbox(
        self, limit: int = 100, *, available_before: datetime | None = None
    ) -> tuple[OutboxRecord, ...]:
        if limit < 1 or limit > 1000:
            raise ValueError("outbox limit must be between 1 and 1000")
        now = _dt(available_before or datetime.now(timezone.utc))
        with self.database.read() as connection:
            rows = connection.execute(
                """
                SELECT * FROM outbox
                WHERE published_at IS NULL AND available_at <= ?
                ORDER BY created_at, outbox_id LIMIT ?
                """,
                (now, limit),
            ).fetchall()
        return tuple(_outbox_from_row(row) for row in rows)

    def mark_outbox_published(
        self,
        outbox_id: str,
        published_at: datetime,
        *,
        delivery_transport: str = "redis",
        published_reference: str | None = None,
    ) -> None:
        if not delivery_transport or len(delivery_transport) > 32:
            raise ValueError("delivery_transport must be a short identifier")
        if published_reference is not None and len(published_reference) > 256:
            raise ValueError("published_reference is too long")
        with self.database.transaction() as connection:
            result = connection.execute(
                """
                UPDATE outbox SET published_at = ?, attempts = attempts + 1,
                    last_error_code = NULL, delivery_transport = ?,
                    published_reference = ?
                WHERE outbox_id = ? AND published_at IS NULL
                """,
                (
                    _dt(published_at), delivery_transport,
                    published_reference, outbox_id,
                ),
            )
            if result.rowcount != 1:
                raise RecordConflictError("outbox record is missing or already published")

    def mark_outbox_failed(
        self, outbox_id: str, *, error_code: str, available_at: datetime
    ) -> None:
        if not error_code or len(error_code) > 128:
            raise ValueError("error_code must be a short machine-readable value")
        with self.database.transaction() as connection:
            result = connection.execute(
                """
                UPDATE outbox SET attempts = attempts + 1, last_error_code = ?,
                    available_at = ? WHERE outbox_id = ? AND published_at IS NULL
                """,
                (error_code, _dt(available_at), outbox_id),
            )
            if result.rowcount != 1:
                raise RecordConflictError("outbox record is missing or already published")

    def next_fencing_token(self, resource: str) -> int:
        if not resource or len(resource) > 256:
            raise ValueError("resource must be a bounded identifier")
        now = _dt(datetime.now(timezone.utc))
        with self.database.transaction() as connection:
            row = connection.execute(
                "SELECT last_token FROM resource_fences WHERE resource = ?",
                (resource,),
            ).fetchone()
            if row is None:
                token = 1
                connection.execute(
                    "INSERT INTO resource_fences(resource, last_token, updated_at) "
                    "VALUES (?, ?, ?)",
                    (resource, token, now),
                )
            else:
                token = int(row["last_token"]) + 1
                connection.execute(
                    "UPDATE resource_fences SET last_token = ?, updated_at = ? "
                    "WHERE resource = ?",
                    (token, now, resource),
                )
        return token

    def get_artifact(self, artifact_id: str) -> ArtifactRecord:
        with self.database.read() as connection:
            row = connection.execute(
                "SELECT * FROM artifacts WHERE artifact_id = ?", (artifact_id,)
            ).fetchone()
        if row is None:
            raise RecordNotFoundError("artifact does not exist")
        return _artifact_from_row(row)

    def verify_database_integrity(self) -> None:
        with self.database.read() as connection:
            rows = connection.execute("PRAGMA integrity_check").fetchall()
            results = [str(row[0]) for row in rows]
            foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
        if results != ["ok"] or foreign_key_errors:
            raise AuditIntegrityError("SQLite integrity verification failed")

        with self.database.read() as connection:
            missing_task_goals = connection.execute(
                """
                SELECT COUNT(*) FROM tasks t
                LEFT JOIN artifacts a ON a.artifact_id = t.goal_artifact_id
                WHERE a.artifact_id IS NULL OR a.task_id <> t.task_id
                """
            ).fetchone()[0]
            missing_plans = connection.execute(
                """
                SELECT COUNT(*) FROM plans p
                LEFT JOIN artifacts a ON a.artifact_id = p.plan_artifact_id
                WHERE a.artifact_id IS NULL OR a.task_id <> p.task_id
                """
            ).fetchone()[0]
            missing_step_artifacts = connection.execute(
                """
                SELECT COUNT(*) FROM steps s
                LEFT JOIN artifacts aa ON aa.artifact_id = s.arguments_artifact_id
                LEFT JOIN artifacts ta ON ta.artifact_id = s.target_artifact_id
                WHERE (s.arguments_artifact_id IS NOT NULL AND aa.artifact_id IS NULL)
                   OR (s.target_artifact_id IS NOT NULL AND ta.artifact_id IS NULL)
                """
            ).fetchone()[0]
        if missing_task_goals or missing_plans or missing_step_artifacts:
            raise AuditIntegrityError("durable artifact references are inconsistent")

    def verify_artifact_integrity(self) -> int:
        with self.database.read() as connection:
            artifact_ids = [
                row[0]
                for row in connection.execute(
                    "SELECT artifact_id FROM artifacts WHERE encrypted = 1 ORDER BY artifact_id"
                ).fetchall()
            ]
        for artifact_id in artifact_ids:
            record = self.get_artifact(artifact_id)
            try:
                self.payload_store.get(_stored_payload(record))
            except AuditIntegrityError:
                raise
            except OSError as exc:
                raise AuditIntegrityError(
                    "encrypted artifact is missing or unreadable"
                ) from exc
        return len(artifact_ids)

    def verify_audit_chain(self) -> int:
        previous: str | None = None
        count = 0
        with self.database.read() as connection:
            rows = connection.execute(
                """
                SELECT event_id, schema_version, event_type, occurred_at, recorded_at,
                       severity, session_id, trace_id, task_id, plan_id, plan_version,
                       step_id, invocation_id, approval_id, previous_event_hash,
                       event_hash, hash_algorithm, envelope_json
                FROM events ORDER BY event_sequence
                """
            ).fetchall()
        for row in rows:
            if row["hash_algorithm"] != self.audit_hasher.algorithm:
                raise AuditIntegrityError("audit hash algorithm mismatch")
            try:
                event = EventEnvelope.model_validate_json(row["envelope_json"])
            except ValidationError as exc:
                raise AuditIntegrityError("stored audit envelope is schema-invalid") from exc
            indexed = {
                "event_id": event.event_id,
                "schema_version": event.schema_version,
                "event_type": event.event_type.value,
                "occurred_at": _dt(event.occurred_at),
                "recorded_at": _dt(event.recorded_at),
                "severity": event.severity.value,
                "session_id": event.session_id,
                "trace_id": event.trace_id,
                "task_id": event.task_id,
                "plan_id": event.plan_id,
                "plan_version": event.plan_version,
                "step_id": event.step_id,
                "invocation_id": event.invocation_id,
                "approval_id": event.approval_id,
                "previous_event_hash": event.previous_event_hash,
                "event_hash": event.event_hash,
            }
            for column, expected in indexed.items():
                if row[column] != expected:
                    raise AuditIntegrityError(f"audit indexed field mismatch: {column}")
            self.audit_hasher.verify(event, previous)
            previous = event.event_hash
            count += 1
        return count

    def _insert_with_event(
        self,
        sql: str,
        values: tuple[object, ...],
        event: EventEnvelope,
        outbox_topic: str,
        conflict_message: str,
    ) -> EventEnvelope:
        try:
            with self.database.transaction() as connection:
                connection.execute(sql, values)
                sealed = self._append_event(connection, event)
                self._enqueue_event(connection, sealed, outbox_topic)
                return sealed
        except sqlite3.IntegrityError as exc:
            raise RecordConflictError(conflict_message) from exc

    def _append_event(
        self, connection: sqlite3.Connection, event: EventEnvelope
    ) -> EventEnvelope:
        previous_row = connection.execute(
            "SELECT event_hash FROM events ORDER BY event_sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous_row["event_hash"] if previous_row is not None else None
        sealed = self.audit_hasher.seal(event, previous_hash)
        envelope_json = canonical_json(sealed.model_dump(mode="json"))
        connection.execute(
            """
            INSERT INTO events(
                event_id, schema_version, event_type, occurred_at, recorded_at,
                severity, session_id, trace_id, task_id, plan_id, plan_version,
                step_id, invocation_id, approval_id, previous_event_hash,
                event_hash, hash_algorithm, envelope_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sealed.event_id, sealed.schema_version, sealed.event_type.value,
                _dt(sealed.occurred_at), _dt(sealed.recorded_at), sealed.severity.value,
                sealed.session_id, sealed.trace_id, sealed.task_id, sealed.plan_id,
                sealed.plan_version, sealed.step_id, sealed.invocation_id,
                sealed.approval_id, sealed.previous_event_hash, sealed.event_hash,
                self.audit_hasher.algorithm, envelope_json,
                _dt(datetime.now(timezone.utc)),
            ),
        )
        return sealed

    def _enqueue_event(
        self, connection: sqlite3.Connection, event: EventEnvelope, topic: str
    ) -> None:
        if not topic or len(topic) > 256:
            raise ValueError("outbox topic must be a short non-empty value")
        now = event.recorded_at
        connection.execute(
            """
            INSERT INTO outbox(
                outbox_id, event_id, topic, partition_key, payload_json,
                attempts, available_at, published_at, last_error_code, created_at
            ) VALUES (?, ?, ?, ?, ?, 0, ?, NULL, NULL, ?)
            """,
            (
                uuid.uuid4().hex, event.event_id, topic,
                event.task_id or event.trace_id,
                canonical_json(event.model_dump(mode="json")), _dt(now), _dt(now),
            ),
        )

    def _insert_payload_artifact(
        self,
        connection: sqlite3.Connection,
        stored: StoredPayload,
        *,
        task_id: str,
        kind: str,
        sensitivity_class: str,
        retention_class: str,
        created_at: datetime,
    ) -> None:
        record = ArtifactRecord(
            artifact_id=stored.artifact_id,
            task_id=task_id,
            kind=kind,
            storage_reference=stored.storage_reference,
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
            sensitivity_class=sensitivity_class,
            retention_class=retention_class,
            encrypted=True,
            encryption_key_reference=stored.encryption_key_reference,
            created_at=created_at,
        )
        connection.execute(_ARTIFACT_INSERT_SQL, _artifact_values(record))

    @staticmethod
    def _validate_event(
        event: EventEnvelope, *, allowed: set[EventType]
    ) -> None:
        if event.event_type not in allowed:
            raise ValueError(
                f"event type {event.event_type.value} is invalid for this mutation"
            )


_ARTIFACT_INSERT_SQL = """
INSERT INTO artifacts(
    artifact_id, task_id, step_id, kind, storage_reference, sha256,
    size_bytes, sensitivity_class, retention_class, encrypted,
    encryption_key_reference, redaction_metadata_json, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def _artifact_values(record: ArtifactRecord) -> tuple[object, ...]:
    return (
        record.artifact_id, record.task_id, record.step_id, record.kind,
        record.storage_reference, record.sha256, record.size_bytes,
        record.sensitivity_class, record.retention_class, int(record.encrypted),
        record.encryption_key_reference, canonical_json(record.redaction_metadata),
        _dt(record.created_at),
    )


def _task_from_row(row: sqlite3.Row) -> TaskRecord:
    return TaskRecord(
        task_id=row["task_id"], session_id=row["session_id"], trace_id=row["trace_id"],
        goal_artifact_id=row["goal_artifact_id"], goal_hash=row["goal_hash"],
        mode=TaskMode(row["mode"]), status=TaskStatus(row["status"]), workspace=row["workspace"],
        owner=row["owner"], cancellation_requested=bool(row["cancellation_requested"]),
        created_at=_parse_dt(row["created_at"]), updated_at=_parse_dt(row["updated_at"]),
    )


def _invocation_from_row(row: sqlite3.Row) -> ToolInvocationRecord:
    return ToolInvocationRecord(
        invocation_id=row["invocation_id"], task_id=row["task_id"],
        step_id=row["step_id"], attempt_id=row["attempt_id"],
        idempotency_key=row["idempotency_key"], tool_name=row["tool_name"],
        normalized_arguments_hash=row["normalized_arguments_hash"],
        status=InvocationStatus(row["status"]),
        side_effect_marker=SideEffectMarker(row["side_effect_marker"]),
        result_reference=row["result_reference"], error_code=row["error_code"],
        started_at=_optional_parse_dt(row["started_at"]),
        completed_at=_optional_parse_dt(row["completed_at"]),
        created_at=_parse_dt(row["created_at"]), updated_at=_parse_dt(row["updated_at"]),
        policy_decision_id=row["policy_decision_id"],
        capability_grant_id=row["capability_grant_id"],
        approval_id=row["approval_id"],
    )


def _approval_from_row(row: sqlite3.Row) -> ApprovalRecord:
    return ApprovalRecord(
        approval_id=row["approval_id"],
        task_id=row["task_id"],
        step_id=row["step_id"],
        plan_id=row["plan_id"],
        plan_version=row["plan_version"],
        risk=RiskLevel(row["risk"]),
        reason=row["reason"],
        scope_hash=row["scope_hash"],
        decision=ApprovalDecision(row["decision"]),
        channel=row["channel"],
        expires_at=_parse_dt(row["expires_at"]),
        approver=row["approver"],
        consumed_at=_optional_parse_dt(row["consumed_at"]),
        created_at=_parse_dt(row["created_at"]),
        policy_decision_id=row["policy_decision_id"],
        tool_name=row["tool_name"],
        normalized_arguments_hash=row["normalized_arguments_hash"],
        exact_target_hash=row["exact_target_hash"],
        revoked_at=_optional_parse_dt(row["revoked_at"]),
        decision_channel=row["decision_channel"],
    )


def _policy_decision_from_row(row: sqlite3.Row) -> PolicyDecisionRecord:
    from ..contracts import PolicyDisposition

    return PolicyDecisionRecord(
        decision_id=row["decision_id"],
        task_id=row["task_id"],
        step_id=row["step_id"],
        plan_id=row["plan_id"],
        plan_version=row["plan_version"],
        policy_version=row["policy_version"],
        risk=RiskLevel(row["risk"]),
        disposition=PolicyDisposition(row["disposition"]),
        reasons=tuple(json.loads(row["reasons_json"])),
        tool_name=row["tool_name"],
        normalized_arguments_hash=row["normalized_arguments_hash"],
        exact_target_hash=row["exact_target_hash"],
        scope_hash=row["scope_hash"],
        capability_constraints=tuple(
            json.loads(row["capability_constraints_json"])
        ),
        evaluated_at=_parse_dt(row["evaluated_at"]),
    )


def _capability_from_row(row: sqlite3.Row) -> CapabilityGrantRecord:
    return CapabilityGrantRecord(
        capability_grant_id=row["capability_grant_id"],
        policy_decision_id=row["policy_decision_id"],
        approval_id=row["approval_id"],
        task_id=row["task_id"],
        step_id=row["step_id"],
        plan_id=row["plan_id"],
        plan_version=row["plan_version"],
        tool_name=row["tool_name"],
        normalized_arguments_hash=row["normalized_arguments_hash"],
        exact_target_hash=row["exact_target_hash"],
        scope_hash=row["scope_hash"],
        risk=RiskLevel(row["risk"]),
        constraints=tuple(json.loads(row["constraints_json"])),
        status=CapabilityGrantStatus(row["status"]),
        expires_at=_parse_dt(row["expires_at"]),
        consumed_at=_optional_parse_dt(row["consumed_at"]),
        created_at=_parse_dt(row["created_at"]),
    )


def _artifact_from_row(row: sqlite3.Row) -> ArtifactRecord:
    return ArtifactRecord(
        artifact_id=row["artifact_id"], task_id=row["task_id"], step_id=row["step_id"],
        kind=row["kind"], storage_reference=row["storage_reference"], sha256=row["sha256"],
        size_bytes=row["size_bytes"], sensitivity_class=row["sensitivity_class"],
        retention_class=row["retention_class"], encrypted=bool(row["encrypted"]),
        encryption_key_reference=row["encryption_key_reference"],
        redaction_metadata=json.loads(row["redaction_metadata_json"]),
        created_at=_parse_dt(row["created_at"]),
    )


def _stored_payload(record: ArtifactRecord) -> StoredPayload:
    if not record.encrypted or not record.encryption_key_reference:
        raise PersistenceError("artifact is not backed by an encrypted payload")
    if record.size_bytes is None:
        raise PersistenceError("encrypted artifact size is missing")
    return StoredPayload(
        artifact_id=record.artifact_id,
        storage_reference=record.storage_reference,
        sha256=record.sha256,
        size_bytes=record.size_bytes,
        encryption_key_reference=record.encryption_key_reference,
    )


def _outbox_from_row(row: sqlite3.Row) -> OutboxRecord:
    return OutboxRecord(
        outbox_id=row["outbox_id"], event_id=row["event_id"], topic=row["topic"],
        partition_key=row["partition_key"], payload_json=row["payload_json"],
        attempts=row["attempts"], available_at=_parse_dt(row["available_at"]),
        published_at=_optional_parse_dt(row["published_at"]),
        delivery_transport=row["delivery_transport"],
        published_reference=row["published_reference"],
        last_error_code=row["last_error_code"], created_at=_parse_dt(row["created_at"]),
    )


def _dt(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("durable timestamps must include a timezone")
    return value.astimezone(timezone.utc).isoformat()


def _optional_dt(value: datetime | None) -> str | None:
    return _dt(value) if value is not None else None


def _parse_dt(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AuditIntegrityError("stored timestamp is missing timezone information")
    return parsed


def _optional_parse_dt(value: str | None) -> datetime | None:
    return _parse_dt(value) if value is not None else None
