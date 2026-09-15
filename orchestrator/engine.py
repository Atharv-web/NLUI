"""Single-process, durable orchestration with explicit approval and evidence gates."""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from functools import wraps
from typing import Any

from .contracts import Intent, Plan, PlanStep, StepDependency, TaskMode, TaskStatus, ToolProposal, ToolOutcome
from .events import EventEnvelope, EventSeverity, EventType
from .persistence import DurableStore, VerificationRecord
from .persistence.hashing import canonical_json, sha256_text
from .safety import ExecutionRequest, GatewayDisposition, GatewayResult
from .safety.policy import derive_exact_target
from .tool_registry import TOOL_REGISTRY, SideEffect

TERMINAL = {TaskStatus.COMPLETED, TaskStatus.CANCELLED, TaskStatus.FAILED, TaskStatus.ROLLED_BACK}
_LEGAL = {
    'received': {'discovering', 'planned', 'failed', 'cancelled'},
    'discovering': {'planned', 'failed', 'paused', 'cancelled'},
    'planned': {'ready', 'awaiting_plan_approval', 'paused', 'cancelled'},
    'awaiting_plan_approval': {'ready', 'failed', 'cancelled', 'paused'},
    'ready': {'queued', 'paused', 'cancelled'},
    'queued': {'running', 'paused', 'cancelled'},
    'running': {'verifying', 'awaiting_step_approval', 'paused', 'failed', 'cancelled', 'completed'},
    'verifying': {'running', 'completed', 'paused', 'failed', 'cancelled'},
    'awaiting_step_approval': {'ready', 'paused', 'failed', 'cancelled'},
    'paused': {'ready', 'awaiting_plan_approval', 'cancelled'},
}

def _id() -> str:
    return uuid.uuid4().hex


def _tracked_work(method):
    """Track callers before their first wait, including nested public calls."""
    @wraps(method)
    async def tracked(self, *args, **kwargs):
        if self._closing:
            raise RuntimeError('orchestrator is shutting down')
        worker = asyncio.current_task()
        outermost = worker not in self._operations
        self._operations.add(worker)
        try:
            return await method(self, *args, **kwargs)
        finally:
            if outermost:
                self._operations.discard(worker)
    return tracked


class LocalOrchestrator:
    """SQLite owns queue state; locks only bound this process's dispatch.

    Mutations share one desktop lock. Independent read-only tasks can overlap.
    A restart conservatively pauses unfinished work for an explicit resume.
    """

    def __init__(self, store: DurableStore, gateway: Any, planner: Any = None,
                 verifier: Any = None, max_concurrency: int = 4) -> None:
        if not 1 <= max_concurrency <= 16:
            raise ValueError('max_concurrency must be between 1 and 16')
        self.store, self.gateway, self.planner = store, gateway, planner
        if verifier is None:
            from .verification import VerificationRegistry
            verifier = VerificationRegistry()
        self.verifier = verifier
        self._slots = asyncio.Semaphore(max_concurrency)
        self._desktop = asyncio.Lock()
        self._intake = asyncio.Lock()
        self._locks: dict[str, asyncio.Lock] = {}
        self._active: dict[str, asyncio.Task] = {}
        self._operations: set[asyncio.Task] = set()
        self._closing = False
        self.blocked_reason: str | None = None
        self.enabled_tools: frozenset[str] | None = None
        from .local_execution import CommandApprovalScopes
        self.command_scopes = CommandApprovalScopes()

    def _rows(self, sql: str, args: tuple = ()) -> list[dict]:
        with self.store.database.read() as connection:
            return [dict(row) for row in connection.execute(sql, args).fetchall()]

    def _event(self, task_id: str, kind: EventType, **fields: Any) -> EventEnvelope:
        task = self.store.get_task(task_id)
        now = datetime.now(timezone.utc)
        return EventEnvelope(event_id=_id(), event_type=kind, occurred_at=now,
            recorded_at=now, severity=EventSeverity.INFO, session_id=task.session_id,
            trace_id=task.trace_id, task_id=task_id, redaction_policy_version='1.0',
            sensitivity_class='operational_metadata', retention_class='audit', **fields)

    def _transition(self, task_id: str, status: TaskStatus, kind: EventType) -> None:
        if status in TERMINAL or status == TaskStatus.PAUSED:
            self.command_scopes.revoke(task_id)
        old = self.store.get_task(task_id).status
        if old == status:
            return
        if status.value not in _LEGAL.get(old.value, set()):
            raise ValueError(f'illegal task transition: {old.value} to {status.value}')
        self.store.transition_task(task_id, old, status, self._event(task_id, kind,
            previous_state=old.value, new_state=status.value))

    def _step(self, task_id: str, step_id: str, status: str, kind: EventType) -> None:
        current = self.store.get_step_security_context(step_id)
        if current.status == status:
            return
        self.store.transition_step(step_id, current.status, status, self._event(task_id,
            kind, step_id=step_id, plan_id=current.plan_id, plan_version=current.plan_version,
            previous_state=current.status, new_state=status))

    def _create(self, intent: Intent, task_id: str) -> None:
        now = datetime.now(timezone.utc)
        self.store.create_task(intent, EventEnvelope(event_id=_id(), event_type=EventType.TASK_CREATED,
            occurred_at=now, recorded_at=now, severity=EventSeverity.INFO,
            session_id=intent.session_id, trace_id=intent.trace_id, task_id=task_id,
            redaction_policy_version='1.0', sensitivity_class='operational_metadata', retention_class='audit'))
        for kind in (EventType.INTENT_RECEIVED, EventType.INTENT_CLASSIFIED):
            self.store.append_event(self._event(task_id, kind))

    def plan(self, task_id: str) -> Plan:
        rows = self._rows('SELECT plan_id,version FROM plans WHERE task_id=? ORDER BY version DESC LIMIT 1', (task_id,))
        if not rows:
            raise ValueError('task has no plan')
        return self.store.get_plan(rows[0]['plan_id'], rows[0]['version'])

    def tasks(self) -> tuple[dict, ...]:
        result = []
        for row in self._rows('SELECT task_id,session_id,trace_id,mode,status,cancellation_requested,created_at,updated_at FROM tasks ORDER BY created_at DESC LIMIT 200'):
            row['steps'] = self._rows('SELECT step_id,tool_name,status,risk,plan_version FROM steps WHERE task_id=?', (row['task_id'],))
            row['approvals'] = self._rows("SELECT approval_id,step_id,risk,decision,expires_at FROM approvals WHERE task_id=? ORDER BY created_at", (row['task_id'],))
            result.append(row)
        return tuple(result)

    def audit(self, task_id: str) -> tuple:
        return self.store.list_events(task_id=task_id)

    @_tracked_work
    async def submit_intent(self, intent: Intent) -> str:
        task_id = sha256_text(canonical_json({'session': intent.session_id, 'intent': intent.intent_id}))
        async with self._intake:
            if self._rows('SELECT task_id FROM tasks WHERE task_id=?', (task_id,)):
                return task_id
            self._create(intent, task_id)
        self._transition(task_id, TaskStatus.DISCOVERING, EventType.DISCOVERY_STARTED)
        self._active[task_id] = asyncio.current_task()
        try:
            if self.planner is None:
                raise ValueError('planner unavailable')
            plan = await self.planner.plan(intent, task_id)
            if self.store.get_task(task_id).status in TERMINAL:
                return task_id
            if plan.task_id != task_id or plan.trace_id != intent.trace_id:
                raise ValueError('planner correlation mismatch')
            if any(step.proposal is None for step in plan.steps):
                raise ValueError('every executable step needs a tool proposal')
            self.store.append_event(self._event(task_id, EventType.DISCOVERY_COMPLETED))
            self.store.save_plan(plan, self._event(task_id, EventType.PLAN_PROPOSED,
                plan_id=plan.plan_id, plan_version=plan.version))
            if self.store.get_task(task_id).status == TaskStatus.PAUSED:
                return task_id
            self._transition(task_id, TaskStatus.PLANNED, EventType.PLAN_PROPOSED)
            self._transition(task_id, TaskStatus.AWAITING_PLAN_APPROVAL, EventType.PLAN_PROPOSED)
        except asyncio.CancelledError:
            await self.cancel(task_id)
            raise
        except Exception:
            if self.store.get_task(task_id).status == TaskStatus.DISCOVERING:
                self._transition(task_id, TaskStatus.FAILED, EventType.TASK_FAILED)
        finally:
            self._active.pop(task_id, None)
        return task_id

    @_tracked_work
    async def execute(self, *, session_id: str, trace_id: str, call_id: str,
                      tool_name: str, arguments: dict, workspace: str | None = None,
                      allowed_domains: tuple[str, ...] = ()) -> GatewayResult:
        metadata = TOOL_REGISTRY[tool_name]
        key = sha256_text(canonical_json({'session_id': session_id, 'call_id': call_id,
            'tool_name': tool_name, 'arguments': arguments}))
        task_id = sha256_text('routine:' + key)
        async with self._intake:
            if not self._rows('SELECT task_id FROM tasks WHERE task_id=?', (task_id,)):
                mode = TaskMode.CODING if tool_name in {'code_helper', 'dev_agent', 'coding_prepare', 'coding_apply', 'coding_restore'} else TaskMode.COMPUTER_USE if tool_name in {'computer_control', 'browser_action'} else TaskMode.ROUTINE
                intent = Intent(intent_id=key, session_id=session_id, trace_id=trace_id, mode=mode,
                    goal=f'Execute registered tool {tool_name}', received_at=datetime.now(timezone.utc), workspace=workspace)
                self._create(intent, task_id)
                plan = Plan(plan_id=_id(), task_id=task_id, trace_id=trace_id, version=1,
                    model_name='deterministic-router', prompt_version='routine-v1',
                    summary=f'Execute {tool_name}', risk_summary=f'Registry floor {metadata.default_risk.value}',
                    steps=(PlanStep(step_id=key, action=f'Execute {tool_name}', expected_result=metadata.verification_method,
                        proposal=ToolProposal(tool_name=tool_name, arguments=arguments,
                            exact_target=derive_exact_target(tool_name, arguments)), risk=metadata.default_risk,
                        timeout_seconds=metadata.default_timeout_seconds,
                        capability_scope=tuple('domain:' + domain for domain in allowed_domains)),))
                self.store.save_plan(plan, self._event(task_id, EventType.PLAN_PROPOSED, plan_id=plan.plan_id, plan_version=1))
                self._transition(task_id, TaskStatus.PLANNED, EventType.PLAN_PROPOSED)
                self._transition(task_id, TaskStatus.READY, EventType.STEP_QUEUED)
        results = await self.run_task(task_id)
        if results:
            return results[-1]
        task = self.store.get_task(task_id)
        return GatewayResult(disposition=GatewayDisposition.REPLAYED if task.status == TaskStatus.COMPLETED else GatewayDisposition.FAILED,
            outcome=ToolOutcome.SUCCEEDED if task.status == TaskStatus.COMPLETED else None,
            reason_codes=(f'task_{task.status.value}',))

    @_tracked_work
    async def submit_commands(self, *, session_id, workspace, commands):
        from .coding import CommandProposal
        from pathlib import Path
        root = str(Path(workspace).resolve(strict=True))
        if not 1 <= len(commands) <= 8:
            raise ValueError('command batch must have 1 to 8 commands')
        proposals = [CommandProposal.model_validate(command) for command in commands]
        task_id, trace_id = _id(), _id()
        intent = Intent(intent_id=_id(), session_id=session_id, trace_id=trace_id,
            mode=TaskMode.CODING, goal='Run reviewed local command plan',
            received_at=datetime.now(timezone.utc), workspace=root)
        self._create(intent, task_id)
        steps = tuple(PlanStep(step_id=_id(), action=command.purpose,
            expected_result='Process exits successfully; output is available for review',
            proposal=ToolProposal(tool_name='coding_command',
                arguments={'workspace': root, **command.model_dump()}, exact_target=derive_exact_target('coding_command', {'workspace': root})),
            risk=TOOL_REGISTRY['coding_command'].default_risk, timeout_seconds=660)
            for command in proposals)
        plan = Plan(plan_id=_id(), task_id=task_id, trace_id=trace_id, version=1,
            model_name='reviewed-local-commands', prompt_version='commands-v1',
            summary='Local command plan', risk_summary='Runs locally without a sandbox; approval required',
            steps=steps, dependencies=tuple(StepDependency(step_id=steps[i].step_id,
                depends_on_step_id=steps[i-1].step_id) for i in range(1, len(steps))))
        self.store.save_plan(plan, self._event(task_id, EventType.PLAN_PROPOSED,
                                             plan_id=plan.plan_id, plan_version=1))
        self._transition(task_id, TaskStatus.PLANNED, EventType.PLAN_PROPOSED)
        self._transition(task_id, TaskStatus.AWAITING_PLAN_APPROVAL, EventType.PLAN_PROPOSED)
        return task_id

    def _request(self, task_id: str, plan: Plan, step: PlanStep) -> ExecutionRequest:
        task = self.store.get_task(task_id)
        proposal = step.proposal
        assert proposal is not None
        key = sha256_text(f'{task_id}:{plan.plan_id}:{plan.version}:{step.step_id}')
        existing = self.store.get_invocation_by_idempotency_key(key)
        grants = self._rows("SELECT approval_id FROM approvals WHERE task_id=? AND step_id=? AND decision='granted' ORDER BY created_at DESC LIMIT 1", (task_id, step.step_id))
        return ExecutionRequest(session_id=task.session_id, trace_id=task.trace_id, task_id=task_id,
            plan_id=plan.plan_id, plan_version=plan.version, step_id=step.step_id,
            attempt_id=existing.attempt_id if existing else _id(), invocation_id=existing.invocation_id if existing else _id(),
            idempotency_key=key, task_mode=task.mode, tool_name=proposal.tool_name,
            arguments=proposal.arguments, exact_target=proposal.exact_target, workspace=task.workspace,
            allowed_domains=tuple(scope.removeprefix('domain:') for scope in step.capability_scope if scope.startswith('domain:')),
            approval_id=grants[0]['approval_id'] if grants else None)

    @_tracked_work
    async def run_task(self, task_id: str) -> list[GatewayResult]:
        async with self._locks.setdefault(task_id, asyncio.Lock()):
            if self.store.get_task(task_id).status != TaskStatus.READY:
                return []
            self._active[task_id] = asyncio.current_task()
            try:
                self._transition(task_id, TaskStatus.QUEUED, EventType.STEP_QUEUED)
                async with self._slots:
                    if self.store.get_task(task_id).status != TaskStatus.QUEUED or self._closing:
                        return []
                    return await self._run(task_id)
            except asyncio.CancelledError:
                await self.cancel(task_id)
                raise
            finally:
                self._active.pop(task_id, None)

    async def _run(self, task_id: str) -> list[GatewayResult]:
        self._transition(task_id, TaskStatus.RUNNING, EventType.STEP_STARTED)
        plan = self.plan(task_id)
        results = []
        while self.store.get_task(task_id).status == TaskStatus.RUNNING:
            states = {r['step_id']: r['status'] for r in self._rows('SELECT step_id,status FROM steps WHERE plan_id=? AND plan_version=?', (plan.plan_id, plan.version))}
            if all(value == 'completed' for value in states.values()):
                self._transition(task_id, TaskStatus.COMPLETED, EventType.TASK_COMPLETED)
                break
            ready = [step for step in plan.steps if states[step.step_id] in {'planned', 'queued', 'awaiting_step_approval'} and all(states[edge.depends_on_step_id] == 'completed' for edge in plan.dependencies if edge.step_id == step.step_id)]
            if not ready:
                self._transition(task_id, TaskStatus.PAUSED, EventType.TASK_PAUSED)
                break
            step = ready[0]
            request = self._request(task_id, plan, step)
            if self.blocked_reason or (self.enabled_tools is not None and request.tool_name not in self.enabled_tools):
                self._transition(task_id, TaskStatus.PAUSED, EventType.TASK_PAUSED)
                results.append(GatewayResult(disposition=GatewayDisposition.DENIED,
                    reason_codes=(self.blocked_reason or 'rollout_stage_disabled',)))
                break
            if request.tool_name in {'code_helper', 'dev_agent', 'computer_control'}:
                self._transition(task_id, TaskStatus.PAUSED, EventType.TASK_PAUSED)
                results.append(GatewayResult(disposition=GatewayDisposition.DENIED, reason_codes=('isolated_worker_not_available',)))
                break
            if not self.verifier.supports(request.tool_name):
                self._transition(task_id, TaskStatus.PAUSED, EventType.TASK_PAUSED)
                results.append(GatewayResult(disposition=GatewayDisposition.DENIED,
                    reason_codes=('verifier_unavailable',)))
                break
            self._step(task_id, step.step_id, 'queued', EventType.STEP_QUEUED)
            desktop_locked = False
            try:
                effects = TOOL_REGISTRY[request.tool_name].side_effects
                if effects <= {SideEffect.NONE, SideEffect.NETWORK_READ, SideEffect.FILE_READ}:
                    self._step(task_id, step.step_id, 'running', EventType.STEP_STARTED)
                    result = await self.gateway.execute(request)
                else:
                    await self._desktop.acquire()
                    desktop_locked = True
                    if self.store.get_task(task_id).status != TaskStatus.RUNNING:
                        break
                    # A cancelled blocking adapter may still be running in its
                    # thread. Durable uncertainty blocks further desktop writes.
                    unresolved = "SELECT 1 FROM tool_invocations WHERE status IN ('started','outcome_unknown') AND side_effect_marker != 'none'"
                    if request.tool_name == "coding_restore":
                        # Coding writes are synchronous, so their original writer
                        # cannot still be running. Restore independently checks drift.
                        unresolved += " AND tool_name NOT IN ('coding_apply','coding_restore')"
                    if self._rows(unresolved + " LIMIT 1"):
                        self._transition(task_id, TaskStatus.PAUSED, EventType.TASK_PAUSED)
                        results.append(GatewayResult(disposition=GatewayDisposition.DENIED,
                            reason_codes=('unresolved_desktop_effect',)))
                        break
                    self._step(task_id, step.step_id, 'running', EventType.STEP_STARTED)
                    result = await self.gateway.execute(request)
                if (result.disposition == GatewayDisposition.APPROVAL_REQUIRED
                        and request.tool_name == 'coding_command'
                        and await asyncio.to_thread(self.command_scopes.matches,
                            task_id, request.workspace, request.arguments['argv'])
                        and self.store.get_task(task_id).status == TaskStatus.RUNNING):
                    self.gateway.approvals.grant(result.approval_id, channel='desktop_click',
                                                 approver='local_user_task_command_scope')
                    result = await self.gateway.execute(request.model_copy(update={'approval_id': result.approval_id}))
                results.append(result)
                if self.store.get_task(task_id).status in TERMINAL:
                    break
                if result.disposition == GatewayDisposition.APPROVAL_REQUIRED:
                    self._step(task_id, step.step_id, 'awaiting_step_approval', EventType.APPROVAL_REQUESTED)
                    if self.store.get_task(task_id).status != TaskStatus.PAUSED:
                        self._transition(task_id, TaskStatus.AWAITING_STEP_APPROVAL, EventType.APPROVAL_REQUESTED)
                    break
                if result.outcome != ToolOutcome.SUCCEEDED or not result.audit_committed:
                    self._step(task_id, step.step_id, 'paused', EventType.STEP_FAILED)
                    self._transition(task_id, TaskStatus.PAUSED, EventType.TASK_PAUSED)
                    break
                if self.store.get_task(task_id).status != TaskStatus.PAUSED:
                    self._transition(task_id, TaskStatus.VERIFYING, EventType.VERIFICATION_STARTED)
                self._step(task_id, step.step_id, 'verifying', EventType.VERIFICATION_STARTED)
                verification = await self.verifier.verify(step, result)
                if self.store.get_task(task_id).status in TERMINAL:
                    break
                passed = verification.status == 'passed' and bool(verification.evidence)
                kind = EventType.VERIFICATION_PASSED if passed else EventType.VERIFICATION_FAILED
                self.store.record_verification(VerificationRecord(verification_id=_id(), task_id=task_id,
                    step_id=step.step_id, invocation_id=result.invocation_id,
                    verifier_type=verification.verifier_type,
                    evidence_references=tuple(e.reference for e in verification.evidence),
                    result='passed' if passed else 'failed', created_at=datetime.now(timezone.utc)),
                    self._event(task_id, kind, step_id=step.step_id, plan_id=plan.plan_id, plan_version=plan.version))
                self._step(task_id, step.step_id, 'completed' if passed else 'paused', EventType.STEP_COMPLETED if passed else EventType.STEP_FAILED)
                if self.store.get_task(task_id).status != TaskStatus.PAUSED:
                    self._transition(task_id, TaskStatus.RUNNING if passed else TaskStatus.PAUSED, kind if passed else EventType.TASK_PAUSED)
                if not passed:
                    results[-1] = GatewayResult(disposition=GatewayDisposition.FAILED, invocation_id=result.invocation_id,
                        reason_codes=('verification_not_passed',))
            except asyncio.CancelledError:
                self._step(task_id, step.step_id, 'paused', EventType.STEP_CANCELLED)
                if self.store.get_task(task_id).status not in TERMINAL:
                    self._transition(task_id, TaskStatus.CANCELLED, EventType.TASK_CANCELLED)
                raise
            except Exception:
                self._step(task_id, step.step_id, 'paused', EventType.STEP_FAILED)
                if self.store.get_task(task_id).status not in TERMINAL:
                    self._transition(task_id, TaskStatus.PAUSED, EventType.TASK_PAUSED)
                results.append(GatewayResult(disposition=GatewayDisposition.FAILED, reason_codes=('orchestration_failed',)))
                break
            finally:
                if desktop_locked:
                    self._desktop.release()
        return results

    @staticmethod
    def _trusted(channel: str, approver: str) -> None:
        if channel not in {'desktop_click', 'typed_confirmation'} or approver in {'model', 'assistant', 'voice_model'} or not approver:
            raise ValueError('trusted desktop approval required')

    @_tracked_work
    async def approve_plan(self, task_id: str, plan_version: int, *, channel: str = 'desktop_click', approver: str = 'local_user') -> None:
        self._trusted(channel, approver)
        plan = self.plan(task_id)
        if plan.version != plan_version or self.store.get_task(task_id).status != TaskStatus.AWAITING_PLAN_APPROVAL:
            raise ValueError('plan is stale or is not awaiting approval')
        self.store.set_plan_acceptance(plan.plan_id, plan.version, None, 'approved', self._event(task_id, EventType.PLAN_APPROVED,
            plan_id=plan.plan_id, plan_version=plan.version, approval_channel=channel))
        self._transition(task_id, TaskStatus.READY, EventType.STEP_QUEUED)
        await self.run_task(task_id)

    @_tracked_work
    async def approve_step(self, approval_id: str, *, channel: str = 'desktop_click', approver: str = 'local_user', allow_matching: bool = False) -> GatewayResult | None:
        self._trusted(channel, approver)
        record = self.store.get_approval(approval_id)
        if self.store.get_task(record.task_id).status != TaskStatus.AWAITING_STEP_APPROVAL:
            raise ValueError('task is not awaiting step approval')
        if allow_matching:
            if record.tool_name != 'coding_command':
                raise ValueError('matching approval only supports local commands')
            step = next(s for s in self.plan(record.task_id).steps if s.step_id == record.step_id)
            scope_job = asyncio.create_task(asyncio.to_thread(self.command_scopes.grant,
                record.task_id, self.store.get_task(record.task_id).workspace,
                step.proposal.arguments['argv']))
            try:
                await asyncio.shield(scope_job)
            except asyncio.CancelledError:
                # Threads cannot be cancelled: wait before revoking so a late
                # fingerprint cannot restore authority after task cancellation.
                try:
                    await scope_job
                finally:
                    self.command_scopes.revoke(record.task_id)
                raise
            if self.store.get_task(record.task_id).status != TaskStatus.AWAITING_STEP_APPROVAL:
                self.command_scopes.revoke(record.task_id)
                raise ValueError('task changed while checking command scope')
        try:
            self.gateway.approvals.grant(approval_id, channel=channel, approver=approver)
        except Exception:
            if allow_matching:
                self.command_scopes.revoke(record.task_id)
            raise
        self._transition(record.task_id, TaskStatus.READY, EventType.STEP_QUEUED)
        results = await self.run_task(record.task_id)
        return results[-1] if results else None

    async def pause(self, task_id: str) -> None:
        if self.store.get_task(task_id).status not in TERMINAL:
            self._transition(task_id, TaskStatus.PAUSED, EventType.TASK_PAUSED)

    async def cancel(self, task_id: str) -> None:
        task = self.store.get_task(task_id)
        if task.status in TERMINAL:
            return
        if not task.cancellation_requested:
            self.store.request_task_cancellation(task_id, self._event(task_id, EventType.STEP_CANCEL_REQUESTED))
        self._transition(task_id, TaskStatus.CANCELLED, EventType.TASK_CANCELLED)
        active = self._active.get(task_id)
        if active and active is not asyncio.current_task():
            active.cancel()

    @_tracked_work
    async def resume(self, task_id: str) -> None:
        task = self.store.get_task(task_id)
        if task.status != TaskStatus.PAUSED or task.cancellation_requested:
            raise ValueError('task cannot be resumed')
        plan = self.plan(task_id)
        acceptance = self._rows('SELECT user_acceptance FROM plans WHERE plan_id=? AND version=?', (plan.plan_id, plan.version))[0]['user_acceptance']
        if plan.model_name != 'deterministic-router' and acceptance != 'approved':
            self._transition(task_id, TaskStatus.AWAITING_PLAN_APPROVAL, EventType.PLAN_PROPOSED)
            return
        # Uncertain effects and failed verification need independent reconciliation.
        uncertain = self._rows("SELECT 1 FROM steps WHERE task_id=? AND status IN ('paused','running','verifying')", (task_id,))
        if uncertain:
            raise ValueError('unfinished effects require verification before resume')
        self._transition(task_id, TaskStatus.READY, EventType.STEP_QUEUED)
        await self.run_task(task_id)

    async def recover(self) -> tuple[str, ...]:
        self.store.verify_audit_chain()
        recovered = []
        for row in self._rows('SELECT task_id FROM tasks'):
            task = self.store.get_task(row['task_id'])
            if task.status in TERMINAL or task.status in {TaskStatus.PAUSED, TaskStatus.AWAITING_PLAN_APPROVAL, TaskStatus.AWAITING_STEP_APPROVAL}:
                continue
            if task.cancellation_requested:
                self._transition(task.task_id, TaskStatus.CANCELLED, EventType.TASK_CANCELLED)
            elif task.status in {TaskStatus.RECEIVED, TaskStatus.DISCOVERING}:
                self._transition(task.task_id, TaskStatus.FAILED, EventType.TASK_FAILED)
            else:
                self._transition(task.task_id, TaskStatus.PAUSED, EventType.TASK_PAUSED)
            recovered.append(task.task_id)
        return tuple(recovered)

    async def shutdown(self) -> None:
        """Stop active work; the gateway records uncertain effects on cancellation."""
        self._closing = True
        workers = tuple(worker for worker in self._operations
                        if worker is not asyncio.current_task())
        active = tuple(self._active.items())
        for task_id, worker in active:
            if worker is not asyncio.current_task():
                await self.cancel(task_id)
        for worker in workers:
            worker.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
