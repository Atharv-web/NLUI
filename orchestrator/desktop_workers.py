"""Trusted desktop coordination for isolated coding and browser workers."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import uuid
from functools import wraps
from datetime import datetime, timezone
from pathlib import Path

from .coding import CodingWorker, CodingSession, CodingPlan, CodingResult, CodingReview, _target
from .computer_use import ComputerUseSession, IsolatedPlaywrightBrowser, StructuredBrowserProvider, BrowserStop
from .contracts import EvidenceKind, ToolOutcome
from .correlation import current_correlation
from .events import EventType
from .persistence.records import ArtifactRecord, CheckpointRecord, InvocationStatus, SideEffectMarker
from .persistence.secrets import StoredPayload
from .safety import GatewayDisposition
from .safety import GatewayResult
from .verification import VerificationResult, result_from_observation


def _worker_call(method):
    @wraps(method)
    async def wrapped(self, *args, **kwargs):
        task = asyncio.current_task()
        self._worker_calls.add(task)
        try:
            return await method(self, *args, **kwargs)
        finally:
            self._worker_calls.discard(task)
    return wrapped


class DesktopWorkers:
    def __init__(self, store, generate, config, session_id):
        self.store, self.generate, self.config, self.session_id = store, generate, config, session_id
        self.engine = None
        async def coding_generate(**values):
            if values["schema"].get("title") == "CodingReview":
                values["model"] = config.models.reviewer.name
            return await generate(**values)
        self.coding = CodingWorker(coding_generate, config.models.planner.name)
        self.codes = {}
        self.browsers = {}
        self.browser_jobs = {}
        self.browser_results = {}
        self.approval_waiters = {}
        self._closed = False
        self._worker_calls = set()
        self.inspection_images = {}
        self.command_receipts = {}
        self.origin_tasks = {}
        self.recovered_tasks = {}
        self.recovery_only = set()

    def _available(self, tool):
        if self._closed or self.engine.blocked_reason or self.engine._closing:
            raise RuntimeError("worker execution is stopped")
        if self.engine.enabled_tools is not None and tool not in self.engine.enabled_tools:
            raise RuntimeError("worker is disabled in this rollout stage")

    @_worker_call
    async def submit_coding(self, workspace, text, mode="edit", image_path=""):
        self._available("coding_prepare")
        if mode not in {'edit', 'explain', 'debug', 'commands'}:
            raise ValueError('unknown coding mode')
        if self._closed or len(self.codes) >= 20:
            raise RuntimeError("worker session limit")
        session = await self.coding.discover(workspace, text)
        self._available("coding_prepare")
        session_id = uuid.uuid4().hex
        self.codes[session_id] = session
        image = b''
        if mode == 'debug':
            import io
            from PIL import Image
            path = Path(image_path)
            if not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
                raise ValueError('select a screenshot under 8 MiB')
            with Image.open(path) as source:
                if source.width * source.height > 16000000:
                    raise ValueError('screenshot too large')
                buffer = io.BytesIO()
                source.convert('RGB').save(buffer, format='PNG')
                image = buffer.getvalue()
            self.inspection_images[session_id] = image
        arguments = {'session_id': session_id, 'plan_hash': session.plan_hash, 'workspace': str(session.workspace)}
        if mode != 'edit':
            arguments.update(mode=mode, image_sha256=hashlib.sha256(image).hexdigest())
        return await self.engine.execute(session_id=self.session_id, trace_id=uuid.uuid4().hex,
            call_id=uuid.uuid4().hex, tool_name="coding_prepare" if mode == 'edit' else 'coding_inspect',
            workspace=str(session.workspace), arguments=arguments)

    async def inspect_code(self, arguments):
        session = self._session(arguments)
        image = self.inspection_images.get(arguments['session_id'], b'')
        if hashlib.sha256(image).hexdigest() != arguments['image_sha256']:
            raise ValueError('screenshot changed')
        self.coding.approve_plan(session, arguments['plan_hash'])
        result = await self.coding.inspect(session, arguments['mode'], image or None)
        return {'explanation_sha256': hashlib.sha256(result.explanation.encode()).hexdigest(),
                'commands': len(result.commands)}

    async def submit_commands(self, workspace, commands):
        self._available('coding_command')
        return await self.engine.submit_commands(session_id=self.session_id, workspace=workspace, commands=commands)

    async def run_command(self, arguments):
        from .local_execution import LocalCommandRunner
        context = current_correlation()
        receipt = await LocalCommandRunner().run(**arguments)
        # Raw process output is private, never included in ordinary event metadata.
        stored = self.store.payload_store.put(json.dumps(receipt).encode())
        self.store.record_artifact(ArtifactRecord(artifact_id=stored.artifact_id,
            task_id=context.task_id, step_id=context.step_id, kind='local_command_report',
            storage_reference=stored.storage_reference, sha256=stored.sha256,
            size_bytes=stored.size_bytes, sensitivity_class='source_code', retention_class='protected_artifact',
            encrypted=True, encryption_key_reference=stored.encryption_key_reference,
            created_at=datetime.now(timezone.utc)),
            self.engine._event(context.task_id, EventType.WORKER_STARTED, step_id=context.step_id, worker_id='local_command'))
        self.command_receipts[context.step_id] = receipt
        return {'exit_code': receipt['exit_code'], 'timed_out': receipt['timed_out'],
                'output_sha256': receipt['output_sha256'], 'artifact_reference': 'artifact:' + stored.artifact_id}

    def _session(self, arguments):
        session = self.codes.get(arguments["session_id"])
        if session is None or str(session.workspace) != arguments["workspace"]:
            raise RuntimeError("coding session expired; discover and approve a new plan")
        return session

    def _protected_checkpoint(self, session):
        context = current_correlation()
        if context is None or context.task_id is None:
            raise RuntimeError("durable worker context required")
        payload = json.dumps({
            "workspace": str(session.workspace), "plan_hash": session.plan_hash,
            "diff": session.result.diff, "diff_hash": session.result.diff_hash,
            "snapshots": {p: base64.b64encode(b).decode() if b is not None else None for p, b in session.snapshots.items()},
            "edits": {p: base64.b64encode(b).decode() for p, b in session.edits.items()},
        }).encode()
        stored = self.store.payload_store.put(payload)
        now = datetime.now(timezone.utc)
        event = self.engine._event(context.task_id, EventType.WORKER_STARTED,
                                  step_id=context.step_id, worker_id="coding")
        self.store.record_artifact(ArtifactRecord(artifact_id=stored.artifact_id,
            task_id=context.task_id, step_id=context.step_id, kind="coding_checkpoint",
            storage_reference=stored.storage_reference, sha256=stored.sha256,
            size_bytes=stored.size_bytes, sensitivity_class="source_code", retention_class="protected_artifact",
            encrypted=True, encryption_key_reference=stored.encryption_key_reference, created_at=now), event)
        self.store.record_checkpoint(CheckpointRecord(checkpoint_id=uuid.uuid4().hex,
            task_id=context.task_id, step_id=context.step_id,
            workspace="sha256:" + hashlib.sha256(str(session.workspace).encode()).hexdigest(),
            state_hash=stored.sha256, metadata={"artifact_id": stored.artifact_id}, created_at=now),
            self.engine._event(context.task_id, EventType.WORKER_STARTED, step_id=context.step_id, worker_id="coding_checkpoint"))
        session.result.artifact_reference = "artifact:" + stored.artifact_id
        return session.result.artifact_reference

    async def prepare(self, arguments):
        session = self._session(arguments)
        self.coding.approve_plan(session, arguments["plan_hash"])
        result = await self.coding.implement(session)
        reference = self._protected_checkpoint(session)
        return {"diff_hash": result.diff_hash, "artifact_reference": reference,
                "file_hashes": self.coding.file_hashes(session), "review_accepted": result.review.accepted}

    async def apply(self, arguments):
        session = self._session(arguments)
        if arguments["session_id"] in self.recovery_only:
            raise RuntimeError("recovered checkpoint is restore-only")
        # Commit encrypted recovery data before changing the user's workspace.
        self._protected_checkpoint(session)
        self.origin_tasks.setdefault(arguments["session_id"], set()).add(current_correlation().task_id)
        self.coding.apply(session, arguments["diff_hash"])
        return {"file_hashes": self.coding.file_hashes(session), "diff_hash": arguments["diff_hash"]}

    async def restore(self, arguments):
        session = self._session(arguments)
        if session.result is None or session.result.diff_hash != arguments["diff_hash"]:
            raise RuntimeError("diff changed")
        self._protected_checkpoint(session)
        self.coding.rollback(session)
        for task_id in self.origin_tasks.get(arguments["session_id"], ()):
            for row in self.engine._rows("SELECT idempotency_key FROM tool_invocations WHERE task_id=? AND tool_name IN ('coding_apply','coding_restore') AND status IN ('started','outcome_unknown')", (task_id,)):
                record = self.store.get_invocation_by_idempotency_key(row["idempotency_key"])
                changed = record.model_copy(update={"status": InvocationStatus.FAILED,
                    "side_effect_marker": SideEffectMarker.NONE, "error_code": "restored_from_checkpoint",
                    "updated_at": datetime.now(timezone.utc)})
                self.store.update_invocation(changed, record.status, self.engine._event(task_id, EventType.TOOL_FAILED,
                    step_id=record.step_id, tool_name=record.tool_name, invocation_id=record.invocation_id,
                    idempotency_key=record.idempotency_key, capability_grant_id=record.capability_grant_id,
                    approval_id=record.approval_id, previous_state=record.status.value, new_state="failed",
                    error_code="restored_from_checkpoint"))
        return {"restored": True}

    def load_checkpoint(self, artifact_id):
        """A desktop reveal restores review context, never authorizes a write."""
        if len(self.codes) >= 20:
            raise RuntimeError("too many coding sessions")
        record = self.store.get_artifact(artifact_id)
        if not record.encrypted or record.kind != "coding_checkpoint":
            raise RuntimeError("not a coding checkpoint")
        payload = self.store.payload_store.get(StoredPayload(record.artifact_id,
            record.storage_reference, record.sha256, record.size_bytes, record.encryption_key_reference))
        data = json.loads(payload)
        root = Path(data["workspace"]).absolute()
        if root.resolve() != root or not root.is_dir():
            raise RuntimeError("workspace has moved")
        snapshots = {p: base64.b64decode(b, validate=True) if b is not None else None for p, b in data["snapshots"].items()}
        edits = {p: base64.b64decode(b, validate=True) for p, b in data["edits"].items()}
        for relative, content in edits.items():
            target = _target(root, relative)
            if target.exists() and not target.is_file():
                raise RuntimeError("checkpoint target is not a file")
            current = target.read_bytes() if target.is_file() else None
            if current not in (content, snapshots[relative]):
                raise RuntimeError("workspace changed since checkpoint")
        session = CodingSession(root, "Restore saved checkpoint",
            CodingPlan(summary="Restore the saved original files", files=list(snapshots)),
            data["plan_hash"], snapshots, {})
        session.edits = edits
        session.applied = True
        session.result = CodingResult(data["diff"], data["diff_hash"], ("Saved checkpoint; fresh restore approval required",),
                                     CodingReview(accepted=True, findings=[]), "")
        session_id = uuid.uuid4().hex
        self.codes[session_id] = session
        self.recovery_only.add(session_id)
        self.origin_tasks[session_id] = {record.task_id}
        self.recovered_tasks[record.task_id] = session_id
        return {"ok": True}

    async def request_code_action(self, action, session_id, diff_hash):
        self._available(action)
        if session_id in self.recovery_only and action != "coding_restore":
            raise RuntimeError("recovered checkpoint is restore-only")
        session = self.codes[session_id]
        return await self.engine.execute(session_id=self.session_id, trace_id=uuid.uuid4().hex,
            call_id=uuid.uuid4().hex, tool_name=action, workspace=str(session.workspace),
            arguments={"session_id": session_id, "diff_hash": diff_hash, "workspace": str(session.workspace)})

    async def browser_action(self, arguments):
        session = self.browsers.get(arguments["session_id"])
        if session is None:
            raise BrowserStop("browser_session_expired")
        return await session.execute_action(arguments)

    @_worker_call
    async def start_browser(self, text, initial_url, domains, browser_name='chromium'):
        self._available("browser_action")
        if self._closed or len(self.browser_jobs) >= 3:
            raise RuntimeError("browser session limit")
        browser = IsolatedPlaywrightBrowser(tuple(domains), headless=False, browser_name=browser_name)
        await browser.start(initial_url)
        session = ComputerUseSession(browser, StructuredBrowserProvider(self.generate, self.config.models.computer_use.name),
                                     timeout_seconds=300)
        self.browsers[session.session_id] = session
        async def dispatch(action, before_sha256):
            url = action.url if action.action in {"navigate", "new_tab"} else browser.current_url
            result = await self.engine.execute(session_id=self.session_id, trace_id=uuid.uuid4().hex,
                call_id=uuid.uuid4().hex, tool_name="browser_action",
                arguments={"session_id": session.session_id, "action": action.model_dump(exclude_none=True),
                           "before_sha256": before_sha256, "url": url},
                allowed_domains=tuple(domains))
            if result.disposition is GatewayDisposition.APPROVAL_REQUIRED:
                approval_id = result.approval_id
                waiter = asyncio.get_running_loop().create_future()
                self.approval_waiters[approval_id] = waiter
                try:
                    result = await waiter
                finally:
                    self.approval_waiters.pop(approval_id, None)
            if result.outcome is not ToolOutcome.SUCCEEDED:
                raise BrowserStop("gateway_action_not_verified")
            return result.output
        async def run():
            try:
                self.browser_results[session.session_id] = await session.run(text, dispatch)
            finally:
                for task in self.engine.tasks():
                    if task["status"] not in {"completed", "failed", "cancelled"}:
                        plan = self.engine.plan(task["task_id"])
                        if any(step.proposal and step.proposal.arguments.get("session_id") == session.session_id for step in plan.steps):
                            await self.engine.cancel(task["task_id"])
                self.browser_jobs.pop(session.session_id, None)
                self.browsers.pop(session.session_id, None)
        self.browser_jobs[session.session_id] = asyncio.create_task(run())
        return session.session_id

    def approval_resolved(self, approval_id, result):
        waiter = self.approval_waiters.get(approval_id)
        if waiter is not None and not waiter.done():
            waiter.set_result(result)

    def approval_denied(self, approval_id):
        self.approval_resolved(approval_id, GatewayResult(disposition=GatewayDisposition.DENIED))

    async def stop_browser(self, session_id):
        session = self.browsers.get(session_id)
        if session:
            session.stop()
        job = self.browser_jobs.get(session_id)
        if job:
            job.cancel()
            await asyncio.gather(job, return_exceptions=True)

    async def verify(self, step, result):
        args = step.proposal.arguments
        if step.proposal.tool_name == 'coding_command':
            receipt = self.command_receipts.get(step.step_id, {})
            passed = (bool(receipt) and receipt.get('exit_code') == 0 and not receipt.get('timed_out')
                      and receipt.get('output_sha256') == result.output.get('output_sha256'))
            return result_from_observation('local_process_receipt', EvidenceKind.PROCESS_STATE,
                result.output, passed=passed)
        if step.proposal.tool_name == 'coding_inspect':
            inspection = self._session(args).inspection
            return result_from_observation('coding_inspection', EvidenceKind.STRUCTURED_RESULT,
                result.output, passed=inspection is not None and hashlib.sha256(inspection.explanation.encode()).hexdigest() == result.output.get('explanation_sha256'))
        if step.proposal.tool_name == "browser_action":
            receipt = result.output
            if not isinstance(receipt, dict) or receipt.get("before_sha256") != args["before_sha256"]:
                return VerificationResult(status="failed", verifier_type="browser_receipt", reason_code="receipt_missing")
            if any(not isinstance(receipt.get(key), str) or len(receipt[key]) != 64
                   for key in ("after_sha256", "url_sha256")):
                return VerificationResult(status="failed", verifier_type="browser_receipt", reason_code="receipt_invalid")
            return result_from_observation("browser_receipt", EvidenceKind.SCREENSHOT, receipt)
        session = self._session(args)
        if step.proposal.tool_name == "coding_prepare":
            passed = session.result is not None and session.result.review.accepted
            root, expected = Path(session.result.candidate_directory), session.edits
        elif step.proposal.tool_name == "coding_restore":
            passed = not session.applied
            root, expected = session.workspace, session.snapshots
        else:
            passed = session.applied
            root, expected = session.workspace, session.edits
        observed = {}
        for relative, content in expected.items():
            from .coding import _target
            path = _target(root, relative)
            current = path.read_bytes() if path.is_file() else None
            passed = passed and current == content
            observed[relative] = hashlib.sha256(current).hexdigest() if current is not None else None
        return result_from_observation("coding_readback", EvidenceKind.FILE_HASH, observed, passed=passed)

    def enrich(self, tasks):
        for task in tasks:
            plan = task.get("plan") or {}
            for step in plan.get("steps", []):
                args = (step.get("proposal") or {}).get("arguments", {})
                session_id = self.recovered_tasks.get(task["task_id"], args.get("session_id"))
                session = self.codes.get(session_id)
                if session:
                    task["coding"] = {"session_id": session_id, "workspace": str(session.workspace),
                        "summary": session.plan.summary, "files": session.plan.files,
                        "checks": list(session.result.checks) if session.result else [],
                        "diff": session.result.diff if session.result else None,
                        "diff_hash": session.result.diff_hash if session.result else None,
                        "applied": session.applied, "ready": session.result is not None,
                        "git_status": getattr(session, "git_status", None)}
                    task["coding"]["inspection"] = session.inspection.model_dump() if session.inspection else None
                    for approval in task["approvals"]:
                        approval.update(plan_summary=session.plan.summary, planned_files=session.plan.files,
                                        diff=session.result.diff if session.result else None,
                                        checks=list(session.result.checks) if session.result else [])
                if (step.get("proposal") or {}).get("tool_name") == "browser_action":
                    task["browser_session_id"] = session_id
                if step['step_id'] in self.command_receipts:
                    task.setdefault('command_reports', []).append(self.command_receipts[step['step_id']])
        return tasks

    async def close(self):
        self._closed = True
        callers = tuple(task for task in self._worker_calls if task is not asyncio.current_task())
        for task in callers:
            task.cancel()
        await asyncio.gather(*callers, return_exceptions=True)
        for session_id in tuple(self.browser_jobs):
            await self.stop_browser(session_id)
        for session in self.codes.values():
            session.close()
