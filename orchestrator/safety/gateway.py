"""The only authorized path from a model-facing request to a tool adapter."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone

from ..config import OrchestratorConfig
from ..correlation import CorrelationContext, bind_correlation
from ..contracts import (
    ApprovalDecision,
    PolicyDisposition,
    RiskLevel,
    TaskStatus,
    ToolOutcome,
)
from ..events import EventSeverity, EventType
from ..persistence import (
    DurableStore,
    InvocationStatus,
    PolicyDecisionRecord,
    RecordConflictError,
    SideEffectMarker,
    ToolInvocationRecord,
)
from ..persistence.hashing import sha256_text
from ..tool_registry import TOOL_REGISTRY
from .adapters import ToolAdapterRegistry
from .approvals import ApprovalService
from .capabilities import CapabilityIssuer
from .contracts import (
    ExecutionRequest,
    GatewayDisposition,
    GatewayResult,
    PolicyEvaluation,
)
from .errors import AuthorizationError, GatewayUnavailableError
from .events import safety_event
from .policy import PolicyEngine, exact_target_hash, normalized_arguments_hash


_TERMINAL_INVOCATIONS = {
    InvocationStatus.SUCCEEDED,
    InvocationStatus.FAILED,
    InvocationStatus.OUTCOME_UNKNOWN,
    InvocationStatus.CANCELLED,
}


class ExecutionGateway:
    def __init__(
        self,
        store: DurableStore,
        adapters: ToolAdapterRegistry,
        config: OrchestratorConfig,
    ) -> None:
        self.store = store
        self.adapters = adapters
        self.config = config
        self.policy = PolicyEngine(config.safety)
        self.approvals = ApprovalService(store, config.safety)
        self.capabilities = CapabilityIssuer(store, config.safety)

    async def execute(self, request: ExecutionRequest) -> GatewayResult:
        from ..tool_declarations import RETIRED_TOOL_NAMES
        if request.tool_name in RETIRED_TOOL_NAMES:
            return GatewayResult(disposition=GatewayDisposition.DENIED,
                                 reason_codes=("legacy_route_retired",))
        adapter = self.adapters.get(request.tool_name)
        if adapter is None:
            return GatewayResult(
                disposition=GatewayDisposition.DENIED,
                reason_codes=("adapter_unavailable",),
            )

        existing = self.store.get_invocation_by_idempotency_key(
            request.idempotency_key
        )
        if existing is not None:
            if existing.status in _TERMINAL_INVOCATIONS:
                return GatewayResult(
                    disposition=GatewayDisposition.REPLAYED,
                    outcome=_outcome_from_status(existing.status),
                    invocation_id=existing.invocation_id,
                    reason_codes=("idempotent_replay",),
                )
            return GatewayResult(
                disposition=GatewayDisposition.DENIED,
                invocation_id=existing.invocation_id,
                reason_codes=("invocation_already_in_progress",),
            )

        validation_error = self._validate_durable_scope(request)
        if validation_error == "durable_scope_mismatch":
            return GatewayResult(
                disposition=GatewayDisposition.DENIED,
                reason_codes=(validation_error,),
            )

        evaluation = self.policy.evaluate(request)
        if validation_error is not None:
            evaluation = evaluation.model_copy(
                update={
                    "disposition": PolicyDisposition.DENY,
                    "reasons": tuple(
                        dict.fromkeys((*evaluation.reasons, validation_error))
                    ),
                }
            )
        self._record_policy(request, evaluation)
        if evaluation.disposition is PolicyDisposition.DENY:
            self._record_rejection(request, evaluation, "policy_denied")
            return GatewayResult(
                disposition=GatewayDisposition.DENIED,
                risk=evaluation.risk,
                reason_codes=evaluation.reasons,
            )

        approval = None
        if evaluation.disposition is PolicyDisposition.REQUIRE_APPROVAL:
            if request.approval_id is None:
                approval = self.approvals.request(request, evaluation)
                return GatewayResult(
                    disposition=GatewayDisposition.APPROVAL_REQUIRED,
                    approval_id=approval.approval_id,
                    risk=evaluation.risk,
                    reason_codes=evaluation.reasons,
                )
            try:
                approval = self.approvals.validate(
                    request.approval_id,
                    request,
                    evaluation,
                    now=datetime.now(timezone.utc),
                )
            except AuthorizationError:
                self._record_rejection(request, evaluation, "approval_invalid")
                return GatewayResult(
                    disposition=GatewayDisposition.DENIED,
                    approval_id=request.approval_id,
                    risk=evaluation.risk,
                    reason_codes=("approval_invalid",),
                )

        now = datetime.now(timezone.utc)
        capability = self.capabilities.issue(request, evaluation, approval, now=now)
        invocation = ToolInvocationRecord(
            invocation_id=request.invocation_id,
            task_id=request.task_id,
            step_id=request.step_id,
            attempt_id=request.attempt_id,
            idempotency_key=request.idempotency_key,
            tool_name=request.tool_name,
            normalized_arguments_hash=evaluation.normalized_arguments_hash,
            status=InvocationStatus.REQUESTED,
            side_effect_marker=(
                SideEffectMarker.POSSIBLE
                if adapter.side_effect_possible
                else SideEffectMarker.NONE
            ),
            created_at=now,
            updated_at=now,
            policy_decision_id=evaluation.decision_id,
            capability_grant_id=capability.capability_grant_id,
            approval_id=approval.approval_id if approval is not None else None,
        )
        try:
            self.store.record_invocation(
                invocation,
                safety_event(
                    EventType.TOOL_REQUESTED,
                    request,
                    now,
                    evaluation=evaluation,
                    approval_id=invocation.approval_id,
                    capability_grant_id=capability.capability_grant_id,
                    outcome=InvocationStatus.REQUESTED.value,
                ),
            )
        except RecordConflictError:
            concurrent = self.store.get_invocation_by_idempotency_key(
                request.idempotency_key
            )
            if concurrent is None:
                raise GatewayUnavailableError(
                    "durable invocation request could not be committed"
                )
            if concurrent.status in _TERMINAL_INVOCATIONS:
                return GatewayResult(
                    disposition=GatewayDisposition.REPLAYED,
                    outcome=_outcome_from_status(concurrent.status),
                    invocation_id=concurrent.invocation_id,
                    reason_codes=("idempotent_replay",),
                )
            return GatewayResult(
                disposition=GatewayDisposition.DENIED,
                invocation_id=concurrent.invocation_id,
                reason_codes=("invocation_already_in_progress",),
            )

        approval_event = None
        if approval is not None:
            approval_event = safety_event(
                EventType.APPROVAL_CONSUMED,
                request,
                now,
                evaluation=evaluation,
                approval_id=approval.approval_id,
                capability_grant_id=capability.capability_grant_id,
                outcome=ApprovalDecision.CONSUMED.value,
            ).model_copy(update={"approval_channel": approval.decision_channel})
        try:
            self.store.consume_authorization(
                invocation.invocation_id,
                capability.capability_grant_id,
                safety_event(
                    EventType.TOOL_AUTHORIZED,
                    request,
                    now,
                    evaluation=evaluation,
                    approval_id=invocation.approval_id,
                    capability_grant_id=capability.capability_grant_id,
                    previous_state=InvocationStatus.REQUESTED.value,
                    new_state=InvocationStatus.AUTHORIZED.value,
                    outcome="authorized",
                ),
                now=now,
                approval_consumed_event=approval_event,
            )
        except Exception as exc:
            raise GatewayUnavailableError(
                "durable authorization could not be committed"
            ) from exc

        started_at = datetime.now(timezone.utc)
        started = invocation.model_copy(
            update={
                "status": InvocationStatus.STARTED,
                "started_at": started_at,
                "updated_at": started_at,
            }
        )
        try:
            self.store.update_invocation(
                started,
                InvocationStatus.AUTHORIZED,
                safety_event(
                    EventType.TOOL_STARTED,
                    request,
                    started_at,
                    evaluation=evaluation,
                    approval_id=invocation.approval_id,
                    capability_grant_id=capability.capability_grant_id,
                    previous_state=InvocationStatus.AUTHORIZED.value,
                    new_state=InvocationStatus.STARTED.value,
                    outcome=InvocationStatus.STARTED.value,
                ),
            )
        except Exception as exc:
            raise GatewayUnavailableError(
                "durable execution start could not be committed"
            ) from exc

        monotonic_started = time.monotonic()
        timeout = min(
            self.store.get_step_security_context(request.step_id).timeout_seconds,
            TOOL_REGISTRY[request.tool_name].default_timeout_seconds,
        )
        try:
            context = CorrelationContext(**{key: getattr(request, key) for key in
                ("session_id", "trace_id", "task_id", "plan_id", "plan_version",
                 "step_id", "attempt_id", "invocation_id", "approval_id")})
            with bind_correlation(context):
                adapter_result = await asyncio.wait_for(
                    adapter.execute(request.arguments), timeout=timeout
                )
        except asyncio.CancelledError:
            try:
                self._record_failure(
                    request,
                    evaluation,
                    started,
                    capability.capability_grant_id,
                    adapter.side_effect_possible,
                    "tool_cancelled",
                    monotonic_started,
                    cancelled=True,
                )
            except Exception as audit_exc:
                raise GatewayUnavailableError(
                    "cancelled execution could not be durably recorded"
                ) from audit_exc
            raise
        except Exception as exc:
            try:
                return self._record_failure(
                    request,
                    evaluation,
                    started,
                    capability.capability_grant_id,
                    adapter.side_effect_possible,
                    "tool_timeout" if isinstance(exc, TimeoutError) else "tool_error",
                    monotonic_started,
                )
            except Exception:
                unknown = adapter.side_effect_possible
                return GatewayResult(
                    disposition=(
                        GatewayDisposition.OUTCOME_UNKNOWN
                        if unknown
                        else GatewayDisposition.FAILED
                    ),
                    outcome=(
                        ToolOutcome.OUTCOME_UNKNOWN if unknown else ToolOutcome.FAILED
                    ),
                    invocation_id=request.invocation_id,
                    risk=evaluation.risk,
                    reason_codes=("failure_audit_unavailable",),
                    audit_committed=False,
                )

        completed_at = datetime.now(timezone.utc)
        output_hash = sha256_text(str(adapter_result.output))
        succeeded = started.model_copy(
            update={
                "status": InvocationStatus.SUCCEEDED,
                "side_effect_marker": (
                    SideEffectMarker.OCCURRED
                    if adapter.side_effect_possible
                    or adapter_result.side_effect_occurred
                    else SideEffectMarker.NONE
                ),
                "result_reference": adapter_result.result_reference
                or f"sha256:{output_hash}",
                "completed_at": completed_at,
                "updated_at": completed_at,
            }
        )
        try:
            self.store.update_invocation(
                succeeded,
                InvocationStatus.STARTED,
                safety_event(
                    EventType.TOOL_SUCCEEDED,
                    request,
                    completed_at,
                    evaluation=evaluation,
                    approval_id=invocation.approval_id,
                    capability_grant_id=capability.capability_grant_id,
                    previous_state=InvocationStatus.STARTED.value,
                    new_state=InvocationStatus.SUCCEEDED.value,
                    outcome=ToolOutcome.SUCCEEDED.value,
                    duration_ms=(time.monotonic() - monotonic_started) * 1000,
                ),
            )
        except Exception:
            return GatewayResult(
                disposition=GatewayDisposition.OUTCOME_UNKNOWN,
                outcome=ToolOutcome.OUTCOME_UNKNOWN,
                invocation_id=request.invocation_id,
                risk=evaluation.risk,
                reason_codes=("post_execution_audit_failed",),
                audit_committed=False,
            )
        return GatewayResult(
            disposition=GatewayDisposition.EXECUTED,
            outcome=ToolOutcome.SUCCEEDED,
            output=adapter_result.output,
            invocation_id=request.invocation_id,
            risk=evaluation.risk,
        )

    def _validate_durable_scope(self, request: ExecutionRequest) -> str | None:
        task = self.store.get_task(request.task_id)
        step = self.store.get_step_security_context(request.step_id)
        if task.cancellation_requested:
            return "task_cancelled"
        if task.status in {
            TaskStatus.PAUSED,
            TaskStatus.COMPLETED,
            TaskStatus.CANCELLED,
            TaskStatus.FAILED,
            TaskStatus.ROLLED_BACK,
        }:
            return "task_not_executable"
        if (
            task.session_id != request.session_id
            or task.trace_id != request.trace_id
            or task.mode != request.task_mode
            or task.workspace != request.workspace
            or step.task_id != request.task_id
            or step.plan_id != request.plan_id
            or step.plan_version != request.plan_version
            or step.tool_name != request.tool_name
            or step.normalized_arguments_hash
            != normalized_arguments_hash(request.arguments)
            or step.exact_target_hash != exact_target_hash(request.exact_target)
        ):
            return "durable_scope_mismatch"
        return None

    def _record_policy(
        self, request: ExecutionRequest, evaluation: PolicyEvaluation
    ) -> None:
        now = datetime.now(timezone.utc)
        self.store.record_policy_decision(
            PolicyDecisionRecord(
                decision_id=evaluation.decision_id,
                task_id=request.task_id,
                step_id=request.step_id,
                plan_id=request.plan_id,
                plan_version=request.plan_version,
                policy_version=evaluation.policy_version,
                risk=evaluation.risk,
                disposition=evaluation.disposition,
                reasons=evaluation.reasons,
                tool_name=request.tool_name,
                normalized_arguments_hash=evaluation.normalized_arguments_hash,
                exact_target_hash=evaluation.exact_target_hash,
                scope_hash=evaluation.scope_hash,
                capability_constraints=evaluation.capability_constraints,
                evaluated_at=now,
            ),
            safety_event(
                EventType.POLICY_EVALUATED,
                request,
                now,
                evaluation=evaluation,
                outcome=evaluation.disposition.value,
            ),
        )

    def _record_rejection(
        self,
        request: ExecutionRequest,
        evaluation: PolicyEvaluation,
        error_code: str,
    ) -> None:
        now = datetime.now(timezone.utc)
        self.store.append_event(
            safety_event(
                EventType.CAPABILITY_REJECTED,
                request,
                now,
                evaluation=evaluation,
                severity=EventSeverity.WARNING,
                outcome="rejected",
                error_code=error_code,
            )
        )

    def _record_failure(
        self,
        request: ExecutionRequest,
        evaluation: PolicyEvaluation,
        started: ToolInvocationRecord,
        capability_grant_id: str,
        side_effect_possible: bool,
        error_code: str,
        monotonic_started: float,
        cancelled: bool = False,
    ) -> GatewayResult:
        completed_at = datetime.now(timezone.utc)
        unknown = side_effect_possible
        status = (
            InvocationStatus.OUTCOME_UNKNOWN
            if unknown
            else InvocationStatus.CANCELLED
            if cancelled
            else InvocationStatus.FAILED
        )
        outcome = (
            ToolOutcome.OUTCOME_UNKNOWN
            if unknown
            else ToolOutcome.CANCELLED
            if cancelled
            else ToolOutcome.FAILED
        )
        failed = started.model_copy(
            update={
                "status": status,
                "side_effect_marker": (
                    SideEffectMarker.OUTCOME_UNKNOWN
                    if unknown
                    else SideEffectMarker.NONE
                ),
                "error_code": error_code,
                "completed_at": completed_at,
                "updated_at": completed_at,
            }
        )
        self.store.update_invocation(
            failed,
            InvocationStatus.STARTED,
            safety_event(
                EventType.TOOL_OUTCOME_UNKNOWN if unknown else EventType.TOOL_FAILED,
                request,
                completed_at,
                evaluation=evaluation,
                approval_id=started.approval_id,
                capability_grant_id=capability_grant_id,
                severity=EventSeverity.ERROR,
                previous_state=InvocationStatus.STARTED.value,
                new_state=status.value,
                outcome=outcome.value,
                error_code=error_code,
                duration_ms=(time.monotonic() - monotonic_started) * 1000,
            ),
        )
        return GatewayResult(
            disposition=(
                GatewayDisposition.OUTCOME_UNKNOWN
                if unknown
                else GatewayDisposition.FAILED
            ),
            outcome=outcome,
            invocation_id=request.invocation_id,
            risk=evaluation.risk,
            reason_codes=(error_code,),
        )


def _outcome_from_status(status: InvocationStatus) -> ToolOutcome:
    return {
        InvocationStatus.SUCCEEDED: ToolOutcome.SUCCEEDED,
        InvocationStatus.FAILED: ToolOutcome.FAILED,
        InvocationStatus.OUTCOME_UNKNOWN: ToolOutcome.OUTCOME_UNKNOWN,
        InvocationStatus.CANCELLED: ToolOutcome.CANCELLED,
    }[status]
