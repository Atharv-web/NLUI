"""Independent, tool-specific verification with hash-only durable evidence."""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import uuid
from datetime import datetime, timezone
from typing import Awaitable, Callable, Literal

from pydantic import Field, model_validator

from .contracts import Evidence, EvidenceKind, PlanStep, StrictContract, ToolOutcome
from .safety.contracts import GatewayResult
from .tool_registry import TOOL_REGISTRY


class VerificationResult(StrictContract):
    status: Literal["passed", "failed", "inconclusive"]
    verifier_type: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    evidence: tuple[Evidence, ...] = ()
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_]{0,127}$")

    @model_validator(mode="after")
    def require_evidence(self) -> "VerificationResult":
        if self.status == "passed" and not self.evidence:
            raise ValueError("passing verification requires evidence")
        return self


def result_from_observation(verifier_type: str, kind: EvidenceKind,
                            observation: dict, passed: bool = True) -> VerificationResult:
    encoded = json.dumps(observation, sort_keys=True, separators=(",", ":"), allow_nan=False)
    digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    return VerificationResult(
        status="passed" if passed else "failed", verifier_type=verifier_type,
        reason_code="postcondition_confirmed" if passed else "postcondition_failed",
        evidence=(Evidence(evidence_id=uuid.uuid4().hex, kind=kind,
                           reference="sha256:" + digest, sha256=digest,
                           captured_at=datetime.now(timezone.utc), sensitivity_class="hash_only"),),
    )


Verifier = Callable[[PlanStep, GatewayResult], Awaitable[VerificationResult]]


class VerificationRegistry:
    def __init__(self, timeout_seconds: float = 10) -> None:
        if not 0 < timeout_seconds <= 120:
            raise ValueError("invalid verification timeout")
        self.timeout_seconds = timeout_seconds
        self._verifiers: dict[str, Verifier] = {"system_status": _verify_metrics}

    def register(self, tool_name: str, verifier: Verifier) -> None:
        if tool_name not in TOOL_REGISTRY or not callable(verifier):
            raise ValueError("invalid verifier registration")
        self._verifiers[tool_name] = verifier

    def supports(self, tool_name: str) -> bool:
        return tool_name in self._verifiers

    async def verify(self, step: PlanStep, result: GatewayResult) -> VerificationResult:
        if not result.audit_committed:
            return _inconclusive("audit_unavailable")
        if result.outcome != ToolOutcome.SUCCEEDED:
            return _inconclusive("execution_not_confirmed")
        if step.proposal is None or step.proposal.tool_name not in self._verifiers:
            return _inconclusive("verifier_unavailable")
        try:
            async with asyncio.timeout(self.timeout_seconds):
                verified = await self._verifiers[step.proposal.tool_name](step, result)
                if not isinstance(verified, VerificationResult):
                    return _inconclusive("invalid_verifier_result")
                return verified
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            return _inconclusive("verification_timeout")
        except Exception:
            return _inconclusive("verification_unavailable")


def _inconclusive(reason: str) -> VerificationResult:
    return VerificationResult(status="inconclusive", verifier_type="independent_evidence",
                              reason_code=reason)


async def _verify_metrics(step: PlanStep, result: GatewayResult) -> VerificationResult:
    # Numeric metric snapshots are the actual read result, not model success prose.
    output = result.output
    if not isinstance(output, dict):
        return _inconclusive("metric_snapshot_missing")
    metrics = {name: output.get(name) for name in ("cpu_percent", "ram_percent")}
    if any(type(value) not in (float, int) or not math.isfinite(value)
           or not 0 <= value <= 100 for value in metrics.values()):
        return _inconclusive("metric_snapshot_invalid")
    return result_from_observation("system_metrics", EvidenceKind.STRUCTURED_RESULT, metrics)
