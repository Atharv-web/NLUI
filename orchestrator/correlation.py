"""Immutable correlation context for concurrent orchestration work."""

from __future__ import annotations

import contextvars
import uuid
from contextlib import contextmanager
from typing import Iterator

from pydantic import BaseModel, ConfigDict, Field


class CorrelationContext(BaseModel):
    """Identifiers propagated with one task/step execution lineage."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    session_id: str = Field(min_length=1, max_length=128)
    trace_id: str = Field(min_length=1, max_length=128)
    task_id: str | None = Field(default=None, min_length=1, max_length=128)
    plan_id: str | None = Field(default=None, min_length=1, max_length=128)
    plan_version: int | None = Field(default=None, ge=1)
    step_id: str | None = Field(default=None, min_length=1, max_length=128)
    parent_step_id: str | None = Field(default=None, min_length=1, max_length=128)
    attempt_id: str | None = Field(default=None, min_length=1, max_length=128)
    invocation_id: str | None = Field(default=None, min_length=1, max_length=128)
    approval_id: str | None = Field(default=None, min_length=1, max_length=128)

    @classmethod
    def new(cls, *, session_id: str, task_id: str | None = None) -> "CorrelationContext":
        return cls(session_id=session_id, trace_id=uuid.uuid4().hex, task_id=task_id)

    def child(self, **changes: object) -> "CorrelationContext":
        """Return a derived immutable context without mutating the parent."""
        return self.model_copy(update=changes)


_CURRENT_CORRELATION: contextvars.ContextVar[CorrelationContext | None] = (
    contextvars.ContextVar("jarvis_correlation_context", default=None)
)


def current_correlation() -> CorrelationContext | None:
    return _CURRENT_CORRELATION.get()


@contextmanager
def bind_correlation(context: CorrelationContext) -> Iterator[CorrelationContext]:
    """Bind a context to the current async/thread context and restore it safely."""
    token = _CURRENT_CORRELATION.set(context)
    try:
        yield context
    finally:
        _CURRENT_CORRELATION.reset(token)
