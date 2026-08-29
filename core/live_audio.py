"""Small, dependency-free helpers for the Gemini Live audio pipeline."""

from __future__ import annotations

import asyncio
import re
from typing import Any


_CTRL_RE = re.compile(r"<ctrl\d+>", re.IGNORECASE)


def clean_transcript(text: str) -> str:
    """Remove control tokens and non-printing characters from transcripts."""
    text = _CTRL_RE.sub("", text or "")
    text = re.sub(r"[\x00-\x08\x0b-\x1f]", "", text)
    return text.strip()


def merge_transcript(current: str, update: str) -> str:
    """Merge Gemini transcript deltas and cumulative updates without repeats."""
    update = clean_transcript(update)
    current = clean_transcript(current)
    if not update:
        return current
    if not current:
        return update
    if update == current or current.endswith(update):
        return current
    if update.startswith(current):
        return update
    if current.startswith(update):
        return current
    return f"{current} {update}".strip()


def drain_async_queue(q: asyncio.Queue | None) -> int:
    """Discard all queued items without blocking and return the item count."""
    if q is None:
        return 0
    drained = 0
    while True:
        try:
            q.get_nowait()
            drained += 1
        except asyncio.QueueEmpty:
            return drained


def put_latest(q: asyncio.Queue, item: Any) -> None:
    """Bound latency by dropping the oldest item when a realtime queue is full."""
    if q.full():
        try:
            q.get_nowait()
        except asyncio.QueueEmpty:
            pass
    try:
        q.put_nowait(item)
    except asyncio.QueueFull:
        # Another producer won the slot. Dropping one realtime frame is safer
        # than blocking the audio callback or growing latency.
        pass
