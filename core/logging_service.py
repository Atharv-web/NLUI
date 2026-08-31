"""Thread-safe, privacy-aware structured logging for JARVIS."""

from __future__ import annotations

import json
import queue
import re
import threading
import time
import traceback
import uuid
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


_SENSITIVE_KEY_RE = re.compile(
    r"(?:api[_-]?key|authorization|password|passwd|secret|token|cookie|credential)",
    re.IGNORECASE,
)
_CONTENT_KEY_RE = re.compile(
    r"(?:content|message|text|prompt|code|audio|image|data|file_path|path)",
    re.IGNORECASE,
)
_MAX_TEXT = 800
_MAX_COLLECTION = 30


class JarvisLogger:
    """Writes redacted JSONL events without blocking the assistant runtime."""

    def __init__(self, base_dir: Path, retention_days: int = 30) -> None:
        self.base_dir = base_dir
        self.logs_dir = base_dir / "logs"
        self.retention_days = retention_days
        self.session_id = uuid.uuid4().hex
        self._queue: queue.Queue[dict[str, Any] | threading.Event | None] = queue.Queue(maxsize=2_000)
        self._closed = threading.Event()
        self._worker = threading.Thread(target=self._write_loop, name="jarvis-log-writer", daemon=True)
        self._cleanup_old_logs()
        self._worker.start()
        self.log("info", "system", "system", "Logging service started.", result={"session_id": self.session_id})

    def new_trace_id(self) -> str:
        return uuid.uuid4().hex

    def log(
        self,
        level: str,
        source: str,
        event_type: str,
        message: str,
        *,
        trace_id: str | None = None,
        tool_name: str | None = None,
        arguments: Any = None,
        result: Any = None,
        duration_ms: float | None = None,
        exception: BaseException | None = None,
    ) -> None:
        """Queue an event. Logging errors are deliberately swallowed."""
        try:
            safe_level = level if level in {"debug", "info", "warn", "error"} else "info"
            event: dict[str, Any] = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": self.session_id,
                "level": safe_level,
                "source": source,
                "event_type": event_type,
                "tool_name": tool_name,
                "arguments": self._redact(arguments),
                "result": self._redact(result),
                "duration_ms": round(duration_ms, 2) if duration_ms is not None else None,
                "message": self._shorten(message),
                "trace_id": trace_id,
            }
            if exception is not None:
                event["error"] = {
                    "type": type(exception).__name__,
                    "message": self._shorten(str(exception)),
                    "stack_trace": self._redact_text("".join(traceback.format_exception(exception))),
                }
            if safe_level in {"info", "warn", "error"}:
                print(f"[JARVIS] {safe_level.upper()} {tool_name or source} {event['message']}")
            self._queue.put_nowait(event)
        except queue.Full:
            # Dropping debug information is safer than stalling the voice loop.
            pass
        except Exception:
            pass

    def get_events(
        self,
        *,
        level: str = "all",
        source: str = "all",
        query: str = "",
        limit: int = 1_000,
    ) -> list[dict[str, Any]]:
        """Return recent local events for the desktop-only debug viewer."""
        # The writer is asynchronous. A short barrier makes an explicit UI
        # refresh include events queued before the user requested it.
        self.flush(timeout=0.5)
        events: list[dict[str, Any]] = []
        try:
            for file_path in self.logs_dir.glob("*/*.jsonl"):
                with file_path.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        with suppress(json.JSONDecodeError):
                            event = json.loads(line)
                            if level != "all" and event.get("level") != level:
                                continue
                            if source != "all" and event.get("source") != source:
                                continue
                            haystack = json.dumps(event, ensure_ascii=False).lower()
                            if query and query.lower() not in haystack:
                                continue
                            events.append(event)
        except Exception:
            pass

        # Session filenames are UUIDs, so filesystem ordering is not event
        # ordering. Sort by the ISO timestamp before applying the recent limit.
        events.sort(key=lambda event: str(event.get("timestamp", "")))
        return events[-limit:] if limit > 0 else []

    def get_sources(self) -> list[str]:
        """Return the source values that actually exist in local logs."""
        self.flush(timeout=0.5)
        sources: set[str] = set()
        try:
            for file_path in self.logs_dir.glob("*/*.jsonl"):
                with file_path.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        with suppress(json.JSONDecodeError):
                            source = json.loads(line).get("source")
                            if isinstance(source, str) and source:
                                sources.add(source)
        except Exception:
            pass
        return sorted(sources)

    def flush(self, timeout: float = 1.0) -> bool:
        """Wait briefly for events already in the queue to reach disk."""
        if self._closed.is_set():
            return False
        barrier = threading.Event()
        try:
            self._queue.put_nowait(barrier)
        except queue.Full:
            return False
        return barrier.wait(max(0.0, timeout))

    def close(self) -> None:
        if self._closed.is_set():
            return
        self.log("info", "system", "system", "Logging service stopping.")
        self._closed.set()
        with suppress(Exception):
            self._queue.put_nowait(None)
        self._worker.join(timeout=1.5)

    def _write_loop(self) -> None:
        while True:
            event = self._queue.get()
            if event is None:
                return
            if isinstance(event, threading.Event):
                event.set()
                continue
            try:
                now = datetime.now()
                day_dir = self.logs_dir / now.strftime("%Y-%m-%d")
                day_dir.mkdir(parents=True, exist_ok=True)
                target = day_dir / f"session_{self.session_id}.jsonl"
                with target.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
            except Exception:
                # Disk failures must never terminate JARVIS or this worker loop.
                continue

    def _cleanup_old_logs(self) -> None:
        try:
            self.logs_dir.mkdir(parents=True, exist_ok=True)
            cutoff = datetime.now().date() - timedelta(days=self.retention_days)
            for child in self.logs_dir.iterdir():
                if not child.is_dir():
                    continue
                with suppress(ValueError):
                    if datetime.strptime(child.name, "%Y-%m-%d").date() < cutoff:
                        for file_path in child.glob("*.jsonl"):
                            file_path.unlink(missing_ok=True)
                        child.rmdir()
        except Exception:
            pass

    @classmethod
    def _shorten(cls, value: Any) -> str:
        return cls._redact_text(str(value))[:_MAX_TEXT]

    @classmethod
    def _redact_text(cls, value: str) -> str:
        value = _SENSITIVE_KEY_RE.sub("[REDACTED]", value)
        # Do not retain full Windows, Unix, or home-directory paths in logs.
        value = re.sub(r"(?:[A-Za-z]:\\|/|~[/\\])[^\s'\"]+", "[PATH]", value)
        return value[:_MAX_TEXT]

    @classmethod
    def _redact(cls, value: Any, key: str = "") -> Any:
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if _SENSITIVE_KEY_RE.search(key):
            return "[REDACTED]"
        if _CONTENT_KEY_RE.search(key):
            return f"[REDACTED CONTENT: {len(str(value))} chars]"
        if isinstance(value, str):
            return cls._redact_text(value)
        if isinstance(value, Path):
            return f"[PATH: {value.name}]"
        if isinstance(value, dict):
            return {str(k): cls._redact(v, str(k)) for k, v in list(value.items())[:_MAX_COLLECTION]}
        if isinstance(value, (list, tuple, set)):
            return [cls._redact(item) for item in list(value)[:_MAX_COLLECTION]]
        return cls._redact_text(repr(value))
