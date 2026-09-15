"""Thread-safe, privacy-aware structured logging for JARVIS."""

from __future__ import annotations

import json
import queue
import re
import threading
import time
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

    def __init__(self, base_dir: Path, retention_days: int = 30, *,
                 queue_capacity: int = 2000, max_file_bytes: int = 10_485_760) -> None:
        self.base_dir = base_dir
        self.logs_dir = base_dir / "logs"
        self.retention_days = retention_days
        self.session_id = uuid.uuid4().hex
        self._queue: queue.Queue[dict[str, Any] | threading.Event | None] = queue.Queue(maxsize=max(1, queue_capacity))
        self.max_file_bytes = max(512, max_file_bytes)
        self._write_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._health = {"dropped_events": 0, "write_failures": 0, "written_events": 0}
        self._rotation = 0
        self._rotation_day = ""
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
        context: dict[str, str] | None = None,
    ) -> None:
        """Queue an event. Logging errors are deliberately swallowed."""
        try:
            if self._closed.is_set():
                return
            from orchestrator.correlation import current_correlation
            lineage = current_correlation()
            if lineage is not None:
                trace_id = trace_id or lineage.trace_id
                context = {**lineage.model_dump(exclude_none=True), **(context or {})}
            safe_level = level if level in {"debug", "info", "warn", "error"} else "info"
            event: dict[str, Any] = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": self.session_id,
                "level": safe_level,
                "source": self._shorten(source),
                "event_type": self._shorten(event_type),
                "tool_name": self._shorten(tool_name) if tool_name else None,
                "arguments": self._redact(arguments),
                "result": self._redact(result),
                "duration_ms": round(duration_ms, 2) if duration_ms is not None else None,
                "message": self._shorten(message),
                "trace_id": trace_id,
            }
            if exception is not None:
                event["error"] = {
                    "type": type(exception).__name__,
                    "message": "[exception details withheld]",
                }
            if context:
                for key in ("task_id", "step_id", "approval_id", "worker_id", "model_name", "risk", "outcome"):
                    if key in context:
                        event[key] = self._shorten(context[key])
            self._queue.put_nowait(event)
        except queue.Full:
            with self._state_lock:
                self._health["dropped_events"] += 1
        except Exception:
            with self._state_lock:
                self._health["dropped_events"] += 1

    def health(self) -> dict:
        with self._state_lock:
            result = dict(self._health)
        result.update(queue_depth=self._queue.qsize(), closed=self._closed.is_set(),
                      writer_alive=self._worker.is_alive())
        result["degraded"] = bool(result["dropped_events"] or result["write_failures"])
        return result

    def emergency_flush(self) -> bool:
        """Drain already-redacted events synchronously after a fatal error."""
        while True:
            try:
                event = self._queue.get_nowait()
            except queue.Empty:
                break
            if isinstance(event, dict):
                self._write_event(event)
            elif isinstance(event, threading.Event):
                event.set()
        return self.health()["write_failures"] == 0

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
        return barrier.wait(max(0.0, timeout)) and not self.health()["write_failures"]

    def close(self) -> None:
        if self._closed.is_set():
            return
        self.log("info", "system", "system", "Logging service stopping.")
        self._closed.set()
        # The writer also exits once a full queue drains; a sentinel isn't needed.
        self._worker.join(timeout=5)

    def _write_loop(self) -> None:
        while True:
            try:
                event = self._queue.get(timeout=.1)
            except queue.Empty:
                if self._closed.is_set():
                    return
                continue
            if event is None:
                return
            if isinstance(event, threading.Event):
                event.set()
                continue
            self._write_event(event)

    def _write_event(self, event) -> None:
        try:
            with self._write_lock:
                day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                if day != self._rotation_day:
                    self._rotation_day, self._rotation = day, 0
                    self._cleanup_old_logs()
                day_dir = self.logs_dir / day
                day_dir.mkdir(parents=True, exist_ok=True)
                encoded = json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
                while True:
                    suffix = f"_{self._rotation}" if self._rotation else ""
                    target = day_dir / f"session_{self.session_id}{suffix}.jsonl"
                    if not target.exists() or target.stat().st_size + len(encoded.encode("utf-8")) <= self.max_file_bytes:
                        break
                    self._rotation += 1
                with target.open("a", encoding="utf-8") as handle:
                    handle.write(encoded)
                with self._state_lock:
                    self._health["written_events"] += 1
        except Exception:
            with self._state_lock:
                self._health["write_failures"] += 1

    def _cleanup_old_logs(self) -> None:
        try:
            self.logs_dir.mkdir(parents=True, exist_ok=True)
            cutoff = datetime.now().date() - timedelta(days=self.retention_days)
            for child in self.logs_dir.iterdir():
                if not child.is_dir() or child.is_symlink() or not child.resolve().is_relative_to(self.logs_dir.resolve()):
                    continue
                with suppress(ValueError):
                    if datetime.strptime(child.name, "%Y-%m-%d").date() < cutoff:
                        for file_path in child.glob("session_*.jsonl"):
                            if not file_path.is_symlink():
                                file_path.unlink(missing_ok=True)
                        if not any(child.iterdir()):
                            child.rmdir()
        except Exception:
            pass

    @classmethod
    def _shorten(cls, value: Any) -> str:
        return cls._redact_text(str(value))[:_MAX_TEXT]

    @classmethod
    def _redact_text(cls, value: str) -> str:
        value = re.sub(r"(?i)(?:api[_-]?key|authorization|password|passwd|secret|token|cookie|credential)\s*[:=]\s*(?:bearer\s+)?[^\s,;]+", "[REDACTED]", value)
        value = re.sub(r"\b(?:AIza[0-9A-Za-z_-]{20,}|sk-[0-9A-Za-z_-]{12,})\b", "[REDACTED]", value)
        value = re.sub(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[PERSONAL DATA]", value, flags=re.I)
        value = _SENSITIVE_KEY_RE.sub("[REDACTED]", value)
        # Do not retain full Windows, Unix, or home-directory paths in logs.
        value = re.sub(r"(?:[A-Za-z]:\\|/|~[/\\])[^\s'\"]+", "[PATH]", value)
        return value[:_MAX_TEXT]

    @classmethod
    def _redact(cls, value: Any, key: str = "") -> Any:
        if _SENSITIVE_KEY_RE.search(key):
            return "[REDACTED]"
        if _CONTENT_KEY_RE.search(key):
            return f"[REDACTED CONTENT: {len(str(value))} chars]"
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            return cls._redact_text(value)
        if isinstance(value, Path):
            return f"[PATH: {value.name}]"
        if isinstance(value, dict):
            return {str(k): cls._redact(v, str(k)) for k, v in list(value.items())[:_MAX_COLLECTION]}
        if isinstance(value, (list, tuple, set)):
            return [cls._redact(item) for item in list(value)[:_MAX_COLLECTION]]
        return cls._redact_text(repr(value))
