"""Small runtime probes. Unsupported actions remain explicitly unverified."""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .contracts import EvidenceKind
from .verification import VerificationRegistry, VerificationResult, result_from_observation


def _unknown(reason):
    return VerificationResult(status="inconclusive", verifier_type="runtime_probe", reason_code=reason)


def _read_memory():
    # Read directly: the legacy loader hides corrupt/missing stores as empty data.
    from memory.memory_manager import MEMORY_PATH, _lock
    with _lock:
        return json.loads(MEMORY_PATH.read_text(encoding="utf-8"))


def _process_observation(name):
    import psutil
    from actions.open_app import _normalize
    target = Path(_normalize(name)).name.lower().removesuffix(".exe")
    for process in psutil.process_iter(["pid", "name"]):
        actual = (process.info.get("name") or "").lower().removesuffix(".exe")
        if actual == target:
            return {"pid": process.info["pid"], "name": actual}
    return None


def build_runtime_verifier(app) -> VerificationRegistry:
    registry = VerificationRegistry()

    async def open_app(step, result):
        observation = await asyncio.to_thread(_process_observation, step.proposal.arguments["app_name"])
        if observation is None:
            return _unknown("application_process_not_observed")
        return result_from_observation("application_process", EvidenceKind.PROCESS_STATE, observation)

    async def save_memory(step, result):
        args = step.proposal.arguments
        memory = await asyncio.to_thread(_read_memory)
        value = memory.get(args.get("category", "notes"), {}).get(args["key"], {}).get("value")
        # A truncated or evicted value is not the requested postcondition.
        return result_from_observation("memory_readback", EvidenceKind.FILE_HASH,
                                       {"stored_value": value}, passed=value == args["value"])

    async def monitor(step, result):
        args = step.proposal.arguments
        memory = await asyncio.to_thread(_read_memory)
        entries = memory.get("monitors", {})
        topics = [entry["topic"].strip().casefold() for entry in entries.values()]
        action = args.get("action", "").strip().lower()
        topic = args.get("topic", "").strip().casefold()
        if action == "list":
            passed = True
        elif action == "add" and topic:
            passed = topic in topics
        elif action == "remove" and topic:
            passed = not any(topic in candidate for candidate in topics)
        else:
            return _unknown("monitor_request_invalid")
        return result_from_observation("monitor_readback", EvidenceKind.FILE_HASH,
                                       {"topics": topics}, passed=passed)

    async def screen(step, result):
        if not isinstance(result.output, str) or not result.output.startswith("[VISION_ACTIVE]"):
            return _unknown("capture_not_performed")
        pending = getattr(app, "_pending_vision", None)
        if not pending or len(pending) != 4:
            return _unknown("captured_image_missing")
        data, mime, prompt, angle = pending
        if angle != step.proposal.arguments.get("angle", "screen").lower():
            return _unknown("capture_source_mismatch")
        if not isinstance(data, bytes) or not data or not mime.startswith("image/"):
            return _unknown("captured_image_invalid")
        from PIL import Image
        def inspect():
            with Image.open(io.BytesIO(data)) as captured:
                size = captured.size
                captured.verify()
            return size
        width, height = await asyncio.to_thread(inspect)
        return result_from_observation("image_capture", EvidenceKind.SCREENSHOT,
                                       {"sha256": hashlib.sha256(data).hexdigest(),
                                        "width": width, "height": height, "source": angle})

    async def close_camera(step, result):
        window = getattr(app.ui, "_win", None)
        stop = getattr(window, "_cam_stop", None)
        if stop is None or not stop.is_set():
            return _unknown("camera_stop_not_observed")
        # The legacy UI does not keep a worker handle. A stop request alone
        # cannot prove that its worker has released the camera.
        for _ in range(10):
            if not any(t.name == "cam-stream" and t.is_alive() for t in threading.enumerate()):
                return result_from_observation("camera_state", EvidenceKind.PROCESS_STATE,
                                               {"stop_requested": True, "worker_alive": False})
            await asyncio.sleep(.05)
        return _unknown("camera_worker_still_running")

    async def web_search(step, result):
        # This receipt is supplied by the adapter from provider metadata. It
        # proves source-backed retrieval, not that the generated text is true.
        output = result.output
        if not isinstance(output, dict) or not isinstance(output.get("text"), str) or not output["text"].strip():
            return _unknown("search_receipt_missing")
        sources = output.get("sources")
        if not isinstance(sources, list) or not sources:
            return _unknown("search_sources_missing")
        for source in sources:
            if not isinstance(source, str):
                return _unknown("search_source_invalid")
            parsed = urlsplit(source)
            if parsed.scheme not in ("https", "http") or not parsed.hostname or parsed.username or parsed.password:
                return _unknown("search_source_invalid")
        try:
            retrieved = datetime.fromisoformat(output["retrieved_at"])
            if retrieved.tzinfo is None:
                return _unknown("search_timestamp_invalid")
            age = (datetime.now(timezone.utc) - retrieved).total_seconds()
        except (KeyError, TypeError, ValueError):
            return _unknown("search_timestamp_invalid")
        if not 0 <= age <= 300:
            return _unknown("search_receipt_stale")
        return result_from_observation("source_backed_retrieval", EvidenceKind.PROVIDER_RECEIPT,
                                       {"text": output["text"], "sources": sources,
                                        "retrieved_at": retrieved.isoformat()})

    for name, probe in (("open_app", open_app), ("save_memory", save_memory),
                        ("manage_monitor", monitor), ("screen_process", screen),
                        ("close_camera", close_camera), ("web_search", web_search)):
        registry.register(name, probe)
    return registry
