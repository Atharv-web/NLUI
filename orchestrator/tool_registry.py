"""Machine-readable inventory of the existing MARK L tool surface."""

from __future__ import annotations

from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from pydantic import ConfigDict, Field

from .contracts import RiskLevel, StrictContract
from .tool_declarations import TOOL_DECLARATIONS, RETIRED_TOOL_DECLARATIONS
from .worker_tools import INTERNAL_TOOL_DECLARATIONS


class SideEffect(str, Enum):
    NONE = "none"
    NETWORK_READ = "network_read"
    PROCESS_LAUNCH = "process_launch"
    UI_CONTROL = "ui_control"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    EXTERNAL_COMMUNICATION = "external_communication"
    SCHEDULE_CHANGE = "schedule_change"
    SYSTEM_STATE_CHANGE = "system_state_change"
    PERSONAL_DATA_ACCESS = "personal_data_access"
    MEMORY_WRITE = "memory_write"
    ARBITRARY_CODE = "arbitrary_code"


class RetryPolicy(str, Enum):
    NEVER = "never"
    TRANSIENT_READ_ONCE = "transient_read_once"


class ToolMetadata(StrictContract):
    """Static floor metadata; later policy may raise risk but never lower it."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    name: str = Field(min_length=1, max_length=128)
    declaration: dict[str, Any]
    implementation: str = Field(min_length=1, max_length=256)
    default_risk: RiskLevel
    side_effects: frozenset[SideEffect]
    default_timeout_seconds: int = Field(ge=1, le=3600)
    retry_policy: RetryPolicy
    verification_method: str = Field(min_length=1, max_length=500)
    sensitivity_classes: frozenset[str] = frozenset()
    risk_notes: str = Field(min_length=1, max_length=1000)


def _spec(
    implementation: str,
    risk: RiskLevel,
    effects: tuple[SideEffect, ...],
    timeout: int,
    retry: RetryPolicy,
    verification: str,
    notes: str,
    sensitivity: tuple[str, ...] = (),
) -> dict[str, object]:
    return {
        "implementation": implementation,
        "default_risk": risk,
        "side_effects": frozenset(effects),
        "default_timeout_seconds": timeout,
        "retry_policy": retry,
        "verification_method": verification,
        "sensitivity_classes": frozenset(sensitivity),
        "risk_notes": notes,
    }


# Conservative whole-tool risk floors. Mixed-action tools stay at the highest
# plausible risk until argument-aware policy evaluation is implemented in M4.
_SPECS: dict[str, dict[str, object]] = {
    "open_app": _spec("actions.open_app.open_app", RiskLevel.R1, (SideEffect.PROCESS_LAUNCH,), 15, RetryPolicy.NEVER, "process/window evidence", "Launching an application is low-impact but changes desktop state."),
    "web_search": _spec("actions.web_search.web_search", RiskLevel.R0, (SideEffect.NETWORK_READ,), 120, RetryPolicy.TRANSIENT_READ_ONCE, "source URLs and response timestamp", "Public read-only search.", ("public_web_content",)),
    "system_status": _spec("actions.system_monitor.get_system_status", RiskLevel.R0, (SideEffect.NONE,), 10, RetryPolicy.TRANSIENT_READ_ONCE, "structured metric snapshot", "Local read-only metrics."),
    "weather_report": _spec("actions.weather_report.weather_action", RiskLevel.R0, (SideEffect.NETWORK_READ,), 30, RetryPolicy.TRANSIENT_READ_ONCE, "weather source URL and retrieval timestamp", "Approved architecture classifies routine weather as R0.", ("approximate_location",)),
    "send_message": _spec("actions.send_message.send_message", RiskLevel.R3, (SideEffect.EXTERNAL_COMMUNICATION, SideEffect.UI_CONTROL), 60, RetryPolicy.NEVER, "provider/UI receipt plus recipient and final-content hashes", "Sends externally and must never be blindly retried.", ("personal_identifier", "message_content")),
    "reminder": _spec("actions.reminder.reminder", RiskLevel.R2, (SideEffect.SCHEDULE_CHANGE, SideEffect.FILE_WRITE), 30, RetryPolicy.NEVER, "scheduler entry lookup", "Creates a durable operating-system schedule entry.", ("personal_message",)),
    "youtube_video": _spec("actions.youtube_video.youtube_video", RiskLevel.R1, (SideEffect.NETWORK_READ, SideEffect.PROCESS_LAUNCH, SideEffect.FILE_WRITE), 120, RetryPolicy.NEVER, "opened URL or saved-file hash", "Some modes save a summary, so argument-aware policy may raise the risk.", ("public_web_content",)),
    "screen_process": _spec("actions.screen_processor capture helpers", RiskLevel.R2, (SideEffect.PERSONAL_DATA_ACCESS,), 45, RetryPolicy.NEVER, "capture hash, source type, and timestamp", "Screens and cameras can contain highly sensitive personal data.", ("screenshot", "camera_frame")),
    "close_camera": _spec("ui.JarvisUI.stop_camera_stream", RiskLevel.R1, (SideEffect.UI_CONTROL,), 5, RetryPolicy.NEVER, "camera stream closed state", "Closes an assistant-owned camera view."),
    "computer_settings": _spec("actions.computer_settings.computer_settings", RiskLevel.R3, (SideEffect.SYSTEM_STATE_CHANGE, SideEffect.UI_CONTROL), 30, RetryPolicy.NEVER, "tool-specific post-state snapshot", "Mixed actions include shutdown, restart, Wi-Fi, typing, and window changes."),
    "browser_control": _spec("actions.browser_control.browser_control", RiskLevel.R3, (SideEffect.NETWORK_READ, SideEffect.PROCESS_LAUNCH, SideEffect.UI_CONTROL, SideEffect.FILE_WRITE), 120, RetryPolicy.NEVER, "fresh URL/DOM/screenshot evidence", "Mixed actions can type, submit, download, or use authenticated sessions.", ("browser_content", "authentication_state")),
    "file_controller": _spec("actions.file_controller.file_controller", RiskLevel.R3, (SideEffect.FILE_READ, SideEffect.FILE_WRITE), 120, RetryPolicy.NEVER, "canonical path plus before/after hashes", "Mixed actions include arbitrary-path deletion, move, and write.", ("file_content", "filesystem_path")),
    "desktop_control": _spec("actions.desktop.desktop_control", RiskLevel.R3, (SideEffect.FILE_READ, SideEffect.FILE_WRITE, SideEffect.ARBITRARY_CODE), 120, RetryPolicy.NEVER, "desktop listing and changed-file hashes", "The task mode can execute model-generated desktop code."),
    "code_helper": _spec("actions.code_helper.code_helper", RiskLevel.R3, (SideEffect.FILE_READ, SideEffect.FILE_WRITE, SideEffect.ARBITRARY_CODE), 360, RetryPolicy.NEVER, "workspace diff, file hashes, and test report", "Can write and execute code; coding-mode controls are not active yet.", ("source_code", "filesystem_path")),
    "dev_agent": _spec("actions.dev_agent.dev_agent", RiskLevel.R3, (SideEffect.FILE_WRITE, SideEffect.ARBITRARY_CODE, SideEffect.PROCESS_LAUNCH), 900, RetryPolicy.NEVER, "workspace diff, dependency record, and test report", "Builds projects, installs dependencies, and executes code.", ("source_code", "filesystem_path")),
    "computer_control": _spec("actions.computer_control.computer_control", RiskLevel.R3, (SideEffect.UI_CONTROL, SideEffect.PERSONAL_DATA_ACCESS, SideEffect.FILE_WRITE), 60, RetryPolicy.NEVER, "fresh screenshot and environment state", "Can click, type, paste, and interact with arbitrary visible applications.", ("screenshot", "clipboard", "typed_content")),
    "game_updater": _spec("actions.game_updater.game_updater", RiskLevel.R3, (SideEffect.PROCESS_LAUNCH, SideEffect.SCHEDULE_CHANGE, SideEffect.SYSTEM_STATE_CHANGE, SideEffect.FILE_WRITE), 1800, RetryPolicy.NEVER, "launcher state, schedule state, and download status", "Can install software, change schedules, and shut down the computer."),
    "flight_finder": _spec("actions.flight_finder.flight_finder", RiskLevel.R2, (SideEffect.NETWORK_READ, SideEffect.FILE_WRITE), 180, RetryPolicy.NEVER, "source URL, retrieval timestamp, and optional report hash", "Searches travel data and may save a report.", ("travel_plan", "approximate_location")),
    "manage_monitor": _spec("actions.background_monitor monitor functions", RiskLevel.R2, (SideEffect.MEMORY_WRITE, SideEffect.NETWORK_READ), 60, RetryPolicy.NEVER, "monitor-store read-back", "Adds or removes durable background monitoring topics.", ("monitor_topic",)),
    "shutdown_jarvis": _spec("main.JarvisLive._execute_tool", RiskLevel.R1, (SideEffect.PROCESS_LAUNCH,), 10, RetryPolicy.NEVER, "assistant process exit", "Stops MARK L only; it does not shut down the operating system."),
    "file_processor": _spec("actions.file_processor.file_processor", RiskLevel.R2, (SideEffect.FILE_READ, SideEffect.FILE_WRITE), 600, RetryPolicy.NEVER, "input/output hashes and format-specific evidence", "May read sensitive files and create converted or extracted artifacts.", ("file_content", "source_code", "filesystem_path")),
    "save_memory": _spec("memory.memory_manager.update_memory", RiskLevel.R2, (SideEffect.MEMORY_WRITE,), 15, RetryPolicy.NEVER, "memory-store read-back and value hash", "Persists personal information to long-term memory.", ("personal_data",)),
}


def _build_registry() -> Mapping[str, ToolMetadata]:
    for name in ("coding_prepare", "coding_apply", "coding_restore"):
        _SPECS[name] = _spec("orchestrator.coding.CodingWorker", RiskLevel.R2,
            (SideEffect.FILE_READ, SideEffect.FILE_WRITE), 600, RetryPolicy.NEVER,
            "approved diff and file hash readback",
            "Internal desktop-only coding session; no project commands are executed.")
    _SPECS["coding_prepare"]["side_effects"] = frozenset({
        SideEffect.FILE_READ, SideEffect.PERSONAL_DATA_ACCESS, SideEffect.NETWORK_READ})
    _SPECS["coding_command"] = _spec("orchestrator.local_execution.LocalCommandRunner", RiskLevel.R3,
        (SideEffect.ARBITRARY_CODE, SideEffect.FILE_WRITE, SideEffect.PROCESS_LAUNCH),
        660, RetryPolicy.NEVER, "local process exit and bounded output receipt",
        "Runs an exact approved command locally. Workspace is not a sandbox.")
    _SPECS["coding_inspect"] = _spec("orchestrator.coding.CodingWorker.inspect", RiskLevel.R2,
        (SideEffect.FILE_READ, SideEffect.PERSONAL_DATA_ACCESS, SideEffect.NETWORK_READ),
        120, RetryPolicy.NEVER, "structured explanation or command proposal",
        "Approved source and optional selected screenshot sent to the configured model.")
    _SPECS["browser_action"] = _spec("orchestrator.computer_use.ComputerUseSession", RiskLevel.R2,
        (SideEffect.UI_CONTROL, SideEffect.NETWORK_READ), 30, RetryPolicy.NEVER,
        "fresh masked screenshot hashes and URL state",
        "One approved action in an isolated browser; sensitive actions require takeover.")
    declarations: dict[str, dict[str, Any]] = {}
    for declaration in (*TOOL_DECLARATIONS, *INTERNAL_TOOL_DECLARATIONS, *RETIRED_TOOL_DECLARATIONS):
        name = declaration.get("name")
        if not isinstance(name, str) or not name:
            raise RuntimeError("tool declaration is missing a valid name")
        if name in declarations:
            raise RuntimeError(f"duplicate tool declaration: {name}")
        declarations[name] = declaration

    missing_metadata = set(declarations) - set(_SPECS)
    stale_metadata = set(_SPECS) - set(declarations)
    if missing_metadata or stale_metadata:
        raise RuntimeError(
            "tool registry mismatch: "
            f"missing={sorted(missing_metadata)}, stale={sorted(stale_metadata)}"
        )

    registry = {
        name: ToolMetadata(name=name, declaration=declaration, **_SPECS[name])
        for name, declaration in declarations.items()
    }
    return MappingProxyType(registry)


TOOL_REGISTRY: Mapping[str, ToolMetadata] = _build_registry()
