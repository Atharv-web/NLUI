"""Deterministic risk and scope policy; model suggestions are never authoritative."""

from __future__ import annotations

import re
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from ..config import SafetyConfig
from ..contracts import PolicyDisposition, RiskLevel, TaskMode
from ..persistence.hashing import canonical_json, sha256_text
from ..tool_registry import SideEffect, TOOL_REGISTRY, ToolMetadata
from .contracts import ExecutionRequest, PolicyEvaluation


_RISK_ORDER = {
    RiskLevel.R0: 0,
    RiskLevel.R1: 1,
    RiskLevel.R2: 2,
    RiskLevel.R3: 3,
    RiskLevel.R4: 4,
}
_HIGH_SENSITIVITY = {
    "authentication_state",
    "clipboard",
    "credential",
    "message_content",
    "personal_data",
    "personal_identifier",
    "screenshot",
    "source_code",
}
_MUTATION_EFFECTS = {
    SideEffect.ARBITRARY_CODE,
    SideEffect.EXTERNAL_COMMUNICATION,
    SideEffect.FILE_WRITE,
    SideEffect.MEMORY_WRITE,
    SideEffect.SCHEDULE_CHANGE,
    SideEffect.SYSTEM_STATE_CHANGE,
    SideEffect.UI_CONTROL,
}
_PROHIBITED_TEXT = re.compile(
    r"\b(?:bypass\s+captcha|evade\s+security|disable\s+security|"
    r"steal\s+(?:cookie|credential|password)|exfiltrat(?:e|ion))\b",
    re.IGNORECASE,
)
_ACTION_ALLOWLISTS = {
    "browser_control": {
        "go_to", "search", "click", "type", "scroll", "fill_form",
        "smart_click", "smart_type", "get_text", "get_url", "press",
        "new_tab", "close_tab", "screenshot", "back", "forward", "reload",
        "switch", "list_browsers", "close", "close_all",
    },
    "file_controller": {
        "list", "create_file", "create_folder", "delete", "move", "copy",
        "rename", "read", "write", "find", "largest", "disk_usage",
        "organize_desktop", "info",
    },
    "desktop_control": {
        "wallpaper", "wallpaper_url", "organize", "clean", "list", "stats",
        "task",
    },
    "code_helper": {"write", "edit", "explain", "run", "build", "auto"},
    "game_updater": {
        "update", "install", "list", "download_status", "schedule",
        "cancel_schedule", "schedule_status",
    },
    "manage_monitor": {"add", "remove", "list"},
    "youtube_video": {"play", "summarize", "get_info", "trending"},
    "computer_control": {
        "type", "smart_type", "click", "double_click", "right_click",
        "hotkey", "press", "scroll", "move", "copy", "paste", "screenshot",
        "wait", "clear_field", "focus_window", "screen_find", "screen_click",
        "random_data", "user_data",
    },
    "file_processor": {
        "describe", "ocr", "resize", "compress", "convert", "info",
        "summarize", "extract_text", "to_word", "fix", "reformat",
        "translate_hint", "word_count", "to_bullet", "analyze", "stats",
        "filter", "sort", "validate", "format", "to_csv", "explain",
        "review", "optimize", "run", "document", "test", "transcribe",
        "trim", "extract_audio", "extract_frame", "list", "extract",
    },
}


def normalized_arguments_hash(arguments: dict[str, object]) -> str:
    return sha256_text(canonical_json(arguments))


def exact_target_hash(target: str | None) -> str:
    return sha256_text(target if target is not None else "null")


def derive_exact_target(tool_name: str, arguments: dict[str, object]) -> str | None:
    keys_by_tool = {
        "coding_prepare": ("workspace",),
        "coding_command": ("workspace",),
        "coding_inspect": ("workspace",),
        "coding_apply": ("workspace",),
        "coding_restore": ("workspace",),
        "browser_action": ("url",),
        "send_message": ("receiver",),
        "open_app": ("app_name",),
        "weather_report": ("city",),
        "manage_monitor": ("topic",),
        "computer_settings": ("action",),
        "computer_control": ("title", "description", "action"),
        "browser_control": ("url", "description", "selector", "action"),
        "file_controller": ("path", "destination", "name"),
        "file_processor": ("file_path", "destination"),
        "code_helper": ("output_path", "file_path"),
        "dev_agent": ("project_name",),
        "desktop_control": ("path", "url", "action"),
        "game_updater": ("game_name", "platform", "action"),
        "flight_finder": ("destination", "origin"),
        "youtube_video": ("url", "query", "action"),
        "screen_process": ("angle",),
        "reminder": ("date", "time"),
        "save_memory": ("category", "key"),
    }
    for key in keys_by_tool.get(tool_name, ()):
        value = arguments.get(key)
        if isinstance(value, (str, int, float)) and str(value).strip():
            return f"{key}:{value}"
    return None


class PolicyEngine:
    def __init__(self, config: SafetyConfig) -> None:
        self.config = config

    def evaluate(self, request: ExecutionRequest) -> PolicyEvaluation:
        metadata = TOOL_REGISTRY[request.tool_name]
        reasons = [f"registry_floor:{metadata.default_risk.value}"]
        malformed = _validate_arguments(metadata, request.arguments)
        risk = metadata.default_risk
        deny = bool(malformed)
        reasons.extend(malformed)

        if metadata.side_effects & {
            SideEffect.FILE_WRITE,
            SideEffect.MEMORY_WRITE,
            SideEffect.PERSONAL_DATA_ACCESS,
            SideEffect.SCHEDULE_CHANGE,
        }:
            risk = _raise_risk(risk, RiskLevel.R2)
        if metadata.side_effects & {
            SideEffect.ARBITRARY_CODE,
            SideEffect.EXTERNAL_COMMUNICATION,
            SideEffect.SYSTEM_STATE_CHANGE,
        }:
            risk = _raise_risk(risk, RiskLevel.R3)

        sensitivity = set(metadata.sensitivity_classes) | set(
            request.data_sensitivity
        )
        if sensitivity & _HIGH_SENSITIVITY:
            risk = _raise_risk(risk, RiskLevel.R3)
            reasons.append("high_sensitivity_data")

        if _contains_prohibited_text(request.arguments):
            risk = RiskLevel.R4
            deny = True
            reasons.append("prohibited_security_evasion")

        scope_error = _workspace_scope_error(request, metadata)
        if scope_error is not None:
            risk = RiskLevel.R4
            deny = True
            reasons.append(scope_error)

        domain_error = _domain_scope_error(request)
        if domain_error is not None:
            risk = RiskLevel.R4
            deny = True
            reasons.append(domain_error)

        if risk is RiskLevel.R4:
            deny = True
        disposition = (
            PolicyDisposition.DENY
            if deny
            else PolicyDisposition.ALLOW
            if risk in {RiskLevel.R0, RiskLevel.R1}
            else PolicyDisposition.REQUIRE_APPROVAL
        )
        if disposition is PolicyDisposition.ALLOW:
            reasons.append("automatic_low_risk")
        elif disposition is PolicyDisposition.REQUIRE_APPROVAL:
            reasons.append("trusted_approval_required")
        else:
            reasons.append("execution_denied")

        arguments_hash = normalized_arguments_hash(request.arguments)
        target_hash = exact_target_hash(request.exact_target)
        constraints = _constraints(request, metadata, arguments_hash, target_hash)
        scope_hash = sha256_text(
            canonical_json(
                {
                    "task_id": request.task_id,
                    "step_id": request.step_id,
                    "plan_id": request.plan_id,
                    "plan_version": request.plan_version,
                    "tool_name": request.tool_name,
                    "arguments_hash": arguments_hash,
                    "target_hash": target_hash,
                    "risk": risk.value,
                    "constraints": list(constraints),
                }
            )
        )
        return PolicyEvaluation(
            decision_id=uuid.uuid4().hex,
            policy_version=self.config.policy_version,
            risk=risk,
            disposition=disposition,
            reasons=tuple(dict.fromkeys(reasons)),
            normalized_arguments_hash=arguments_hash,
            exact_target_hash=target_hash,
            scope_hash=scope_hash,
            capability_constraints=constraints,
        )


def _raise_risk(current: RiskLevel, minimum: RiskLevel) -> RiskLevel:
    return minimum if _RISK_ORDER[minimum] > _RISK_ORDER[current] else current


def _validate_arguments(metadata: ToolMetadata, arguments: dict[str, object]) -> list[str]:
    parameters = metadata.declaration.get("parameters", {})
    properties = parameters.get("properties", {})
    required = parameters.get("required", [])
    errors: list[str] = []
    if metadata.name == "open_app":
        app_name = arguments.get("app_name")
        if not isinstance(app_name, str) or not re.fullmatch(r"[\w .-]{1,128}", app_name):
            errors.append("application_name_must_not_be_a_command")
    unknown = set(arguments) - set(properties)
    if unknown:
        errors.append("unknown_arguments")
    if any(name not in arguments for name in required):
        errors.append("missing_required_arguments")
    type_map = {
        "STRING": str,
        "BOOLEAN": bool,
        "INTEGER": int,
        "NUMBER": (int, float),
        "ARRAY": list,
        "OBJECT": dict,
    }
    for name, value in arguments.items():
        spec = properties.get(name)
        if not isinstance(spec, dict):
            continue
        expected = type_map.get(spec.get("type"))
        if expected is not None and (
            not isinstance(value, expected)
            or isinstance(value, bool) and spec.get("type") in {"INTEGER", "NUMBER"}
        ):
            errors.append("invalid_argument_type")
            break
        if spec.get("type") == "ARRAY" and isinstance(value, list):
            item_type = type_map.get(spec.get("items", {}).get("type"))
            if item_type is not None and any(
                not isinstance(item, item_type) for item in value
            ):
                errors.append("invalid_array_item_type")
                break
    action = arguments.get("action")
    allowed_actions = _ACTION_ALLOWLISTS.get(metadata.name)
    if (
        allowed_actions is not None
        and isinstance(action, str)
        and action.lower().strip() not in allowed_actions
    ):
        errors.append("unsupported_tool_action")
    return errors


def _contains_prohibited_text(arguments: dict[str, object]) -> bool:
    def values(value: object):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for child in value.values():
                yield from values(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                yield from values(child)

    return any(_PROHIBITED_TEXT.search(text) for text in values(arguments))


def _workspace_scope_error(
    request: ExecutionRequest, metadata: ToolMetadata
) -> str | None:
    if request.task_mode is not TaskMode.CODING:
        return None
    if not metadata.side_effects & _MUTATION_EFFECTS:
        return None
    if request.workspace is None or request.exact_target is None:
        return "confirmed_workspace_required"
    target_text = request.exact_target.split(":", 1)[-1]
    if urlsplit(target_text).scheme in {"http", "https"}:
        return "workspace_target_must_be_local"
    try:
        workspace = Path(request.workspace).resolve(strict=False)
        target = Path(target_text).resolve(strict=False)
        target.relative_to(workspace)
    except (OSError, ValueError):
        return "target_outside_confirmed_workspace"
    return None


def _domain_scope_error(request: ExecutionRequest) -> str | None:
    if not request.allowed_domains or request.exact_target is None:
        return None
    target_text = request.exact_target.split(":", 1)[-1]
    parsed = urlsplit(target_text)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return None
    host = parsed.hostname.lower().rstrip(".")
    allowed = tuple(domain.lower().rstrip(".") for domain in request.allowed_domains)
    if any(host == domain or host.endswith("." + domain) for domain in allowed):
        return None
    return "domain_outside_task_scope"


def _constraints(
    request: ExecutionRequest,
    metadata: ToolMetadata,
    arguments_hash: str,
    target_hash: str,
) -> tuple[str, ...]:
    values = [
        f"tool:{request.tool_name}",
        f"arguments_sha256:{arguments_hash}",
        f"target_sha256:{target_hash}",
        f"plan_version:{request.plan_version}",
        f"timeout_max:{metadata.default_timeout_seconds}",
    ]
    if request.workspace is not None:
        values.append(f"workspace_sha256:{sha256_text(request.workspace)}")
    for domain in sorted(set(request.allowed_domains)):
        values.append(f"domain:{domain.lower()}")
    return tuple(values)
