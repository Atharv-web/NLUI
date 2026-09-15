"""Deterministic local and optional remote model capability checks."""

from __future__ import annotations

from enum import Enum
from typing import Protocol, TYPE_CHECKING

from pydantic import Field

from .contracts import StrictContract

if TYPE_CHECKING:
    from .config import OrchestratorConfig


class ModelRole(str, Enum):
    VOICE = "voice"
    ROUTINE = "routine"
    PLANNER = "planner"
    REVIEWER = "reviewer"
    COMPUTER_USE = "computer_use"


class ModelCapability(str, Enum):
    LIVE_API = "live_api"
    AUDIO_OUTPUT = "audio_output"
    GENERATE_CONTENT = "generate_content"
    FUNCTION_CALLING = "function_calling"
    STRUCTURED_OUTPUT = "structured_output"
    COMPUTER_USE = "computer_use"


class CapabilityStatus(str, Enum):
    PASS = "pass"
    WARNING = "warning"
    FAIL = "fail"


class RemoteModelMetadata(StrictContract):
    name: str = Field(min_length=1, max_length=256)
    supported_actions: frozenset[str] = frozenset()


class ModelMetadataProvider(Protocol):
    def get(self, model_name: str) -> RemoteModelMetadata: ...


class GoogleModelMetadataProvider:
    """Adapter around ``google-genai`` without owning or logging credentials."""

    def __init__(self, client: object) -> None:
        self._client = client

    def get(self, model_name: str) -> RemoteModelMetadata:
        model = self._client.models.get(model=model_name)  # type: ignore[attr-defined]
        return RemoteModelMetadata(
            name=(getattr(model, "name", None) or model_name).removeprefix("models/"),
            supported_actions=frozenset(getattr(model, "supported_actions", None) or ()),
        )


class ModelRoleCheck(StrictContract):
    role: ModelRole
    model_name: str
    status: CapabilityStatus
    required: frozenset[ModelCapability]
    known: frozenset[ModelCapability]
    missing: frozenset[ModelCapability]
    remote_checked: bool
    detail: str


class ModelCapabilityReport(StrictContract):
    checks: tuple[ModelRoleCheck, ...]

    @property
    def passed(self) -> bool:
        return all(check.status is not CapabilityStatus.FAIL for check in self.checks)


# Capability assertions for the approved defaults and documented migration
# target. Unknown overrides fail local validation until explicitly catalogued.
KNOWN_MODEL_CAPABILITIES: dict[str, frozenset[ModelCapability]] = {
    "gemini-2.5-flash-native-audio-preview-12-2025": frozenset(
        {ModelCapability.LIVE_API, ModelCapability.AUDIO_OUTPUT, ModelCapability.FUNCTION_CALLING}
    ),
    "gemini-3.1-flash-live-preview": frozenset(
        {ModelCapability.LIVE_API, ModelCapability.AUDIO_OUTPUT, ModelCapability.FUNCTION_CALLING}
    ),
    "gemini-2.5-flash": frozenset(
        {ModelCapability.GENERATE_CONTENT, ModelCapability.FUNCTION_CALLING, ModelCapability.STRUCTURED_OUTPUT}
    ),
    "gemini-2.5-flash-lite": frozenset(
        {ModelCapability.GENERATE_CONTENT, ModelCapability.FUNCTION_CALLING, ModelCapability.STRUCTURED_OUTPUT}
    ),
    "gemini-2.5-computer-use-preview-10-2025": frozenset({ModelCapability.COMPUTER_USE}),
}


_REMOTE_ACTION_CAPABILITIES = {
    "generatecontent": ModelCapability.GENERATE_CONTENT,
    "bidigeneratecontent": ModelCapability.LIVE_API,
}


def check_model_capabilities(
    config: "OrchestratorConfig",
    provider: ModelMetadataProvider | None = None,
) -> ModelCapabilityReport:
    """Validate role requirements locally, then check remote availability once."""
    checks: list[ModelRoleCheck] = []
    remote_cache: dict[str, RemoteModelMetadata | Exception] = {}

    for role, role_config in config.models.by_role().items():
        known = KNOWN_MODEL_CAPABILITIES.get(role_config.name, frozenset())
        missing = role_config.required_capabilities - known
        status = CapabilityStatus.PASS
        detail = "configured capabilities match the local compatibility catalog"
        remote_checked = False

        if missing:
            status = CapabilityStatus.FAIL
            detail = "model is unknown or lacks required locally documented capabilities"
        elif provider is not None and config.capability_checks.remote_metadata_check:
            remote_checked = True
            if role_config.name not in remote_cache:
                try:
                    remote_cache[role_config.name] = provider.get(role_config.name)
                except Exception as exc:  # never include provider text; it may contain secrets
                    remote_cache[role_config.name] = exc
            remote = remote_cache[role_config.name]
            if isinstance(remote, Exception):
                status = (
                    CapabilityStatus.FAIL
                    if config.capability_checks.fail_startup_on_remote_unavailable
                    else CapabilityStatus.WARNING
                )
                detail = f"remote metadata lookup failed ({type(remote).__name__})"
            else:
                remote_caps = {
                    capability
                    for action in remote.supported_actions
                    if (capability := _REMOTE_ACTION_CAPABILITIES.get(action.replace("_", "").lower()))
                }
                remotely_testable = role_config.required_capabilities & set(_REMOTE_ACTION_CAPABILITIES.values())
                remote_missing = remotely_testable - remote_caps
                if remote_missing:
                    status = CapabilityStatus.FAIL
                    missing = frozenset(set(missing) | remote_missing)
                    detail = "remote model metadata lacks a required supported action"
                else:
                    detail = "local capability catalog passed and remote model metadata is available"

        checks.append(
            ModelRoleCheck(
                role=role,
                model_name=role_config.name,
                status=status,
                required=role_config.required_capabilities,
                known=known,
                missing=frozenset(missing),
                remote_checked=remote_checked,
                detail=detail,
            )
        )

    return ModelCapabilityReport(checks=tuple(checks))
