"""Validated, secret-free configuration structure for orchestration."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal

from pydantic import ConfigDict, Field, field_validator

from .contracts import StrictContract
from .model_capabilities import ModelCapability, ModelRole


CONFIG_SCHEMA_VERSION = "1.0"


class ModelRoleConfig(StrictContract):
    name: str = Field(min_length=1, max_length=256)
    required_capabilities: frozenset[ModelCapability]
    fallbacks: tuple[str, ...] = ()

    @field_validator("required_capabilities", mode="before")
    @classmethod
    def capabilities_from_json(cls, value: object) -> object:
        if isinstance(value, (list, set, frozenset, tuple)):
            return frozenset(
                item if isinstance(item, ModelCapability) else ModelCapability(item)
                for item in value
            )
        return value

    @field_validator("fallbacks", mode="before")
    @classmethod
    def fallbacks_from_json(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class ModelRegistryConfig(StrictContract):
    voice: ModelRoleConfig = ModelRoleConfig(
        name="gemini-2.5-flash-native-audio-preview-12-2025",
        required_capabilities=frozenset(
            {ModelCapability.LIVE_API, ModelCapability.AUDIO_OUTPUT, ModelCapability.FUNCTION_CALLING}
        ),
        fallbacks=("gemini-3.1-flash-live-preview",),
    )
    routine: ModelRoleConfig = ModelRoleConfig(
        name="gemini-2.5-flash-lite",
        required_capabilities=frozenset({ModelCapability.GENERATE_CONTENT}),
    )
    planner: ModelRoleConfig = ModelRoleConfig(
        name="gemini-2.5-flash",
        required_capabilities=frozenset(
            {ModelCapability.GENERATE_CONTENT, ModelCapability.STRUCTURED_OUTPUT, ModelCapability.FUNCTION_CALLING}
        ),
    )
    reviewer: ModelRoleConfig = ModelRoleConfig(
        name="gemini-2.5-flash",
        required_capabilities=frozenset(
            {ModelCapability.GENERATE_CONTENT, ModelCapability.STRUCTURED_OUTPUT}
        ),
    )
    computer_use: ModelRoleConfig = ModelRoleConfig(
        name="gemini-2.5-computer-use-preview-10-2025",
        required_capabilities=frozenset({ModelCapability.COMPUTER_USE}),
    )

    def by_role(self) -> dict[ModelRole, ModelRoleConfig]:
        return {
            ModelRole.VOICE: self.voice,
            ModelRole.ROUTINE: self.routine,
            ModelRole.PLANNER: self.planner,
            ModelRole.REVIEWER: self.reviewer,
            ModelRole.COMPUTER_USE: self.computer_use,
        }


class CapabilityCheckConfig(StrictContract):
    enabled: bool = True
    remote_metadata_check: bool = True
    fail_startup_on_local_mismatch: bool = True
    fail_startup_on_remote_unavailable: bool = False


class EventConfig(StrictContract):
    schema_version: Literal["1.0"] = "1.0"
    compatibility_versions: tuple[str, ...] = ("1.0",)
    redaction_policy_version: str = "1.0"
    policy_version: str = "1.0"

    @field_validator("compatibility_versions", mode="before")
    @classmethod
    def versions_from_json(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class DiagnosticConfig(StrictContract):
    queue_capacity: int = Field(default=2000, ge=100, le=100_000)
    retention_days: int = Field(default=30, ge=1, le=365)
    max_file_bytes: int = Field(default=10_485_760, ge=1_048_576)


class PersistenceConfig(StrictContract):
    database_path: str = Field(
        default="data/orchestrator.sqlite3", min_length=1, max_length=4096
    )
    backup_directory: str = Field(
        default="data/backups", min_length=1, max_length=4096
    )
    artifact_directory: str = Field(
        default="data/artifacts", min_length=1, max_length=4096
    )
    busy_timeout_ms: int = Field(default=5000, ge=100, le=60_000)
    busy_retry_attempts: int = Field(default=2, ge=0, le=10)
    integrity_check_on_startup: bool = True
    audit_hash_algorithm: Literal["sha256", "hmac-sha256"] = "sha256"
    audit_retention_days: int = Field(default=3650, ge=365, le=36500)
    encrypted_artifact_retention_days: int = Field(default=90, ge=1, le=3650)
    backup_retention_days: int = Field(default=30, ge=1, le=3650)


class SafetyConfig(StrictContract):
    policy_version: str = Field(default="1.0", pattern=r"^[0-9]+\.[0-9]+$")
    approval_ttl_seconds: int = Field(default=300, ge=30, le=3600)
    high_risk_approval_ttl_seconds: int = Field(default=60, ge=15, le=300)
    capability_ttl_seconds: int = Field(default=30, ge=5, le=300)
    trusted_approval_channels: tuple[str, ...] = (
        "desktop_click",
        "typed_confirmation",
    )

    @field_validator("trusted_approval_channels", mode="before")
    @classmethod
    def channels_from_json(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("trusted_approval_channels")
    @classmethod
    def safe_channels_only(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        allowed = {"desktop_click", "typed_confirmation"}
        if not value or len(value) != len(set(value)) or not set(value) <= allowed:
            raise ValueError("trusted approval channels must be unique desktop channels")
        return value


class RolloutConfig(StrictContract):
    stage: Literal["read_only", "reversible", "coding", "supervised"] = "supervised"
    kill_switch: bool = False
    audit_interval_seconds: int = Field(default=30, ge=5, le=300)


class OrchestratorConfig(StrictContract):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["1.0"] = CONFIG_SCHEMA_VERSION
    models: ModelRegistryConfig = ModelRegistryConfig()
    capability_checks: CapabilityCheckConfig = CapabilityCheckConfig()
    events: EventConfig = EventConfig()
    diagnostics: DiagnosticConfig = DiagnosticConfig()
    persistence: PersistenceConfig = PersistenceConfig()
    safety: SafetyConfig = SafetyConfig()
    rollout: RolloutConfig = RolloutConfig()


_MODEL_ENV = {
    "JARVIS_VOICE_MODEL": "voice",
    "JARVIS_ROUTINE_MODEL": "routine",
    "JARVIS_PLANNER_MODEL": "planner",
    "JARVIS_REVIEWER_MODEL": "reviewer",
    "JARVIS_COMPUTER_USE_MODEL": "computer_use",
}


def load_orchestrator_config(base_dir: Path, environ: dict[str, str] | None = None) -> OrchestratorConfig:
    """Load optional non-secret config and apply explicit model-name overrides."""
    path = base_dir / "config" / "orchestrator.json"
    raw: dict[str, object] = {}
    if path.exists():
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise ValueError("orchestrator config root must be an object")
        # Legacy coordination settings are retired; never open a broker connection.
        raw = {key: value for key, value in loaded.items() if key != "coordination"}

    config = OrchestratorConfig.model_validate(raw)
    env = os.environ if environ is None else environ
    models = config.models
    updates: dict[str, ModelRoleConfig] = {}
    for env_name, field_name in _MODEL_ENV.items():
        value = env.get(env_name, "").strip()
        if value:
            current = getattr(models, field_name)
            updates[field_name] = current.model_copy(update={"name": value})
    if updates:
        config = config.model_copy(update={"models": models.model_copy(update=updates)})
    return config
