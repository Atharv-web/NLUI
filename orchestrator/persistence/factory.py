"""Production construction from validated configuration."""

from __future__ import annotations

from pathlib import Path

from ..config import OrchestratorConfig
from .database import DatabaseSettings, SQLiteDatabase
from .hashing import AuditHasher
from .secrets import (
    EncryptedPayloadStore,
    KeyringSecretStore,
    SecretStore,
    get_or_create_key,
)
from .store import DurableStore


def create_durable_store(
    base_dir: Path,
    config: OrchestratorConfig,
    *,
    secret_store: SecretStore | None = None,
    initialize: bool = True,
) -> DurableStore:
    """Build the durability layer without reading or logging application API keys."""
    secrets = secret_store or KeyringSecretStore()
    settings = DatabaseSettings.from_config(base_dir, config.persistence)
    artifact_directory = Path(config.persistence.artifact_directory)
    if not artifact_directory.is_absolute():
        artifact_directory = base_dir / artifact_directory
    payloads = EncryptedPayloadStore(artifact_directory, secrets)
    if config.persistence.audit_hash_algorithm == "hmac-sha256":
        hasher = AuditHasher(
            "hmac-sha256", get_or_create_key(secrets, "audit-hmac-v1")
        )
    else:
        hasher = AuditHasher("sha256")
    store = DurableStore(SQLiteDatabase(settings), payloads, audit_hasher=hasher)
    if initialize:
        store.initialize(
            verify_integrity=config.persistence.integrity_check_on_startup
        )
    return store
