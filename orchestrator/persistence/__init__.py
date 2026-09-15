"""Crash-safe SQLite durability primitives through Milestone 4."""

from .backup import BackupBundle, BackupManager, BackupManifest
from .database import DatabaseSettings, SQLiteDatabase
from .errors import (
    AuditIntegrityError,
    DatabaseBusyError,
    MigrationError,
    PersistenceError,
    RecordConflictError,
    RecordNotFoundError,
)
from .hashing import AuditHasher
from .factory import create_durable_store
from .repositories import (
    AuditRepository,
    FencingRepository,
    InvocationRepository,
    OutboxRepository,
    PlanRepository,
    SafetyRepository,
    TaskRepository,
)
from .records import (
    ApprovalRecord,
    ArtifactRecord,
    CapabilityGrantRecord,
    CapabilityGrantStatus,
    CheckpointRecord,
    InvocationStatus,
    OutboxRecord,
    PolicyDecisionRecord,
    SideEffectMarker,
    StepSecurityRecord,
    TaskRecord,
    ToolInvocationRecord,
    VerificationRecord,
)
from .secrets import EncryptedPayloadStore, KeyringSecretStore, SecretStore
from .store import DurableStore

__all__ = [
    "AuditHasher",
    "AuditRepository",
    "AuditIntegrityError",
    "BackupBundle",
    "BackupManager",
    "BackupManifest",
    "ApprovalRecord",
    "ArtifactRecord",
    "CapabilityGrantRecord",
    "CapabilityGrantStatus",
    "DatabaseBusyError",
    "DatabaseSettings",
    "DurableStore",
    "EncryptedPayloadStore",
    "FencingRepository",
    "InvocationStatus",
    "InvocationRepository",
    "KeyringSecretStore",
    "MigrationError",
    "PersistenceError",
    "RecordConflictError",
    "RecordNotFoundError",
    "SecretStore",
    "SideEffectMarker",
    "SQLiteDatabase",
    "TaskRecord",
    "ToolInvocationRecord",
    "VerificationRecord",
    "CheckpointRecord",
    "OutboxRecord",
    "OutboxRepository",
    "PlanRepository",
    "PolicyDecisionRecord",
    "SafetyRepository",
    "StepSecurityRecord",
    "TaskRepository",
    "create_durable_store",
]
