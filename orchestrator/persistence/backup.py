"""Verified backup bundles for SQLite state and encrypted artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from pydantic import Field

from ..contracts import StrictContract
from .database import DatabaseSettings, SQLiteDatabase
from .errors import AuditIntegrityError, PersistenceError
from .hashing import canonical_json
from .secrets import EncryptedPayloadStore
from .store import DurableStore


class BackupManifest(StrictContract):
    format_version: str = "1.0"
    created_at: datetime
    schema_version: int = Field(ge=1)
    database_file: str
    database_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifacts: dict[str, str]


class BackupBundle(StrictContract):
    path: str
    created_at: datetime
    schema_version: int
    database_sha256: str
    artifact_count: int = Field(ge=0)


class BackupManager:
    """Requires the application to quiesce mutations while restoring."""

    _lock = threading.RLock()

    def __init__(self, store: DurableStore) -> None:
        self.store = store
        self.database = store.database
        self.payload_store = store.payload_store

    def create(self) -> BackupBundle:
        with self._lock:
            self.store.verify_database_integrity()
            self.store.verify_audit_chain()
            self.database.checkpoint("FULL")
            root = self.database.settings.backup_directory
            root.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now(timezone.utc)
            name = f"backup-{timestamp.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
            temporary = root / f".{name}.tmp"
            target = root / name
            if temporary.exists() or target.exists():
                raise PersistenceError("backup target already exists")
            temporary.mkdir()
            try:
                database_target = temporary / "orchestrator.sqlite3"
                _sqlite_backup(self.database.settings.path, database_target)
                artifacts_dir = temporary / "artifacts"
                artifacts_dir.mkdir()
                artifact_hashes: dict[str, str] = {}
                for reference in _encrypted_artifact_references(database_target):
                    source = _safe_child(self.payload_store.directory, reference)
                    destination = artifacts_dir / source.name
                    shutil.copy2(source, destination)
                    artifact_hashes[source.name] = _file_hash(destination)
                manifest = BackupManifest(
                    created_at=timestamp,
                    schema_version=self.store.migrations.current_version(),
                    database_file=database_target.name,
                    database_sha256=_file_hash(database_target),
                    artifacts=artifact_hashes,
                )
                (temporary / "manifest.json").write_text(
                    canonical_json(manifest.model_dump(mode="json")), encoding="utf-8"
                )
                os.replace(temporary, target)
            except Exception:
                shutil.rmtree(temporary, ignore_errors=True)
                raise
            self.validate(target)
            return BackupBundle(
                path=str(target),
                created_at=timestamp,
                schema_version=manifest.schema_version,
                database_sha256=manifest.database_sha256,
                artifact_count=len(artifact_hashes),
            )

    def validate(self, bundle_path: Path) -> BackupManifest:
        bundle = bundle_path.resolve()
        if not bundle.is_dir():
            raise PersistenceError("backup bundle does not exist")
        manifest_path = bundle / "manifest.json"
        try:
            manifest = BackupManifest.model_validate_json(
                manifest_path.read_text(encoding="utf-8")
            )
        except Exception as exc:
            raise AuditIntegrityError("backup manifest is missing or invalid") from exc
        database_file = _safe_child(bundle, manifest.database_file)
        if _file_hash(database_file) != manifest.database_sha256:
            raise AuditIntegrityError("backup database hash mismatch")
        for name, expected_hash in manifest.artifacts.items():
            artifact = _safe_child(bundle / "artifacts", name)
            if _file_hash(artifact) != expected_hash:
                raise AuditIntegrityError("backup artifact hash mismatch")
        actual_artifacts = {
            path.name for path in (bundle / "artifacts").glob("*.enc") if path.is_file()
        }
        if actual_artifacts != set(manifest.artifacts):
            raise AuditIntegrityError("backup artifact manifest does not match bundle contents")
        _verify_sqlite_file(database_file)
        temporary_database = SQLiteDatabase(
            DatabaseSettings(
                path=database_file,
                backup_directory=bundle,
                busy_timeout_ms=self.database.settings.busy_timeout_ms,
                busy_retry_attempts=0,
            )
        )
        bundle_payloads = EncryptedPayloadStore(
            bundle / "artifacts",
            self.payload_store.secret_store,
            key_reference=self.payload_store.key_reference,
        )
        verifier = DurableStore(
            temporary_database,
            bundle_payloads,
            audit_hasher=self.store.audit_hasher,
        )
        verifier.verify_database_integrity()
        verifier.verify_audit_chain()
        verifier.verify_artifact_integrity()
        return manifest

    def restore(self, bundle_path: Path) -> BackupBundle:
        """Restore a validated bundle, retaining a verified safety backup."""
        with self._lock:
            manifest = self.validate(bundle_path)
            safety = self.create()
            try:
                self._apply(bundle_path.resolve(), manifest)
                self.store.verify_database_integrity()
                self.store.verify_audit_chain()
                self.store.verify_artifact_integrity()
            except Exception:
                safety_path = Path(safety.path)
                safety_manifest = self.validate(safety_path)
                self._apply(safety_path, safety_manifest)
                raise
            return safety

    def _apply(self, bundle: Path, manifest: BackupManifest) -> None:
        database_source = _safe_child(bundle, manifest.database_file)
        self.database.checkpoint("TRUNCATE")
        _sqlite_backup(database_source, self.database.settings.path)

        current = self.payload_store.directory
        parent = current.parent
        parent.mkdir(parents=True, exist_ok=True)
        staged = parent / f".{current.name}.restore-{uuid.uuid4().hex}"
        previous = parent / f".{current.name}.previous-{uuid.uuid4().hex}"
        staged.mkdir()
        try:
            for name in manifest.artifacts:
                shutil.copy2(_safe_child(bundle / "artifacts", name), staged / name)
            if current.exists():
                os.replace(current, previous)
            os.replace(staged, current)
            shutil.rmtree(previous, ignore_errors=True)
        except Exception:
            shutil.rmtree(staged, ignore_errors=True)
            if previous.exists() and not current.exists():
                os.replace(previous, current)
            raise

def _sqlite_backup(source_path: Path, destination_path: Path) -> None:
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    source_uri = f"{source_path.resolve().as_uri()}?mode=ro"
    source = sqlite3.connect(source_uri, uri=True, timeout=5)
    destination = sqlite3.connect(destination_path, timeout=5)
    try:
        source.backup(destination)
    finally:
        destination.close()
        source.close()


def _verify_sqlite_file(path: Path) -> None:
    uri = f"{path.resolve().as_uri()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=5)
    try:
        results = [row[0] for row in connection.execute("PRAGMA integrity_check")]
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
    finally:
        connection.close()
    if results != ["ok"] or foreign_keys:
        raise AuditIntegrityError("backup SQLite integrity check failed")


def _encrypted_artifact_references(path: Path) -> tuple[str, ...]:
    uri = f"{path.resolve().as_uri()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=5)
    try:
        rows = connection.execute(
            "SELECT storage_reference FROM artifacts WHERE encrypted = 1 "
            "ORDER BY storage_reference"
        ).fetchall()
    finally:
        connection.close()
    references = tuple(str(row[0]) for row in rows)
    if len(references) != len(set(references)):
        raise AuditIntegrityError("encrypted artifact references are not unique")
    if any(Path(reference).name != reference for reference in references):
        raise AuditIntegrityError("encrypted artifact reference is unsafe")
    return references


def _safe_child(parent: Path, name: str) -> Path:
    if not name or Path(name).name != name:
        raise AuditIntegrityError("backup contains an unsafe path")
    child = (parent / name).resolve()
    if child.parent != parent.resolve() or not child.is_file():
        raise AuditIntegrityError("backup file is missing or escapes its bundle")
    return child


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
