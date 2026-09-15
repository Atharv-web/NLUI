"""OS credential-store adapter and encrypted artifact payload storage."""

from __future__ import annotations

import base64
import hashlib
import os
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import AuditIntegrityError, PersistenceError


_KEY_CREATION_LOCK = threading.Lock()


class SecretStore(Protocol):
    def get(self, name: str) -> str | None: ...
    def set(self, name: str, value: str) -> None: ...


class KeyringSecretStore:
    """Stores keys in the platform credential backend through `keyring`."""

    def __init__(self, service_name: str = "mark-l-orchestrator") -> None:
        self.service_name = service_name

    def get(self, name: str) -> str | None:
        import keyring

        return keyring.get_password(self.service_name, name)

    def set(self, name: str, value: str) -> None:
        import keyring

        keyring.set_password(self.service_name, name, value)


def get_or_create_key(store: SecretStore, name: str) -> bytes:
    with _KEY_CREATION_LOCK:
        encoded = store.get(name)
        if encoded is None:
            key = AESGCM.generate_key(bit_length=256)
            store.set(name, base64.urlsafe_b64encode(key).decode("ascii"))
            return key
    try:
        key = base64.urlsafe_b64decode(encoded.encode("ascii"))
    except Exception as exc:
        raise PersistenceError("credential store returned an invalid encryption key") from exc
    if len(key) != 32:
        raise PersistenceError("credential store returned an invalid encryption key length")
    return key


@dataclass(frozen=True, slots=True)
class StoredPayload:
    artifact_id: str
    storage_reference: str
    sha256: str
    size_bytes: int
    encryption_key_reference: str


class EncryptedPayloadStore:
    _FORMAT = b"MARKLENC1"

    def __init__(
        self,
        directory: Path,
        secret_store: SecretStore,
        *,
        key_reference: str = "artifact-encryption-v1",
    ) -> None:
        self.directory = directory.resolve()
        self.secret_store = secret_store
        self.key_reference = key_reference

    def ensure_key(self) -> None:
        """Create or validate the process-shared encryption key at startup."""
        get_or_create_key(self.secret_store, self.key_reference)

    def put(self, payload: bytes, *, artifact_id: str | None = None) -> StoredPayload:
        artifact_id = artifact_id or uuid.uuid4().hex
        if not artifact_id or any(char not in "0123456789abcdef-" for char in artifact_id.lower()):
            raise ValueError("artifact_id must contain only hexadecimal characters or hyphens")
        key = get_or_create_key(self.secret_store, self.key_reference)
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, payload, artifact_id.encode("ascii"))
        encoded = self._FORMAT + nonce + ciphertext
        self.directory.mkdir(parents=True, exist_ok=True)
        target = self.directory / f"{artifact_id}.enc"
        temporary = self.directory / f".{artifact_id}.{uuid.uuid4().hex}.tmp"
        try:
            with temporary.open("xb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            try:
                os.link(temporary, target)
            except FileExistsError as exc:
                raise PersistenceError("encrypted artifact already exists") from exc
        finally:
            temporary.unlink(missing_ok=True)
        return StoredPayload(
            artifact_id=artifact_id,
            storage_reference=target.name,
            sha256=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
            encryption_key_reference=self.key_reference,
        )

    def get(self, stored: StoredPayload) -> bytes:
        target = self._resolve_reference(stored.storage_reference)
        encoded = target.read_bytes()
        if not encoded.startswith(self._FORMAT) or len(encoded) < len(self._FORMAT) + 13:
            raise AuditIntegrityError("encrypted artifact format is invalid")
        offset = len(self._FORMAT)
        nonce = encoded[offset : offset + 12]
        ciphertext = encoded[offset + 12 :]
        key = get_or_create_key(self.secret_store, stored.encryption_key_reference)
        try:
            payload = AESGCM(key).decrypt(
                nonce, ciphertext, stored.artifact_id.encode("ascii")
            )
        except Exception as exc:
            raise AuditIntegrityError("encrypted artifact authentication failed") from exc
        if not hmac_compare_hash(payload, stored.sha256):
            raise AuditIntegrityError("encrypted artifact content hash mismatch")
        return payload

    def delete(self, storage_reference: str) -> None:
        self._resolve_reference(storage_reference).unlink(missing_ok=True)

    def _resolve_reference(self, reference: str) -> Path:
        if Path(reference).name != reference:
            raise PersistenceError("artifact reference must be an opaque filename")
        target = (self.directory / reference).resolve()
        if target.parent != self.directory:
            raise PersistenceError("artifact reference escapes the artifact directory")
        return target


def hmac_compare_hash(payload: bytes, expected: str) -> bool:
    import hmac

    return hmac.compare_digest(hashlib.sha256(payload).hexdigest(), expected)
