"""Canonical SHA-256 or HMAC-SHA-256 event-chain sealing."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

from ..events import EventEnvelope
from .errors import AuditIntegrityError


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class AuditHasher:
    algorithm: str = "sha256"
    key: bytes | None = None

    def __post_init__(self) -> None:
        if self.algorithm not in {"sha256", "hmac-sha256"}:
            raise ValueError(f"unsupported audit hash algorithm: {self.algorithm}")
        if self.algorithm == "hmac-sha256" and not self.key:
            raise ValueError("hmac-sha256 requires an OS-protected key")
        if self.algorithm == "sha256" and self.key is not None:
            raise ValueError("a key may only be supplied for hmac-sha256")

    def seal(
        self, event: EventEnvelope, previous_event_hash: str | None
    ) -> EventEnvelope:
        if event.event_hash is not None or event.previous_event_hash is not None:
            raise AuditIntegrityError("unsealed events must not supply chain hashes")
        chained = event.model_copy(update={"previous_event_hash": previous_event_hash})
        digest = self._digest(self._canonical_bytes(chained))
        return chained.model_copy(update={"event_hash": digest})

    def verify(self, event: EventEnvelope, expected_previous_hash: str | None) -> None:
        if event.previous_event_hash != expected_previous_hash:
            raise AuditIntegrityError("audit previous-event hash mismatch")
        if event.event_hash is None:
            raise AuditIntegrityError("audit event hash is missing")
        expected = self._digest(self._canonical_bytes(event))
        if not hmac.compare_digest(event.event_hash, expected):
            raise AuditIntegrityError("audit event hash mismatch")

    def _canonical_bytes(self, event: EventEnvelope) -> bytes:
        value = event.model_dump(mode="json", exclude={"event_hash"})
        return canonical_json(value).encode("utf-8")

    def _digest(self, payload: bytes) -> str:
        if self.algorithm == "hmac-sha256":
            return hmac.new(self.key, payload, hashlib.sha256).hexdigest()
        return hashlib.sha256(payload).hexdigest()
