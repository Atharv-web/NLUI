"""Stable persistence-layer error types without sensitive database details."""


class PersistenceError(RuntimeError):
    """Base error safe for orchestration control flow."""


class DatabaseBusyError(PersistenceError):
    """A bounded SQLite busy retry was exhausted."""


class MigrationError(PersistenceError):
    """Database migrations are missing, invalid, or have drifted."""


class AuditIntegrityError(PersistenceError):
    """The append-only event chain or indexed event metadata is invalid."""


class RecordConflictError(PersistenceError):
    """A unique record or optimistic state expectation conflicted."""


class RecordNotFoundError(PersistenceError):
    """A requested durable record does not exist."""
