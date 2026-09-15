"""SQLite connection policy and bounded transaction handling."""

from __future__ import annotations

import sqlite3
import time
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from ..config import PersistenceConfig
from .errors import DatabaseBusyError, PersistenceError


@dataclass(frozen=True, slots=True)
class DatabaseSettings:
    path: Path
    backup_directory: Path
    busy_timeout_ms: int = 5000
    busy_retry_attempts: int = 2

    @classmethod
    def from_config(
        cls, base_dir: Path, config: PersistenceConfig
    ) -> "DatabaseSettings":
        database_path = Path(config.database_path)
        backup_directory = Path(config.backup_directory)
        if not database_path.is_absolute():
            database_path = base_dir / database_path
        if not backup_directory.is_absolute():
            backup_directory = base_dir / backup_directory
        return cls(
            path=database_path.resolve(),
            backup_directory=backup_directory.resolve(),
            busy_timeout_ms=config.busy_timeout_ms,
            busy_retry_attempts=config.busy_retry_attempts,
        )


class SQLiteDatabase:
    """Creates short-lived configured connections; it holds no global cursor."""

    def __init__(self, settings: DatabaseSettings) -> None:
        self.settings = settings

    def connect(self, *, read_only: bool = False) -> sqlite3.Connection:
        if read_only:
            if not self.settings.path.exists():
                raise PersistenceError("database does not exist")
            uri = f"{self.settings.path.as_uri()}?mode=ro"
            connection = sqlite3.connect(
                uri,
                uri=True,
                timeout=self.settings.busy_timeout_ms / 1000,
                isolation_level=None,
            )
        else:
            self.settings.path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(
                self.settings.path,
                timeout=self.settings.busy_timeout_ms / 1000,
                isolation_level=None,
            )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {self.settings.busy_timeout_ms}")
        if not read_only:
            journal_mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(journal_mode).lower() != "wal":
                connection.close()
                raise PersistenceError("SQLite WAL mode could not be enabled")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA wal_autocheckpoint = 1000")
        return connection

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect(read_only=True)
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        began = False
        try:
            for attempt in range(self.settings.busy_retry_attempts + 1):
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    began = True
                    break
                except sqlite3.OperationalError as exc:
                    if not _is_busy(exc):
                        raise
                    if attempt >= self.settings.busy_retry_attempts:
                        raise DatabaseBusyError(
                            "SQLite remained busy after bounded retries"
                        ) from None
                    time.sleep(min(0.02 * (2**attempt), 0.25))
            yield connection
            connection.execute("COMMIT")
        except Exception:
            if began and connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def checkpoint(self, mode: str = "PASSIVE") -> tuple[int, int, int]:
        allowed = {"PASSIVE", "FULL", "RESTART", "TRUNCATE"}
        normalized = mode.upper()
        if normalized not in allowed:
            raise ValueError(f"unsupported WAL checkpoint mode: {mode}")
        with closing(self.connect()) as connection:
            row = connection.execute(f"PRAGMA wal_checkpoint({normalized})").fetchone()
            return int(row[0]), int(row[1]), int(row[2])


def _is_busy(exc: sqlite3.OperationalError) -> bool:
    message = str(exc).lower()
    return "locked" in message or "busy" in message
