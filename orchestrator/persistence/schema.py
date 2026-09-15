"""Checksummed, forward-only SQLite schema migrations."""

from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .database import SQLiteDatabase
from .errors import MigrationError


_MIGRATION_NAME = re.compile(r"^(?P<version>[0-9]{4})_(?P<name>[a-z0-9_]+)\.sql$")


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    path: Path
    sql: str
    checksum: str


class MigrationRunner:
    def __init__(self, database: SQLiteDatabase, directory: Path | None = None) -> None:
        self.database = database
        self.directory = directory or Path(__file__).with_name("sql")

    def discover(self) -> tuple[Migration, ...]:
        migrations: list[Migration] = []
        seen: set[int] = set()
        for path in sorted(self.directory.glob("*.sql")):
            match = _MIGRATION_NAME.fullmatch(path.name)
            if not match:
                raise MigrationError(f"invalid migration filename: {path.name}")
            version = int(match.group("version"))
            if version in seen:
                raise MigrationError(f"duplicate migration version: {version}")
            seen.add(version)
            sql = path.read_text(encoding="utf-8")
            migrations.append(
                Migration(
                    version=version,
                    name=match.group("name"),
                    path=path,
                    sql=sql,
                    checksum=hashlib.sha256(sql.encode("utf-8")).hexdigest(),
                )
            )
        if not migrations:
            raise MigrationError("no schema migrations were found")
        versions = [item.version for item in migrations]
        if versions != list(range(1, len(versions) + 1)):
            raise MigrationError("migration versions must be contiguous starting at 0001")
        return tuple(migrations)

    def migrate(self) -> int:
        self._bootstrap_history()
        migrations = self.discover()
        applied = self._applied()
        known_versions = {item.version for item in migrations}
        unknown = set(applied) - known_versions
        if unknown:
            raise MigrationError(f"database has unknown migration versions: {sorted(unknown)}")

        for migration in migrations:
            existing = applied.get(migration.version)
            if existing:
                if existing["checksum"] != migration.checksum or existing["name"] != migration.name:
                    raise MigrationError(f"migration drift detected at version {migration.version}")
                continue
            with self.database.transaction() as connection:
                for statement in _split_statements(migration.sql):
                    connection.execute(statement)
                connection.execute(
                    """
                    INSERT INTO schema_migrations(version, name, checksum, applied_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        migration.version,
                        migration.name,
                        migration.checksum,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                connection.execute(f"PRAGMA user_version = {migration.version}")
        return migrations[-1].version

    def current_version(self) -> int:
        if not self.database.settings.path.exists():
            return 0
        with self.database.read() as connection:
            row = connection.execute("PRAGMA user_version").fetchone()
            return int(row[0])

    def _bootstrap_history(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    checksum TEXT NOT NULL CHECK(length(checksum) = 64),
                    applied_at TEXT NOT NULL
                ) STRICT
                """
            )

    def _applied(self) -> dict[int, sqlite3.Row]:
        with self.database.read() as connection:
            rows = connection.execute(
                "SELECT version, name, checksum FROM schema_migrations ORDER BY version"
            ).fetchall()
            return {int(row["version"]): row for row in rows}


def _split_statements(script: str) -> tuple[str, ...]:
    statements: list[str] = []
    buffer = ""
    for line in script.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            statement = buffer.strip()
            if statement:
                statements.append(statement)
            buffer = ""
    if buffer.strip():
        raise MigrationError("migration ends with an incomplete SQL statement")
    return tuple(statements)
