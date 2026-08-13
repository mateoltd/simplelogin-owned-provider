"""Small database boundary supporting SQLite tests and PostgreSQL production."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.resources
import sqlite3
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from .errors import ConfigurationError


class Result:
    def __init__(self, cursor: Any):
        self._cursor = cursor

    @property
    def rowcount(self) -> int:
        return self._cursor.rowcount

    def fetchone(self) -> dict[str, Any] | None:
        row = self._cursor.fetchone()
        return None if row is None else dict(row)

    def fetchall(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self._cursor.fetchall()]


class Connection:
    def __init__(self, raw: Any, dialect: str):
        self.raw = raw
        self.dialect = dialect

    def execute(self, sql: str, parameters: Sequence[Any] = ()) -> Result:
        if self.dialect == "postgresql":
            sql = sql.replace("?", "%s")
        return Result(self.raw.execute(sql, tuple(parameters)))


@dataclass(frozen=True, slots=True)
class Database:
    url: str
    dialect: str = field(init=False)

    def __post_init__(self) -> None:
        parsed = urlparse(self.url)
        scheme = parsed.scheme.split("+", 1)[0]
        if scheme not in {"sqlite", "postgresql", "postgres"}:
            raise ConfigurationError("database URL must use sqlite or postgresql")
        object.__setattr__(
            self, "dialect", "sqlite" if scheme == "sqlite" else "postgresql"
        )

    def _connect(self) -> Any:
        if self.dialect == "sqlite":
            parsed = urlparse(self.url)
            if parsed.path in {"/:memory:", ""}:
                path = ":memory:"
            else:
                path = unquote(parsed.path)
            connection = sqlite3.connect(path, timeout=30, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA busy_timeout = 30000")
            return connection
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:  # pragma: no cover - install contract
            raise ConfigurationError("psycopg is required for PostgreSQL") from exc
        return psycopg.connect(self.url, row_factory=dict_row, autocommit=False)

    @contextlib.contextmanager
    def transaction(self, *, immediate: bool = False) -> Iterator[Connection]:
        raw = self._connect()
        wrapped = Connection(raw, self.dialect)
        try:
            if self.dialect == "sqlite":
                raw.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield wrapped
            raw.commit()
        except BaseException:
            raw.rollback()
            raise
        finally:
            raw.close()

    def ping(self) -> bool:
        with self.transaction() as connection:
            return connection.execute("SELECT 1 AS ok").fetchone() == {"ok": 1}


def _migration_files(dialect: str) -> list[Any]:
    root = importlib.resources.files("mail_edge.migrations")
    return sorted(
        (
            entry
            for entry in root.iterdir()
            if entry.name.endswith(".sql")
            and not (entry.name.endswith(".sqlite.sql") and dialect != "sqlite")
            and not (entry.name.endswith(".postgresql.sql") and dialect != "postgresql")
        ),
        key=lambda entry: entry.name,
    )


def _migration_version(name: str) -> str:
    version = name.removesuffix(".sql")
    return version.removesuffix(".sqlite").removesuffix(".postgresql")


def _statements(sql: str) -> list[str]:
    if "-- statement-break" in sql:
        return [item for item in sql.split("-- statement-break") if item.strip()]
    if "CREATE TRIGGER" in sql and "BEGIN" in sql:
        return [sql]
    return [item for item in sql.split(";") if item.strip()]


def migration_status(database: Database) -> tuple[list[str], list[str]]:
    expected = [
        _migration_version(entry.name) for entry in _migration_files(database.dialect)
    ]
    try:
        with database.transaction() as connection:
            rows = connection.execute(
                "SELECT version FROM mail_edge_schema_migrations ORDER BY version"
            ).fetchall()
    except Exception:
        return expected, []
    return expected, [str(row["version"]) for row in rows]


def migrate(database: Database) -> list[str]:
    applied: list[str] = []
    with database.transaction(immediate=True) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS mail_edge_schema_migrations (
                version TEXT PRIMARY KEY,
                checksum TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )

    for entry in _migration_files(database.dialect):
        version = _migration_version(entry.name)
        sql = entry.read_text(encoding="utf-8")
        checksum = hashlib.sha256(sql.encode()).hexdigest()
        with database.transaction(immediate=True) as connection:
            existing = connection.execute(
                "SELECT checksum FROM mail_edge_schema_migrations WHERE version = ?",
                (version,),
            ).fetchone()
            if existing:
                if existing["checksum"] != checksum:
                    raise ConfigurationError(f"migration checksum changed: {version}")
                continue
            for statement in _statements(sql):
                connection.execute(statement)
            connection.execute(
                """
                INSERT INTO mail_edge_schema_migrations(version, checksum, applied_at)
                VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                """
                if database.dialect == "sqlite"
                else """
                INSERT INTO mail_edge_schema_migrations(version, checksum, applied_at)
                VALUES (?, ?, to_char(clock_timestamp() AT TIME ZONE 'UTC',
                    'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'))
                """,
                (version, checksum),
            )
            applied.append(version)
    return applied


def sqlite_url(path: Path) -> str:
    return f"sqlite://{path.resolve()}"
