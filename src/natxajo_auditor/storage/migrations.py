"""Migraciones versionadas. Cada migración se aplica una sola vez, dentro de una transacción."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from natxajo_auditor.core.exceptions import StorageError
from natxajo_auditor.storage.database import Database


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    statements: tuple[str, ...]


MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        version=1,
        name="metadatos_de_plataforma",
        statements=(
            """
            CREATE TABLE platform_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """,
        ),
    ),
    Migration(
        version=2,
        name="eventos_de_auditoria",
        statements=(
            """
            CREATE TABLE audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """,
        ),
    ),
    Migration(
        version=3,
        name="estado_de_modulos",
        statements=(
            """
            CREATE TABLE module_states (
                module_id TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """,
        ),
    ),
    Migration(
        version=4,
        name="plugins",
        statements=(
            """
            CREATE TABLE plugin_publishers (
                key_id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                public_key TEXT NOT NULL,
                trust_level TEXT NOT NULL CHECK (
                    trust_level IN ('official', 'verified', 'third_party', 'revoked')
                ),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE plugin_installs (
                plugin_id TEXT PRIMARY KEY,
                version TEXT NOT NULL,
                enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                publisher_key_id TEXT NOT NULL REFERENCES plugin_publishers (key_id),
                integrity_sha256 TEXT NOT NULL,
                dependencies TEXT NOT NULL,
                installed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE plugin_reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plugin_id TEXT NOT NULL,
                version TEXT NOT NULL,
                reviewer TEXT NOT NULL,
                decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
                findings TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """,
        ),
    ),
    Migration(
        version=5,
        name="seguridad",
        statements=(
            """
            CREATE TABLE accounts (
                username TEXT PRIMARY KEY CHECK (length(username) BETWEEN 3 AND 40),
                password_hash TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
                failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
                locked_until TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE roles (
                name TEXT PRIMARY KEY,
                builtin INTEGER NOT NULL CHECK (builtin IN (0, 1)),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE role_grants (
                role_name TEXT NOT NULL REFERENCES roles (name) ON DELETE CASCADE,
                permission TEXT NOT NULL,
                PRIMARY KEY (role_name, permission)
            )
            """,
            """
            CREATE TABLE role_parents (
                role_name TEXT NOT NULL REFERENCES roles (name) ON DELETE CASCADE,
                parent_name TEXT NOT NULL REFERENCES roles (name) ON DELETE CASCADE,
                PRIMARY KEY (role_name, parent_name)
            )
            """,
            """
            CREATE TABLE account_roles (
                username TEXT NOT NULL REFERENCES accounts (username) ON DELETE CASCADE,
                role_name TEXT NOT NULL REFERENCES roles (name) ON DELETE CASCADE,
                PRIMARY KEY (username, role_name)
            )
            """,
            """
            CREATE TABLE permission_grants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL REFERENCES accounts (username) ON DELETE CASCADE,
                permission TEXT NOT NULL,
                minutes INTEGER NOT NULL CHECK (minutes BETWEEN 1 AND 240),
                reason TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                approved_by TEXT,
                status TEXT NOT NULL CHECK (
                    status IN ('pending', 'active', 'rejected', 'revoked')
                ),
                expires_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL REFERENCES accounts (username) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                last_activity TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                reauth_at TEXT,
                revoked_at TEXT
            )
            """,
        ),
    ),
)

_BOOKKEEPING = (
    "CREATE TABLE IF NOT EXISTS schema_migrations ("
    "version INTEGER PRIMARY KEY, name TEXT NOT NULL, "
    "applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
)


def apply_migrations(
    database: Database, migrations: tuple[Migration, ...] = MIGRATIONS
) -> list[int]:
    """Aplica las migraciones pendientes y devuelve las versiones aplicadas en esta llamada."""
    _check_definitions(migrations)
    database.execute(_BOOKKEEPING)
    known = {migration.version for migration in migrations}
    applied = {int(row[0]) for row in database.fetchall("SELECT version FROM schema_migrations")}
    unknown = sorted(applied - known)
    if unknown:
        raise StorageError(f"La base de datos tiene migraciones desconocidas: {unknown}")

    newly_applied: list[int] = []
    for migration in sorted(migrations, key=lambda item: item.version):
        if migration.version in applied:
            continue
        try:
            with database.transaction() as connection:
                for statement in migration.statements:
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
                    (migration.version, migration.name),
                )
        except sqlite3.Error as exc:
            raise StorageError(f"Falló la migración {migration.version}: {exc}") from exc
        newly_applied.append(migration.version)
    return newly_applied


def _check_definitions(migrations: tuple[Migration, ...]) -> None:
    versions = [migration.version for migration in migrations]
    if versions != sorted(set(versions)) or any(version < 1 for version in versions):
        raise StorageError(
            "Las versiones de migración deben ser enteros positivos, únicos y ascendentes"
        )
