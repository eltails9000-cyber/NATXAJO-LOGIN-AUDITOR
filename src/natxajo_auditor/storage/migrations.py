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
