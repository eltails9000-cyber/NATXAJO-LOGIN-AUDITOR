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
    # Sentencias que deshacen la migración. Vacío significa que no es reversible.
    down: tuple[str, ...] = ()


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
    Migration(
        version=6,
        name="empresas",
        statements=(
            """
            CREATE TABLE companies (
                id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 3 AND 40),
                name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """,
            "INSERT INTO companies (id, name) VALUES ('plataforma', 'Plataforma')",
            # Las cuentas existentes pertenecían a la única instalación, que no tenía clientes.
            # SQLite no admite una clave foránea en ADD COLUMN con valor por defecto, así que la
            # integridad se garantiza con los disparadores de abajo.
            "ALTER TABLE accounts ADD COLUMN company_id TEXT NOT NULL DEFAULT 'plataforma'",
            "CREATE INDEX accounts_company_id ON accounts (company_id)",
            """
            CREATE TRIGGER accounts_company_must_exist_insert BEFORE INSERT ON accounts
            WHEN NOT EXISTS (SELECT 1 FROM companies WHERE id = NEW.company_id)
            BEGIN SELECT RAISE(ABORT, 'la empresa de la cuenta no existe'); END
            """,
            """
            CREATE TRIGGER accounts_company_must_exist_update BEFORE UPDATE OF company_id ON accounts
            WHEN NOT EXISTS (SELECT 1 FROM companies WHERE id = NEW.company_id)
            BEGIN SELECT RAISE(ABORT, 'la empresa de la cuenta no existe'); END
            """,
            """
            CREATE TRIGGER accounts_company_is_immutable BEFORE UPDATE OF company_id ON accounts
            WHEN OLD.company_id <> NEW.company_id
            BEGIN SELECT RAISE(ABORT, 'la empresa de una cuenta no puede cambiarse'); END
            """,
            """
            CREATE TRIGGER companies_id_is_immutable BEFORE UPDATE OF id ON companies
            BEGIN SELECT RAISE(ABORT, 'el identificador de empresa no puede cambiarse'); END
            """,
            """
            CREATE TRIGGER companies_with_accounts_cannot_be_deleted BEFORE DELETE ON companies
            WHEN EXISTS (SELECT 1 FROM accounts WHERE company_id = OLD.id)
            BEGIN SELECT RAISE(ABORT, 'la empresa tiene cuentas'); END
            """,
            """
            CREATE TRIGGER platform_company_cannot_be_deleted BEFORE DELETE ON companies
            WHEN OLD.id = 'plataforma'
            BEGIN SELECT RAISE(ABORT, 'la empresa de plataforma no puede borrarse'); END
            """,
        ),
        down=(
            "DROP TRIGGER platform_company_cannot_be_deleted",
            "DROP TRIGGER companies_with_accounts_cannot_be_deleted",
            "DROP TRIGGER companies_id_is_immutable",
            "DROP TRIGGER accounts_company_is_immutable",
            "DROP TRIGGER accounts_company_must_exist_update",
            "DROP TRIGGER accounts_company_must_exist_insert",
            "DROP INDEX accounts_company_id",
            "ALTER TABLE accounts DROP COLUMN company_id",
            "DROP TABLE companies",
        ),
    ),
    Migration(
        version=7,
        name="instalacion",
        statements=(
            """
            CREATE TABLE installation (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                state TEXT NOT NULL CHECK (state IN ('pending', 'completed')),
                code_hash TEXT,
                code_expires_at TEXT,
                code_failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (code_failed_attempts >= 0),
                completed_at TEXT,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """,
            # Una instalación que ya tiene cuentas se considera completada: no debe reabrirse.
            """
            INSERT INTO installation (id, state, completed_at)
            SELECT 1,
                   CASE WHEN EXISTS (SELECT 1 FROM accounts) THEN 'completed' ELSE 'pending' END,
                   CASE WHEN EXISTS (SELECT 1 FROM accounts) THEN CURRENT_TIMESTAMP END
            """,
            """
            CREATE TRIGGER installation_is_locked_after_completion BEFORE UPDATE ON installation
            WHEN OLD.state = 'completed'
            BEGIN SELECT RAISE(ABORT, 'la instalación ya está completada y no puede modificarse'); END
            """,
            """
            CREATE TRIGGER installation_cannot_be_deleted BEFORE DELETE ON installation
            BEGIN SELECT RAISE(ABORT, 'la instalación no puede borrarse'); END
            """,
        ),
        down=(
            "DROP TRIGGER installation_cannot_be_deleted",
            "DROP TRIGGER installation_is_locked_after_completion",
            "DROP TABLE installation",
        ),
    ),
    Migration(
        version=8,
        name="eventos",
        statements=(
            """
            CREATE TABLE event_outbox (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                category TEXT NOT NULL CHECK (category IN ('operativo', 'seguridad')),
                company_id TEXT,
                actor TEXT,
                occurred_at TEXT NOT NULL,
                payload TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'delivered', 'dead')),
                attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
                last_error TEXT
            )
            """,
            "CREATE INDEX event_outbox_status ON event_outbox (status, seq)",
            """
            CREATE TABLE event_deliveries (
                event_id TEXT NOT NULL REFERENCES event_outbox (event_id) ON DELETE CASCADE,
                consumer TEXT NOT NULL,
                delivered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (event_id, consumer)
            )
            """,
            "ALTER TABLE audit_events ADD COLUMN event_id TEXT",
            (
                "ALTER TABLE audit_events ADD COLUMN category TEXT NOT NULL DEFAULT 'operativo' "
                "CHECK (category IN ('operativo', 'seguridad'))"
            ),
            "ALTER TABLE audit_events ADD COLUMN company_id TEXT",
            "ALTER TABLE audit_events ADD COLUMN actor TEXT",
            # Clasificación de los eventos ya registrados, según su tipo.
            (
                "UPDATE audit_events SET category = 'seguridad' WHERE "
                "event_type LIKE 'account.%' OR event_type LIKE 'session.%' "
                "OR event_type LIKE 'grant.%' OR event_type LIKE 'operation.%' "
                "OR event_type IN ('plugin.rejected', 'plugin.reviewed', 'plugin.publisher_revoked')"
            ),
            "CREATE UNIQUE INDEX audit_events_event_id ON audit_events (event_id)",
            "CREATE INDEX audit_events_company_id ON audit_events (company_id)",
        ),
        down=(
            "DROP INDEX audit_events_company_id",
            "DROP INDEX audit_events_event_id",
            "ALTER TABLE audit_events DROP COLUMN actor",
            "ALTER TABLE audit_events DROP COLUMN company_id",
            "ALTER TABLE audit_events DROP COLUMN category",
            "ALTER TABLE audit_events DROP COLUMN event_id",
            "DROP TABLE event_deliveries",
            "DROP INDEX event_outbox_status",
            "DROP TABLE event_outbox",
        ),
    ),
    Migration(
        version=9,
        name="editores_de_confianza",
        # Invariantes de los editores en la propia base, con independencia del código que escriba:
        # la clave no cambia, un editor revocado no vuelve a estar activo y no se borran editores.
        statements=(
            """
            CREATE TRIGGER plugin_publishers_key_is_immutable
            BEFORE UPDATE OF key_id, public_key ON plugin_publishers
            BEGIN
                SELECT RAISE(ABORT, 'la clave de un editor es inmutable');
            END
            """,
            """
            CREATE TRIGGER plugin_publishers_revocation_is_final
            BEFORE UPDATE OF trust_level ON plugin_publishers
            WHEN OLD.trust_level = 'revoked' AND NEW.trust_level <> 'revoked'
            BEGIN
                SELECT RAISE(ABORT, 'un editor revocado no puede volver a estar activo');
            END
            """,
            """
            CREATE TRIGGER plugin_publishers_cannot_be_deleted
            BEFORE DELETE ON plugin_publishers
            BEGIN
                SELECT RAISE(ABORT, 'los editores no se eliminan: se revocan');
            END
            """,
        ),
        down=(
            "DROP TRIGGER plugin_publishers_cannot_be_deleted",
            "DROP TRIGGER plugin_publishers_revocation_is_final",
            "DROP TRIGGER plugin_publishers_key_is_immutable",
        ),
    ),
    Migration(
        version=10,
        name="evaluaciones_e_informes",
        statements=(
            """
            CREATE TABLE audit_runs (
                id TEXT PRIMARY KEY CHECK (length(id) = 36),
                company_id TEXT NOT NULL REFERENCES companies(id),
                username TEXT NOT NULL,
                profile TEXT NOT NULL CHECK (length(profile) BETWEEN 1 AND 40),
                overrides TEXT NOT NULL,
                authorization_reference TEXT NOT NULL
                    CHECK (length(authorization_reference) BETWEEN 3 AND 200),
                snapshot_sha256 TEXT NOT NULL CHECK (length(snapshot_sha256) = 64),
                engine_version TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                passed INTEGER NOT NULL CHECK (passed >= 0),
                failed INTEGER NOT NULL CHECK (failed >= 0),
                not_evaluable INTEGER NOT NULL CHECK (not_evaluable >= 0),
                risk TEXT NOT NULL
                    CHECK (risk IN ('ninguno', 'bajo', 'medio', 'alto', 'critico'))
            )
            """,
            """
            CREATE TABLE audit_findings (
                run_id TEXT NOT NULL REFERENCES audit_runs(id),
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                path TEXT NOT NULL,
                status TEXT NOT NULL
                    CHECK (status IN ('cumple', 'no_cumple', 'no_evaluable')),
                severity TEXT NOT NULL CHECK (severity IN ('bajo', 'medio', 'alto', 'critico')),
                observed TEXT,
                expected TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                PRIMARY KEY (run_id, rule_id)
            )
            """,
            """
            CREATE TRIGGER audit_runs_are_immutable
            BEFORE UPDATE ON audit_runs
            BEGIN
                SELECT RAISE(ABORT, 'una evaluación no se modifica');
            END
            """,
            """
            CREATE TRIGGER audit_runs_cannot_be_deleted
            BEFORE DELETE ON audit_runs
            BEGIN
                SELECT RAISE(ABORT, 'una evaluación no se elimina');
            END
            """,
            """
            CREATE TRIGGER audit_findings_are_immutable
            BEFORE UPDATE ON audit_findings
            BEGIN
                SELECT RAISE(ABORT, 'los hallazgos no se modifican');
            END
            """,
            """
            CREATE TRIGGER audit_findings_cannot_be_deleted
            BEFORE DELETE ON audit_findings
            BEGIN
                SELECT RAISE(ABORT, 'los hallazgos no se eliminan');
            END
            """,
            """
            CREATE TABLE report_exports (
                id TEXT PRIMARY KEY CHECK (length(id) = 36),
                run_id TEXT NOT NULL REFERENCES audit_runs(id),
                company_id TEXT NOT NULL REFERENCES companies(id),
                format TEXT NOT NULL CHECK (format IN ('json', 'csv', 'html', 'txt')),
                username TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
                size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
                created_at TEXT NOT NULL
            )
            """,
            """
            CREATE TRIGGER report_exports_are_immutable
            BEFORE UPDATE ON report_exports
            BEGIN
                SELECT RAISE(ABORT, 'un informe exportado no se modifica');
            END
            """,
            """
            CREATE TRIGGER report_exports_cannot_be_deleted
            BEFORE DELETE ON report_exports
            BEGIN
                SELECT RAISE(ABORT, 'un informe exportado no se elimina');
            END
            """,
        ),
        down=(
            "DROP TRIGGER report_exports_cannot_be_deleted",
            "DROP TRIGGER report_exports_are_immutable",
            "DROP TABLE report_exports",
            "DROP TRIGGER audit_findings_cannot_be_deleted",
            "DROP TRIGGER audit_findings_are_immutable",
            "DROP TABLE audit_findings",
            "DROP TRIGGER audit_runs_cannot_be_deleted",
            "DROP TRIGGER audit_runs_are_immutable",
            "DROP TABLE audit_runs",
        ),
    ),
    Migration(
        version=11,
        name="cuarentena_y_version_anterior_de_plugins",
        statements=(
            # Un plugin en cuarentena no puede habilitarse. La clave incluye la versión: liberar
            # o actualizar no afecta a una cuarentena de otra versión.
            """
            CREATE TABLE plugin_quarantine (
                plugin_id TEXT NOT NULL,
                version TEXT NOT NULL,
                reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 200),
                username TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (plugin_id, version)
            )
            """,
            # Una sola versión anterior por plugin: la que se restaura al revertir.
            """
            CREATE TABLE plugin_history (
                plugin_id TEXT PRIMARY KEY,
                version TEXT NOT NULL,
                publisher_key_id TEXT NOT NULL REFERENCES plugin_publishers (key_id),
                integrity_sha256 TEXT NOT NULL CHECK (length(integrity_sha256) = 64),
                dependencies TEXT NOT NULL,
                retired_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """,
        ),
        down=(
            "DROP TABLE plugin_history",
            "DROP TABLE plugin_quarantine",
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


def pending_versions(
    database: Database, migrations: tuple[Migration, ...] = MIGRATIONS
) -> list[int]:
    """Versiones que aún no están aplicadas. Una base sin tabla de control tiene todas pendientes."""
    table = database.fetchall(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
    )
    applied: set[int] = set()
    if table:
        applied = {
            int(row[0]) for row in database.fetchall("SELECT version FROM schema_migrations")
        }
    return [
        m.version
        for m in sorted(migrations, key=lambda item: item.version)
        if m.version not in applied
    ]


def rollback_migrations(
    database: Database, target_version: int, migrations: tuple[Migration, ...] = MIGRATIONS
) -> list[int]:
    """Revierte, de la más reciente a la más antigua, las migraciones posteriores a target_version.

    Antes de ejecutar nada comprueba que todas las migraciones a revertir son reversibles. Cada
    reversión es transaccional. Devuelve las versiones revertidas.
    """
    _check_definitions(migrations)
    known = {migration.version: migration for migration in migrations}
    applied = sorted(
        int(row[0]) for row in database.fetchall("SELECT version FROM schema_migrations")
    )
    to_revert = [version for version in reversed(applied) if version > target_version]
    for version in to_revert:
        migration = known.get(version)
        if migration is None:
            raise StorageError(f"no se puede revertir la migración desconocida {version}")
        if not migration.down:
            raise StorageError(f"la migración {version} ({migration.name}) no es reversible")
        if _needs_drop_column(migration) and sqlite3.sqlite_version_info < MIN_SQLITE_DROP_COLUMN:
            # Se comprueba antes de cambiar nada: una reversión a medias sería peor que no empezar.
            raise StorageError(
                f"la migración {version} ({migration.name}) necesita SQLite "
                f"{_format_version(MIN_SQLITE_DROP_COLUMN)} o posterior para DROP COLUMN; "
                f"este intérprete usa SQLite {_format_version(sqlite3.sqlite_version_info)}"
            )
    for version in to_revert:
        migration = known[version]
        try:
            with database.transaction() as connection:
                for statement in migration.down:
                    connection.execute(statement)
                connection.execute("DELETE FROM schema_migrations WHERE version = ?", (version,))
        except sqlite3.Error as exc:
            raise StorageError(f"Falló la reversión de la migración {version}: {exc}") from exc
    return to_revert


# DROP COLUMN existe desde SQLite 3.35.0. Revertir una migración que lo usa exige esa versión.
MIN_SQLITE_DROP_COLUMN: tuple[int, int, int] = (3, 35, 0)


def _needs_drop_column(migration: Migration) -> bool:
    return any("DROP COLUMN" in statement.upper() for statement in migration.down)


def _format_version(version: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in version)


def _check_definitions(migrations: tuple[Migration, ...]) -> None:
    versions = [migration.version for migration in migrations]
    if versions != sorted(set(versions)) or any(version < 1 for version in versions):
        raise StorageError(
            "Las versiones de migración deben ser enteros positivos, únicos y ascendentes"
        )
