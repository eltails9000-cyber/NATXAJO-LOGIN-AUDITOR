"""Migración 10 (evaluaciones e informes): base nueva, actualización desde la versión 9 con datos,
reversión, interrupciones, guardia de versión de SQLite y tablas protegidas."""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from natxajo_auditor.core.exceptions import StorageError
from natxajo_auditor.security.roles import RoleStore
from natxajo_auditor.storage.database import Database
from natxajo_auditor.storage.migrations import (
    MIGRATIONS,
    apply_migrations,
    pending_versions,
    rollback_migrations,
)
from natxajo_auditor.storage.outbox import PROTECTED_TABLES

V9 = MIGRATIONS[:9]
EVALUATION = MIGRATIONS[9]
NEW_TABLES = {"audit_findings", "audit_runs", "report_exports"}
NEW_TRIGGERS = {
    "audit_findings_are_immutable",
    "audit_findings_cannot_be_deleted",
    "audit_runs_are_immutable",
    "audit_runs_cannot_be_deleted",
    "report_exports_are_immutable",
    "report_exports_cannot_be_deleted",
}
# Una sentencia que falla al final de la migración 10: simula una interrupción a mitad de cambio.
BROKEN_EVALUATION = replace(
    EVALUATION,
    statements=(*EVALUATION.statements, "SELECT * FROM tabla_que_no_existe"),
)


def _open(path: Path) -> Database:
    database = Database(path)
    database.open()
    return database


def _names(database: Database, kind: str) -> set[str]:
    rows = database.fetchall("SELECT name FROM sqlite_master WHERE type = ?", (kind,))
    return {str(row[0]) for row in rows}


def _applied(database: Database) -> list[int]:
    rows = database.fetchall("SELECT version FROM schema_migrations ORDER BY version")
    return [int(row[0]) for row in rows]


def _v9_with_data(path: Path) -> Database:
    """Instalación anterior (versión 9) con una cuenta, un rol y un evento reales."""
    database = _open(path)
    apply_migrations(database, V9)
    RoleStore(database).ensure_builtins()
    database.execute(
        "INSERT INTO accounts (username, password_hash, status) "
        "VALUES ('admin_viejo', 'hash-antiguo', 'active')"
    )
    database.execute(
        "INSERT INTO account_roles (username, role_name) VALUES ('admin_viejo', 'administrador')"
    )
    database.execute(
        "INSERT INTO audit_events (event_type, payload) "
        "VALUES ('account.created', '{\"username\": \"admin_viejo\"}')"
    )
    return database


def test_a_fresh_database_gets_every_evaluation_table_and_trigger(tmp_path: Path) -> None:
    database = _open(tmp_path / "nueva.db")
    assert apply_migrations(database) == list(range(1, 11))
    assert pending_versions(database) == []
    assert NEW_TABLES <= _names(database, "table")
    assert NEW_TRIGGERS <= _names(database, "trigger")
    assert database.fetchall("SELECT COUNT(*) FROM audit_runs") == [(0,)]
    assert database.fetchall("PRAGMA integrity_check") == [("ok",)]
    assert database.fetchall("PRAGMA foreign_key_check") == []
    database.close()


def test_the_evaluation_migration_is_recorded_under_its_name(tmp_path: Path) -> None:
    database = _open(tmp_path / "nombre.db")
    apply_migrations(database)
    assert database.fetchall("SELECT name FROM schema_migrations WHERE version = 10") == [
        ("evaluaciones_e_informes",)
    ]
    database.close()


def test_every_protected_table_exists_after_the_migrations(tmp_path: Path) -> None:
    database = _open(tmp_path / "protegidas.db")
    apply_migrations(database)
    assert sorted(PROTECTED_TABLES - _names(database, "table")) == []
    database.close()


def test_upgrade_from_v9_keeps_every_row_and_adds_the_evaluation_tables(tmp_path: Path) -> None:
    database = _v9_with_data(tmp_path / "v9.db")
    assert pending_versions(database) == [10]
    assert apply_migrations(database) == [10]
    assert database.fetchall("SELECT username, company_id FROM accounts") == [
        ("admin_viejo", "plataforma")
    ]
    assert database.fetchall("SELECT role_name FROM account_roles") == [("administrador",)]
    assert database.fetchall("SELECT event_type FROM audit_events") == [("account.created",)]
    assert database.fetchall("SELECT COUNT(*) FROM audit_runs") == [(0,)]
    assert NEW_TRIGGERS <= _names(database, "trigger")
    assert database.fetchall("PRAGMA integrity_check") == [("ok",)]
    assert database.fetchall("PRAGMA foreign_key_check") == []
    database.close()


def test_rolling_back_the_evaluation_migration_keeps_earlier_data(tmp_path: Path) -> None:
    database = _v9_with_data(tmp_path / "ida.db")
    apply_migrations(database)
    assert rollback_migrations(database, 9) == [10]
    assert _applied(database)[-1] == 9
    assert not (NEW_TABLES & _names(database, "table"))
    assert not (NEW_TRIGGERS & _names(database, "trigger"))
    assert database.fetchall("SELECT username FROM accounts") == [("admin_viejo",)]
    assert database.fetchall("SELECT event_type FROM audit_events") == [("account.created",)]
    assert database.fetchall("PRAGMA integrity_check") == [("ok",)]
    database.close()


def test_reapplying_after_a_rollback_creates_the_evaluation_tables_again(tmp_path: Path) -> None:
    database = _v9_with_data(tmp_path / "vuelta.db")
    apply_migrations(database)
    rollback_migrations(database, 9)
    assert apply_migrations(database) == [10]
    assert NEW_TABLES <= _names(database, "table")
    assert NEW_TRIGGERS <= _names(database, "trigger")
    assert database.fetchall("SELECT COUNT(*) FROM audit_runs") == [(0,)]
    database.close()


def test_an_interrupted_evaluation_migration_leaves_the_v9_schema_intact(tmp_path: Path) -> None:
    database = _v9_with_data(tmp_path / "interrumpida.db")
    with pytest.raises(StorageError, match="Falló la migración 10"):
        apply_migrations(database, (*V9, BROKEN_EVALUATION))
    assert _applied(database)[-1] == 9
    assert not (NEW_TABLES & _names(database, "table"))
    assert not (NEW_TRIGGERS & _names(database, "trigger"))
    assert database.fetchall("SELECT username FROM accounts") == [("admin_viejo",)]
    assert database.fetchall("PRAGMA integrity_check") == [("ok",)]
    database.close()


def test_recovery_after_an_interruption_applies_the_real_migration(tmp_path: Path) -> None:
    database = _v9_with_data(tmp_path / "recuperada.db")
    with pytest.raises(StorageError):
        apply_migrations(database, (*V9, BROKEN_EVALUATION))
    assert apply_migrations(database) == [10]
    assert NEW_TABLES <= _names(database, "table")
    assert database.fetchall("SELECT username FROM accounts") == [("admin_viejo",)]
    assert database.fetchall("PRAGMA integrity_check") == [("ok",)]
    database.close()


def test_the_rollback_checks_the_sqlite_version_before_changing_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = _v9_with_data(tmp_path / "version.db")
    apply_migrations(database)
    monkeypatch.setattr(sqlite3, "sqlite_version_info", (3, 34, 0))
    with pytest.raises(StorageError, match="DROP COLUMN"):
        rollback_migrations(database, 5)
    monkeypatch.undo()
    assert _applied(database) == list(range(1, 11))
    assert NEW_TABLES <= _names(database, "table")
    assert database.fetchall("PRAGMA integrity_check") == [("ok",)]
    database.close()


def test_reverting_only_the_evaluation_migration_needs_no_drop_column(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = _v9_with_data(tmp_path / "sin_drop.db")
    apply_migrations(database)
    monkeypatch.setattr(sqlite3, "sqlite_version_info", (3, 34, 0))
    assert rollback_migrations(database, 9) == [10]
    monkeypatch.undo()
    database.close()
