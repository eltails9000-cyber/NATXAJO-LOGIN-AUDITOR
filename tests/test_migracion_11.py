"""Migración 11 (cuarentena y versión anterior de plugins): reversible y sin pérdida de esquema."""

from pathlib import Path

from natxajo_auditor.storage.database import Database
from natxajo_auditor.storage.migrations import (
    apply_migrations,
    pending_versions,
    rollback_migrations,
)


def test_migration_11_reverts_and_reapplies(tmp_path: Path) -> None:
    database = Database(tmp_path / "migracion_11.db")
    database.open()
    try:
        apply_migrations(database)
        assert rollback_migrations(database, 10) == [14, 13, 12, 11]
        tables = {
            row[0]
            for row in database.fetchall("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert "plugin_quarantine" not in tables
        assert "plugin_history" not in tables
        assert "plugin_installs" in tables
        assert pending_versions(database) == [11, 12, 13, 14]
        assert apply_migrations(database) == [11, 12, 13, 14]
        assert database.fetchall("PRAGMA integrity_check") == [("ok",)]
        assert database.fetchall("PRAGMA foreign_key_check") == []
    finally:
        database.close()
