from pathlib import Path

import pytest

from natxajo_auditor.core.exceptions import AuthorizationError, StorageError
from natxajo_auditor.storage.audit import AuditLog
from natxajo_auditor.storage.backups import BackupManager
from natxajo_auditor.storage.database import Database
from natxajo_auditor.storage.migrations import Migration, apply_migrations


@pytest.fixture
def database(tmp_path: Path) -> Database:
    db = Database(tmp_path / "storage" / "test.db")
    db.open()
    yield db
    db.close()


def _applied(database: Database) -> list[int]:
    return [int(row[0]) for row in database.fetchall("SELECT version FROM schema_migrations")]


def test_migrations_apply_once(database: Database) -> None:
    assert apply_migrations(database) == [1, 2, 3, 4]
    assert apply_migrations(database) == []
    assert _applied(database) == [1, 2, 3, 4]


def test_failed_migration_leaves_no_partial_changes(database: Database) -> None:
    broken = (
        Migration(
            version=1,
            name="roto",
            statements=("CREATE TABLE parcial (x INTEGER)", "CREATE TABLE parcial (x INTEGER)"),
        ),
    )
    with pytest.raises(StorageError):
        apply_migrations(database, broken)
    assert database.fetchall("SELECT name FROM sqlite_master WHERE name = 'parcial'") == []
    assert _applied(database) == []


def test_database_with_unknown_migration_is_refused(database: Database) -> None:
    apply_migrations(database)
    only_first = (Migration(1, "metadatos_de_plataforma", ("SELECT 1",)),)
    with pytest.raises(StorageError):
        apply_migrations(database, only_first)


def test_migration_versions_must_be_ascending(database: Database) -> None:
    unordered = (
        Migration(2, "b", ("SELECT 1",)),
        Migration(1, "a", ("SELECT 1",)),
    )
    with pytest.raises(StorageError):
        apply_migrations(database, unordered)


def test_audit_log_records_and_lists(database: Database) -> None:
    apply_migrations(database)
    audit = AuditLog(database)
    audit.record("prueba", {"b": 2, "a": 1})
    events = audit.list_events()
    assert events[0]["event_type"] == "prueba"
    assert events[0]["payload"] == {"a": 1, "b": 2}


def _backup(tmp_path: Path) -> tuple[BackupManager, Path, Path]:
    source = tmp_path / "origen.txt"
    source.write_text("original", encoding="utf-8")
    manager = BackupManager(tmp_path / "backups")
    backup = manager.create(source, label="prueba")
    return manager, source, backup


def test_fresh_backup_is_healthy(tmp_path: Path) -> None:
    manager, _, _ = _backup(tmp_path)
    assert manager.integrity() == {"status": "healthy", "problems": []}


def _problems(result: dict[str, object]) -> list[str]:
    problems = result["problems"]
    assert isinstance(problems, list)
    return [str(problem) for problem in problems]


def test_altered_backup_is_detected(tmp_path: Path) -> None:
    manager, _, backup = _backup(tmp_path)
    backup.write_text("alterada", encoding="utf-8")
    result = manager.integrity()
    assert result["status"] == "degraded"
    assert any("hash no coincide" in problem for problem in _problems(result))


def test_missing_manifest_is_detected(tmp_path: Path) -> None:
    manager, _, backup = _backup(tmp_path)
    backup.with_name(backup.name + ".manifest.json").unlink()
    result = manager.integrity()
    assert result["status"] == "degraded"
    assert any("falta el manifiesto" in problem for problem in _problems(result))


def test_restore_requires_authorization(tmp_path: Path) -> None:
    manager, _, backup = _backup(tmp_path)
    with pytest.raises(AuthorizationError):
        manager.restore(backup, tmp_path / "destino.txt")


def test_restore_refuses_existing_target_without_overwrite(tmp_path: Path) -> None:
    manager, _, backup = _backup(tmp_path)
    target = tmp_path / "destino.txt"
    target.write_text("no tocar", encoding="utf-8")
    with pytest.raises(StorageError):
        manager.restore(backup, target, authorized=True)
    assert target.read_text(encoding="utf-8") == "no tocar"


def test_restore_overwrites_only_with_explicit_flag(tmp_path: Path) -> None:
    manager, _, backup = _backup(tmp_path)
    target = tmp_path / "destino.txt"
    target.write_text("no tocar", encoding="utf-8")
    manager.restore(backup, target, authorized=True, overwrite=True)
    assert target.read_text(encoding="utf-8") == "original"


def test_restore_refuses_altered_backup(tmp_path: Path) -> None:
    manager, _, backup = _backup(tmp_path)
    backup.write_text("alterada", encoding="utf-8")
    target = tmp_path / "destino.txt"
    with pytest.raises(StorageError):
        manager.restore(backup, target, authorized=True)
    assert not target.exists()
