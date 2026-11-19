from pathlib import Path

import pytest

from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.storage.storage_manager import MANIFEST_SUFFIX, StorageManager


def _make_backup(tmp_path: Path) -> tuple[StorageManager, Path]:
    source = tmp_path / "data.txt"
    source.write_text("original", encoding="utf-8")
    storage = StorageManager(tmp_path / "storage")
    return storage, storage.backup_file(source, label="test")


def test_integrity_is_healthy_for_fresh_backup(tmp_path: Path) -> None:
    storage, _ = _make_backup(tmp_path)
    assert storage.integrity() == {"status": "healthy", "problems": []}


def test_integrity_detects_altered_backup(tmp_path: Path) -> None:
    storage, backup = _make_backup(tmp_path)
    backup.write_text("alterada", encoding="utf-8")
    result = storage.integrity()
    assert result["status"] == "degraded"
    assert any("hash no coincide" in problem for problem in result["problems"])  # type: ignore[union-attr]


def test_integrity_detects_missing_backup(tmp_path: Path) -> None:
    storage, backup = _make_backup(tmp_path)
    backup.unlink()
    result = storage.integrity()
    assert result["status"] == "degraded"
    assert any("falta la copia" in problem for problem in result["problems"])  # type: ignore[union-attr]


def test_integrity_detects_missing_manifest(tmp_path: Path) -> None:
    storage, backup = _make_backup(tmp_path)
    backup.with_name(backup.name + MANIFEST_SUFFIX).unlink()
    result = storage.integrity()
    assert result["status"] == "degraded"
    assert any("falta el manifiesto" in problem for problem in result["problems"])  # type: ignore[union-attr]


def test_restore_refuses_altered_backup(tmp_path: Path) -> None:
    storage, backup = _make_backup(tmp_path)
    backup.write_text("alterada", encoding="utf-8")
    target = tmp_path / "restored.txt"
    with pytest.raises(ValidationError):
        storage.restore_file(backup, target, authorized=True)
    assert not target.exists()


def test_restore_copies_valid_backup_when_authorized(tmp_path: Path) -> None:
    storage, backup = _make_backup(tmp_path)
    target = tmp_path / "restored.txt"
    storage.restore_file(backup, target, authorized=True)
    assert target.read_text(encoding="utf-8") == "original"
