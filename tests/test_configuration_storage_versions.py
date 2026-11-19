from pathlib import Path

from natxajo_auditor.configuration.configuration_manager import ConfigurationManager
from natxajo_auditor.core.exceptions import AuthorizationError
from natxajo_auditor.storage.storage_manager import StorageManager
from natxajo_auditor.versioning.version_manager import VersionManager
from natxajo_auditor.versioning.version_registry import VersionRegistry


def test_configuration_backup_and_restore(tmp_path: Path) -> None:
    config = ConfigurationManager(tmp_path / "app.json")
    config.set("general", "theme", "light")
    backup = config.backup()
    config.set("general", "theme", "contrast")
    config.restore(backup, authorized=True)
    assert config.get("general", "theme") == "light"


def test_restore_requires_authorization(tmp_path: Path) -> None:
    config = ConfigurationManager(tmp_path / "app.json")
    backup = config.backup()
    try:
        config.restore(backup, authorized=False)
    except AuthorizationError:
        pass
    else:
        raise AssertionError("Debe requerirse autorización")


def test_version_switch_and_rollback(tmp_path: Path) -> None:
    registry = VersionRegistry(tmp_path)
    registry.register(VersionManifest if False else __import__("natxajo_auditor.versioning.version_registry", fromlist=["VersionManifest"]).VersionManifest("0.2.0", "beta", "0.2.x"))
    manager = VersionManager(registry)
    manager.load("0.1.0")
    manager.switch("0.2.0")
    assert manager.rollback() == "0.1.0"


def test_storage_backup_requires_explicit_restore(tmp_path: Path) -> None:
    source = tmp_path / "data.txt"
    source.write_text("prueba", encoding="utf-8")
    storage = StorageManager(tmp_path / "storage")
    backup = storage.backup_file(source)
    target = tmp_path / "restored.txt"
    try:
        storage.restore_file(backup, target)
    except PermissionError:
        pass
    else:
        raise AssertionError("Debe requerirse autorización")
