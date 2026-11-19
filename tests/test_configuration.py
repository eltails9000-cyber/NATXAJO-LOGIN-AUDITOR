import json
from pathlib import Path

import pytest

from natxajo_auditor.configuration.manager import ConfigurationManager
from natxajo_auditor.core.exceptions import AuthorizationError, ConfigurationError


def test_creates_defaults_on_first_load(tmp_path: Path) -> None:
    manager = ConfigurationManager(tmp_path / "config")
    assert (tmp_path / "config" / "app.json").is_file()
    assert manager.get("general", "locale") == "es"
    assert manager.get("auditing", "require_authorization") is True


def test_set_persists_and_keeps_previous_version(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    manager = ConfigurationManager(config_dir)
    manager.set("general", "theme", "light")
    assert ConfigurationManager(config_dir).get("general", "theme") == "light"
    assert len(manager.history()) == 1


def test_invalid_value_is_rejected_without_changing_file(tmp_path: Path) -> None:
    manager = ConfigurationManager(tmp_path / "config")
    path = tmp_path / "config" / "app.json"
    before = path.read_text(encoding="utf-8")
    with pytest.raises(ConfigurationError):
        manager.set("general", "theme", "neon")
    assert path.read_text(encoding="utf-8") == before
    assert manager.get("general", "theme") == "dark"


def test_authorization_requirement_cannot_be_disabled(tmp_path: Path) -> None:
    manager = ConfigurationManager(tmp_path / "config")
    with pytest.raises(ConfigurationError):
        manager.set("auditing", "require_authorization", False)


@pytest.mark.parametrize("value", [0, 21, True, "5"])
def test_max_requests_bounds_and_types(tmp_path: Path, value: object) -> None:
    manager = ConfigurationManager(tmp_path / "config")
    with pytest.raises(ConfigurationError):
        manager.set("auditing", "max_requests", value)


def test_unknown_key_is_rejected(tmp_path: Path) -> None:
    manager = ConfigurationManager(tmp_path / "config")
    with pytest.raises(ConfigurationError):
        manager.set("general", "colour", "red")


def test_invalid_json_is_never_overwritten(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    path = config_dir / "app.json"
    path.write_text("{no es json", encoding="utf-8")
    with pytest.raises(ConfigurationError):
        ConfigurationManager(config_dir)
    assert path.read_text(encoding="utf-8") == "{no es json"


def test_backup_restore_requires_authorization(tmp_path: Path) -> None:
    manager = ConfigurationManager(tmp_path / "config")
    manager.set("general", "theme", "light")
    backup = manager.backup()
    manager.set("general", "theme", "contrast")

    with pytest.raises(AuthorizationError):
        manager.restore(backup)
    assert manager.get("general", "theme") == "contrast"

    manager.restore(backup, authorized=True)
    assert manager.get("general", "theme") == "light"


def test_altered_backup_is_refused(tmp_path: Path) -> None:
    manager = ConfigurationManager(tmp_path / "config")
    backup = manager.backup()
    backup.write_text(json.dumps({"general": {"theme": "light"}}), encoding="utf-8")
    with pytest.raises(ConfigurationError):
        manager.restore(backup, authorized=True)
