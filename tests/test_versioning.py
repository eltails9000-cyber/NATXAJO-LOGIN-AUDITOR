from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from natxajo_auditor.core.exceptions import ValidationError, VersionError
from natxajo_auditor.storage.audit import AuditLog
from natxajo_auditor.storage.database import Database
from natxajo_auditor.storage.migrations import apply_migrations
from natxajo_auditor.versioning.channels import Channel
from natxajo_auditor.versioning.manager import ACTIVE_KEY, VersionManager
from natxajo_auditor.versioning.manifest import VersionManifest, kernel_matches
from natxajo_auditor.versioning.registry import VersionRegistry

REPO_ROOT = Path(__file__).resolve().parents[1]


def _valid_data() -> dict[str, Any]:
    return {
        "version": "0.1.0",
        "channel": "development",
        "compatible_kernel": "0.1.x",
        "name": "Versión",
        "description": "Descripción",
    }


def test_shipped_manifest_is_valid() -> None:
    versions = VersionRegistry(REPO_ROOT / "versions").available()
    assert [item.version for item in versions] == ["0.1.0"]
    assert versions[0].channel is Channel.DEVELOPMENT


def test_kernel_compatibility_rules() -> None:
    assert kernel_matches("0.1.x", "0.1.0")
    assert kernel_matches("0.1.x", "0.1.7")
    assert not kernel_matches("0.1.x", "0.2.0")
    assert kernel_matches("0.1.0", "0.1.0")
    assert not kernel_matches("0.1.0", "0.1.1")


@pytest.mark.parametrize(
    "overrides",
    [
        {"channel": "rc"},
        {"version": "1.0"},
        {"compatible_kernel": "0.1"},
        {"name": "  "},
        {"dependencies": "no-es-lista"},
        {"extra": 1},
    ],
)
def test_invalid_manifest_is_rejected(overrides: dict[str, Any]) -> None:
    data = {**_valid_data(), **overrides}
    with pytest.raises(ValidationError):
        VersionManifest.from_mapping(data)


def test_manifest_missing_field_is_rejected() -> None:
    data = _valid_data()
    del data["description"]
    with pytest.raises(ValidationError):
        VersionManifest.from_mapping(data)


def test_directory_must_match_declared_version(
    tmp_path: Path, make_manifest: Callable[..., Path]
) -> None:
    folder_version = tmp_path / "versions"
    make_manifest(folder_version, "0.3.0", version="0.2.0")
    with pytest.raises(ValidationError):
        VersionRegistry(folder_version).available()


@pytest.fixture
def manager(tmp_path: Path, make_manifest: Callable[..., Path]) -> VersionManager:
    versions = tmp_path / "versions"
    make_manifest(versions, "0.1.0")
    make_manifest(versions, "0.1.1")
    make_manifest(versions, "0.2.0", compatible_kernel="0.2.x")
    database = Database(tmp_path / "storage" / "versions.db")
    database.open()
    apply_migrations(database)
    return VersionManager(
        registry=VersionRegistry(versions),
        database=database,
        audit=AuditLog(database),
        kernel_version="0.1.0",
    )


def test_load_activates_and_persists(manager: VersionManager) -> None:
    assert manager.active is None
    manager.load("0.1.0")
    assert manager.active == "0.1.0"


def test_incompatible_version_cannot_be_loaded(manager: VersionManager) -> None:
    with pytest.raises(VersionError):
        manager.load("0.2.0")
    assert manager.active is None


def test_unknown_version_cannot_be_loaded(manager: VersionManager) -> None:
    with pytest.raises(VersionError):
        manager.load("9.9.9")


def test_unresolved_dependencies_block_loading(
    tmp_path: Path, make_manifest: Callable[..., Path]
) -> None:
    versions = tmp_path / "versions"
    make_manifest(versions, "0.1.0", dependencies=["modulo-inexistente"])
    database = Database(tmp_path / "storage" / "deps.db")
    database.open()
    apply_migrations(database)
    manager = VersionManager(
        VersionRegistry(versions), database, AuditLog(database), kernel_version="0.1.0"
    )
    with pytest.raises(VersionError):
        manager.load("0.1.0")


def test_switch_history_and_rollback(manager: VersionManager) -> None:
    manager.load("0.1.0")
    manager.load("0.1.1")
    assert manager.rollback().version == "0.1.0"
    assert manager.active == "0.1.0"
    assert manager.history() == ["0.1.0", "0.1.1", "0.1.0"]


def test_rollback_without_previous_version_is_refused(manager: VersionManager) -> None:
    manager.load("0.1.0")
    with pytest.raises(VersionError):
        manager.rollback()


def test_rollback_without_active_version_is_refused(manager: VersionManager) -> None:
    with pytest.raises(VersionError):
        manager.rollback()


def test_status_reports_compatibility(manager: VersionManager) -> None:
    statuses = {item.manifest.version: item for item in manager.available()}
    assert statuses["0.1.0"].compatible
    assert not statuses["0.2.0"].compatible
    assert statuses["0.2.0"].problems


def test_active_version_survives_new_manager_instance(
    manager: VersionManager, tmp_path: Path, make_manifest: Callable[..., Path]
) -> None:
    manager.load("0.1.0")
    database = Database(tmp_path / "storage" / "versions.db")
    database.open()
    reopened = VersionManager(
        VersionRegistry(tmp_path / "versions"), database, AuditLog(database), "0.1.0"
    )
    assert reopened.active == "0.1.0"
    assert database.fetchall(
        "SELECT value FROM platform_metadata WHERE key = ?", (ACTIVE_KEY,)
    ) == [("0.1.0",)]
