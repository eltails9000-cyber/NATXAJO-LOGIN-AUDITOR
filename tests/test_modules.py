from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from natxajo_auditor.core.exceptions import ModuleError, ValidationError, VersionError
from natxajo_auditor.modules.dependency_graph import resolve_load_order
from natxajo_auditor.modules.discovery import discover_modules
from natxajo_auditor.modules.manager import DISABLED_EVENT, ENABLED_EVENT, ModuleManager
from natxajo_auditor.modules.manifest import ModuleManifest
from natxajo_auditor.storage.audit import AuditLog
from natxajo_auditor.storage.database import Database
from natxajo_auditor.storage.migrations import apply_migrations
from natxajo_auditor.versioning.manager import VersionManager
from natxajo_auditor.versioning.registry import VersionRegistry


def _valid() -> dict[str, Any]:
    return {"id": "base_mod", "name": "Base", "version": "0.1.0", "description": "Prueba"}


def _manifest(**overrides: Any) -> ModuleManifest:
    return ModuleManifest.from_mapping({**_valid(), **overrides})


def _graph(spec: dict[str, tuple[str, ...]]) -> dict[str, ModuleManifest]:
    return {
        module_id: _manifest(id=module_id, requires=list(req)) for module_id, req in spec.items()
    }


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    db = Database(tmp_path / "storage" / "modulos.db")
    db.open()
    apply_migrations(db)
    yield db
    db.close()


@pytest.fixture
def modules(tmp_path: Path, database: Database) -> ModuleManager:
    return ModuleManager(tmp_path / "modules", database, AuditLog(database))


# Manifiesto


@pytest.mark.parametrize(
    "overrides",
    [
        {"id": "A"},
        {"id": "Mayusculas_no"},
        {"version": "1.0"},
        {"requires": "texto"},
        {"requires": ["base_mod"]},
        {"requires": ["Mal Id"]},
        {"requires": ["otro", "otro"]},
        {"permissions": ["no.existe"]},
        {"permissions": ["auditoria:nucleo:evento:leer", "auditoria:nucleo:evento:leer"]},
        {"extra": 1},
    ],
)
def test_invalid_module_manifest_is_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        _manifest(**overrides)


def test_module_manifest_missing_field_is_rejected() -> None:
    data = _valid()
    del data["name"]
    with pytest.raises(ValidationError):
        ModuleManifest.from_mapping(data)


def test_valid_module_manifest_keeps_declared_permissions() -> None:
    manifest = _manifest(
        permissions=["auditoria:nucleo:evento:leer", "almacenamiento:nucleo:copia:leer"],
        requires=["otro_mod"],
    )
    assert manifest.permissions == (
        "auditoria:nucleo:evento:leer",
        "almacenamiento:nucleo:copia:leer",
    )
    assert manifest.requires == ("otro_mod",)


# Descubrimiento


def test_broken_module_does_not_stop_discovery(
    tmp_path: Path, make_module: Callable[..., Path]
) -> None:
    modules_dir = tmp_path / "modules"
    make_module(modules_dir, "modulo_bueno")
    make_module(modules_dir, "modulo_roto", permissions=["no.existe"])
    make_module(modules_dir, "carpeta_distinta", id="otro_id")
    result = discover_modules(modules_dir)
    assert set(result.manifests) == {"modulo_bueno"}
    assert set(result.errors) == {"modulo_roto", "carpeta_distinta"}


# Grafo de dependencias


def test_dependencies_are_loaded_first() -> None:
    manifests = _graph({"a_mod": ("b_mod",), "b_mod": ("c_mod",), "c_mod": ()})
    assert resolve_load_order(manifests, "a_mod") == ["c_mod", "b_mod", "a_mod"]


def test_missing_dependency_is_reported() -> None:
    manifests = _graph({"a_mod": ("falta_mod",)})
    with pytest.raises(ValidationError, match="no instalado"):
        resolve_load_order(manifests, "a_mod")


def test_dependency_cycle_is_reported() -> None:
    manifests = _graph({"a_mod": ("b_mod",), "b_mod": ("a_mod",)})
    with pytest.raises(ValidationError, match="ciclo de dependencias"):
        resolve_load_order(manifests, "a_mod")


# Habilitación


def test_enable_also_enables_dependencies(
    modules: ModuleManager, tmp_path: Path, make_module: Callable[..., Path]
) -> None:
    make_module(tmp_path / "modules", "base_mod")
    make_module(tmp_path / "modules", "ui_mod", requires=["base_mod"])
    assert modules.enable("ui_mod") == ["base_mod", "ui_mod"]
    assert modules.enabled_ids() == {"base_mod", "ui_mod"}
    assert modules.enable("ui_mod") == []


def test_broken_module_cannot_be_enabled(
    modules: ModuleManager, tmp_path: Path, make_module: Callable[..., Path]
) -> None:
    make_module(tmp_path / "modules", "roto_mod", permissions=["mal.permiso"])
    with pytest.raises(ModuleError, match="manifiesto inválido"):
        modules.enable("roto_mod")


def test_unknown_module_cannot_be_enabled(modules: ModuleManager) -> None:
    with pytest.raises(ModuleError, match="no instalado"):
        modules.enable("no_existe")


def test_missing_dependency_leaves_state_unchanged(
    modules: ModuleManager, tmp_path: Path, make_module: Callable[..., Path]
) -> None:
    make_module(tmp_path / "modules", "ui_mod", requires=["falta_mod"])
    with pytest.raises(ModuleError):
        modules.enable("ui_mod")
    assert modules.enabled_ids() == set()


def test_disable_is_blocked_by_enabled_dependents(
    modules: ModuleManager, tmp_path: Path, make_module: Callable[..., Path]
) -> None:
    make_module(tmp_path / "modules", "base_mod")
    make_module(tmp_path / "modules", "ui_mod", requires=["base_mod"])
    modules.enable("ui_mod")
    with pytest.raises(ModuleError, match="lo requieren ui_mod"):
        modules.disable("base_mod")
    modules.disable("ui_mod")
    modules.disable("base_mod")
    assert modules.enabled_ids() == set()


def test_state_changes_are_audited(
    modules: ModuleManager,
    tmp_path: Path,
    make_module: Callable[..., Path],
    database: Database,
) -> None:
    make_module(tmp_path / "modules", "base_mod")
    modules.enable("base_mod")
    modules.disable("base_mod")
    types = {event["event_type"] for event in AuditLog(database).list_events(limit=10)}
    assert {ENABLED_EVENT, DISABLED_EVENT} <= types


def test_state_survives_reopening_the_database(
    modules: ModuleManager,
    tmp_path: Path,
    make_module: Callable[..., Path],
    database: Database,
) -> None:
    make_module(tmp_path / "modules", "base_mod")
    modules.enable("base_mod")
    database.close()
    reopened = Database(tmp_path / "storage" / "modulos.db")
    reopened.open()
    try:
        assert ModuleManager(tmp_path / "modules", reopened, AuditLog(reopened)).is_enabled(
            "base_mod"
        )
    finally:
        reopened.close()


# Diagnóstico


def test_diagnose_reports_broken_and_missing(
    modules: ModuleManager, tmp_path: Path, make_module: Callable[..., Path]
) -> None:
    make_module(tmp_path / "modules", "roto_mod", permissions=["desconocido:nucleo:evento:leer"])
    make_module(tmp_path / "modules", "ui_mod", requires=["falta_mod"])
    report = modules.diagnose()
    assert "subsistema desconocido" in report["roto_mod"][0]
    assert any("no instalado" in problem for problem in report["ui_mod"])


def test_diagnose_flags_enabled_module_with_disabled_dependency(
    modules: ModuleManager,
    tmp_path: Path,
    make_module: Callable[..., Path],
    database: Database,
) -> None:
    make_module(tmp_path / "modules", "base_mod")
    make_module(tmp_path / "modules", "ui_mod", requires=["base_mod"])
    modules.enable("ui_mod")
    database.execute("UPDATE module_states SET enabled = 0 WHERE module_id = 'base_mod'")
    assert any("dependencias deshabilitadas" in problem for problem in modules.diagnose()["ui_mod"])


# Integración con versiones


def test_version_requires_its_modules_to_be_enabled(
    modules: ModuleManager,
    tmp_path: Path,
    make_manifest: Callable[..., Path],
    make_module: Callable[..., Path],
    database: Database,
) -> None:
    versions = tmp_path / "versions"
    make_manifest(versions, "0.1.0", dependencies=["base_mod"])
    make_module(tmp_path / "modules", "base_mod")
    manager = VersionManager(
        registry=VersionRegistry(versions),
        database=database,
        audit=AuditLog(database),
        kernel_version="0.1.0",
        module_enabled=modules.is_enabled,
    )
    with pytest.raises(VersionError, match="base_mod"):
        manager.load("0.1.0")
    modules.enable("base_mod")
    assert manager.load("0.1.0").version == "0.1.0"
