"""Mantenimiento: diagnóstico, limpieza de temporales con confirmación y permisos."""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from natxajo_auditor.core.exceptions import AuthorizationError, ValidationError
from natxajo_auditor.kernel.kernel import SERVICE_DATABASE, Kernel
from natxajo_auditor.maintenance.cleanup import apply_cleanup, plan_cleanup, temp_files
from natxajo_auditor.maintenance.diagnostics import Status, collect_checks, overall
from natxajo_auditor.storage.database import Database
from tests.conftest import install_administrator

PASSWORD = "contraseña-de-prueba-5"
HOURS_AGO = 3 * 3600


@pytest.fixture
def world(kernel: Kernel) -> Kernel:
    install_administrator(kernel)
    security = kernel.security
    security.companies.create("acme", "Acme S.A.")
    security.create_account("admin_acme", PASSWORD, ["administrador"], "acme")
    for folder in (
        kernel.context.config_dir,
        kernel.context.storage_dir,
        kernel.context.reports_dir,
    ):
        folder.mkdir(parents=True, exist_ok=True)
    return kernel


def _old_file(path: Path, seconds: int = HOURS_AGO) -> Path:
    """Crea un archivo y lo fecha en el pasado."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("contenido de prueba", encoding="utf-8")
    past = time.time() - seconds
    os.utime(path, (past, past))
    return path


def _status(report: dict[str, object], name: str) -> str:
    checks = cast(list[dict[str, str]], report["comprobaciones"])
    return next(item["estado"] for item in checks if item["nombre"] == name)


def test_diagnostics_are_platform_only_and_cover_every_area(
    world: Kernel, platform_token: str
) -> None:
    with pytest.raises(AuthorizationError):
        world.maintenance.diagnose(world.security.login("admin_acme", PASSWORD))
    report = world.maintenance.diagnose(platform_token)
    names = [item["nombre"] for item in cast(list[dict[str, str]], report["comprobaciones"])]
    assert names == [
        "python",
        "sqlite",
        "base_de_datos",
        "migraciones",
        "eventos",
        "copias",
        "temporales",
        "escritura",
    ]
    assert _status(report, "base_de_datos") == "ok"
    assert _status(report, "migraciones") == "ok"
    assert _status(report, "copias") == "ok"
    assert report["estado"] in {"ok", "aviso"}


def test_a_leftover_temporary_file_is_reported_as_a_warning(
    world: Kernel, platform_token: str
) -> None:
    (world.context.config_dir / "perfil.json.tmp").write_text("pendiente", encoding="utf-8")
    report = world.maintenance.diagnose(platform_token)
    assert _status(report, "temporales") == "aviso"
    assert report["estado"] == "aviso"


def test_an_unsupported_python_is_an_error_and_an_old_sqlite_is_a_warning(
    world: Kernel,
) -> None:
    database = cast(Database, world.services.get(SERVICE_DATABASE))
    checks = collect_checks(
        database=database,
        outbox=world.outbox,
        backups=world.backups,
        managed_dirs=[],
        python_version=(3, 10, 12),
        sqlite_version=(3, 30, 0),
    )
    by_name = {check.name: check.status for check in checks}
    assert by_name["python"] is Status.ERROR
    assert by_name["sqlite"] is Status.AVISO
    assert overall(checks) is Status.ERROR


def test_cleanup_plans_only_old_temporary_files_inside_managed_folders(
    world: Kernel, platform_token: str
) -> None:
    config = world.context.config_dir
    reports = world.context.reports_dir / "acme"
    old_config = _old_file(config / "perfil.json.tmp")
    old_report = _old_file(reports / f"informe-{'0' * 8}.json.tmp")
    fresh = config / "reciente.json.tmp"
    fresh.write_text("en uso", encoding="utf-8")
    keep = _old_file(config / "perfil.json")
    outside = _old_file(world.context.project_root / "fuera.json.tmp")

    planned = world.maintenance.plan_cleanup(platform_token, older_than_hours=1)
    assert set(planned) == {str(old_config), str(old_report)}
    assert keep.exists() and outside.exists() and fresh.exists()


def test_cleanup_needs_explicit_confirmation_and_then_removes_only_the_planned_files(
    world: Kernel, platform_token: str
) -> None:
    old = _old_file(world.context.config_dir / "sesion.json.tmp")
    keep = _old_file(world.context.config_dir / "configuracion.json")
    with pytest.raises(AuthorizationError, match="confirmación"):
        world.maintenance.apply_cleanup(platform_token, older_than_hours=1, confirmed=False)
    assert old.exists()

    result = world.maintenance.apply_cleanup(platform_token, older_than_hours=1, confirmed=True)
    assert result == {
        "planeados": 1,
        "eliminados": 1,
        "fallidos": 0,
        "detalle_fallidos": [],
    }
    assert not old.exists()
    assert keep.exists()
    events = world.audit.events_of_type("maintenance.cleanup_applied")
    assert len(events) == 1


def test_company_administrators_cannot_diagnose_or_clean(world: Kernel) -> None:
    token = world.security.login("admin_acme", PASSWORD)
    _old_file(world.context.config_dir / "x.json.tmp")
    with pytest.raises(AuthorizationError):
        world.maintenance.diagnose(token)
    with pytest.raises(AuthorizationError):
        world.maintenance.plan_cleanup(token, older_than_hours=1)
    with pytest.raises(AuthorizationError):
        world.maintenance.apply_cleanup(token, older_than_hours=1, confirmed=True)


@pytest.mark.parametrize("hours", [0, -1, 24 * 365 + 1])
def test_the_age_limit_is_enforced(world: Kernel, platform_token: str, hours: int) -> None:
    with pytest.raises(ValidationError, match="antigüedad"):
        world.maintenance.plan_cleanup(platform_token, older_than_hours=hours)


def test_symbolic_links_are_never_planned_or_followed(
    world: Kernel, platform_token: str, tmp_path: Path
) -> None:
    target = _old_file(tmp_path / "Objetivo ñ fuera.txt")
    target.write_text("no tocar", encoding="utf-8")
    link = world.context.config_dir / "enlace.tmp"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("este sistema no permite crear enlaces simbólicos")
    past = time.time() - HOURS_AGO
    os.utime(link, (past, past), follow_symlinks=False)

    planned = world.maintenance.plan_cleanup(platform_token, older_than_hours=1)
    assert str(link) not in planned
    world.maintenance.apply_cleanup(platform_token, older_than_hours=1, confirmed=True)
    assert target.read_text(encoding="utf-8") == "no tocar"
    assert link.is_symlink()


def test_a_path_outside_the_managed_folders_is_not_removed(tmp_path: Path) -> None:
    managed = tmp_path / "gestionada"
    managed.mkdir()
    outside = _old_file(tmp_path / "fuera.tmp")
    result = apply_cleanup([outside], [managed])
    assert result.removed == ()
    assert result.skipped == (outside,)
    assert outside.exists()


def test_temporary_detection_looks_one_level_deep_only(tmp_path: Path) -> None:
    managed = tmp_path / "gestionada"
    (managed / "nivel1" / "nivel2").mkdir(parents=True)
    shallow = managed / "nivel1" / "a.tmp"
    deep = managed / "nivel1" / "nivel2" / "b.tmp"
    shallow.write_text("x", encoding="utf-8")
    deep.write_text("x", encoding="utf-8")
    found = temp_files([managed])
    assert shallow in found
    assert deep not in found


def test_planning_respects_the_clock(tmp_path: Path) -> None:
    managed = tmp_path / "gestionada"
    managed.mkdir()
    file = _old_file(managed / "viejo.tmp", seconds=2 * 3600)
    now = datetime.now(UTC)
    assert plan_cleanup([managed], now=now, older_than=timedelta(hours=1)) == [file]
    assert plan_cleanup([managed], now=now, older_than=timedelta(hours=3)) == []
