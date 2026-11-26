"""Errores de E/S en limpieza, copias y diagnóstico: un fallo se ve como fallo, no se oculta y no
detiene el resto del trabajo.

- Limpieza: un archivo que no se puede borrar no detiene la limpieza ni cuenta como eliminado.
- Copias: un manifiesto ilegible o una copia que no se puede leer es un problema devuelto, no una
  excepción sin tratar ni una copia válida. Una copia que falla al crearse no queda a medias.
- Diagnóstico: cada comprobación se ejecuta por separado; una que falla queda como error visible.
"""

from __future__ import annotations

import errno
from pathlib import Path
from typing import Any

import pytest

from natxajo_auditor.core.exceptions import StorageError
from natxajo_auditor.kernel.kernel import Kernel
from natxajo_auditor.maintenance import diagnostics
from natxajo_auditor.maintenance.cleanup import apply_cleanup, temp_files
from natxajo_auditor.storage import backups as backups_module
from natxajo_auditor.storage.backups import BackupManager
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER

NOMBRES_COMPROBACIONES = {
    "python",
    "sqlite",
    "base_de_datos",
    "migraciones",
    "eventos",
    "copias",
    "temporales",
    "escritura",
}


def _temp(folder: Path, name: str) -> Path:
    path = folder / name
    path.write_text("temporal", encoding="utf-8")
    return path


def _denied(*_args: Any, **_kwargs: Any) -> None:
    raise PermissionError(errno.EACCES, "Permission denied")


# --- Limpieza -----------------------------------------------------------------------------------


def test_a_file_that_cannot_be_removed_does_not_stop_the_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    managed = tmp_path / "gestionada"
    managed.mkdir()
    primero = _temp(managed, "a.tmp")
    bloqueado = _temp(managed, "b.tmp")
    ultimo = _temp(managed, "c.tmp")
    original = Path.unlink

    def unlink(self: Path, missing_ok: bool = False) -> None:
        if self.name == bloqueado.name:
            raise PermissionError(errno.EACCES, "Permission denied")
        original(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", unlink)
    result = apply_cleanup(temp_files([managed]), [managed])
    assert [path.name for path in result.removed] == [primero.name, ultimo.name]
    assert [(path.name, reason) for path, reason in result.failed] == [
        (bloqueado.name, "Permission denied")
    ]
    assert not primero.exists()
    assert not ultimo.exists()
    # Lo que no se borró sigue en el disco y no figura como eliminado.
    assert bloqueado.exists()


def test_paths_outside_the_rules_are_skipped_not_failed(tmp_path: Path) -> None:
    managed = tmp_path / "gestionada"
    managed.mkdir()
    datos = managed / "datos.sqlite"
    datos.write_text("no es temporal", encoding="utf-8")
    result = apply_cleanup([datos], [managed])
    assert result.removed == ()
    assert result.failed == ()
    assert result.skipped == (datos,)
    assert datos.exists()


# --- Copias -------------------------------------------------------------------------------------


def _copia(tmp_path: Path) -> tuple[BackupManager, Path]:
    origen = tmp_path / "origen.sqlite"
    origen.write_bytes(b"datos de prueba")
    manager = BackupManager(tmp_path / "copias")
    return manager, manager.create(origen, "prueba")


def test_an_unreadable_manifest_is_a_problem_not_an_exception(tmp_path: Path) -> None:
    manager, copia = _copia(tmp_path)
    manifiesto = copia.with_name(copia.name + ".manifest.json")
    manifiesto.write_bytes(b"\xff\xfe no es utf-8")
    motivo = manager.problem(copia)
    assert motivo is not None
    assert motivo.startswith("manifiesto ilegible")
    assert manager.integrity()["status"] == "degraded"


def test_a_copy_that_cannot_be_read_is_reported_not_declared_valid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager, copia = _copia(tmp_path)
    monkeypatch.setattr(backups_module, "sha256_file", _denied)
    assert manager.problem(copia) == "copia ilegible: Permission denied"


def test_a_failed_copy_leaves_no_partial_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    origen = tmp_path / "origen.sqlite"
    origen.write_bytes(b"datos")
    manager = BackupManager(tmp_path / "copias")

    def sin_espacio(*_args: Any, **_kwargs: Any) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(backups_module, "atomic_write_text", sin_espacio)
    with pytest.raises(StorageError, match="No space left on device"):
        manager.create(origen, "prueba")
    assert list(manager.backup_dir.iterdir()) == []


def test_a_restore_that_cannot_write_reports_a_storage_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager, copia = _copia(tmp_path)
    destino = tmp_path / "destino.sqlite"
    monkeypatch.setattr(backups_module, "atomic_write_bytes", _denied)
    with pytest.raises(StorageError, match="Permission denied"):
        manager.restore(copia, destino, authorized=True)
    assert not destino.exists()


# --- Diagnóstico --------------------------------------------------------------------------------


def _diagnostico(kernel: Kernel) -> dict[str, tuple[str, str]]:
    token = kernel.security.login(ADMIN_USER, ADMIN_PASSWORD)
    resultado = kernel.maintenance.diagnose(token)
    comprobaciones = resultado["comprobaciones"]
    assert isinstance(comprobaciones, list)
    return {
        str(item["nombre"]): (str(item["estado"]), str(item["detalle"]))
        for item in comprobaciones
        if isinstance(item, dict)
    }


def test_a_check_that_raises_is_an_error_and_the_others_still_run(
    kernel: Kernel, admin: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(BackupManager, "integrity", _denied)
    estados = _diagnostico(kernel)
    assert set(estados) == NOMBRES_COMPROBACIONES
    assert estados["copias"] == ("error", "no se pudo comprobar: PermissionError")
    assert estados["python"][0] == "ok"
    assert estados["base_de_datos"][0] == "ok"


def test_an_unreadable_temporary_folder_is_an_error_not_a_hidden_problem(
    kernel: Kernel, admin: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(diagnostics, "temp_files", _denied)
    estados = _diagnostico(kernel)
    assert estados["temporales"] == ("error", "no se pudo comprobar: PermissionError")
    assert estados["copias"][0] == "ok"
