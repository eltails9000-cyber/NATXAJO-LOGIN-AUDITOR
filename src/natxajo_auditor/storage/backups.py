"""Copias de seguridad con manifiesto SHA-256.

Una copia solo se restaura si su hash coincide con el registrado al crearla. La restauración
requiere autorización explícita y nunca sobrescribe un destino existente sin confirmación
adicional (overwrite=True).
"""

from __future__ import annotations

import contextlib
import json
import shutil
from pathlib import Path
from typing import Any

from natxajo_auditor.core.exceptions import AuthorizationError, StorageError
from natxajo_auditor.core.utilities import (
    atomic_write_bytes,
    atomic_write_text,
    sha256_file,
    utc_iso,
    utc_stamp,
)

MANIFEST_SUFFIX = ".manifest.json"


class BackupManager:
    def __init__(self, backup_dir: Path) -> None:
        self.backup_dir = backup_dir

    def create(self, source: Path, label: str) -> Path:
        if not source.is_file():
            raise StorageError(f"No existe el archivo a copiar: {source}")
        target = self.backup_dir / f"{utc_stamp()}-{_slug(label)}-{source.name}"
        try:
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            manifest: dict[str, Any] = {
                "source": str(source),
                "backup": target.name,
                "sha256": sha256_file(target),
                "created_at": utc_iso(),
            }
            atomic_write_text(
                _manifest_path(target), json.dumps(manifest, ensure_ascii=False, indent=2)
            )
        except OSError as exc:
            # Una copia incompleta no debe quedar. Si su borrado falla, queda sin manifiesto y
            # la verificación de copias la marca como problema.
            with contextlib.suppress(OSError):
                target.unlink(missing_ok=True)
                _manifest_path(target).unlink(missing_ok=True)
            raise StorageError(f"No se pudo crear la copia: {_motivo(exc)}") from exc
        return target

    def problem(self, backup: Path) -> str | None:
        """Devuelve el motivo por el que la copia no es válida, o None si lo es.

        Nunca lanza por un archivo ilegible: un manifiesto roto o una copia que no se puede leer
        es un problema que se devuelve, no una copia válida ni un error sin tratar.
        """
        if not backup.is_file():
            return "falta la copia"
        manifest_path = _manifest_path(backup)
        if not manifest_path.is_file():
            return "falta el manifiesto"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            # JSONDecodeError y UnicodeDecodeError son ValueError.
            return f"manifiesto ilegible: {_motivo(exc)}"
        expected = manifest.get("sha256") if isinstance(manifest, dict) else None
        if not isinstance(expected, str):
            return "el manifiesto no contiene sha256"
        try:
            actual = sha256_file(backup)
        except OSError as exc:
            return f"copia ilegible: {_motivo(exc)}"
        if actual != expected:
            return "el hash no coincide: la copia fue alterada"
        return None

    def restore(
        self,
        backup: Path,
        target: Path,
        *,
        authorized: bool = False,
        overwrite: bool = False,
    ) -> None:
        if not authorized:
            raise AuthorizationError("La restauración requiere autorización explícita")
        reason = self.problem(backup)
        if reason is not None:
            raise StorageError(f"La copia no se puede restaurar: {reason}")
        if target.exists() and not overwrite:
            raise StorageError(
                "El destino ya existe; sustituirlo requiere confirmación explícita (overwrite)"
            )
        try:
            content = backup.read_bytes()
            atomic_write_bytes(target, content)
        except OSError as exc:
            raise StorageError(f"No se pudo restaurar la copia: {_motivo(exc)}") from exc

    def backups(self) -> list[Path]:
        if not self.backup_dir.is_dir():
            return []
        return sorted(
            path
            for path in self.backup_dir.iterdir()
            if path.is_file() and not path.name.endswith(MANIFEST_SUFFIX)
        )

    def integrity(self) -> dict[str, object]:
        """Verifica cada copia y detecta manifiestos huérfanos."""
        problems: list[str] = []
        for backup in self.backups():
            reason = self.problem(backup)
            if reason is not None:
                problems.append(f"{backup.name}: {reason}")
        if self.backup_dir.is_dir():
            for manifest in sorted(self.backup_dir.glob(f"*{MANIFEST_SUFFIX}")):
                original = manifest.name[: -len(MANIFEST_SUFFIX)]
                if not (self.backup_dir / original).is_file():
                    problems.append(f"{manifest.name}: falta la copia")
        return {"status": "healthy" if not problems else "degraded", "problems": problems}


def _manifest_path(backup: Path) -> Path:
    return backup.with_name(backup.name + MANIFEST_SUFFIX)


def _motivo(error: BaseException) -> str:
    """Motivo legible sin rutas ni contenido: el mensaje del sistema o el tipo de error."""
    if isinstance(error, OSError) and error.strerror:
        return error.strerror
    return type(error).__name__


def _slug(label: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in "-_" else "-" for char in label)
    return cleaned or "copia"
