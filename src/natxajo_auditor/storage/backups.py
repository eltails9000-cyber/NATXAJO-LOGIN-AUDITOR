"""Copias de seguridad con manifiesto SHA-256.

Una copia solo se restaura si su hash coincide con el registrado al crearla. La restauración
requiere autorización explícita y nunca sobrescribe un destino existente sin confirmación
adicional (overwrite=True).
"""

from __future__ import annotations

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
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        target = self.backup_dir / f"{utc_stamp()}-{_slug(label)}-{source.name}"
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
        return target

    def problem(self, backup: Path) -> str | None:
        """Devuelve el motivo por el que la copia no es válida, o None si lo es."""
        if not backup.is_file():
            return "falta la copia"
        manifest_path = _manifest_path(backup)
        if not manifest_path.is_file():
            return "falta el manifiesto"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return f"manifiesto ilegible: {exc}"
        expected = manifest.get("sha256") if isinstance(manifest, dict) else None
        if not isinstance(expected, str):
            return "el manifiesto no contiene sha256"
        if sha256_file(backup) != expected:
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
        atomic_write_bytes(target, backup.read_bytes())

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


def _slug(label: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in "-_" else "-" for char in label)
    return cleaned or "copia"
