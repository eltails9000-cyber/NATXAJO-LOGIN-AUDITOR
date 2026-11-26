"""Limpieza de archivos temporales de la plataforma. Solo borra `*.tmp` regulares y dentro de carpetas
gestionadas.

Los escritores atómicos crean un `.tmp` junto al destino y lo sustituyen al terminar. Un proceso
que se interrumpe deja ese temporal. La limpieza solo considera esos archivos: nunca borra bases de
datos, copias, informes ni configuración. No sigue enlaces simbólicos. Solo mira las carpetas
gestionadas y sus subcarpetas directas (por ejemplo `reports/<empresa>/`).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Final

TEMP_SUFFIX: Final = ".tmp"


@dataclass(frozen=True)
class CleanupResult:
    """Qué pasó con cada ruta de la lista. Solo está en `removed` lo que se borró de verdad.

    `failed` guarda la ruta y el motivo (tipo o mensaje del sistema, sin ruta). `skipped` son las
    rutas que no cumplen las reglas (enlaces, carpetas no gestionadas, otra extensión).
    """

    removed: tuple[Path, ...]
    failed: tuple[tuple[Path, str], ...]
    skipped: tuple[Path, ...]


def _folders(directories: Iterable[Path]) -> list[Path]:
    """Cada carpeta gestionada y sus subcarpetas directas, sin enlaces."""
    folders: list[Path] = []
    for directory in directories:
        if not directory.is_dir() or directory.is_symlink():
            continue
        folders.append(directory)
        folders.extend(
            child
            for child in sorted(directory.iterdir())
            if child.is_dir() and not child.is_symlink()
        )
    return folders


def temp_files(directories: Iterable[Path]) -> list[Path]:
    """Temporales `*.tmp` regulares de las carpetas gestionadas, ordenados por ruta."""
    found: list[Path] = []
    for folder in _folders(directories):
        for path in folder.iterdir():
            if path.name.endswith(TEMP_SUFFIX) and path.is_file() and not path.is_symlink():
                found.append(path)
    return sorted(found)


def plan_cleanup(
    directories: Iterable[Path], *, now: datetime, older_than: timedelta
) -> list[Path]:
    """Temporales con más antigüedad que `older_than`. No borra nada."""
    limit = now.timestamp() - older_than.total_seconds()
    return [path for path in temp_files(directories) if path.stat().st_mtime < limit]


def apply_cleanup(paths: Sequence[Path], directories: Iterable[Path]) -> CleanupResult:
    """Borra los temporales de la lista que siguen cumpliendo las reglas.

    Un fallo en un archivo no detiene la limpieza: se anota y se sigue con el resto. Un archivo
    cuyo borrado falla nunca cuenta como eliminado.
    """
    allowed = {folder.resolve() for folder in _folders(directories)}
    removed: list[Path] = []
    failed: list[tuple[Path, str]] = []
    skipped: list[Path] = []
    for path in paths:
        try:
            if not _eligible(path, allowed):
                skipped.append(path)
                continue
            path.unlink()
        except OSError as exc:
            failed.append((path, _reason(exc)))
            continue
        removed.append(path)
    return CleanupResult(tuple(removed), tuple(failed), tuple(skipped))


def _eligible(path: Path, allowed: set[Path]) -> bool:
    return (
        not path.is_symlink()
        and path.is_file()
        and path.name.endswith(TEMP_SUFFIX)
        and path.parent.resolve() in allowed
    )


def _reason(error: OSError) -> str:
    """Motivo legible sin la ruta: el mensaje del sistema o el nombre del tipo de error."""
    return error.strerror or type(error).__name__
