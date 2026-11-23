"""Limpieza de archivos temporales de la plataforma. Solo borra `*.tmp` regulares y dentro de carpetas
gestionadas.

Los escritores atómicos crean un `.tmp` junto al destino y lo sustituyen al terminar. Un proceso
que se interrumpe deja ese temporal. La limpieza solo considera esos archivos: nunca borra bases de
datos, copias, informes ni configuración. No sigue enlaces simbólicos. Solo mira las carpetas
gestionadas y sus subcarpetas directas (por ejemplo `reports/<empresa>/`).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import Final

TEMP_SUFFIX: Final = ".tmp"


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


def apply_cleanup(paths: Sequence[Path], directories: Iterable[Path]) -> int:
    """Borra los temporales de la lista que siguen cumpliendo las reglas. Devuelve cuántos borró."""
    allowed = {folder.resolve() for folder in _folders(directories)}
    removed = 0
    for path in paths:
        if path.is_symlink() or not path.is_file() or not path.name.endswith(TEMP_SUFFIX):
            continue
        if path.parent.resolve() not in allowed:
            continue
        path.unlink()
        removed += 1
    return removed
