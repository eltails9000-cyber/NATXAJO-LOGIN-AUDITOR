"""Utilidades de bajo nivel: hashes, marcas de tiempo y escritura atómica."""

from __future__ import annotations

import hashlib
import os
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

Clock = Callable[[], datetime]

# Celdas que una hoja de cálculo interpretaría como fórmula. Se neutralizan con una comilla previa.
FORMULA_PREFIXES: tuple[str, ...] = ("=", "+", "-", "@", "\t", "\r")


def csv_cell(value: object) -> str:
    """Texto de una celda CSV segura: sin formulas ejecutables y con booleanos en minúsculas."""
    if value is None:
        text = ""
    elif isinstance(value, bool):
        text = "true" if value else "false"
    else:
        text = str(value)
    if text.startswith(FORMULA_PREFIXES):
        return "'" + text
    return text


def utc_now() -> datetime:
    """Instante actual con zona horaria UTC. Es el reloj por defecto del núcleo."""
    return datetime.now(UTC)


def utc_stamp() -> str:
    """Marca UTC con microsegundos, útil para nombres de archivo únicos."""
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")


def utc_iso() -> str:
    """Marca UTC en formato ISO 8601."""
    return datetime.now(UTC).isoformat(timespec="seconds")


def to_iso(moment: datetime) -> str:
    """Texto ISO 8601 en UTC, en segundos. Así las comparaciones de texto y de instante coinciden."""
    if moment.tzinfo is None:
        raise ValueError("el instante debe tener zona horaria")
    return moment.astimezone(UTC).isoformat(timespec="seconds")


def from_iso(text: str | None) -> datetime | None:
    return None if text is None else datetime.fromisoformat(text)


def sha256_file(path: Path) -> str:
    """Calcula el SHA-256 de un archivo en bloques."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """SHA-256 de un bloque de bytes en hexadecimal."""
    return hashlib.sha256(data).hexdigest()


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Escribe en un temporal del mismo directorio y lo sustituye de forma atómica.

    Si la escritura falla, el destino original no se modifica.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def atomic_write_text(path: Path, text: str) -> None:
    """Versión de texto UTF-8 de atomic_write_bytes."""
    atomic_write_bytes(path, text.encode("utf-8"))
