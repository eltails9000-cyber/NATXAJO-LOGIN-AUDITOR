"""Utilidades de bajo nivel: hashes, marcas de tiempo y escritura atómica."""

from __future__ import annotations

import hashlib
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path


def utc_stamp() -> str:
    """Marca UTC con microsegundos, útil para nombres de archivo únicos."""
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")


def utc_iso() -> str:
    """Marca UTC en formato ISO 8601."""
    return datetime.now(UTC).isoformat(timespec="seconds")


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
