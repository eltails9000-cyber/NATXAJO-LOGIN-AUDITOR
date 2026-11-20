"""Estructura de un paquete de plugin: listado, integridad, firma y copia.

Un paquete es una carpeta con:
  plugin.json     manifiesto declarativo
  integrity.json  hash SHA-256 de cada archivo del paquete (salvo integrity.json y signature.json)
  signature.json  firma Ed25519 de los bytes exactos de integrity.json
  ...             contenido del plugin

Como integrity.json incluye el hash de plugin.json, la firma protege también el manifiesto.
Los enlaces simbólicos y las entradas que no son archivos regulares se rechazan.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
from collections.abc import Mapping
from pathlib import Path

from natxajo_auditor.core import ed25519
from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.core.utilities import sha256_file

INTEGRITY_FILE = "integrity.json"
SIGNATURE_FILE = "signature.json"
META_FILES = frozenset({INTEGRITY_FILE, SIGNATURE_FILE})
INTEGRITY_FORMAT = 1


def list_files(root: Path) -> dict[str, Path]:
    """Todos los archivos del paquete, indexados por ruta relativa POSIX."""
    if not root.is_dir():
        raise ValidationError(f"no es una carpeta de paquete: {root}")
    found: dict[str, Path] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        for name in (*dirnames, *filenames):
            entry = base / name
            if entry.is_symlink():
                raise ValidationError(
                    f"enlaces simbólicos no permitidos: {entry.relative_to(root).as_posix()}"
                )
        for name in filenames:
            entry = base / name
            relative = entry.relative_to(root).as_posix()
            if not entry.is_file():
                raise ValidationError(f"entrada no admitida en el paquete: {relative}")
            found[relative] = entry
    return found


def compute_hashes(root: Path) -> dict[str, str]:
    return {
        relative: sha256_file(path)
        for relative, path in sorted(list_files(root).items())
        if relative not in META_FILES
    }


def write_integrity(root: Path) -> bytes:
    """Escribe integrity.json con el hash de cada archivo y devuelve sus bytes exactos."""
    document = {"format": INTEGRITY_FORMAT, "files": compute_hashes(root)}
    data = (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    (root / INTEGRITY_FILE).write_bytes(data)
    return data


def verify_files(root: Path, expected: Mapping[str, str]) -> None:
    """Comprueba que el paquete tiene exactamente los archivos declarados, con sus hashes."""
    actual = compute_hashes(root)
    missing = sorted(set(expected) - set(actual))
    undeclared = sorted(set(actual) - set(expected))
    altered = sorted(path for path in expected if path in actual and actual[path] != expected[path])
    problems: list[str] = []
    if missing:
        problems.append("faltan archivos: " + ", ".join(missing))
    if undeclared:
        problems.append("archivos no declarados: " + ", ".join(undeclared))
    if altered:
        problems.append("archivos alterados: " + ", ".join(altered))
    if problems:
        raise ValidationError("integridad no válida: " + "; ".join(problems))


def copy_package(source: Path, destination: Path) -> None:
    """Copia todos los archivos del paquete. El destino no debe existir."""
    files = list_files(source)
    destination.mkdir(parents=True, exist_ok=False)
    for relative, path in sorted(files.items()):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)


def build_package(root: Path, secret_key: bytes, key_id: str) -> None:
    """Genera integrity.json y signature.json para una carpeta con plugin.json y su contenido."""
    integrity = write_integrity(root)
    signature = ed25519.sign(secret_key, integrity)
    document = {
        "algorithm": "ed25519",
        "key_id": key_id,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    (root / SIGNATURE_FILE).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
