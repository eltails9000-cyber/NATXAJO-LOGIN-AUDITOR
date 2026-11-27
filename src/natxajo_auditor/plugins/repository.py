"""Repositorio local de paquetes (catálogo). Sirve tanto para un catálogo público en disco como para
un repositorio privado accesible por ruta de red.

Formato del índice (index.json):
  {"format": 1, "plugins": [{"id", "version", "path", "sha256"}]}

El índice no está firmado. Su papel es comprobar que la entrada corresponde al paquete: el hash
debe coincidir con integrity.json del paquete. La confianza real procede de la firma del editor,
que se verifica al instalar. Los repositorios remotos por HTTPS no están implementados.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from natxajo_auditor.core.exceptions import PluginError, ValidationError
from natxajo_auditor.core.utilities import sha256_bytes
from natxajo_auditor.core.validation import require_identifier, require_semver, require_text
from natxajo_auditor.plugins.package import INTEGRITY_FILE, copy_package

INDEX_FILE = "index.json"
INDEX_FORMAT = 1
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class CatalogEntry:
    plugin_id: str
    version: str
    relative_path: str
    package_sha256: str


class LocalRepository:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def entries(self) -> list[CatalogEntry]:
        index_path = self.root / INDEX_FILE
        if not index_path.is_file():
            raise ValidationError(f"el repositorio no contiene {INDEX_FILE}")
        try:
            document = json.loads(index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValidationError(f"{INDEX_FILE} ilegible: {exc}") from exc
        if not isinstance(document, dict) or document.get("format") != INDEX_FORMAT:
            raise ValidationError(f"formato de índice no soportado en {INDEX_FILE}")
        raw_entries = document.get("plugins")
        if not isinstance(raw_entries, list):
            raise ValidationError(f"{INDEX_FILE} no contiene la lista plugins")
        return [_parse_entry(raw) for raw in raw_entries]

    def find(self, plugin_id: str, version: str) -> CatalogEntry:
        for entry in self.entries():
            if entry.plugin_id == plugin_id and entry.version == version:
                return entry
        raise PluginError(f"el repositorio no tiene {plugin_id} {version}")

    def fetch(self, entry: CatalogEntry, staging_dir: Path) -> Path:
        """Copia el paquete a una carpeta de trabajo tras comprobar que coincide con el índice."""
        source = (self.root / entry.relative_path).resolve()
        if not source.is_relative_to(self.root):
            raise ValidationError("la ruta del catálogo sale del repositorio")
        if not source.is_dir():
            raise PluginError(f"el paquete del catálogo no existe: {entry.relative_path}")
        integrity_path = source / INTEGRITY_FILE
        if not integrity_path.is_file():
            raise ValidationError(f"el paquete del catálogo no contiene {INTEGRITY_FILE}")
        if sha256_bytes(integrity_path.read_bytes()) != entry.package_sha256:
            raise ValidationError(
                f"el índice no coincide con el paquete {entry.plugin_id} {entry.version}"
            )
        destination = staging_dir / f"{entry.plugin_id}-{entry.version}"
        copy_package(source, destination)
        return destination


def _parse_entry(raw: Any) -> CatalogEntry:
    if not isinstance(raw, dict):
        raise ValidationError(f"entrada no válida en {INDEX_FILE}")
    relative = require_text(raw.get("path"), "path", INDEX_FILE)
    _check_relative(relative)
    digest = require_text(raw.get("sha256"), "sha256", INDEX_FILE)
    if not _SHA256_HEX.fullmatch(digest):
        raise ValidationError(f"sha256 no válido en {INDEX_FILE}: {digest}")
    return CatalogEntry(
        plugin_id=require_identifier(raw.get("id"), "id", INDEX_FILE),
        version=require_semver(raw.get("version"), "version", INDEX_FILE),
        relative_path=relative,
        package_sha256=digest,
    )


def _check_relative(relative: str) -> None:
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or "\\" in relative:
        raise ValidationError(f"ruta fuera del repositorio: {relative}")
