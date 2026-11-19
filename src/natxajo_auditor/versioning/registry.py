"""Registro de versiones leído desde versions/<versión>/manifest.json.

Las carpetas sin manifiesto se ignoran. Una carpeta con manifiesto inválido o cuyo nombre
no coincide con la versión declarada provoca un error, para no cargar datos dudosos.
"""

from __future__ import annotations

from pathlib import Path

from natxajo_auditor.core.exceptions import ValidationError, VersionError
from natxajo_auditor.versioning.manifest import VersionManifest, load_manifest

MANIFEST_NAME = "manifest.json"


class VersionRegistry:
    def __init__(self, versions_dir: Path) -> None:
        self.versions_dir = versions_dir

    def available(self) -> list[VersionManifest]:
        """Lee todos los manifiestos en cada llamada, ordenados por versión."""
        if not self.versions_dir.is_dir():
            return []
        manifests: list[VersionManifest] = []
        for folder in sorted(path for path in self.versions_dir.iterdir() if path.is_dir()):
            manifest_path = folder / MANIFEST_NAME
            if not manifest_path.is_file():
                continue
            manifest = load_manifest(manifest_path)
            if folder.name != manifest.version:
                raise ValidationError(
                    f"{manifest_path}: el directorio {folder.name} no coincide "
                    f"con la versión {manifest.version}"
                )
            manifests.append(manifest)
        return sorted(manifests, key=lambda item: _semver_key(item.version))

    def get(self, version: str) -> VersionManifest:
        for manifest in self.available():
            if manifest.version == version:
                return manifest
        raise VersionError(f"Versión no disponible: {version}")


def _semver_key(version: str) -> tuple[int, int, int]:
    major, minor, patch = (int(part) for part in version.split("."))
    return major, minor, patch
