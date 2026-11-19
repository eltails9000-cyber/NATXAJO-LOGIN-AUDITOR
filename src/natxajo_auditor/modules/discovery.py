"""Descubrimiento de módulos en la carpeta modules/.

Un módulo con manifiesto inválido no detiene el descubrimiento de los demás: su error se
registra y se muestra en el diagnóstico. Así un módulo roto no bloquea el resto.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.modules.manifest import MODULE_FILE, ModuleManifest, load_module_manifest


@dataclass(frozen=True)
class Discovery:
    manifests: dict[str, ModuleManifest] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)


def discover_modules(modules_dir: Path) -> Discovery:
    manifests: dict[str, ModuleManifest] = {}
    errors: dict[str, str] = {}
    if not modules_dir.is_dir():
        return Discovery(manifests, errors)
    for folder in sorted(path for path in modules_dir.iterdir() if path.is_dir()):
        manifest_path = folder / MODULE_FILE
        if not manifest_path.is_file():
            continue
        try:
            manifest = load_module_manifest(manifest_path)
            if folder.name != manifest.module_id:
                raise ValidationError(
                    f"la carpeta {folder.name} no coincide con el id {manifest.module_id}"
                )
        except ValidationError as exc:
            errors[folder.name] = str(exc)
            continue
        manifests[manifest.module_id] = manifest
    return Discovery(manifests, errors)
