"""Almacén de copias verificadas: storage/plugins/store/<id>/<versión>/.

Cada versión instalada tiene su propia copia. Así un plugin no depende de la carpeta de origen, y
la integridad puede comprobarse de nuevo en cualquier momento.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from natxajo_auditor.core.exceptions import PluginError, ValidationError
from natxajo_auditor.core.validation import IDENTIFIER, SEMVER
from natxajo_auditor.plugins.package import copy_package


class PluginStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def path_for(self, plugin_id: str, version: str) -> Path:
        if not IDENTIFIER.fullmatch(plugin_id) or not SEMVER.fullmatch(version):
            raise ValidationError(f"identificador o versión no válidos: {plugin_id} {version}")
        return self.root / plugin_id / version

    def copy_in(self, source: Path, plugin_id: str, version: str) -> Path:
        destination = self.path_for(plugin_id, version)
        if destination.exists():
            raise PluginError(f"ya existe una copia almacenada de {plugin_id} {version}")
        try:
            copy_package(source, destination)
        except (OSError, ValidationError):
            shutil.rmtree(destination, ignore_errors=True)
            raise
        return destination

    def remove(self, plugin_id: str, version: str) -> None:
        destination = self.path_for(plugin_id, version)
        shutil.rmtree(destination, ignore_errors=True)
        parent = destination.parent
        if parent.is_dir() and not any(parent.iterdir()):
            parent.rmdir()
