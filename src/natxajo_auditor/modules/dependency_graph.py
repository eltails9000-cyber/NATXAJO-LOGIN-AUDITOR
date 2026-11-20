"""Grafo de dependencias entre módulos: orden de habilitación y detección de errores.

La lógica genérica vive en core/graph.py. Este módulo solo adapta los manifiestos.
"""

from __future__ import annotations

from collections.abc import Mapping

from natxajo_auditor.core.graph import dependents_of as _dependents
from natxajo_auditor.core.graph import resolve_load_order as _resolve
from natxajo_auditor.modules.manifest import ModuleManifest


def resolve_load_order(manifests: Mapping[str, ModuleManifest], target: str) -> list[str]:
    """Devuelve target y sus dependencias, con cada dependencia antes que quien la necesita.

    Lanza ValidationError si falta una dependencia o si hay un ciclo.
    """

    def requires_of(module_id: str) -> tuple[str, ...] | None:
        manifest = manifests.get(module_id)
        return None if manifest is None else manifest.requires

    return _resolve(requires_of, target, noun="módulo")


def dependents_of(manifests: Mapping[str, ModuleManifest], module_id: str) -> list[str]:
    """Módulos conocidos que requieren directamente a module_id."""
    return _dependents({name: m.requires for name, m in manifests.items()}, module_id)
