"""Grafo de dependencias entre módulos: orden de habilitación y detección de errores."""

from __future__ import annotations

from collections.abc import Mapping

from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.modules.manifest import ModuleManifest


def resolve_load_order(manifests: Mapping[str, ModuleManifest], target: str) -> list[str]:
    """Devuelve target y sus dependencias, con cada dependencia antes que quien la necesita.

    Lanza ValidationError si falta una dependencia o si hay un ciclo.
    """
    order: list[str] = []
    done: set[str] = set()

    def visit(module_id: str, chain: tuple[str, ...]) -> None:
        if module_id in done:
            return
        if module_id in chain:
            cycle = " -> ".join((*chain, module_id))
            raise ValidationError(f"ciclo de dependencias: {cycle}")
        manifest = manifests.get(module_id)
        if manifest is None:
            requester = f" (requerido por {chain[-1]})" if chain else ""
            raise ValidationError(f"módulo no instalado: {module_id}{requester}")
        for dependency in manifest.requires:
            visit(dependency, (*chain, module_id))
        done.add(module_id)
        order.append(module_id)

    visit(target, ())
    return order


def dependents_of(manifests: Mapping[str, ModuleManifest], module_id: str) -> list[str]:
    """Módulos conocidos que requieren directamente a module_id."""
    return sorted(
        candidate for candidate, manifest in manifests.items() if module_id in manifest.requires
    )
