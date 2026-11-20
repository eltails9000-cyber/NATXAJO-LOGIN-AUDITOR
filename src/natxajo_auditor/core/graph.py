"""Orden de carga y búsqueda de dependientes para cualquier conjunto de elementos con requisitos.

Lo usan los módulos y los plugins. No depende de lo que representan los elementos.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping

from natxajo_auditor.core.exceptions import ValidationError


def resolve_load_order(
    requires_of: Callable[[str], tuple[str, ...] | None],
    target: str,
    noun: str = "elemento",
) -> list[str]:
    """Devuelve target y sus dependencias, con cada dependencia antes que quien la necesita.

    requires_of devuelve None si el elemento no está disponible. Lanza ValidationError si falta
    una dependencia o si hay un ciclo.
    """
    order: list[str] = []
    done: set[str] = set()

    def visit(item: str, chain: tuple[str, ...]) -> None:
        if item in done:
            return
        if item in chain:
            raise ValidationError("ciclo de dependencias: " + " -> ".join((*chain, item)))
        requires = requires_of(item)
        if requires is None:
            requester = f" (requerido por {chain[-1]})" if chain else ""
            raise ValidationError(f"{noun} no instalado: {item}{requester}")
        for dependency in requires:
            visit(dependency, (*chain, item))
        done.add(item)
        order.append(item)

    visit(target, ())
    return order


def dependents_of(requires_map: Mapping[str, Iterable[str]], item: str) -> list[str]:
    """Elementos que requieren directamente a item, ordenados por nombre."""
    return sorted(name for name, requires in requires_map.items() if item in requires)
