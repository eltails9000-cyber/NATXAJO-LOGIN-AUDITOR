"""Catálogo de permisos que un módulo puede declarar.

El catálogo es cerrado: un permiso desconocido es un error de manifiesto, así se detectan
erratas. Por ahora los permisos solo se declaran y se validan; no se aplican. La asignación a
roles y su comprobación llegan con RBAC (fase 7).
"""

from __future__ import annotations

from natxajo_auditor.core.exceptions import ValidationError

KNOWN_PERMISSIONS: frozenset[str] = frozenset(
    {
        "configuracion.leer",
        "versiones.leer",
        "auditoria.leer",
        "copias.leer",
    }
)


def validate_permissions(values: object, source: str) -> tuple[str, ...]:
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        raise ValidationError(f"{source}: permissions debe ser una lista de textos")
    if len(set(values)) != len(values):
        raise ValidationError(f"{source}: hay permisos repetidos")
    unknown = sorted(item for item in values if item not in KNOWN_PERMISSIONS)
    if unknown:
        raise ValidationError(f"{source}: permisos desconocidos: {', '.join(unknown)}")
    return tuple(values)
