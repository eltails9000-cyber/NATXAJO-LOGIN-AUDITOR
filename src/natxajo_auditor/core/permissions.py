"""Permisos con formato subsistema:modulo:recurso:accion.

- Declaraciones de módulos y plugins: códigos exactos, sin comodines. Un manifiesto no puede
  conceder más de lo que declara.
- Concesiones (roles y permisos temporales): admiten "*" en cualquier segmento.
- Un código desconocido se rechaza para detectar erratas.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from natxajo_auditor.core.exceptions import ValidationError

WILDCARD = "*"
SUBSYSTEMS: frozenset[str] = frozenset(
    {
        "nucleo",
        "versiones",
        "modulos",
        "plugins",
        "configuracion",
        "seguridad",
        "auditoria",
        "almacenamiento",
        "automatizacion",
        "diagnosticos",
        "informes",
        "mantenimiento",
    }
)
ACTIONS: frozenset[str] = frozenset(
    {"leer", "escribir", "ejecutar", "administrar", "restaurar", "aprobar", "revocar"}
)
SEGMENT_NAMES = ("subsistema", "modulo", "recurso", "accion")
_SEGMENT = re.compile(r"[a-z][a-z0-9_]{0,39}")


@dataclass(frozen=True)
class Permission:
    subsystem: str
    module: str
    resource: str
    action: str

    @property
    def segments(self) -> tuple[str, str, str, str]:
        return (self.subsystem, self.module, self.resource, self.action)

    def is_exact(self) -> bool:
        return WILDCARD not in self.segments

    def __str__(self) -> str:
        return ":".join(self.segments)


def parse_permission(
    code: object, *, allow_wildcards: bool = False, source: str = "permiso"
) -> Permission:
    if not isinstance(code, str):
        raise ValidationError(f"{source}: el permiso debe ser un texto")
    parts = code.split(":")
    if len(parts) != 4:
        raise ValidationError(
            f"{source}: '{code}' debe tener cuatro segmentos subsistema:modulo:recurso:accion"
        )
    for index, value in enumerate(parts):
        name = SEGMENT_NAMES[index]
        if value == WILDCARD:
            if not allow_wildcards:
                raise ValidationError(f"{source}: '{code}' no admite comodines en {name}")
            continue
        if index == 0 and value not in SUBSYSTEMS:
            raise ValidationError(f"{source}: subsistema desconocido: {value}")
        if index == 3 and value not in ACTIONS:
            raise ValidationError(f"{source}: acción desconocida: {value}")
        if index in (1, 2) and not _SEGMENT.fullmatch(value):
            raise ValidationError(f"{source}: {name} no válido en '{code}': {value}")
    return Permission(parts[0], parts[1], parts[2], parts[3])


def covers(grant: Permission, other: Permission) -> bool:
    """True si la concesión cubre el otro permiso.

    Un comodín en la concesión cubre cualquier valor del segmento. Un valor concreto no cubre
    un comodín del otro permiso.
    """
    return all(g == WILDCARD or g == o for g, o in zip(grant.segments, other.segments, strict=True))


def validate_declared(values: object, source: str) -> tuple[str, ...]:
    """Valida la lista de un manifiesto: códigos exactos, sin repetir, con subsistema y acción conocidos."""
    if values is None:
        return ()
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        raise ValidationError(f"{source}: permissions debe ser una lista de textos")
    if len(set(values)) != len(values):
        raise ValidationError(f"{source}: permissions tiene permisos repetidos")
    for item in values:
        parse_permission(item, source=source)
    return tuple(values)
