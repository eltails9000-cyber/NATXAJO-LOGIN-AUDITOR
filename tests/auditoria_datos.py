"""Documentos de configuración de ejemplo para las pruebas de auditoría. Son datos ficticios."""

from __future__ import annotations

import copy
from typing import Any

GOOD: dict[str, Any] = {
    "esquema": 1,
    "contrasenas": {"longitud_minima": 12, "complejidad": True, "algoritmo": "argon2id"},
    "bloqueo": {"intentos_maximos": 5, "duracion_minutos": 15, "mensaje_generico": True},
    "sesiones": {"inactividad_minutos": 15, "absoluta_horas": 8, "simultaneas_maximas": 3},
    "cookies": {"secure": True, "http_only": True, "same_site": "Lax"},
    "transporte": {"tls_minimo": "1.2", "hsts": True},
    "mfa": {"administradores_obligatorio": True},
    "frecuencia": {"habilitado": True, "solicitudes_por_minuto": 30},
}

# Todas las reglas fallan. Incluye un null (declarado sin configurar) y un algoritmo inseguro.
WEAK: dict[str, Any] = {
    "esquema": 1,
    "contrasenas": {"longitud_minima": 6, "complejidad": False, "algoritmo": "md5"},
    "bloqueo": {"intentos_maximos": 0, "duracion_minutos": 0, "mensaje_generico": False},
    "sesiones": {"inactividad_minutos": 60, "absoluta_horas": 24, "simultaneas_maximas": None},
    "cookies": {"secure": False, "http_only": False, "same_site": "None"},
    "transporte": {"tls_minimo": "1.0", "hsts": False},
    "mfa": {"administradores_obligatorio": False},
    "frecuencia": {"habilitado": False, "solicitudes_por_minuto": 600},
}


def copy_of(document: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(document)


def without(document: dict[str, Any], *sections: str) -> dict[str, Any]:
    result = copy_of(document)
    for section in sections:
        result.pop(section, None)
    return result
