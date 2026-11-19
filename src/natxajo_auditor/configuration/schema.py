"""Esquema de configuración: valores por defecto, tipos y restricciones.

El esquema es estricto: secciones y claves desconocidas se rechazan para detectar errores
tipográficos. La exigencia de autorización para auditar no puede desactivarse, porque es un
límite de seguridad y no una preferencia.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from natxajo_auditor.core.exceptions import ConfigurationError

Config = dict[str, dict[str, Any]]

DEFAULTS: Config = {
    "general": {"locale": "es", "theme": "dark", "level": "basic"},
    "auditing": {"enabled": False, "require_authorization": True, "max_requests": 5},
    "logging": {"level": "INFO", "structured": True},
}

MAX_REQUESTS_LIMIT = 20

_ENUMS: dict[tuple[str, str], frozenset[str]] = {
    ("general", "locale"): frozenset({"es", "en"}),
    ("general", "theme"): frozenset({"dark", "light", "contrast"}),
    ("general", "level"): frozenset({"basic", "advanced", "administrator", "developer"}),
    ("logging", "level"): frozenset({"DEBUG", "INFO", "WARNING", "ERROR"}),
}
_BOOLEANS: frozenset[tuple[str, str]] = frozenset(
    {("auditing", "enabled"), ("auditing", "require_authorization"), ("logging", "structured")}
)


def defaults() -> Config:
    return deepcopy(DEFAULTS)


def complete(data: Mapping[str, Any]) -> Config:
    """Rellena las claves ausentes con su valor por defecto. Rechaza secciones y claves desconocidas.

    No corrige valores inválidos: eso lo hace validate().
    """
    result = defaults()
    for section, values in data.items():
        if section not in DEFAULTS:
            raise ConfigurationError(f"Sección desconocida: {section}")
        if not isinstance(values, dict):
            raise ConfigurationError(f"La sección no es un objeto: {section}")
        for key, value in values.items():
            if key not in DEFAULTS[section]:
                raise ConfigurationError(f"Clave desconocida: {section}.{key}")
            result[section][key] = value
    return result


def validate(config: Mapping[str, Any]) -> None:
    """Valida la configuración completa. Informa de todos los problemas a la vez."""
    problems: list[str] = []
    for section, keys in DEFAULTS.items():
        values = config.get(section)
        if not isinstance(values, dict):
            problems.append(f"falta la sección {section}")
            continue
        for key in keys:
            if key not in values:
                problems.append(f"falta la clave {section}.{key}")
                continue
            problem = _check_value(section, key, values[key])
            if problem is not None:
                problems.append(problem)
    if problems:
        raise ConfigurationError("Configuración no válida: " + "; ".join(problems))


def _check_value(section: str, key: str, value: object) -> str | None:
    path = f"{section}.{key}"
    if (section, key) in _BOOLEANS:
        if not isinstance(value, bool):
            return f"{path} debe ser booleano"
        if path == "auditing.require_authorization" and value is not True:
            return "auditing.require_authorization no puede desactivarse"
        return None
    if (section, key) == ("auditing", "max_requests"):
        if isinstance(value, bool) or not isinstance(value, int):
            return f"{path} debe ser un entero"
        if not 1 <= value <= MAX_REQUESTS_LIMIT:
            return f"{path} debe estar entre 1 y {MAX_REQUESTS_LIMIT}"
        return None
    allowed = _ENUMS.get((section, key))
    if allowed is not None:
        if not isinstance(value, str) or value not in allowed:
            return f"{path} debe ser uno de: {', '.join(sorted(allowed))}"
        return None
    return f"clave sin regla de validación: {path}"
