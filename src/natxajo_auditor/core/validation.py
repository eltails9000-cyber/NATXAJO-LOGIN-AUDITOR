"""Validadores compartidos por los manifiestos de módulos, plugins y versiones."""

from __future__ import annotations

import re

from natxajo_auditor.core.exceptions import ValidationError

IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{2,39}$")
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
KERNEL_PATTERN = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(x|0|[1-9]\d*)$")
KEY_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")


def require_text(value: object, field: str, source: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{source}: {field} debe ser un texto no vacío")
    return value


def require_identifier(value: object, field: str, source: str) -> str:
    text = require_text(value, field, source)
    if not IDENTIFIER.match(text):
        raise ValidationError(
            f"{source}: {field} no válido: {text} "
            "(minúsculas, dígitos y guion bajo, de 3 a 40 caracteres)"
        )
    return text


def require_semver(value: object, field: str, source: str) -> str:
    text = require_text(value, field, source)
    if not SEMVER.match(text):
        raise ValidationError(f"{source}: {field} no es una versión semántica válida: {text}")
    return text


def require_kernel_pattern(value: object, field: str, source: str) -> str:
    text = require_text(value, field, source)
    if not KERNEL_PATTERN.match(text):
        raise ValidationError(f"{source}: {field} no válido: {text} (use 0.1.0 o 0.1.x)")
    return text


def require_string_list(value: object, field: str, source: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValidationError(f"{source}: {field} debe ser una lista de textos")
    if len(set(value)) != len(value):
        raise ValidationError(f"{source}: {field} tiene elementos repetidos")
    return tuple(value)


def kernel_matches(pattern: str, kernel_version: str) -> bool:
    """Compara una versión de núcleo con un patrón exacto (0.1.0) o de parche (0.1.x)."""
    if not SEMVER.match(kernel_version):
        raise ValidationError(f"Versión de núcleo no válida: {kernel_version}")
    if pattern.endswith(".x"):
        return pattern.split(".")[:2] == kernel_version.split(".")[:2]
    return pattern == kernel_version
