"""Versiones de la API de plugins que la plataforma acepta."""

from __future__ import annotations

from natxajo_auditor.core.exceptions import ValidationError

API_VERSION = "1.0"
SUPPORTED_API_VERSIONS: frozenset[str] = frozenset({API_VERSION})


def check_api_version(version: str) -> None:
    if version not in SUPPORTED_API_VERSIONS:
        supported = ", ".join(sorted(SUPPORTED_API_VERSIONS))
        raise ValidationError(f"versión de API no soportada: {version} (soportadas: {supported})")
