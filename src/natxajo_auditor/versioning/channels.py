"""Canales de distribución iniciales. Los canales personalizados están pendientes (ver docs/IMPLEMENTATION_STATUS.md)."""

from __future__ import annotations

from enum import Enum

from natxajo_auditor.core.exceptions import ValidationError


class Channel(str, Enum):
    STABLE = "stable"
    BETA = "beta"
    ALPHA = "alpha"
    EXPERIMENTAL = "experimental"
    DEVELOPMENT = "development"


def parse_channel(value: object) -> Channel:
    if not isinstance(value, str):
        raise ValidationError("El canal debe ser un texto")
    try:
        return Channel(value)
    except ValueError:
        raise ValidationError(f"Canal no reconocido: {value}") from None
