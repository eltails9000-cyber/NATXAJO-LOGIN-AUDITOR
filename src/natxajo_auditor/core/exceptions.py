"""Jerarquía de errores de la plataforma."""

from __future__ import annotations


class NatxajoError(Exception):
    """Error base de la plataforma."""


class LifecycleError(NatxajoError):
    """Transición de ciclo de vida no permitida."""


class ServiceError(NatxajoError):
    """Registro o búsqueda de servicios no válida."""


class ConfigurationError(NatxajoError):
    """Configuración inválida, ilegible o no guardable."""


class StorageError(NatxajoError):
    """Fallo de almacenamiento, migraciones o copias."""


class ValidationError(NatxajoError):
    """Entrada o manifiesto que no cumple el contrato."""


class AuthorizationError(NatxajoError):
    """Operación sensible sin autorización explícita."""


class VersionError(NatxajoError):
    """Versión no disponible, incompatible o no cargable."""
