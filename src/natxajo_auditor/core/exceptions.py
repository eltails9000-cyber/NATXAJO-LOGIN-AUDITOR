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


class SessionError(AuthorizationError):
    """La sesión no existe, está revocada o ha caducado."""


class VersionError(NatxajoError):
    """Versión no disponible, incompatible o no cargable."""


class ModuleError(NatxajoError):
    """Módulo no instalado, con manifiesto inválido o con una habilitación no permitida."""


class PluginError(NatxajoError):
    """Plugin no instalado, con un estado que no permite la operación o con una copia alterada."""
