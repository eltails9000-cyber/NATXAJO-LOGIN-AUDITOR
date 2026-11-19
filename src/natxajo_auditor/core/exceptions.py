class NatxajoError(Exception):
    """Error base de la plataforma."""


class ConfigurationError(NatxajoError):
    """Error de configuración."""


class LifecycleError(NatxajoError):
    """Error durante el ciclo de vida."""


class ValidationError(NatxajoError):
    """Error de validación de entradas o manifiestos."""


class AuthorizationError(NatxajoError):
    """Operación no autorizada."""
