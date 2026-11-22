"""Registro de servicios. Cada nombre solo puede registrarse una vez.

Hay dos formas de acceder. La tipada usa una `ServiceKey`, que indica el nombre y la clase del
servicio: al registrar y al consultar se comprueba el tipo, así que el acceso devuelve la clase
declarada sin `cast`. La forma por nombre se conserva por compatibilidad y no comprueba el tipo.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from natxajo_auditor.core.exceptions import ServiceError

T = TypeVar("T")


@dataclass(frozen=True)
class ServiceKey(Generic[T]):
    """Identidad de un servicio: su nombre en el contenedor y la clase que debe tener."""

    name: str
    kind: type[T]


class ServiceContainer:
    def __init__(self) -> None:
        self._services: dict[str, Any] = {}

    def register(self, name: str, service: Any) -> None:
        if name in self._services:
            raise ServiceError(f"El servicio ya está registrado: {name}")
        self._services[name] = service

    def put(self, key: ServiceKey[T], service: T) -> None:
        """Registra un servicio comprobando que es de la clase declarada en la clave."""
        if not isinstance(service, key.kind):
            raise ServiceError(f"El servicio {key.name} no es {key.kind.__name__}")
        self.register(key.name, service)

    def get(self, name: str) -> Any:
        try:
            return self._services[name]
        except KeyError:
            raise ServiceError(f"Servicio no registrado: {name}") from None

    def fetch(self, key: ServiceKey[T]) -> T:
        """Devuelve el servicio de la clave con su tipo declarado. Comprueba la clase en ejecución."""
        service = self.get(key.name)
        if not isinstance(service, key.kind):
            raise ServiceError(f"El servicio {key.name} no es {key.kind.__name__}")
        return service

    def has(self, name: str) -> bool:
        return name in self._services

    def names(self) -> list[str]:
        return sorted(self._services)

    def clear(self) -> None:
        self._services.clear()
