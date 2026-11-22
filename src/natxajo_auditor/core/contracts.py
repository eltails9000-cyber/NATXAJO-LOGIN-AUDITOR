"""Contratos públicos entre subsistemas.

Los subsistemas de módulos y plugins dependen de estos tipos y no de las implementaciones de
security/. Así no importan la seguridad concreta y pueden probarse con un guardián sustituto.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, TypeVar

T = TypeVar("T")


class OperationGate(Protocol):
    """Puerta de operaciones: identifica al actor y ejecuta una operación con autorización.

    La implementación de producción es security.guard.OperationGuard. Sin empresa indicada, la
    operación es de plataforma.
    """

    def username_for(self, token: str) -> str:
        """Cuenta de una sesión válida. Lanza una excepción si la sesión no es válida."""
        ...

    def run(
        self,
        token: str,
        permission: str,
        operation: Callable[[], T],
        *,
        confirmed: bool = False,
        company_id: str | None = None,
    ) -> T:
        """Ejecuta operation solo si la sesión tiene el permiso y se cumple el ámbito."""
        ...
