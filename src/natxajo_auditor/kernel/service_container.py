"""Registro de servicios por nombre. Cada nombre solo puede registrarse una vez."""

from __future__ import annotations

from typing import Any

from natxajo_auditor.core.exceptions import ServiceError


class ServiceContainer:
    def __init__(self) -> None:
        self._services: dict[str, Any] = {}

    def register(self, name: str, service: Any) -> None:
        if name in self._services:
            raise ServiceError(f"El servicio ya está registrado: {name}")
        self._services[name] = service

    def get(self, name: str) -> Any:
        try:
            return self._services[name]
        except KeyError:
            raise ServiceError(f"Servicio no registrado: {name}") from None

    def has(self, name: str) -> bool:
        return name in self._services

    def names(self) -> list[str]:
        return sorted(self._services)

    def clear(self) -> None:
        self._services.clear()
