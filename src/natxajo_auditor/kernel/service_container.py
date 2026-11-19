from typing import Any, Hashable


class ServiceContainer:
    def __init__(self) -> None:
        self._services: dict[Hashable, Any] = {}

    def register(self, name: Hashable, service: Any) -> None:
        if name in self._services:
            raise KeyError(f"El servicio ya está registrado: {name}")
        self._services[name] = service

    def replace(self, name: Hashable, service: Any) -> None:
        self._services[name] = service

    def get(self, name: Hashable) -> Any:
        if name not in self._services:
            raise KeyError(f"Servicio no registrado: {name}")
        return self._services[name]

    def has(self, name: Hashable) -> bool:
        return name in self._services
