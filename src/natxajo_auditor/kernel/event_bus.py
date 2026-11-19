"""Bus de eventos síncrono. Los manejadores se ejecutan en orden de suscripción."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from typing import Any

EventHandler = Callable[[str, Any], None]


class EventBus:
    def __init__(self) -> None:
        self._handlers: defaultdict[str, list[EventHandler]] = defaultdict(list)

    def subscribe(self, event_name: str, handler: EventHandler) -> None:
        handlers = self._handlers[event_name]
        if handler not in handlers:
            handlers.append(handler)

    def publish(self, event_name: str, payload: Any = None) -> None:
        for handler in tuple(self._handlers.get(event_name, ())):
            handler(event_name, payload)
