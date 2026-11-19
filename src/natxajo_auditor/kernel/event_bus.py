from collections import defaultdict
from collections.abc import Callable
from typing import Any

EventHandler = Callable[[str, Any], None]


class EventBus:
    def __init__(self) -> None:
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)

    def subscribe(self, event_name: str, handler: EventHandler) -> None:
        if handler not in self._handlers[event_name]:
            self._handlers[event_name].append(handler)

    def publish(self, event_name: str, payload: Any = None) -> None:
        for handler in tuple(self._handlers.get(event_name, [])):
            handler(event_name, payload)
