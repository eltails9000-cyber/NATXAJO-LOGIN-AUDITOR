from collections.abc import Callable

CommandHandler = Callable[[object], object]


class CommandBus:
    def __init__(self) -> None:
        self._handlers: dict[str, CommandHandler] = {}

    def register(self, name: str, handler: CommandHandler) -> None:
        if name in self._handlers:
            raise KeyError(f"El comando ya está registrado: {name}")
        self._handlers[name] = handler

    def execute(self, name: str, payload: object | None = None) -> object:
        if name not in self._handlers:
            raise KeyError(f"Comando no registrado: {name}")
        return self._handlers[name](payload)
