import json
from pathlib import Path
from typing import Any

from natxajo_auditor.core.exceptions import ConfigurationError


DEFAULTS: dict[str, Any] = {
    "general": {"locale": "es", "theme": "dark"},
    "auditing": {"enabled": False, "require_authorization": True, "max_requests": 5},
    "logging": {"level": "INFO", "structured": True},
}


class ConfigurationManager:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._configuration = dict(DEFAULTS)
        self.load()

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            self.save()
            return self._configuration
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise ConfigurationError(f"No se pudo cargar la configuración: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigurationError("La configuración raíz debe ser un objeto JSON")
        self._configuration = data
        return self._configuration

    def get(self, section: str, key: str, fallback: Any = None) -> Any:
        section_data = self._configuration.get(section, {})
        return section_data.get(key, fallback) if isinstance(section_data, dict) else fallback

    def set(self, section: str, key: str, value: Any) -> None:
        section_data = self._configuration.setdefault(section, {})
        if not isinstance(section_data, dict):
            raise ConfigurationError(f"La sección no es válida: {section}")
        section_data[key] = value
        self.save()

    def save(self) -> None:
        try:
            self.path.write_text(
                json.dumps(self._configuration, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError as exc:
            raise ConfigurationError(f"No se pudo guardar la configuración: {exc}") from exc
