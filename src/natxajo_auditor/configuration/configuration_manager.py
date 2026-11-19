from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from natxajo_auditor.core.exceptions import ConfigurationError, AuthorizationError


DEFAULTS: dict[str, Any] = {
    "general": {"locale": "es", "theme": "dark", "level": "basic"},
    "auditing": {"enabled": False, "require_authorization": True, "max_requests": 5},
    "logging": {"level": "INFO", "structured": True},
}


class ConfigurationManager:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.history_dir = path.parent / "history"
        self.backup_dir = path.parent / "backups"
        self.history_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self._configuration = json.loads(json.dumps(DEFAULTS))
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
        self._validate()
        self.save()

    def update(self, section: str, values: dict[str, Any]) -> None:
        if not isinstance(values, dict):
            raise ConfigurationError("Los valores deben ser un objeto")
        section_data = self._configuration.setdefault(section, {})
        if not isinstance(section_data, dict):
            raise ConfigurationError(f"La sección no es válida: {section}")
        section_data.update(values)
        self._validate()
        self.save()

    def _validate(self) -> None:
        auditing = self._configuration.get("auditing", {})
        if isinstance(auditing, dict):
            limit = auditing.get("max_requests")
            if isinstance(limit, (int, float)) and limit < 1:
                raise ConfigurationError("max_requests debe ser al menos 1")

    def save(self) -> None:
        try:
            self.path.write_text(
                json.dumps(self._configuration, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError as exc:
            raise ConfigurationError(f"No se pudo guardar la configuración: {exc}") from exc

    def snapshot(self, label: str = "manual") -> Path:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        target = self.history_dir / f"{stamp}-{label}.json"
        shutil.copy2(self.path, target)
        return target

    def backup(self) -> Path:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        target = self.backup_dir / f"app-{stamp}.json"
        shutil.copy2(self.path, target)
        return target

    def restore(self, source: Path, authorized: bool = False) -> None:
        if not authorized:
            raise AuthorizationError("La restauración requiere autorización explícita")
        if not source.exists():
            raise ConfigurationError("La copia de configuración no existe")
        try:
            data = json.loads(source.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise ConfigurationError(f"Copia inválida: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigurationError("La copia debe contener un objeto JSON")
        self.snapshot("before_restore")
        self._configuration = data
        self._validate()
        self.save()
