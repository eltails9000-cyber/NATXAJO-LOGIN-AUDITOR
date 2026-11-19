"""Gestor de configuración: persistencia atómica, historial y copias verificadas."""

from __future__ import annotations

import json
import shutil
from copy import deepcopy
from pathlib import Path
from typing import Any

from natxajo_auditor.configuration import schema
from natxajo_auditor.core.exceptions import AuthorizationError, ConfigurationError
from natxajo_auditor.core.utilities import atomic_write_text, utc_stamp
from natxajo_auditor.storage.backups import BackupManager

CONFIG_FILE = "app.json"


class ConfigurationManager:
    def __init__(self, config_dir: Path) -> None:
        self.config_dir = config_dir
        self.path = config_dir / CONFIG_FILE
        self.history_dir = config_dir / "history"
        self.backups = BackupManager(config_dir / "backups")
        self._data: schema.Config = self._load_or_create()

    def get(self, section: str, key: str) -> Any:
        try:
            return self._data[section][key]
        except KeyError:
            raise ConfigurationError(f"Clave desconocida: {section}.{key}") from None

    def set(self, section: str, key: str, value: Any) -> None:
        candidate = deepcopy(self._data)
        if section not in candidate or key not in candidate[section]:
            raise ConfigurationError(f"Clave desconocida: {section}.{key}")
        candidate[section][key] = value
        self._commit(candidate, reason="cambio")

    def history(self) -> list[Path]:
        if not self.history_dir.is_dir():
            return []
        return sorted(self.history_dir.glob("*.json"))

    def backup(self) -> Path:
        return self.backups.create(self.path, label="configuracion")

    def restore(self, source: Path, *, authorized: bool = False) -> None:
        """Restaura una copia. Requiere autorización explícita y verifica su hash."""
        if not authorized:
            raise AuthorizationError(
                "La restauración de configuración requiere autorización explícita"
            )
        reason = self.backups.problem(source)
        if reason is not None:
            raise ConfigurationError(f"Copia no válida: {reason}")
        try:
            data = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigurationError(f"Copia ilegible: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigurationError("La copia debe contener un objeto JSON")
        self._commit(schema.complete(data), reason="restauracion")

    def _load_or_create(self) -> schema.Config:
        self.config_dir.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            data = schema.defaults()
            self._write(data)
            return data
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigurationError(f"No se pudo leer la configuración: {exc}") from exc
        if not isinstance(raw, dict):
            raise ConfigurationError("La configuración raíz debe ser un objeto JSON")
        data = schema.complete(raw)
        schema.validate(data)
        return data

    def _commit(self, candidate: schema.Config, reason: str) -> None:
        """Valida, guarda la versión anterior en el historial y escribe la nueva de forma atómica."""
        schema.validate(candidate)
        if self.path.exists():
            self.history_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.path, self.history_dir / f"{utc_stamp()}-{reason}.json")
        self._write(candidate)
        self._data = candidate

    def _write(self, data: schema.Config) -> None:
        text = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)
        try:
            atomic_write_text(self.path, text)
        except OSError as exc:
            raise ConfigurationError(f"No se pudo guardar la configuración: {exc}") from exc
