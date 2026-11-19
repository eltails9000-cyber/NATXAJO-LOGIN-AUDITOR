"""Contexto de ejecución: rutas del proyecto. No usa estado global."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RuntimeContext:
    project_root: Path

    @property
    def config_dir(self) -> Path:
        return self.project_root / "config"

    @property
    def storage_dir(self) -> Path:
        return self.project_root / "storage"

    @property
    def versions_dir(self) -> Path:
        return self.project_root / "versions"
