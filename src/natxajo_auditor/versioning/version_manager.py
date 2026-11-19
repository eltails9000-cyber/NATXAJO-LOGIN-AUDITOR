from pathlib import Path

from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.versioning.version_registry import VersionRegistry


class VersionManager:
    def __init__(self, registry: VersionRegistry) -> None:
        self.registry = registry
        self.active: str | None = None
        self.history: list[str] = []

    def load(self, version: str) -> str:
        manifest = self.registry.get(version)
        if manifest is None:
            raise ValidationError(f"Versión no disponible: {version}")
        if manifest.channel not in {"stable", "beta", "alpha", "experimental", "development"}:
            raise ValidationError("Canal de distribución no reconocido")
        self.active = manifest.version
        self.history.append(manifest.version)
        return manifest.version

    def switch(self, version: str) -> str:
        if version == self.active:
            return version
        return self.load(version)

    def rollback(self) -> str:
        if len(self.history) < 2:
            raise ValidationError("No existe una versión anterior para revertir")
        self.history.pop()
        self.active = self.history[-1]
        return self.active
