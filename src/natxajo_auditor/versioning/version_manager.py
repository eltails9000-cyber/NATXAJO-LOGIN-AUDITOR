from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.versioning.version_registry import VersionRegistry


class VersionManager:
    def __init__(self, registry: VersionRegistry) -> None:
        self.registry = registry
        self.active: str | None = None

    def load(self, version: str) -> str:
        manifest = self.registry.get(version)
        if manifest is None:
            raise ValidationError(f"Versión no disponible: {version}")
        if self.active is not None:
            raise RuntimeError("Solo puede estar activa una versión")
        self.active = manifest.version
        return manifest.version
