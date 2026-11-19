from dataclasses import dataclass
from pathlib import Path
import json

from natxajo_auditor.core.exceptions import ValidationError


@dataclass(frozen=True)
class VersionManifest:
    version: str
    channel: str
    compatible_kernel: str


class VersionRegistry:
    def __init__(self, versions_dir: Path | None = None) -> None:
        self.versions_dir = versions_dir
        self._versions: dict[str, VersionManifest] = {
            "0.1.0": VersionManifest("0.1.0", "development", "0.1.x")
        }

    def available(self) -> list[VersionManifest]:
        if self.versions_dir:
            self._load_manifests()
        return sorted(self._versions.values(), key=lambda item: item.version)

    def get(self, version: str) -> VersionManifest | None:
        if self.versions_dir:
            self._load_manifests()
        return self._versions.get(version)

    def register(self, manifest: VersionManifest) -> None:
        self._versions[manifest.version] = manifest

    def _load_manifests(self) -> None:
        if not self.versions_dir or not self.versions_dir.exists():
            return
        for path in self.versions_dir.glob("*/manifest.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                manifest = VersionManifest(
                    version=str(data["version"]),
                    channel=str(data["channel"]),
                    compatible_kernel=str(data["compatible_kernel"]),
                )
            except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
                raise ValidationError(f"Manifiesto inválido en {path}: {exc}") from exc
            self.register(manifest)
