"""Manifiesto de versión: contrato de datos validado antes de cualquier carga."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.core.validation import (
    SEMVER,
    require_kernel_pattern,
    require_semver,
    require_string_list,
    require_text,
)
from natxajo_auditor.versioning.channels import Channel, parse_channel

REQUIRED_FIELDS = frozenset({"version", "channel", "compatible_kernel", "name", "description"})
OPTIONAL_FIELDS = frozenset({"dependencies"})


@dataclass(frozen=True)
class VersionManifest:
    version: str
    channel: Channel
    compatible_kernel: str
    name: str
    description: str
    dependencies: tuple[str, ...] = ()

    def is_compatible_with(self, kernel_version: str) -> bool:
        return kernel_matches(self.compatible_kernel, kernel_version)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], source: str = "manifiesto") -> VersionManifest:
        missing = REQUIRED_FIELDS - set(data)
        if missing:
            raise ValidationError(f"{source}: faltan campos {sorted(missing)}")
        unknown = set(data) - REQUIRED_FIELDS - OPTIONAL_FIELDS
        if unknown:
            raise ValidationError(f"{source}: campos desconocidos {sorted(unknown)}")

        return cls(
            version=require_semver(data["version"], "version", source),
            channel=parse_channel(data["channel"]),
            compatible_kernel=require_kernel_pattern(
                data["compatible_kernel"], "compatible_kernel", source
            ),
            name=require_text(data["name"], "name", source),
            description=require_text(data["description"], "description", source),
            dependencies=require_string_list(data.get("dependencies"), "dependencies", source),
        )


def load_manifest(path: Path) -> VersionManifest:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{path}: manifiesto ilegible: {exc}") from exc
    if not isinstance(data, dict):
        raise ValidationError(f"{path}: el manifiesto debe ser un objeto JSON")
    return VersionManifest.from_mapping(data, source=str(path))


def kernel_matches(pattern: str, kernel_version: str) -> bool:
    """Compara una versión de núcleo con un patrón exacto (0.1.0) o de parche (0.1.x)."""
    if not SEMVER.match(kernel_version):
        raise ValidationError(f"Versión de núcleo no válida: {kernel_version}")
    if pattern.endswith(".x"):
        return pattern.split(".")[:2] == kernel_version.split(".")[:2]
    return pattern == kernel_version
