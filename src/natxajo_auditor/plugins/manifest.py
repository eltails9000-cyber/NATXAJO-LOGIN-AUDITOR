"""Manifiesto de plugin (plugin.json): contrato declarativo validado antes de cualquier uso."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.core.permissions import validate_declared
from natxajo_auditor.core.validation import (
    require_identifier,
    require_kernel_pattern,
    require_semver,
    require_string_list,
    require_text,
)

PLUGIN_FILE = "plugin.json"
REQUIRED_FIELDS = frozenset(
    {"id", "name", "version", "author", "description", "api_version", "compatible_kernel"}
)
OPTIONAL_FIELDS = frozenset({"dependencies", "permissions"})


@dataclass(frozen=True)
class PluginManifest:
    plugin_id: str
    name: str
    version: str
    author: str
    description: str
    api_version: str
    compatible_kernel: str
    dependencies: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], source: str = PLUGIN_FILE) -> PluginManifest:
        missing = REQUIRED_FIELDS - set(data)
        if missing:
            raise ValidationError(f"{source}: faltan campos {sorted(missing)}")
        unknown = set(data) - REQUIRED_FIELDS - OPTIONAL_FIELDS
        if unknown:
            raise ValidationError(f"{source}: campos desconocidos {sorted(unknown)}")

        plugin_id = require_identifier(data["id"], "id", source)
        dependencies = require_string_list(data.get("dependencies"), "dependencies", source)
        if plugin_id in dependencies:
            raise ValidationError(f"{source}: un plugin no puede depender de sí mismo")
        for dependency in dependencies:
            require_identifier(dependency, "dependencia", source)

        return cls(
            plugin_id=plugin_id,
            name=require_text(data["name"], "name", source),
            version=require_semver(data["version"], "version", source),
            author=require_text(data["author"], "author", source),
            description=require_text(data["description"], "description", source),
            api_version=require_text(data["api_version"], "api_version", source),
            compatible_kernel=require_kernel_pattern(
                data["compatible_kernel"], "compatible_kernel", source
            ),
            dependencies=dependencies,
            permissions=validate_declared(data.get("permissions"), source),
        )


def load_plugin_manifest(path: Path) -> PluginManifest:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{path}: manifiesto ilegible: {exc}") from exc
    if not isinstance(data, dict):
        raise ValidationError(f"{path}: el manifiesto debe ser un objeto JSON")
    return PluginManifest.from_mapping(data, source=str(path))
