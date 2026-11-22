"""Manifiesto de módulo: contrato declarativo validado antes de cualquier uso."""

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
    require_semver,
    require_string_list,
    require_text,
)

MODULE_FILE = "module.json"
REQUIRED_FIELDS = frozenset({"id", "name", "version", "description"})
OPTIONAL_FIELDS = frozenset({"requires", "permissions"})


@dataclass(frozen=True)
class ModuleManifest:
    module_id: str
    name: str
    version: str
    description: str
    requires: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], source: str = MODULE_FILE) -> ModuleManifest:
        missing = REQUIRED_FIELDS - set(data)
        if missing:
            raise ValidationError(f"{source}: faltan campos {sorted(missing)}")
        unknown = set(data) - REQUIRED_FIELDS - OPTIONAL_FIELDS
        if unknown:
            raise ValidationError(f"{source}: campos desconocidos {sorted(unknown)}")

        module_id = require_identifier(data["id"], "id", source)
        requires = require_string_list(data.get("requires"), "requires", source)
        if module_id in requires:
            raise ValidationError(f"{source}: un módulo no puede requerirse a sí mismo")
        for item in requires:
            require_identifier(item, "identificador requerido", source)

        return cls(
            module_id=module_id,
            name=require_text(data["name"], "name", source),
            version=require_semver(data["version"], "version", source),
            description=require_text(data["description"], "description", source),
            requires=requires,
            permissions=validate_declared(data.get("permissions"), source),
        )


def load_module_manifest(path: Path) -> ModuleManifest:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{path}: manifiesto ilegible: {exc}") from exc
    if not isinstance(data, dict):
        raise ValidationError(f"{path}: el manifiesto debe ser un objeto JSON")
    return ModuleManifest.from_mapping(data, source=str(path))
