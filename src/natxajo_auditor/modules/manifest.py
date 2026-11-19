"""Manifiesto de módulo: contrato declarativo validado antes de cualquier uso."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.modules.permissions import validate_permissions

MODULE_FILE = "module.json"
_ID = re.compile(r"^[a-z][a-z0-9_]{2,39}$")
_VERSION = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
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

        module_id = _text(data["id"], "id", source)
        if not _ID.match(module_id):
            raise ValidationError(
                f"{source}: id no válido: {module_id} (minúsculas, dígitos y guion bajo, 3 a 40)"
            )
        version = _text(data["version"], "version", source)
        if not _VERSION.match(version):
            raise ValidationError(f"{source}: versión no válida: {version}")

        requires_raw = data.get("requires", [])
        if not isinstance(requires_raw, list) or not all(
            isinstance(item, str) for item in requires_raw
        ):
            raise ValidationError(f"{source}: requires debe ser una lista de identificadores")
        if module_id in requires_raw:
            raise ValidationError(f"{source}: un módulo no puede requerirse a sí mismo")
        if len(set(requires_raw)) != len(requires_raw):
            raise ValidationError(f"{source}: hay dependencias repetidas")
        for item in requires_raw:
            if not _ID.match(item):
                raise ValidationError(f"{source}: identificador requerido no válido: {item}")

        permissions = validate_permissions(data.get("permissions", []), source)

        return cls(
            module_id=module_id,
            name=_text(data["name"], "name", source),
            version=version,
            description=_text(data["description"], "description", source),
            requires=tuple(requires_raw),
            permissions=permissions,
        )


def load_module_manifest(path: Path) -> ModuleManifest:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{path}: manifiesto ilegible: {exc}") from exc
    if not isinstance(data, dict):
        raise ValidationError(f"{path}: el manifiesto debe ser un objeto JSON")
    return ModuleManifest.from_mapping(data, source=str(path))


def _text(value: object, field: str, source: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{source}: {field} debe ser un texto no vacío")
    return value
