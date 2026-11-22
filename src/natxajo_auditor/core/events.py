"""Contratos de eventos: catálogo cerrado, categoría y claves de carga de cada tipo.

Un evento solo puede publicarse si su nombre está en el catálogo y su carga tiene exactamente
las claves declaradas (obligatorias y opcionales). Los valores son escalares JSON o listas de
texto. Las claves que parecen secretos se rechazan aunque el catálogo no las declare.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.core.utilities import to_iso

COMPANY_ID = re.compile(r"^[a-z][a-z0-9-]{2,39}$")
_SECRET_HINTS = ("password", "contrase", "token", "secret", "clave", "ficha")


class Category(StrEnum):
    OPERATIONAL = "operativo"
    SECURITY = "seguridad"


@dataclass(frozen=True)
class EventSpec:
    category: Category
    required: frozenset[str]
    optional: frozenset[str] = frozenset()


def _spec(category: Category, required: str = "", optional: str = "") -> EventSpec:
    return EventSpec(
        category=category,
        required=frozenset(required.split()),
        optional=frozenset(optional.split()),
    )


_OP = Category.OPERATIONAL
_SEC = Category.SECURITY

CATALOG: Mapping[str, EventSpec] = {
    "kernel.started": _spec(_OP, "version"),
    "kernel.stopped": _spec(_OP),
    "module.enabled": _spec(_OP, "module"),
    "module.disabled": _spec(_OP, "module"),
    "version.activated": _spec(_OP, "from to reason"),
    "plugin.installed": _spec(_OP, "plugin version publisher trust_level"),
    "plugin.rejected": _spec(_SEC, "source reason"),
    "plugin.enabled": _spec(_OP, "plugin version"),
    "plugin.disabled": _spec(_OP, "plugin", "reason"),
    "plugin.uninstalled": _spec(_OP, "plugin version"),
    "plugin.reviewed": _spec(_SEC, "plugin version reviewer decision"),
    "plugin.publisher_registered": _spec(_SEC, "publisher trust_level username"),
    "plugin.publisher_revoked": _spec(_SEC, "publisher disabled username"),
    "account.created": _spec(_SEC, "username roles"),
    "account.login_failed": _spec(_SEC, "username locked"),
    "account.login_blocked": _spec(_SEC, "username"),
    "account.authenticated": _spec(_SEC, "username"),
    "account.status_changed": _spec(_SEC, "username status"),
    "account.password_changed": _spec(_SEC, "username"),
    "account.roles_changed": _spec(_SEC, "username roles"),
    "session.opened": _spec(_SEC, "username"),
    "session.expired": _spec(_SEC, "username"),
    "session.closed": _spec(_SEC, "username"),
    "session.closed_all": _spec(_SEC, "username"),
    "session.reauthenticated": _spec(_SEC, "username"),
    "grant.requested": _spec(_SEC, "grant username permission"),
    "grant.approved": _spec(_SEC, "grant approver permission"),
    "grant.rejected": _spec(_SEC, "grant actor"),
    "grant.revoked": _spec(_SEC, "grant actor"),
    "operation.denied": _spec(_SEC, "username permission reason", "empresa_destino"),
    "operation.executed": _spec(_SEC, "username permission critical"),
    "installation.code_issued": _spec(_SEC),
    "installation.code_rejected": _spec(_SEC, "intentos"),
    "installation.completed": _spec(_SEC, "username"),
    "company.created": _spec(_SEC, "empresa nombre"),
}

JsonValue = str | int | bool | None | list[str]


@dataclass(frozen=True)
class Event:
    event_id: str
    name: str
    category: Category
    occurred_at: str
    company_id: str | None
    actor: str | None
    payload: dict[str, JsonValue]


def build_event(
    name: str,
    payload: Mapping[str, Any],
    *,
    event_id: str,
    occurred_at: datetime,
    company_id: str | None = None,
    actor: str | None = None,
) -> Event:
    """Valida un evento contra el catálogo y devuelve su versión inmutable."""
    spec = CATALOG.get(name)
    if spec is None:
        raise ValidationError(f"evento no declarado en el catálogo: {name}")
    keys = set(payload)
    missing = sorted(spec.required - keys)
    if missing:
        raise ValidationError(f"evento {name}: faltan claves {missing}")
    extra = sorted(keys - spec.required - spec.optional)
    if extra:
        raise ValidationError(f"evento {name}: claves no declaradas {extra}")
    for key in keys:
        if any(hint in key.lower() for hint in _SECRET_HINTS):
            raise ValidationError(f"evento {name}: la clave {key} parece sensible")
    if company_id is not None and not COMPANY_ID.match(company_id):
        raise ValidationError(f"identificador de empresa no válido: {company_id}")
    return Event(
        event_id=event_id,
        name=name,
        category=spec.category,
        occurred_at=to_iso(occurred_at),
        company_id=company_id,
        actor=actor,
        payload={key: _normalize(name, key, payload[key]) for key in sorted(keys)},
    )


def _normalize(name: str, key: str, value: object) -> JsonValue:
    """Convierte un valor admitido en su forma JSON. Cualquier otro tipo se rechaza."""
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
        return [str(item) for item in value]
    raise ValidationError(f"evento {name}: valor no admitido en {key}")
