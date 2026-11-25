"""Preferencias visuales de la interfaz gráfica, guardadas en `config/interfaz.json`.

Son valores de presentación: no afectan a la seguridad ni a la auditoría. Un archivo ilegible o
con valores no válidos no impide arrancar la interfaz: se usan los valores por defecto y se
informa del problema. Al guardar, el archivo se escribe en una copia temporal y se sustituye de
una vez, para no dejar una mitad escrita.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from natxajo_auditor.core.exceptions import ValidationError

FILE_NAME = "interfaz.json"
MAX_FILE_BYTES = 4096
THEMES = ("oscuro", "claro")
DENSITIES = ("comoda", "compacta")
MOTION = ("normal", "reducido")
START_PAGES = (
    "panel",
    "auditoria",
    "usuarios",
    "sesiones",
    "plugins",
    "modulos",
    "reportes",
    "eventos",
    "seguridad",
    "mantenimiento",
    "configuracion",
)
REFRESH_SECONDS = (0, 30, 60, 300)
PAGE_SIZES = (10, 25, 50, 100)


@dataclass(frozen=True)
class Preferences:
    tema: str = "oscuro"
    densidad: str = "comoda"
    movimiento: str = "normal"
    pagina_inicio: str = "panel"
    actualizacion_segundos: int = 0
    filas_por_pagina: int = 25
    notificaciones: bool = True

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LoadResult:
    preferences: Preferences
    warning: str | None


def from_mapping(data: Mapping[str, object]) -> Preferences:
    """Valida un diccionario de preferencias. Las claves desconocidas y los valores fuera de
    rango se rechazan: un error tipográfico no debe pasar en silencio."""
    unknown = sorted(set(data) - set(Preferences.__dataclass_fields__))
    if unknown:
        raise ValidationError(f"preferencia desconocida: {unknown[0]}")
    base = Preferences()
    return Preferences(
        tema=_choice(data, "tema", THEMES, base.tema),
        densidad=_choice(data, "densidad", DENSITIES, base.densidad),
        movimiento=_choice(data, "movimiento", MOTION, base.movimiento),
        pagina_inicio=_choice(data, "pagina_inicio", START_PAGES, base.pagina_inicio),
        actualizacion_segundos=_int_choice(
            data, "actualizacion_segundos", REFRESH_SECONDS, base.actualizacion_segundos
        ),
        filas_por_pagina=_int_choice(data, "filas_por_pagina", PAGE_SIZES, base.filas_por_pagina),
        notificaciones=_flag(data, "notificaciones", base.notificaciones),
    )


def load(path: Path) -> LoadResult:
    """Lee las preferencias. Nunca lanza: ante cualquier problema devuelve los valores por defecto
    y un aviso para mostrar en la pantalla de configuración."""
    if not path.exists():
        return LoadResult(Preferences(), None)
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise ValidationError("el archivo es demasiado grande")
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValidationError("el archivo debe contener un objeto JSON")
        return LoadResult(from_mapping(data), None)
    except (OSError, ValueError, ValidationError) as exc:
        return LoadResult(Preferences(), f"Preferencias ignoradas: {exc}")


def save(path: Path, preferences: Preferences) -> None:
    """Guarda las preferencias de forma atómica: primero una copia temporal, luego el cambio."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    text = json.dumps(preferences.as_dict(), ensure_ascii=False, indent=2) + "\n"
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def _choice(data: Mapping[str, object], key: str, allowed: tuple[str, ...], default: str) -> str:
    value = data.get(key, default)
    if not isinstance(value, str) or value not in allowed:
        raise ValidationError(f"valor no válido para {key}")
    return value


def _int_choice(
    data: Mapping[str, object], key: str, allowed: tuple[int, ...], default: int
) -> int:
    value = data.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value not in allowed:
        raise ValidationError(f"valor no válido para {key}")
    return value


def _flag(data: Mapping[str, object], key: str, default: bool) -> bool:
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise ValidationError(f"valor no válido para {key}")
    return value
