"""Objetivos de prueba: normalización del origen y comprobación de la lista permitida.

Un origen es esquema, host y puerto. No admite credenciales en la URL, ruta, consulta ni fragmento,
porque cada petición se construye a partir de la ruta del formulario y el origen no debe llevar
nada más. El registro de objetivos permitidos vive en la base de datos (ver repositorio.py).
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Final

from natxajo_auditor.core.exceptions import ValidationError

MAX_ORIGEN_LEN: Final = 300
_HOST: Final = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")
_HOST_IPV6: Final = re.compile(r"[0-9a-f:]{2,45}")
PUERTOS_POR_DEFECTO: Final[dict[str, int]] = {"http": 80, "https": 443}


@dataclass(frozen=True)
class Origen:
    esquema: str
    host: str
    puerto: int

    @property
    def texto(self) -> str:
        """Forma canónica con el puerto explícito. Es la clave con la que se registra el objetivo."""
        anfitrion = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.esquema}://{anfitrion}:{self.puerto}"

    @property
    def https(self) -> bool:
        return self.esquema == "https"


def normalizar_origen(texto: str) -> Origen:
    """Origen canónico a partir de una URL base. Rechaza todo lo que no sea esquema, host y puerto."""
    valor = texto.strip()
    if not valor or len(valor) > MAX_ORIGEN_LEN:
        raise ValidationError("el origen está vacío o es demasiado largo")
    partes = urllib.parse.urlsplit(valor)
    if partes.scheme not in PUERTOS_POR_DEFECTO:
        raise ValidationError("el origen debe empezar por http:// o https://")
    if "@" in partes.netloc or partes.username is not None or partes.password is not None:
        raise ValidationError("el origen no admite usuario ni contraseña en la URL")
    if partes.path not in ("", "/") or partes.query or partes.fragment:
        raise ValidationError("el origen no admite ruta, consulta ni fragmento")
    host = (partes.hostname or "").lower()
    if not host or not (_HOST.fullmatch(host) or _HOST_IPV6.fullmatch(host)):
        raise ValidationError("el host del origen no es válido")
    try:
        puerto = partes.port
    except ValueError as exc:
        raise ValidationError("el puerto del origen no es válido") from exc
    return Origen(
        esquema=partes.scheme,
        host=host,
        puerto=puerto if puerto is not None else PUERTOS_POR_DEFECTO[partes.scheme],
    )


def esta_permitido(origen: Origen, registrados: frozenset[str]) -> bool:
    """Un origen solo se usa si su forma canónica está registrada como objetivo."""
    return origen.texto in registrados
