"""Modelo del motor de pruebas HTTP: resultados, formularios, límites y catálogo de pruebas.

Las credenciales viven solo en memoria durante una ejecución. Los tipos marcan con `repr=False`
los campos secretos para que no aparezcan en trazas ni en registros.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

IDENTIFICADOR: Final = re.compile(r"[a-z][a-z0-9-]{0,39}")
NOMBRE_CAMPO: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_.\-]{0,63}")
RUTA: Final = re.compile(r"/[A-Za-z0-9_./-]{0,199}")
USUARIO_SINTETICO: Final = re.compile(r"(?:prueba|sintetica)-[a-z0-9][a-z0-9-]{0,30}")
CORREO_SINTETICO: Final = re.compile(
    r"[a-z0-9][a-z0-9._-]{0,40}@(?:example\.(?:com|org|net)|[a-z0-9-]+\.(?:invalid|test))"
)
VARIABLE_ENTORNO: Final = re.compile(r"NATXAJO_PRUEBA_[A-Z0-9_]{1,50}")

# Roles lógicos de los campos. El nombre real del campo en cada formulario se declara en su esquema.
IDENTIDAD: Final = "identidad"
CONTRASENA: Final = "contrasena"


# Respuesta observada tras clasificarla. Es lo que el servidor hizo, no el resultado de la prueba.
class Observado(StrEnum):
    ACEPTADA = "aceptada"
    RECHAZADA = "rechazada"
    BLOQUEADA = "bloqueada"
    INCONSISTENTE = "inconsistente"
    ERROR = "error"


# Resultado de la prueba. BLOCKED: un control del servidor bloqueó la solicitud. ERROR: fallo técnico.
class Resultado(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class TipoFormulario(StrEnum):
    USUARIO_CONTRASENA = "usuario_contrasena"
    CORREO_CONTRASENA = "correo_contrasena"
    NOMBRE_USUARIO_CONTRASENA = "nombre_usuario_contrasena"
    IDENTIFICADOR_CONTRASENA = "identificador_contrasena"
    USUARIO_CONTRASENA_MFA = "usuario_contrasena_mfa"


@dataclass(frozen=True)
class Limites:
    """Límites de una ejecución. Los valores se validan contra LIMITES_MAXIMOS y LIMITES_MINIMOS."""

    max_solicitudes: int = 100
    max_cuentas: int = 10
    concurrencia: int = 1
    pausa_ms: int = 0
    timeout_s: float = 5.0
    max_intentos: int = 6


LIMITES_MAXIMOS: Final = Limites(
    max_solicitudes=500,
    max_cuentas=50,
    concurrencia=4,
    pausa_ms=5000,
    timeout_s=30.0,
    max_intentos=10,
)
LIMITES_MINIMOS: Final = Limites(
    max_solicitudes=1,
    max_cuentas=1,
    concurrencia=1,
    pausa_ms=0,
    timeout_s=0.5,
    max_intentos=1,
)


@dataclass(frozen=True)
class CuentaSintetica:
    """Cuenta de prueba declarada en configuración. La contraseña se lee del entorno, no se guarda."""

    id: str
    usuario: str
    variable_contrasena: str
    variable_mfa: str | None = None
    correo: str | None = None


@dataclass(frozen=True)
class Credencial:
    usuario: str
    contrasena: str = field(repr=False)
    correo: str | None = None
    codigo_mfa: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class Csrf:
    campo: str
    pagina: str


@dataclass(frozen=True)
class Mfa:
    campo: str
    ruta: str
    marcador: str


@dataclass(frozen=True)
class ReglasRespuesta:
    """Marcadores que el formulario usa para interpretar la respuesta del servidor."""

    exito: tuple[str, ...]
    fallo: tuple[str, ...]
    bloqueo: tuple[str, ...]
    ruta_login: str


@dataclass(frozen=True)
class Formulario:
    id: str
    tipo: TipoFormulario
    ruta: str
    campos: Mapping[str, str]
    longitudes: Mapping[str, tuple[int, int]]
    extra: Mapping[str, str]
    reglas: ReglasRespuesta
    csrf: Csrf | None = None
    mfa: Mfa | None = None


@dataclass(frozen=True)
class Caso:
    """Una solicitud de formulario con su resultado esperado. La contraseña solo vive en memoria."""

    id: str
    formulario: Formulario
    esperado: Observado
    cuenta: str | None
    identidad: str | None
    contrasena: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class ResultadoCaso:
    posicion: int
    caso_id: str
    formulario_id: str
    tipo: str
    cuenta: str | None
    resultado: Resultado
    esperado: str
    observado: str
    codigo_http: int | None
    duracion_ms: int | None
    motivo: str


SUITES: Final[Mapping[str, str]] = {
    "validation": "Campos vacíos, omitidos o formulario vacío: el servidor debe rechazar la solicitud.",
    "format": "Longitudes mínimas y máximas, caracteres especiales y formato de correo inválido.",
    "credentials": "Credencial sintética válida, contraseña incorrecta y cuenta inexistente.",
    "synthetic-accounts": "Cada cuenta sintética: credencial válida y contraseña incorrecta.",
    "login-validation": "Agrupa las suites validation y format.",
}

PROCEDURES: Final[Mapping[str, str]] = {
    "rate-limit": "Intentos incorrectos sobre una cuenta sintética hasta observar bloqueo, con tope.",
    "csrf": "Envío sin token, con token incorrecto y con token válido.",
    "mfa": "Primer factor, código incorrecto y código de prueba válido.",
    "sessions": "Atributos HttpOnly, Secure y SameSite de las cookies de sesión.",
    "response-check": "Diferencias de respuesta entre una cuenta existente y una inexistente.",
}
