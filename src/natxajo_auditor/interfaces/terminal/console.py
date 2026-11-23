"""Tipos compartidos de la terminal: consola, opciones de menú y confirmaciones.

Los usan la aplicación de terminal (app.py) y las acciones por áreas (operaciones.py). Esta capa
presenta datos y pide confirmaciones; no decide permisos ni empresas.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from natxajo_auditor.kernel.kernel import Kernel

Read = Callable[[str], str]
Write = Callable[[str], None]

SCOPE_NONE = "ninguno"
SCOPE_OWN = "propia"
SCOPE_PLATFORM = "plataforma"
CONFIRMATIONS = frozenset({"sí", "si", "s"})


@dataclass
class Console:
    kernel: Kernel
    read: Read
    read_secret: Read
    write: Write
    token: str = ""
    username: str = ""
    company: str = ""


@dataclass(frozen=True)
class Option:
    """Opción de menú.

    `guarded` indica que el servicio del núcleo ya aplica el guardián (sesión, permiso, empresa,
    confirmación y reautenticación) y registra la operación. En ese caso la terminal no lo envuelve
    otra vez, para no registrar dos veces ni pedir dos confirmaciones.
    """

    key: str
    label: str
    permission: str | None
    critical: bool
    action: Callable[[Console], None]
    scope: str = SCOPE_NONE
    guarded: bool = False


def confirm(console: Console) -> bool:
    answer = console.read("¿Confirma la operación? (sí/no): ").strip().lower()
    return answer in CONFIRMATIONS
