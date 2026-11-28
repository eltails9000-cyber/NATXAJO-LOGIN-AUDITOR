"""Matrices de pruebas: casos generados a partir del formulario y de las cuentas sintéticas.

Todas las matrices usan solo cuentas sintéticas y valores fijos de prueba. No se generan contraseñas
candidatas, ni variantes de nombres, fechas u otros datos personales, ni se repite un valor para
adivinar una contraseña: cada caso prueba una propiedad concreta de la validación del servidor.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Final

from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.pruebas.cuentas import identidad_de
from natxajo_auditor.pruebas.modelo import (
    CONTRASENA,
    IDENTIDAD,
    SUITES,
    Caso,
    Credencial,
    Formulario,
    Observado,
    TipoFormulario,
)

CONTRASENA_INCORRECTA: Final = "clave-incorrecta-sintetica-0001"
USUARIO_INEXISTENTE: Final = "prueba-inexistente-0001"
CARACTERES_ESPECIALES: Final = "ñáé <>&\"'%20 ✓"
_DOMINIO_INEXISTENTE: Final = "@example.invalid"

Constructor = Callable[[Formulario, Sequence[tuple[str, Credencial]]], list[Caso]]


def identidad_inexistente(formulario: Formulario) -> str:
    """Identidad de una cuenta que no existe, con el mismo formato que la de una cuenta sintética."""
    if formulario.tipo is TipoFormulario.CORREO_CONTRASENA:
        return USUARIO_INEXISTENTE + _DOMINIO_INEXISTENTE
    return USUARIO_INEXISTENTE


def suites_que_componen(nombre: str) -> tuple[str, ...]:
    """Suites reales de un nombre. «login-validation» agrupa dos suites; el resto es una sola."""
    if nombre == "login-validation":
        return ("validation", "format")
    if nombre not in SUITES:
        opciones = ", ".join(sorted(SUITES))
        raise ValidationError(f"suite no conocida; use una de: {opciones}")
    return (nombre,)


def generar_casos(
    nombre: str,
    formulario: Formulario,
    credenciales: Sequence[tuple[str, Credencial]],
) -> list[Caso]:
    """Casos de una suite. Las suites de cuenta usan la primera cuenta, salvo synthetic-accounts."""
    if not credenciales:
        raise ValidationError("la suite necesita al menos una cuenta sintética")
    casos: list[Caso] = []
    for suite in suites_que_componen(nombre):
        casos.extend(_CONSTRUCTORES[suite](formulario, credenciales))
    return casos


def _validacion(
    formulario: Formulario, credenciales: Sequence[tuple[str, Credencial]]
) -> list[Caso]:
    cuenta, credencial = credenciales[0]
    identidad = identidad_de(formulario, credencial)
    contrasena = credencial.contrasena
    rechazo = Observado.RECHAZADA
    return [
        Caso("validacion-identidad-vacia", formulario, rechazo, cuenta, "", contrasena),
        Caso("validacion-contrasena-vacia", formulario, rechazo, cuenta, identidad, ""),
        Caso("validacion-ambos-vacios", formulario, rechazo, cuenta, "", ""),
        Caso("validacion-identidad-omitida", formulario, rechazo, cuenta, None, contrasena),
        Caso("validacion-contrasena-omitida", formulario, rechazo, cuenta, identidad, None),
        Caso("validacion-formulario-vacio", formulario, rechazo, None, None, None),
    ]


def _formato(formulario: Formulario, credenciales: Sequence[tuple[str, Credencial]]) -> list[Caso]:
    cuenta, credencial = credenciales[0]
    identidad = identidad_de(formulario, credencial)
    contrasena = credencial.contrasena
    rechazo = Observado.RECHAZADA
    minimo_id, maximo_id = formulario.longitudes.get(IDENTIDAD, (1, 254))
    minimo_pw, maximo_pw = formulario.longitudes.get(CONTRASENA, (1, 256))
    casos = [
        Caso(
            "formato-identidad-supera-maximo",
            formulario,
            rechazo,
            cuenta,
            "a" * (maximo_id + 1),
            contrasena,
        ),
        Caso(
            "formato-contrasena-supera-maximo",
            formulario,
            rechazo,
            cuenta,
            identidad,
            "x" * (maximo_pw + 1),
        ),
        Caso(
            "formato-caracteres-especiales",
            formulario,
            rechazo,
            cuenta,
            CARACTERES_ESPECIALES,
            contrasena,
        ),
    ]
    if minimo_id >= 2:
        casos.append(
            Caso(
                "formato-identidad-bajo-minimo",
                formulario,
                rechazo,
                cuenta,
                "a" * (minimo_id - 1),
                contrasena,
            )
        )
    if minimo_pw >= 2:
        casos.append(
            Caso(
                "formato-contrasena-bajo-minimo",
                formulario,
                rechazo,
                cuenta,
                identidad,
                "x" * (minimo_pw - 1),
            )
        )
    if formulario.tipo is TipoFormulario.CORREO_CONTRASENA:
        casos.append(
            Caso(
                "formato-correo-invalido",
                formulario,
                rechazo,
                cuenta,
                "no-es-un-correo",
                contrasena,
            )
        )
    return casos


def _credenciales(
    formulario: Formulario, credenciales: Sequence[tuple[str, Credencial]]
) -> list[Caso]:
    cuenta, credencial = credenciales[0]
    identidad = identidad_de(formulario, credencial)
    return [
        Caso(
            "credencial-valida",
            formulario,
            Observado.ACEPTADA,
            cuenta,
            identidad,
            credencial.contrasena,
        ),
        Caso(
            "credencial-contrasena-incorrecta",
            formulario,
            Observado.RECHAZADA,
            cuenta,
            identidad,
            CONTRASENA_INCORRECTA,
        ),
        Caso(
            "credencial-cuenta-inexistente",
            formulario,
            Observado.RECHAZADA,
            None,
            identidad_inexistente(formulario),
            CONTRASENA_INCORRECTA,
        ),
    ]


def _cuentas(formulario: Formulario, credenciales: Sequence[tuple[str, Credencial]]) -> list[Caso]:
    casos: list[Caso] = []
    for cuenta, credencial in credenciales:
        identidad = identidad_de(formulario, credencial)
        casos.append(
            Caso(
                f"cuenta-{cuenta}-valida",
                formulario,
                Observado.ACEPTADA,
                cuenta,
                identidad,
                credencial.contrasena,
            )
        )
        casos.append(
            Caso(
                f"cuenta-{cuenta}-incorrecta",
                formulario,
                Observado.RECHAZADA,
                cuenta,
                identidad,
                CONTRASENA_INCORRECTA,
            )
        )
    return casos


_CONSTRUCTORES: Final[dict[str, Constructor]] = {
    "validation": _validacion,
    "format": _formato,
    "credentials": _credenciales,
    "synthetic-accounts": _cuentas,
}
