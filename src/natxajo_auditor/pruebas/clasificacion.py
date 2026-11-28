"""Clasificación de respuestas y evaluación de resultados. Funciones puras: sin red ni base de datos.

Dos pasos separados: `clasificar` dice qué hizo el servidor (aceptó, rechazó, bloqueó, falló o dio
una respuesta inconsistente); `evaluar` compara eso con lo esperado y produce el resultado de la
prueba. Los motivos son textos fijos o derivados de códigos HTTP, nunca fragmentos del cuerpo de la
respuesta, de modo que no pueden contener datos sensibles.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final
from urllib.parse import urlsplit

from natxajo_auditor.pruebas.cliente import Respuesta
from natxajo_auditor.pruebas.modelo import Observado, ReglasRespuesta, Resultado

MAX_MOTIVO: Final = 300
_CODIGOS_DE_RECHAZO: Final = frozenset({400, 401, 403, 422})


def clasificar(respuesta: Respuesta, reglas: ReglasRespuesta) -> tuple[Observado, str]:
    """Qué hizo el servidor, con un motivo fijo que explica la decisión."""
    if respuesta.error is not None:
        return Observado.ERROR, respuesta.error
    codigo = respuesta.codigo
    cuerpo = respuesta.cuerpo
    if codigo in (423, 429) or _contiene(cuerpo, reglas.bloqueo):
        return Observado.BLOQUEADA, f"el servidor limitó la solicitud (HTTP {codigo})"
    if codigo == 404:
        return Observado.ERROR, "ruta no encontrada en el objetivo (HTTP 404)"
    if codigo >= 500:
        return Observado.ERROR, f"error interno del servidor (HTTP {codigo})"
    if 300 <= codigo < 400:
        if respuesta.ubicacion is None:
            return Observado.INCONSISTENTE, "redirección sin destino"
        destino = urlsplit(respuesta.ubicacion).path or respuesta.ubicacion
        if destino == reglas.ruta_login:
            return Observado.RECHAZADA, "redirige al formulario de inicio de sesión"
        return Observado.ACEPTADA, "redirige fuera del formulario de inicio de sesión"

    exito = _contiene(cuerpo, reglas.exito)
    fallo = _contiene(cuerpo, reglas.fallo)
    if exito and fallo:
        return Observado.INCONSISTENTE, "la respuesta contiene marcadores de éxito y de fallo"
    if 200 <= codigo < 300:
        if fallo:
            return Observado.RECHAZADA, "la página muestra un mensaje de fallo"
        if exito:
            return Observado.ACEPTADA, "la página muestra un marcador de éxito"
        return Observado.INCONSISTENTE, "respuesta 2xx sin marcador de éxito ni de fallo"
    if codigo in _CODIGOS_DE_RECHAZO:
        if exito:
            return Observado.INCONSISTENTE, f"HTTP {codigo} con marcador de éxito"
        return Observado.RECHAZADA, f"el servidor rechazó la solicitud (HTTP {codigo})"
    return Observado.INCONSISTENTE, f"código HTTP inesperado ({codigo})"


def evaluar(esperado: Observado, observado: Observado, motivo: str) -> tuple[Resultado, str]:
    """Resultado de la prueba a partir de lo esperado y lo observado."""
    if observado is Observado.BLOQUEADA:
        return Resultado.BLOCKED, _acotar(f"bloqueo observado: {motivo}")
    if observado is Observado.ERROR:
        return Resultado.ERROR, _acotar(motivo)
    if observado is Observado.INCONSISTENTE:
        return Resultado.FAIL, _acotar(f"respuesta inconsistente: {motivo}")
    if observado is esperado:
        return Resultado.PASS, _acotar(f"comportamiento esperado ({observado.value}): {motivo}")
    return Resultado.FAIL, _acotar(
        f"se esperaba {esperado.value} y el servidor respondió {observado.value}: {motivo}"
    )


def _contiene(cuerpo: str, marcadores: Iterable[str]) -> bool:
    return any(marcador in cuerpo for marcador in marcadores)


def _acotar(texto: str) -> str:
    return texto if len(texto) <= MAX_MOTIVO else texto[: MAX_MOTIVO - 1] + "…"
