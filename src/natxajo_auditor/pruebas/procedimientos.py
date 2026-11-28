"""Procedimientos de seguridad: límite de intentos, CSRF, MFA, cookies de sesión y consistencia.

Cada procedimiento es una secuencia pequeña y acotada de peticiones. Todas pasan por el mismo
presupuesto y el mismo control de cancelación que las matrices. Ninguno intenta eludir un control:
si el servidor bloquea, el procedimiento se detiene y no reintenta.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from typing import Final

from natxajo_auditor.pruebas.clasificacion import clasificar, evaluar
from natxajo_auditor.pruebas.cliente import CookieInfo, Respuesta, Sesion
from natxajo_auditor.pruebas.cuentas import identidad_de
from natxajo_auditor.pruebas.formulario import construir_campos
from natxajo_auditor.pruebas.matrices import CONTRASENA_INCORRECTA, identidad_inexistente
from natxajo_auditor.pruebas.modelo import (
    Credencial,
    Formulario,
    Observado,
    Resultado,
    ResultadoCaso,
    TipoFormulario,
)
from natxajo_auditor.pruebas.motor import (
    Contexto,
    Detenida,
    FalloTecnico,
    interrupcion,
    obtener_token,
    resultado_de,
)

INTENTOS_MAXIMOS_PROCEDIMIENTO: Final = 10
TOKEN_INCORRECTO: Final = "token-incorrecto-sintetico"
CODIGO_MFA_INCORRECTO: Final = "000000"
_TOLERANCIA_MINIMA_BYTES: Final = 32

Procedimiento = Callable[[Contexto, Formulario, Credencial, str], list[ResultadoCaso]]


def limite_de_frecuencia(
    contexto: Contexto,
    formulario: Formulario,
    credencial: Credencial,
    cuenta: str,
) -> list[ResultadoCaso]:
    """Intentos incorrectos hasta observar bloqueo. Se detiene en el primer bloqueo o error."""
    maximo = min(contexto.limites.max_intentos, INTENTOS_MAXIMOS_PROCEDIMIENTO)
    resultados: list[ResultadoCaso] = []
    bloqueado_en: int | None = None
    interrumpida: ResultadoCaso | None = None
    ultimo: Observado | None = None
    try:
        for intento in range(1, maximo + 1):
            sesion = Sesion()
            token = obtener_token(formulario, contexto, sesion)
            campos = construir_campos(
                formulario,
                identidad=identidad_de(formulario, credencial),
                contrasena=CONTRASENA_INCORRECTA,
                token=token,
            )
            respuesta = contexto.peticion("POST", formulario.ruta, campos, sesion)
            observado, motivo = clasificar(respuesta, formulario.reglas)
            resultado, detalle = evaluar(Observado.RECHAZADA, observado, motivo)
            resultados.append(
                resultado_de(
                    formulario,
                    f"limite-frecuencia-intento-{intento:02d}",
                    cuenta,
                    Observado.RECHAZADA.value,
                    resultado,
                    observado.value,
                    detalle,
                    respuesta,
                )
            )
            ultimo = observado
            if observado is Observado.BLOQUEADA:
                bloqueado_en = intento
                break
            if observado is Observado.ERROR:
                break
    except (Detenida, FalloTecnico) as exc:
        interrumpida = interrupcion(formulario, "limite-frecuencia-interrumpido", cuenta, exc)
        resultados.append(interrumpida)

    if bloqueado_en is not None:
        resumen = resultado_de(
            formulario,
            "limite-frecuencia-resumen",
            cuenta,
            "bloqueada",
            Resultado.PASS,
            Observado.BLOQUEADA.value,
            f"el servidor bloqueó la cuenta tras {bloqueado_en} intentos incorrectos",
        )
    elif interrumpida is not None:
        resumen = dataclasses.replace(interrumpida, caso_id="limite-frecuencia-resumen")
    elif ultimo is Observado.ERROR:
        resumen = resultado_de(
            formulario,
            "limite-frecuencia-resumen",
            cuenta,
            "bloqueada",
            Resultado.ERROR,
            "error",
            "la prueba se detuvo por un error técnico antes de observar bloqueo",
        )
    else:
        resumen = resultado_de(
            formulario,
            "limite-frecuencia-resumen",
            cuenta,
            "bloqueada",
            Resultado.FAIL,
            "rechazada",
            f"no se observó bloqueo en {maximo} intentos; la prueba no demuestra que no exista límite",
        )
    resultados.append(resumen)
    return resultados


def proteccion_csrf(
    contexto: Contexto,
    formulario: Formulario,
    credencial: Credencial,
    cuenta: str,
) -> list[ResultadoCaso]:
    """Envío sin token, con token incorrecto y con token válido, cada uno con sesión nueva."""
    if formulario.csrf is None:
        return [
            resultado_de(
                formulario,
                "csrf-no-configurado",
                cuenta,
                "-",
                Resultado.SKIPPED,
                "",
                "el formulario no declara token CSRF en su esquema",
            )
        ]
    pasos: tuple[tuple[str, str, Observado], ...] = (
        ("csrf-envio-sin-token", "omitido", Observado.RECHAZADA),
        ("csrf-token-incorrecto", "incorrecto", Observado.RECHAZADA),
        ("csrf-token-valido", "valido", Observado.ACEPTADA),
    )
    resultados: list[ResultadoCaso] = []
    try:
        for caso_id, modo, esperado in pasos:
            sesion = Sesion()
            token_real = obtener_token(formulario, contexto, sesion)
            token: str | None
            if modo == "omitido":
                token = None
            elif modo == "incorrecto":
                token = TOKEN_INCORRECTO
            else:
                token = token_real
            campos = construir_campos(
                formulario,
                identidad=identidad_de(formulario, credencial),
                contrasena=credencial.contrasena,
                token=token,
            )
            respuesta = contexto.peticion("POST", formulario.ruta, campos, sesion)
            observado, motivo = clasificar(respuesta, formulario.reglas)
            resultado, detalle = evaluar(esperado, observado, motivo)
            resultados.append(
                resultado_de(
                    formulario,
                    caso_id,
                    cuenta,
                    esperado.value,
                    resultado,
                    observado.value,
                    detalle,
                    respuesta,
                )
            )
    except (Detenida, FalloTecnico) as exc:
        resultados.append(interrupcion(formulario, "csrf-interrumpido", cuenta, exc))
    return resultados


def prueba_mfa(
    contexto: Contexto,
    formulario: Formulario,
    credencial: Credencial,
    cuenta: str,
) -> list[ResultadoCaso]:
    """Primer factor, código incorrecto y código de prueba válido. Solo para formularios MFA."""
    mfa = formulario.mfa
    if mfa is None or formulario.tipo is not TipoFormulario.USUARIO_CONTRASENA_MFA:
        return [
            resultado_de(
                formulario,
                "mfa-no-aplicable",
                cuenta,
                "-",
                Resultado.SKIPPED,
                "",
                "el formulario no es de tipo usuario_contrasena_mfa",
            )
        ]
    if credencial.codigo_mfa is None:
        return [
            resultado_de(
                formulario,
                "mfa-sin-codigo",
                cuenta,
                "-",
                Resultado.ERROR,
                "error",
                "la cuenta sintética no tiene código MFA de prueba en el entorno",
            )
        ]
    codigo_valido = credencial.codigo_mfa
    reglas_primer_factor = dataclasses.replace(
        formulario.reglas, exito=(*formulario.reglas.exito, mfa.marcador)
    )
    resultados: list[ResultadoCaso] = []
    try:
        sesion = Sesion()
        token = obtener_token(formulario, contexto, sesion)
        respuesta = contexto.peticion(
            "POST",
            formulario.ruta,
            construir_campos(
                formulario,
                identidad=identidad_de(formulario, credencial),
                contrasena=credencial.contrasena,
                token=token,
            ),
            sesion,
        )
        observado, motivo = clasificar(respuesta, reglas_primer_factor)
        resultado, detalle = evaluar(Observado.ACEPTADA, observado, motivo)
        resultados.append(
            resultado_de(
                formulario,
                "mfa-primer-factor",
                cuenta,
                Observado.ACEPTADA.value,
                resultado,
                observado.value,
                detalle,
                respuesta,
            )
        )
        if resultado is not Resultado.PASS:
            resultados.append(
                resultado_de(
                    formulario,
                    "mfa-segundo-factor",
                    cuenta,
                    "-",
                    Resultado.SKIPPED,
                    "",
                    "el primer factor no fue aceptado; no se envía el segundo",
                )
            )
            return resultados
        for caso_id, codigo, esperado in (
            ("mfa-codigo-incorrecto", CODIGO_MFA_INCORRECTO, Observado.RECHAZADA),
            ("mfa-codigo-valido", codigo_valido, Observado.ACEPTADA),
        ):
            respuesta_mfa = contexto.peticion(
                "POST",
                mfa.ruta,
                construir_campos(
                    formulario, identidad=None, contrasena=None, token=token, codigo_mfa=codigo
                ),
                sesion,
            )
            observado_mfa, motivo_mfa = clasificar(respuesta_mfa, formulario.reglas)
            resultado_mfa, detalle_mfa = evaluar(esperado, observado_mfa, motivo_mfa)
            resultados.append(
                resultado_de(
                    formulario,
                    caso_id,
                    cuenta,
                    esperado.value,
                    resultado_mfa,
                    observado_mfa.value,
                    detalle_mfa,
                    respuesta_mfa,
                )
            )
    except (Detenida, FalloTecnico) as exc:
        resultados.append(interrupcion(formulario, "mfa-interrumpido", cuenta, exc))
    return resultados


def atributos_de_cookies(
    contexto: Contexto,
    formulario: Formulario,
    credencial: Credencial,
    cuenta: str,
) -> list[ResultadoCaso]:
    """HttpOnly, Secure (solo en HTTPS) y SameSite de cada cookie que establece el inicio de sesión."""
    try:
        sesion = Sesion()
        token = obtener_token(formulario, contexto, sesion)
        respuesta = contexto.peticion(
            "POST",
            formulario.ruta,
            construir_campos(
                formulario,
                identidad=identidad_de(formulario, credencial),
                contrasena=credencial.contrasena,
                token=token,
            ),
            sesion,
        )
    except (Detenida, FalloTecnico) as exc:
        return [interrupcion(formulario, "sesion-interrumpida", cuenta, exc)]
    observado, motivo = clasificar(respuesta, formulario.reglas)
    if observado is not Observado.ACEPTADA:
        return [
            resultado_de(
                formulario,
                "sesion-sin-inicio",
                cuenta,
                "-",
                Resultado.SKIPPED,
                observado.value,
                f"el inicio de sesión no fue aceptado ({motivo}); no hay cookies que analizar",
                respuesta,
            )
        ]
    if not respuesta.cookies:
        return [
            resultado_de(
                formulario,
                "sesion-sin-cookies",
                cuenta,
                "-",
                Resultado.SKIPPED,
                observado.value,
                "el inicio de sesión no establece cookies; revisar el mecanismo de sesión a mano",
                respuesta,
            )
        ]
    resultados: list[ResultadoCaso] = []
    for indice, cookie in enumerate(respuesta.cookies, start=1):
        resultados.extend(_atributos_de(formulario, cuenta, indice, cookie, contexto, respuesta))
    return resultados


def consistencia_de_respuestas(
    contexto: Contexto,
    formulario: Formulario,
    credencial: Credencial,
    cuenta: str,
) -> list[ResultadoCaso]:
    """Compara la respuesta a una cuenta existente con la de una inexistente, misma contraseña."""
    try:
        sesion_existente = Sesion()
        token_existente = obtener_token(formulario, contexto, sesion_existente)
        existente = contexto.peticion(
            "POST",
            formulario.ruta,
            construir_campos(
                formulario,
                identidad=identidad_de(formulario, credencial),
                contrasena=CONTRASENA_INCORRECTA,
                token=token_existente,
            ),
            sesion_existente,
        )
        sesion_inexistente = Sesion()
        token_inexistente = obtener_token(formulario, contexto, sesion_inexistente)
        inexistente = contexto.peticion(
            "POST",
            formulario.ruta,
            construir_campos(
                formulario,
                identidad=identidad_inexistente(formulario),
                contrasena=CONTRASENA_INCORRECTA,
                token=token_inexistente,
            ),
            sesion_inexistente,
        )
    except (Detenida, FalloTecnico) as exc:
        return [interrupcion(formulario, "consistencia-interrumpida", cuenta, exc)]

    obs_existente, _ = clasificar(existente, formulario.reglas)
    obs_inexistente, _ = clasificar(inexistente, formulario.reglas)
    resultados = [
        _comparar(
            formulario,
            "consistencia-clasificacion",
            cuenta,
            obs_existente.value == obs_inexistente.value,
            f"cuenta existente: {obs_existente.value}; inexistente: {obs_inexistente.value}",
        ),
        _comparar(
            formulario,
            "consistencia-codigo-http",
            cuenta,
            existente.codigo == inexistente.codigo,
            f"cuenta existente: HTTP {existente.codigo}; inexistente: HTTP {inexistente.codigo}",
        ),
    ]
    tamano_a = len(existente.cuerpo)
    tamano_b = len(inexistente.cuerpo)
    tolerancia = max(_TOLERANCIA_MINIMA_BYTES, max(tamano_a, tamano_b) // 20)
    resultados.append(
        _comparar(
            formulario,
            "consistencia-tamano-cuerpo",
            cuenta,
            abs(tamano_a - tamano_b) <= tolerancia,
            f"diferencia de {abs(tamano_a - tamano_b)} caracteres; tolerancia {tolerancia}",
        )
    )
    return resultados


def _atributos_de(
    formulario: Formulario,
    cuenta: str,
    indice: int,
    cookie: CookieInfo,
    contexto: Contexto,
    respuesta: Respuesta,
) -> list[ResultadoCaso]:
    controles: list[ResultadoCaso] = [
        _comparar(
            formulario,
            f"sesion-cookie-{indice}-httponly",
            cuenta,
            cookie.httponly,
            f"cookie '{cookie.nombre}': HttpOnly {'presente' if cookie.httponly else 'ausente'}",
            respuesta,
        ),
        _comparar(
            formulario,
            f"sesion-cookie-{indice}-samesite",
            cuenta,
            cookie.samesite in ("Lax", "Strict"),
            f"cookie '{cookie.nombre}': SameSite={cookie.samesite or 'ausente'}",
            respuesta,
        ),
    ]
    if contexto.cliente.origen.https:
        controles.append(
            _comparar(
                formulario,
                f"sesion-cookie-{indice}-secure",
                cuenta,
                cookie.secure,
                f"cookie '{cookie.nombre}': Secure {'presente' if cookie.secure else 'ausente'}",
                respuesta,
            )
        )
    else:
        controles.append(
            resultado_de(
                formulario,
                f"sesion-cookie-{indice}-secure",
                cuenta,
                "presente",
                Resultado.SKIPPED,
                "",
                f"cookie '{cookie.nombre}': Secure no aplica a un objetivo HTTP",
                respuesta,
            )
        )
    return controles


def _comparar(
    formulario: Formulario,
    caso_id: str,
    cuenta: str,
    cumple: bool,
    motivo: str,
    respuesta: Respuesta | None = None,
) -> ResultadoCaso:
    return resultado_de(
        formulario,
        caso_id,
        cuenta,
        "cumple",
        Resultado.PASS if cumple else Resultado.FAIL,
        "cumple" if cumple else "no_cumple",
        motivo,
        respuesta,
    )


PROCEDIMIENTOS: Final[dict[str, Procedimiento]] = {
    "rate-limit": limite_de_frecuencia,
    "csrf": proteccion_csrf,
    "mfa": prueba_mfa,
    "sessions": atributos_de_cookies,
    "response-check": consistencia_de_respuestas,
}
