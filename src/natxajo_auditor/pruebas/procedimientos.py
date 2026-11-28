"""Procedimientos de seguridad: límite de intentos, CSRF, MFA, cookies, consistencia, cabeceras,
TLS y tiempos de respuesta.

Cada procedimiento es una secuencia pequeña y acotada de peticiones. Todas pasan por el mismo
presupuesto y el mismo control de cancelación que las matrices. Ninguno intenta eludir un control:
si el servidor bloquea, el procedimiento se detiene y no reintenta.
"""

from __future__ import annotations

import dataclasses
import re
import statistics
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
    anotar,
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
            anotar(
                contexto,
                resultados,
                resultado_de(
                    formulario,
                    f"limite-frecuencia-intento-{intento:02d}",
                    cuenta,
                    Observado.RECHAZADA.value,
                    resultado,
                    observado.value,
                    detalle,
                    respuesta,
                ),
            )
            ultimo = observado
            if observado is Observado.BLOQUEADA:
                bloqueado_en = intento
                break
            if observado is Observado.ERROR:
                break
    except (Detenida, FalloTecnico) as exc:
        interrumpida = interrupcion(formulario, "limite-frecuencia-interrumpido", cuenta, exc)
        anotar(contexto, resultados, interrumpida)

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
    anotar(contexto, resultados, resumen)
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
            anotar(
                contexto,
                resultados,
                resultado_de(
                    formulario,
                    caso_id,
                    cuenta,
                    esperado.value,
                    resultado,
                    observado.value,
                    detalle,
                    respuesta,
                ),
            )
    except (Detenida, FalloTecnico) as exc:
        anotar(contexto, resultados, interrupcion(formulario, "csrf-interrumpido", cuenta, exc))
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
        anotar(
            contexto,
            resultados,
            resultado_de(
                formulario,
                "mfa-primer-factor",
                cuenta,
                Observado.ACEPTADA.value,
                resultado,
                observado.value,
                detalle,
                respuesta,
            ),
        )
        if resultado is not Resultado.PASS:
            anotar(
                contexto,
                resultados,
                resultado_de(
                    formulario,
                    "mfa-segundo-factor",
                    cuenta,
                    "-",
                    Resultado.SKIPPED,
                    "",
                    "el primer factor no fue aceptado; no se envía el segundo",
                ),
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
            anotar(
                contexto,
                resultados,
                resultado_de(
                    formulario,
                    caso_id,
                    cuenta,
                    esperado.value,
                    resultado_mfa,
                    observado_mfa.value,
                    detalle_mfa,
                    respuesta_mfa,
                ),
            )
    except (Detenida, FalloTecnico) as exc:
        anotar(contexto, resultados, interrupcion(formulario, "mfa-interrumpido", cuenta, exc))
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
        for resultado in _atributos_de(formulario, cuenta, indice, cookie, contexto, respuesta):
            anotar(contexto, resultados, resultado)
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
    resultados: list[ResultadoCaso] = []
    anotar(
        contexto,
        resultados,
        _comparar(
            formulario,
            "consistencia-clasificacion",
            cuenta,
            obs_existente.value == obs_inexistente.value,
            f"cuenta existente: {obs_existente.value}; inexistente: {obs_inexistente.value}",
        ),
    )
    anotar(
        contexto,
        resultados,
        _comparar(
            formulario,
            "consistencia-codigo-http",
            cuenta,
            existente.codigo == inexistente.codigo,
            f"cuenta existente: HTTP {existente.codigo}; inexistente: HTTP {inexistente.codigo}",
        ),
    )
    tamano_a = len(existente.cuerpo)
    tamano_b = len(inexistente.cuerpo)
    tolerancia = max(_TOLERANCIA_MINIMA_BYTES, max(tamano_a, tamano_b) // 20)
    anotar(
        contexto,
        resultados,
        _comparar(
            formulario,
            "consistencia-tamano-cuerpo",
            cuenta,
            abs(tamano_a - tamano_b) <= tolerancia,
            f"diferencia de {abs(tamano_a - tamano_b)} caracteres; tolerancia {tolerancia}",
        ),
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


# ----- Cabeceras de seguridad, TLS y tiempos de respuesta -------------------------------------

DIAS_MINIMOS_CERTIFICADO: Final = 30
PROTOCOLOS_TLS_ADMITIDOS: Final = ("TLSv1.2", "TLSv1.3")
HSTS_MINIMO_S: Final = 15_552_000  # 180 días
POLITICAS_REFERRER_SEGURAS: Final = frozenset(
    {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
)
MUESTRAS_TIEMPO: Final = 5
TIEMPO_MINIMO_MS: Final = 100.0
TIEMPO_RELATIVO: Final = 0.5


def cabeceras_de_seguridad(
    contexto: Contexto,
    formulario: Formulario,
    credencial: Credencial,
    cuenta: str,
) -> list[ResultadoCaso]:
    """Cabeceras de seguridad de la página del formulario. Una sola petición GET, sin credenciales."""
    try:
        respuesta = contexto.peticion("GET", formulario.ruta, None, Sesion())
    except (Detenida, FalloTecnico) as exc:
        return [interrupcion(formulario, "cabeceras-interrumpida", cuenta, exc)]
    if respuesta.error is not None:
        return [
            resultado_de(
                formulario,
                "cabeceras-sin-respuesta",
                cuenta,
                "cumple",
                Resultado.ERROR,
                "error",
                respuesta.error,
                respuesta,
            )
        ]
    https = contexto.cliente.origen.https
    resultados: list[ResultadoCaso] = []
    for caso_id, cumple, motivo in _controles_de_cabeceras(respuesta, https):
        anotar(
            contexto,
            resultados,
            _comparar(formulario, caso_id, cuenta, cumple, motivo, respuesta),
        )
    return resultados


def _controles_de_cabeceras(respuesta: Respuesta, https: bool) -> list[tuple[str, bool, str]]:
    csp = respuesta.cabecera_de_seguridad("content-security-policy")
    nosniff = (respuesta.cabecera_de_seguridad("x-content-type-options") or "").strip().lower()
    encuadre = (respuesta.cabecera_de_seguridad("x-frame-options") or "").strip().upper()
    referrer = (respuesta.cabecera_de_seguridad("referrer-policy") or "").strip().lower()
    hsts = respuesta.cabecera_de_seguridad("strict-transport-security")
    frame_ancestors = csp is not None and "frame-ancestors" in csp.lower()
    edad = _max_age(hsts)
    return [
        (
            "cabecera-csp",
            csp is not None,
            f"Content-Security-Policy {'presente' if csp is not None else 'ausente'}",
        ),
        (
            "cabecera-nosniff",
            nosniff == "nosniff",
            f"X-Content-Type-Options: {nosniff or 'ausente'}",
        ),
        (
            "cabecera-encuadre",
            encuadre in ("DENY", "SAMEORIGIN") or frame_ancestors,
            (
                f"X-Frame-Options={encuadre or 'ausente'}; "
                f"frame-ancestors {'presente' if frame_ancestors else 'ausente'}"
            ),
        ),
        (
            "cabecera-referrer",
            referrer in POLITICAS_REFERRER_SEGURAS,
            f"Referrer-Policy: {referrer or 'ausente'}",
        ),
        (
            "cabecera-hsts",
            https and edad is not None and edad >= HSTS_MINIMO_S,
            _motivo_hsts(hsts, https, edad),
        ),
    ]


def _max_age(valor: str | None) -> int | None:
    if valor is None:
        return None
    coincidencia = re.search(r'max-age\s*=\s*"?(\d+)', valor, re.IGNORECASE)
    return int(coincidencia.group(1)) if coincidencia else None


def _motivo_hsts(valor: str | None, https: bool, edad: int | None) -> str:
    if not https:
        return "HSTS solo tiene efecto sobre HTTPS; el objetivo no usa HTTPS"
    if valor is None:
        return "Strict-Transport-Security ausente"
    if edad is None:
        return "Strict-Transport-Security sin max-age"
    return f"Strict-Transport-Security max-age={edad} s (mínimo {HSTS_MINIMO_S})"


def verificar_tls(
    contexto: Contexto,
    formulario: Formulario,
    credencial: Credencial,
    cuenta: str,
) -> list[ResultadoCaso]:
    """Certificado verificado, protocolo admitido y días hasta su caducidad. Una conexión TLS."""
    try:
        informe = contexto.informe_tls()
    except (Detenida, FalloTecnico) as exc:
        return [interrupcion(formulario, "tls-interrumpido", cuenta, exc)]
    motivo = (
        "certificado verificado con la autoridad de confianza"
        if informe.verificado
        else (informe.motivo or "certificado no verificado")
    )
    resultados: list[ResultadoCaso] = []
    anotar(
        contexto,
        resultados,
        _comparar(formulario, "tls-verificacion", cuenta, informe.verificado, motivo),
    )
    if informe.verificado:
        anotar(
            contexto,
            resultados,
            _comparar(
                formulario,
                "tls-protocolo",
                cuenta,
                informe.protocolo in PROTOCOLOS_TLS_ADMITIDOS,
                f"protocolo negociado: {informe.protocolo or 'desconocido'}",
            ),
        )
        anotar(contexto, resultados, _caducidad(formulario, cuenta, informe.dias_restantes))
    else:
        for caso_id, texto in (
            ("tls-protocolo", "no se negoció TLS verificado; protocolo no analizado"),
            ("tls-caducidad", "sin certificado verificado; caducidad no analizada"),
        ):
            anotar(
                contexto,
                resultados,
                resultado_de(formulario, caso_id, cuenta, "cumple", Resultado.SKIPPED, "", texto),
            )
    return resultados


def _caducidad(formulario: Formulario, cuenta: str, dias: int | None) -> ResultadoCaso:
    if dias is None:
        return resultado_de(
            formulario,
            "tls-caducidad",
            cuenta,
            "cumple",
            Resultado.SKIPPED,
            "",
            "fecha de caducidad no disponible",
        )
    return _comparar(
        formulario,
        "tls-caducidad",
        cuenta,
        dias >= DIAS_MINIMOS_CERTIFICADO,
        f"el certificado caduca en {dias} días (mínimo {DIAS_MINIMOS_CERTIFICADO})",
    )


def tiempos_de_respuesta(
    contexto: Contexto,
    formulario: Formulario,
    credencial: Credencial,
    cuenta: str,
) -> list[ResultadoCaso]:
    """Tiempo mediano de respuesta ante una cuenta existente y otra inexistente, en muestras alternas.

    Una diferencia grande permite distinguir las cuentas por el tiempo, aunque el mensaje sea igual.
    """
    existentes: list[float] = []
    inexistentes: list[float] = []
    try:
        for _ in range(MUESTRAS_TIEMPO):
            for muestras, identidad in (
                (existentes, identidad_de(formulario, credencial)),
                (inexistentes, identidad_inexistente(formulario)),
            ):
                respuesta = _intento(contexto, formulario, identidad)
                if respuesta.error is not None:
                    return [
                        resultado_de(
                            formulario,
                            "tiempos-sin-respuesta",
                            cuenta,
                            "cumple",
                            Resultado.ERROR,
                            "error",
                            respuesta.error,
                            respuesta,
                        )
                    ]
                muestras.append(float(respuesta.duracion_ms))
    except (Detenida, FalloTecnico) as exc:
        return [interrupcion(formulario, "tiempos-interrumpidos", cuenta, exc)]
    mediana_a = statistics.median(existentes)
    mediana_b = statistics.median(inexistentes)
    diferencia = abs(mediana_a - mediana_b)
    umbral = max(TIEMPO_MINIMO_MS, TIEMPO_RELATIVO * min(mediana_a, mediana_b))
    resultados: list[ResultadoCaso] = []
    anotar(
        contexto,
        resultados,
        _comparar(
            formulario,
            "tiempos-diferencia",
            cuenta,
            diferencia <= umbral,
            f"medianas de {MUESTRAS_TIEMPO} muestras: cuenta existente {mediana_a:.0f} ms, "
            f"inexistente {mediana_b:.0f} ms; diferencia {diferencia:.0f} ms, umbral {umbral:.0f} ms",
        ),
    )
    return resultados


def _intento(contexto: Contexto, formulario: Formulario, identidad: str) -> Respuesta:
    sesion = Sesion()
    token = obtener_token(formulario, contexto, sesion)
    return contexto.peticion(
        "POST",
        formulario.ruta,
        construir_campos(
            formulario,
            identidad=identidad,
            contrasena=CONTRASENA_INCORRECTA,
            token=token,
        ),
        sesion,
    )


PROCEDIMIENTOS: Final[dict[str, Procedimiento]] = {
    "rate-limit": limite_de_frecuencia,
    "csrf": proteccion_csrf,
    "mfa": prueba_mfa,
    "sessions": atributos_de_cookies,
    "response-check": consistencia_de_respuestas,
    "security-headers": cabeceras_de_seguridad,
    "tls": verificar_tls,
    "timing": tiempos_de_respuesta,
}
