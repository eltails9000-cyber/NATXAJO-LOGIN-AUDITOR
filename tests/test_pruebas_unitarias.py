"""Pruebas unitarias del motor HTTP: clasificación, objetivos, cuentas, esquema, cookies y matrices.

Las funciones de este grupo son puras o usan archivos temporales. Las pruebas que necesitan la
plataforma completa (persistencia, guardián, informes) están en test_pruebas_http.py.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest

from natxajo_auditor.core.exceptions import AuthorizationError, ValidationError
from natxajo_auditor.core.utilities import csv_cell
from natxajo_auditor.pruebas.clasificacion import MAX_MOTIVO, clasificar, evaluar
from natxajo_auditor.pruebas.cliente import CookieInfo, Respuesta, Sesion, _procesar_cookies
from natxajo_auditor.pruebas.cuentas import identidad_de, resolver_credenciales
from natxajo_auditor.pruebas.esquema import (
    ARCHIVO_CUENTAS,
    ARCHIVO_FORMULARIOS,
    ARCHIVO_LIMITES,
    cargar_cuentas,
    cargar_formularios,
    cargar_limites,
    leer_json,
)
from natxajo_auditor.pruebas.formulario import campos_ocultos, construir_campos, nombres_de_campos
from natxajo_auditor.pruebas.informes import renderizar
from natxajo_auditor.pruebas.matrices import (
    CARACTERES_ESPECIALES,
    CONTRASENA_INCORRECTA,
    USUARIO_INEXISTENTE,
    generar_casos,
    identidad_inexistente,
    suites_que_componen,
)
from natxajo_auditor.pruebas.modelo import (
    LIMITES_MAXIMOS,
    Credencial,
    CuentaSintetica,
    Formulario,
    Limites,
    Observado,
    ReglasRespuesta,
    Resultado,
    TipoFormulario,
)
from natxajo_auditor.pruebas.objetivos import esta_permitido, normalizar_origen
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER, install_administrator
from tests.laboratorio_http import (
    CLAVE_A,
    CUENTAS_PRUEBA,
    FORMULARIOS_PRUEBA,
    LIMITES_PRUEBA,
)

REGLAS = ReglasRespuesta(
    exito=("Bienvenido",),
    fallo=("Credenciales incorrectas",),
    bloqueo=("Demasiados intentos",),
    ruta_login="/login",
)


def _respuesta(
    codigo: int = 200,
    cuerpo: str = "",
    ubicacion: str | None = None,
    error: str | None = None,
) -> Respuesta:
    return Respuesta(
        codigo=codigo,
        ubicacion=ubicacion,
        cuerpo=cuerpo,
        duracion_ms=3,
        cookies=(),
        error=error,
    )


def _formulario(tipo: TipoFormulario = TipoFormulario.USUARIO_CONTRASENA) -> Formulario:
    return Formulario(
        id="login",
        tipo=tipo,
        ruta="/login",
        campos={"identidad": "usuario", "contrasena": "clave"},
        longitudes={"identidad": (2, 32), "contrasena": (1, 64)},
        extra={"origen": "web"},
        reglas=REGLAS,
    )


# ----- Clasificación y evaluación --------------------------------------------------------------


@pytest.mark.parametrize(
    ("respuesta", "esperado"),
    [
        (_respuesta(error="tiempo máximo de la petición agotado"), Observado.ERROR),
        (_respuesta(codigo=429), Observado.BLOQUEADA),
        (_respuesta(codigo=423), Observado.BLOQUEADA),
        (_respuesta(cuerpo="Demasiados intentos ahora"), Observado.BLOQUEADA),
        (_respuesta(codigo=404), Observado.ERROR),
        (_respuesta(codigo=503), Observado.ERROR),
        (_respuesta(codigo=302), Observado.INCONSISTENTE),
        (_respuesta(codigo=302, ubicacion="/login"), Observado.RECHAZADA),
        (_respuesta(codigo=302, ubicacion="http://127.0.0.1:9/login"), Observado.RECHAZADA),
        (_respuesta(codigo=302, ubicacion="/inicio"), Observado.ACEPTADA),
        (_respuesta(cuerpo="Bienvenido y Credenciales incorrectas"), Observado.INCONSISTENTE),
        (_respuesta(cuerpo="Credenciales incorrectas"), Observado.RECHAZADA),
        (_respuesta(cuerpo="Bienvenido"), Observado.ACEPTADA),
        (_respuesta(cuerpo="página sin marcadores"), Observado.INCONSISTENTE),
        (_respuesta(codigo=400, cuerpo="Bienvenido"), Observado.INCONSISTENTE),
        (_respuesta(codigo=400, cuerpo="campo obligatorio"), Observado.RECHAZADA),
        (_respuesta(codigo=422), Observado.RECHAZADA),
        (_respuesta(codigo=100), Observado.INCONSISTENTE),
    ],
)
def test_cada_respuesta_se_clasifica_con_su_motivo(
    respuesta: Respuesta, esperado: Observado
) -> None:
    observado, motivo = clasificar(respuesta, REGLAS)

    assert observado is esperado
    assert motivo


def test_evaluar_compara_lo_esperado_con_lo_observado() -> None:
    assert evaluar(Observado.ACEPTADA, Observado.ACEPTADA, "x")[0] is Resultado.PASS
    assert evaluar(Observado.ACEPTADA, Observado.RECHAZADA, "x")[0] is Resultado.FAIL
    assert evaluar(Observado.RECHAZADA, Observado.BLOQUEADA, "x")[0] is Resultado.BLOCKED
    assert evaluar(Observado.RECHAZADA, Observado.ERROR, "x")[0] is Resultado.ERROR
    resultado, motivo = evaluar(Observado.RECHAZADA, Observado.INCONSISTENTE, "x")
    assert resultado is Resultado.FAIL
    assert "inconsistente" in motivo


def test_el_motivo_se_acota_a_la_longitud_maxima() -> None:
    _, motivo = evaluar(Observado.ACEPTADA, Observado.RECHAZADA, "x" * 1000)

    assert len(motivo) <= MAX_MOTIVO


# ----- Objetivos -------------------------------------------------------------------------------


def test_un_origen_se_normaliza_con_su_puerto_explicito() -> None:
    origen = normalizar_origen("HTTP://127.0.0.1")

    assert origen.texto == "http://127.0.0.1:80"
    assert origen.https is False
    assert normalizar_origen("https://ejemplo.test").texto == "https://ejemplo.test:443"


@pytest.mark.parametrize(
    "entrada",
    [
        "",
        "ftp://127.0.0.1",
        "http://usuario:clave@127.0.0.1",
        "http://127.0.0.1/ruta",
        "http://127.0.0.1?x=1",
        "http://127.0.0.1#fragmento",
        "http://127.0.0.1:99999",
        "http://no válido.test",
        "http://" + "a" * 400 + ".test",
    ],
)
def test_un_origen_no_valido_se_rechaza(entrada: str) -> None:
    with pytest.raises(ValidationError):
        normalizar_origen(entrada)


def test_solo_se_usan_los_origenes_registrados() -> None:
    registrado = normalizar_origen("http://127.0.0.1:8080")

    assert esta_permitido(registrado, frozenset({"http://127.0.0.1:8080"}))
    assert not esta_permitido(
        normalizar_origen("http://127.0.0.1:8081"), frozenset({"http://127.0.0.1:8080"})
    )


# ----- Cuentas e identidad ---------------------------------------------------------------------


def test_una_variable_ausente_se_nombra_sin_revelar_valores() -> None:
    cuenta = CuentaSintetica(id="a", usuario="prueba-a", variable_contrasena="NATXAJO_PRUEBA_X")

    with pytest.raises(ValidationError, match="NATXAJO_PRUEBA_X") as info:
        resolver_credenciales([cuenta], {}, con_mfa=False)

    assert CLAVE_A not in str(info.value)


def test_el_codigo_mfa_se_exige_solo_cuando_se_pide() -> None:
    cuenta = CuentaSintetica(
        id="a",
        usuario="prueba-a",
        variable_contrasena="NATXAJO_PRUEBA_X",
        variable_mfa="NATXAJO_PRUEBA_MFA",
    )
    entorno = {"NATXAJO_PRUEBA_X": "clave-sintetica-1"}

    assert resolver_credenciales([cuenta], entorno, con_mfa=False)["a"].codigo_mfa is None
    with pytest.raises(ValidationError, match="NATXAJO_PRUEBA_MFA"):
        resolver_credenciales([cuenta], entorno, con_mfa=True)


def test_la_identidad_es_el_correo_en_los_formularios_de_correo() -> None:
    credencial = Credencial(usuario="prueba-a", contrasena="x", correo="prueba-a@example.com")

    assert (
        identidad_de(_formulario(TipoFormulario.CORREO_CONTRASENA), credencial)
        == "prueba-a@example.com"
    )
    assert identidad_de(_formulario(), credencial) == "prueba-a"
    sin_correo = Credencial(usuario="prueba-a", contrasena="x")
    with pytest.raises(ValidationError, match="no declara correo"):
        identidad_de(_formulario(TipoFormulario.CORREO_CONTRASENA), sin_correo)


def test_las_credenciales_no_aparecen_en_su_representacion() -> None:
    credencial = Credencial(usuario="prueba-a", contrasena=CLAVE_A, codigo_mfa="424242")
    cuenta = CuentaSintetica(id="a", usuario="prueba-a", variable_contrasena="NATXAJO_PRUEBA_X")

    assert CLAVE_A not in repr(credencial)
    assert "424242" not in repr(credencial)
    assert CLAVE_A not in repr(cuenta)


# ----- Esquema de configuración ----------------------------------------------------------------


def _escribir(directorio: Path, nombre: str, datos: Any) -> None:
    directorio.mkdir(parents=True, exist_ok=True)
    (directorio / nombre).write_text(json.dumps(datos, ensure_ascii=False), encoding="utf-8")


def test_los_formularios_de_ejemplo_se_cargan_con_sus_tipos(tmp_path: Path) -> None:
    _escribir(tmp_path, ARCHIVO_FORMULARIOS, FORMULARIOS_PRUEBA)

    formularios = cargar_formularios(tmp_path)

    assert set(formularios) == {"login", "acceso", "mfa"}
    assert formularios["mfa"].tipo is TipoFormulario.USUARIO_CONTRASENA_MFA
    assert formularios["login"].csrf is not None
    assert formularios["acceso"].extra == {"origen": "web"}


def test_sin_archivos_las_listas_estan_vacias_y_los_limites_son_los_de_fabrica(
    tmp_path: Path,
) -> None:
    assert cargar_formularios(tmp_path) == {}
    assert cargar_cuentas(tmp_path) == {}
    assert cargar_limites(tmp_path) == Limites()


@pytest.mark.parametrize(
    ("archivo", "modificar", "mensaje"),
    [
        (ARCHIVO_FORMULARIOS, lambda d: d.update(version=2), "version"),
        (ARCHIVO_FORMULARIOS, lambda d: d["formularios"][0].update(clave_extra=1), "no admitidas"),
        (
            ARCHIVO_FORMULARIOS,
            lambda d: d["formularios"][0].update(tipo="inventado"),
            "tipo no válido",
        ),
        (
            ARCHIVO_FORMULARIOS,
            lambda d: d["formularios"][0].update(ruta="sin-barra"),
            "valor no válido",
        ),
        (
            ARCHIVO_FORMULARIOS,
            lambda d: d["formularios"][2].update(mfa=None),
            "exige el bloque mfa",
        ),
        (
            ARCHIVO_FORMULARIOS,
            lambda d: d["formularios"][0].update(
                longitudes={"identidad": [30, 2], "contrasena": [1, 64]}
            ),
            "supera al máximo",
        ),
        (
            ARCHIVO_FORMULARIOS,
            lambda d: d["formularios"][0]["extra"].update(clave="x"),
            "sobrescribe identidad o contraseña",
        ),
        (
            ARCHIVO_CUENTAS,
            lambda d: d["cuentas"][0].update(usuario="usuario-real"),
            "valor no válido",
        ),
        (
            ARCHIVO_CUENTAS,
            lambda d: d["cuentas"][0].update(variable_contrasena="PASSWORD"),
            "valor no válido",
        ),
        (
            ARCHIVO_CUENTAS,
            lambda d: d["cuentas"].append(dict(d["cuentas"][0], id="otra")),
            "repetido",
        ),
        (
            ARCHIVO_LIMITES,
            lambda d: d.update(concurrencia=LIMITES_MAXIMOS.concurrencia + 1),
            "entre",
        ),
        (ARCHIVO_LIMITES, lambda d: d.update(timeout_s=True), "número"),
    ],
)
def test_una_configuracion_no_valida_se_rechaza_con_la_ruta_del_campo(
    tmp_path: Path,
    archivo: str,
    modificar: Any,
    mensaje: str,
) -> None:
    base = {
        ARCHIVO_FORMULARIOS: FORMULARIOS_PRUEBA,
        ARCHIVO_CUENTAS: CUENTAS_PRUEBA,
        ARCHIVO_LIMITES: LIMITES_PRUEBA,
    }[archivo]
    datos = json.loads(json.dumps(base))
    modificar(datos)
    _escribir(tmp_path, archivo, datos)

    with pytest.raises(ValidationError, match=mensaje):
        {
            ARCHIVO_FORMULARIOS: cargar_formularios,
            ARCHIVO_CUENTAS: cargar_cuentas,
            ARCHIVO_LIMITES: cargar_limites,
        }[archivo](tmp_path)


def test_un_valor_invalido_no_se_refleja_en_el_error(tmp_path: Path) -> None:
    datos = json.loads(json.dumps(CUENTAS_PRUEBA))
    datos["cuentas"][0]["usuario"] = "secreto-real-no-sintetico"
    _escribir(tmp_path, ARCHIVO_CUENTAS, datos)

    with pytest.raises(ValidationError) as info:
        cargar_cuentas(tmp_path)

    assert "secreto-real-no-sintetico" not in str(info.value)


def test_un_archivo_demasiado_grande_se_rechaza(tmp_path: Path) -> None:
    (tmp_path / ARCHIVO_FORMULARIOS).write_text("x" * 300_000, encoding="utf-8")

    with pytest.raises(ValidationError, match="supera"):
        leer_json(tmp_path / ARCHIVO_FORMULARIOS)


def test_un_json_mal_formado_se_rechaza_sin_detalles(tmp_path: Path) -> None:
    (tmp_path / ARCHIVO_LIMITES).write_text("{no es json", encoding="utf-8")

    with pytest.raises(ValidationError, match="no es JSON válido"):
        cargar_limites(tmp_path)


# ----- Cookies y formularios -------------------------------------------------------------------


def test_los_atributos_de_una_cookie_se_leen_sin_exponer_su_valor() -> None:
    sesion = Sesion()

    cookies = _procesar_cookies(["sid=valor-secreto; Path=/; HttpOnly; SameSite=strict"], sesion)

    assert cookies == (CookieInfo(nombre="sid", httponly=True, secure=False, samesite="Strict"),)
    assert sesion.valores == {"sid": "valor-secreto"}
    assert "valor-secreto" not in repr(cookies)


def test_una_cookie_con_max_age_cero_se_elimina_de_la_sesion() -> None:
    sesion = Sesion(valores={"sid": "antiguo"})

    _procesar_cookies(["sid=; Max-Age=0; Path=/"], sesion)

    assert sesion.valores == {}


def test_los_campos_ocultos_se_leen_de_la_pagina() -> None:
    html = (
        '<form><input type="hidden" name="csrf_token" value="abc123">'
        '<input name="usuario"><select name="rol"></select></form>'
    )

    assert campos_ocultos(html) == {"csrf_token": "abc123"}
    assert nombres_de_campos(html) == {"csrf_token", "usuario", "rol"}


def test_un_valor_nulo_omite_el_campo_y_una_cadena_vacia_lo_envia_vacio() -> None:
    formulario = _formulario()

    omitido = construir_campos(formulario, identidad=None, contrasena="x")
    vacio = construir_campos(formulario, identidad="", contrasena="x")

    assert "usuario" not in omitido
    assert vacio["usuario"] == ""
    assert vacio["origen"] == "web"


# ----- Matrices --------------------------------------------------------------------------------


def _credenciales(usuario: str = "prueba-a") -> list[tuple[str, Credencial]]:
    return [("a", Credencial(usuario=usuario, contrasena=CLAVE_A))]


def test_las_matrices_no_generan_mas_de_una_clave_incorrecta_por_identidad() -> None:
    casos = generar_casos("credentials", _formulario(), _credenciales())
    por_identidad: defaultdict[str | None, set[str | None]] = defaultdict(set)
    for caso in casos:
        por_identidad[caso.identidad].add(caso.contrasena)

    assert all(len(claves) <= 2 for claves in por_identidad.values())
    assert CONTRASENA_INCORRECTA in por_identidad["prueba-a"]
    assert CLAVE_A in por_identidad["prueba-a"]


def test_las_matrices_usan_solo_valores_fijos_de_prueba() -> None:
    casos = generar_casos("login-validation", _formulario(), _credenciales())
    usados = {c.identidad for c in casos} | {c.contrasena for c in casos}

    assert CARACTERES_ESPECIALES in usados
    assert "prueba-a" in usados
    assert all(v is None or len(v) <= 300 for v in usados)


def test_la_identidad_inexistente_no_coincide_con_ninguna_cuenta() -> None:
    assert identidad_inexistente(_formulario()) == USUARIO_INEXISTENTE
    correo = identidad_inexistente(_formulario(TipoFormulario.CORREO_CONTRASENA))
    assert correo.endswith("@example.invalid")


def test_una_suite_desconocida_se_rechaza() -> None:
    with pytest.raises(ValidationError, match="suite no conocida"):
        suites_que_componen("inventada")
    assert suites_que_componen("login-validation") == ("validation", "format")


# ----- Informes --------------------------------------------------------------------------------


def _resultado_informe(**cambios: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "posicion": 1,
        "caso": "validacion-identidad-vacia",
        "formulario": "login",
        "tipo": "usuario_contrasena",
        "cuenta": "a",
        "resultado": "PASS",
        "esperado": "rechazada",
        "observado": "rechazada",
        "codigo_http": 400,
        "duracion_ms": 4,
        "motivo": "comportamiento esperado",
    }
    base.update(cambios)
    return base


def _ejecucion(resultados: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "id": "run-1",
        "suite": "validation",
        "origen": "http://127.0.0.1:1",
        "estado": "completada",
        "solicitudes": 4,
        "resultados": resultados,
    }


META = {
    "solicitado_por": ADMIN_USER,
    "generado_en": "2026-11-27T00:00:00Z",
    "version_plataforma": "0.1.0",
}


def test_el_csv_neutraliza_formulas_inyectadas() -> None:
    assert csv_cell("=HYPERLINK(1)").startswith("'")
    contenido = renderizar(
        _ejecucion([_resultado_informe(motivo="=cmd|' /C calc'!A0")]), META, "csv"
    ).decode("utf-8")

    assert "'=cmd" in contenido
    assert "\n=cmd" not in contenido


def test_el_html_escapa_el_contenido_de_las_respuestas() -> None:
    contenido = renderizar(
        _ejecucion([_resultado_informe(motivo="<script>alert(1)</script>")]), META, "html"
    ).decode("utf-8")

    assert "<script>alert(1)</script>" not in contenido
    assert "&lt;script&gt;" in contenido


def test_el_json_contiene_totales_y_no_campos_secretos() -> None:
    documento = json.loads(renderizar(_ejecucion([_resultado_informe()]), META, "json"))

    assert documento["totales"]["PASS"] == 1
    assert documento["totales"]["FAIL"] == 0
    assert not {"contrasena", "clave", "codigo_mfa"} & set(documento["resultados"][0])


def test_un_formato_desconocido_no_produce_informe() -> None:
    with pytest.raises(ValueError, match="formato no admitido"):
        renderizar(_ejecucion([]), META, "pdf")


def test_el_txt_y_el_html_incluyen_la_metodologia() -> None:
    texto = renderizar(_ejecucion([_resultado_informe()]), META, "txt").decode("utf-8")
    html = renderizar(_ejecucion([_resultado_informe()]), META, "html").decode("utf-8")

    assert "INFORME DE PRUEBAS HTTP" in texto
    assert "Cada caso envía una solicitud" in html


# ----- Registro de objetivos (servicio) --------------------------------------------------------


@pytest.fixture
def kernel_administrado(context: Any) -> Any:
    from natxajo_auditor.kernel.kernel import Kernel

    kernel = Kernel(context, password_iterations=1_000)
    kernel.start()
    install_administrator(kernel)
    yield kernel
    kernel.stop()


def test_un_objetivo_no_se_registra_dos_veces(kernel_administrado: Any) -> None:
    token = kernel_administrado.security.login(ADMIN_USER, ADMIN_PASSWORD)
    kernel_administrado.security.reauthenticate(token, ADMIN_PASSWORD)
    kernel_administrado.pruebas.registrar_objetivo(token, "http://127.0.0.1:8080", confirmed=True)

    with pytest.raises(ValidationError, match="ya está registrado"):
        kernel_administrado.pruebas.registrar_objetivo(
            token, "http://127.0.0.1:8080", confirmed=True
        )
    assert [o["origen"] for o in kernel_administrado.pruebas.objetivos(token)] == [
        "http://127.0.0.1:8080"
    ]


def test_un_origen_con_ruta_no_se_registra(kernel_administrado: Any) -> None:
    token = kernel_administrado.security.login(ADMIN_USER, ADMIN_PASSWORD)
    kernel_administrado.security.reauthenticate(token, ADMIN_PASSWORD)

    with pytest.raises(ValidationError, match="ruta"):
        kernel_administrado.pruebas.registrar_objetivo(
            token, "http://127.0.0.1:8080/login", confirmed=True
        )


def test_registrar_un_objetivo_sin_confirmar_se_rechaza(kernel_administrado: Any) -> None:
    token = kernel_administrado.security.login(ADMIN_USER, ADMIN_PASSWORD)
    kernel_administrado.security.reauthenticate(token, ADMIN_PASSWORD)

    with pytest.raises(AuthorizationError, match="confirmación"):
        kernel_administrado.pruebas.registrar_objetivo(
            token, "http://127.0.0.1:8080", confirmed=False
        )
