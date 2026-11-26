"""Capa HTTP de la interfaz gráfica: origen, ficha CSRF, cookies, cuerpos, rutas y sesiones.

Las pruebas llaman a GuiApp.handle con peticiones construidas a mano, sin abrir sockets.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from natxajo_auditor.interfaces.gui import app as gui_app
from natxajo_auditor.interfaces.gui import preferences
from natxajo_auditor.interfaces.gui.app import CREDENTIALS_MESSAGE, GuiApp
from natxajo_auditor.interfaces.gui.http_security import (
    CONTENT_SECURITY_POLICY,
    security_headers,
)
from natxajo_auditor.kernel.kernel import Kernel
from natxajo_auditor.security.sessions import MAX_CONCURRENT_SESSIONS
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER
from tests.gui_cliente import PORT, ClienteGui


@pytest.fixture
def app(kernel: Kernel, admin: tuple[str, str]) -> GuiApp:
    return GuiApp(kernel, PORT)


@pytest.fixture
def cliente(app: GuiApp) -> ClienteGui:
    return ClienteGui(app)


@pytest.fixture
def entrada(cliente: ClienteGui) -> ClienteGui:
    respuesta = cliente.entrar(ADMIN_USER, ADMIN_PASSWORD)
    assert respuesta.estado == 200
    return cliente


# --- Origen y transporte ---------------------------------------------------------------------


def test_a_foreign_host_header_is_refused(cliente: ClienteGui) -> None:
    # Protege frente a la reasignación de DNS: el Host debe ser la propia dirección local.
    respuesta = cliente.pedir("GET", "/api/sesion", cabeceras={"host": "evil.example"})
    assert respuesta.estado == 403
    assert respuesta.codigo == "host"


def test_a_post_from_another_origin_is_refused(cliente: ClienteGui) -> None:
    cliente.pedir("GET", "/api/sesion")
    respuesta = cliente.pedir(
        "POST",
        "/api/sesion/entrar",
        datos={"usuario": ADMIN_USER, "contrasena": ADMIN_PASSWORD},
        cabeceras={"origin": "http://evil.example"},
    )
    assert respuesta.estado == 403
    assert respuesta.codigo == "origen"


def test_a_cross_site_fetch_is_refused_even_for_reads(cliente: ClienteGui) -> None:
    respuesta = cliente.pedir("GET", "/api/sesion", cabeceras={"sec-fetch-site": "cross-site"})
    assert respuesta.estado == 403
    assert respuesta.codigo == "origen"


def test_a_post_without_the_csrf_token_is_refused(cliente: ClienteGui) -> None:
    respuesta = cliente.pedir(
        "POST",
        "/api/sesion/entrar",
        datos={"usuario": ADMIN_USER, "contrasena": ADMIN_PASSWORD},
    )
    assert respuesta.estado == 403
    assert respuesta.codigo == "csrf"


def test_a_wrong_csrf_token_is_refused_after_login(entrada: ClienteGui) -> None:
    respuesta = entrada.pedir(
        "POST", "/api/preferencias", datos={"tema": "claro"}, cabeceras={"x-csrf-token": "falso"}
    )
    assert respuesta.estado == 403
    assert respuesta.codigo == "csrf"


def test_unsupported_methods_are_rejected(entrada: ClienteGui) -> None:
    respuesta = entrada.pedir("DELETE", "/api/sesion")
    assert respuesta.estado == 405
    assert respuesta.codigo == "metodo"


def test_unknown_routes_and_static_files_are_not_found(entrada: ClienteGui) -> None:
    assert entrada.pedir("GET", "/api/no-existe").codigo == "no_encontrada"
    assert entrada.pedir("GET", "/static/secreto.txt").codigo == "no_encontrada"
    assert entrada.pedir("GET", "/static/../../pyproject.toml").codigo == "no_encontrada"


def test_only_whitelisted_static_files_are_served(cliente: ClienteGui) -> None:
    pagina = cliente.pedir("GET", "/")
    assert pagina.estado == 200
    assert b'id="app"' in pagina.cuerpo
    assert cliente.pedir("GET", "/static/app.js").estado == 200
    assert cliente.pedir("GET", "/static/core.js").estado == 200


def test_oversized_targets_are_refused(cliente: ClienteGui) -> None:
    respuesta = cliente.pedir("GET", "/api/" + "a" * 3000)
    assert respuesta.estado == 414


# --- Cuerpos JSON -----------------------------------------------------------------------------


def test_bodies_must_be_json(entrada: ClienteGui) -> None:
    respuesta = entrada.pedir("POST", "/api/preferencias", cuerpo=b"tema=claro", tipo="text/plain")
    assert respuesta.estado == 415
    assert respuesta.codigo == "tipo"


def test_bodies_above_the_limit_are_refused(entrada: ClienteGui) -> None:
    grande = b"{" + b" " * (17 * 1024) + b"}"
    respuesta = entrada.pedir("POST", "/api/preferencias", cuerpo=grande, tipo="application/json")
    assert respuesta.estado == 413
    assert respuesta.codigo == "tamano"


def test_malformed_json_is_refused(entrada: ClienteGui) -> None:
    respuesta = entrada.pedir(
        "POST", "/api/preferencias", cuerpo=b"{no-json", tipo="application/json"
    )
    assert respuesta.estado == 400
    assert respuesta.codigo == "json"


# --- Sesión web ----------------------------------------------------------------------------------


def test_protected_routes_require_a_session(cliente: ClienteGui) -> None:
    cliente.pedir("GET", "/api/sesion")
    respuesta = cliente.pedir("GET", "/api/usuarios")
    assert respuesta.estado == 401
    assert respuesta.codigo == "no_autenticado"


def test_login_rotates_the_session_identifier_and_the_csrf_token(
    app: GuiApp, cliente: ClienteGui
) -> None:
    cliente.pedir("GET", "/api/sesion")
    antes_cookie, antes_csrf = cliente.cookie, cliente.csrf
    respuesta = cliente.entrar(ADMIN_USER, ADMIN_PASSWORD)
    assert respuesta.estado == 200
    assert respuesta.datos["autenticado"] is True
    assert cliente.cookie != antes_cookie
    assert cliente.csrf != antes_csrf
    # La cookie anterior ya no identifica ninguna sesión.
    anterior = ClienteGui(app)
    anterior.cookie = antes_cookie
    assert anterior.pedir("GET", "/api/sesion").datos["autenticado"] is False


def test_the_session_cookie_is_http_only_and_strict(entrada: ClienteGui) -> None:
    # El inicio de sesión emite la cookie, con los atributos requeridos.
    nueva = ClienteGui(entrada.app)
    emitida = nueva.entrar(ADMIN_USER, ADMIN_PASSWORD)
    cookies = [valor for nombre, valor in emitida.cabeceras if nombre == "Set-Cookie"]
    assert len(cookies) == 1
    assert cookies[0].startswith(f"natxajo_gui={nueva.cookie}; Path=/; HttpOnly; SameSite=Strict")


def test_the_csrf_token_never_appears_in_a_cookie(entrada: ClienteGui) -> None:
    for nombre, valor in entrada.pedir("GET", "/api/sesion").cabeceras:
        if nombre == "Set-Cookie":
            assert entrada.csrf not in valor


def test_logout_ends_the_session(entrada: ClienteGui) -> None:
    respuesta = entrada.pedir("POST", "/api/sesion/salir", datos={})
    assert respuesta.estado == 200
    assert respuesta.datos["autenticado"] is False
    assert entrada.pedir("GET", "/api/usuarios").codigo == "no_autenticado"


def test_a_session_closed_in_the_core_returns_401(entrada: ClienteGui, kernel: Kernel) -> None:
    kernel.security.sessions.close_all(ADMIN_USER)
    respuesta = entrada.pedir("GET", "/api/panel")
    assert respuesta.estado == 401
    assert respuesta.codigo == "sesion"


def test_every_login_failure_gives_the_same_answer(entrada: ClienteGui, kernel: Kernel) -> None:
    # Usuario inexistente, contraseña errónea y cuenta deshabilitada responden igual: no se
    # puede descubrir qué cuentas existen ni cuáles están deshabilitadas.
    kernel.security.companies.create("acme", "Acme S.A.")
    kernel.security.create_account("auditor_acme", "contraseña-de-prueba-7", ["auditor"], "acme")
    kernel.security.disable_account("auditor_acme")
    intentos = [
        ClienteGui(entrada.app).entrar("no_existe", "contraseña-cualquiera"),
        ClienteGui(entrada.app).entrar(ADMIN_USER, "contraseña-erronea"),
        ClienteGui(entrada.app).entrar("auditor_acme", "contraseña-de-prueba-7"),
    ]
    for respuesta in intentos:
        assert respuesta.estado == 401
        assert respuesta.codigo == "credenciales"
        assert respuesta.mensaje == "Usuario o contraseña incorrectos."


def test_the_session_limit_gets_the_same_answer_as_a_wrong_password(
    app: GuiApp, kernel: Kernel
) -> None:
    # Con el límite de la cuenta alcanzado, la contraseña correcta y la errónea responden igual:
    # la respuesta no revela que la contraseña era buena. El motivo queda en la auditoría.
    for _ in range(MAX_CONCURRENT_SESSIONS):
        assert ClienteGui(app).entrar(ADMIN_USER, ADMIN_PASSWORD).estado == 200
    con_limite = ClienteGui(app).entrar(ADMIN_USER, ADMIN_PASSWORD)
    contrasena_erronea = ClienteGui(app).entrar(ADMIN_USER, "contraseña-erronea-1")
    for respuesta in (con_limite, contrasena_erronea):
        assert respuesta.estado == 401
        assert respuesta.codigo == "credenciales"
        assert respuesta.mensaje == CREDENTIALS_MESSAGE
    assert len(kernel.audit.events_of_type("session.limit_reached")) == 1


# --- Sesiones de la interfaz: visitantes y sesiones autenticadas ---------------------------------

# Más peticiones que los dos límites juntos: si el tráfico anónimo pudiera expulsar sesiones, la
# del usuario legítimo caería antes de terminar.
TRAFICO_ANONIMO = 400


def test_anonymous_traffic_does_not_log_out_an_authenticated_user(
    app: GuiApp, kernel: Kernel
) -> None:
    legitimo = ClienteGui(app)
    assert legitimo.entrar(ADMIN_USER, ADMIN_PASSWORD).estado == 200
    for _ in range(TRAFICO_ANONIMO):
        assert ClienteGui(app).pedir("GET", "/api/sesion").estado == 200
    assert legitimo.pedir("GET", "/api/panel").estado == 200
    assert kernel.audit.events_of_type("session.closed") == []


def test_visitor_pool_is_bounded(app: GuiApp, monkeypatch: pytest.MonkeyPatch) -> None:
    # El límite de visitantes sigue protegiendo los recursos: el pool no crece sin fin.
    monkeypatch.setattr(gui_app, "ANONYMOUS_SESSION_LIMIT", 5)
    for _ in range(50):
        assert ClienteGui(app).pedir("GET", "/api/sesion").estado == 200
    assert len(app._sessions) <= 5


def test_a_full_pool_refuses_new_logins_and_evicts_nobody(
    app: GuiApp, kernel: Kernel, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gui_app, "WEB_SESSION_LIMIT", 2)
    primero = ClienteGui(app)
    segundo = ClienteGui(app)
    assert primero.entrar(ADMIN_USER, ADMIN_PASSWORD).estado == 200
    assert segundo.entrar(ADMIN_USER, ADMIN_PASSWORD).estado == 200
    # La negativa llega antes de comprobar la contraseña: la misma para cualquier credencial.
    rechazado = ClienteGui(app).entrar(ADMIN_USER, ADMIN_PASSWORD)
    erroneo = ClienteGui(app).entrar(ADMIN_USER, "contraseña-erronea-1")
    for respuesta in (rechazado, erroneo):
        assert respuesta.estado == 503
        assert respuesta.codigo == "capacidad"
    assert primero.pedir("GET", "/api/panel").estado == 200
    assert segundo.pedir("GET", "/api/panel").estado == 200
    assert kernel.audit.events_of_type("session.closed") == []


def test_sessions_that_are_no_longer_live_free_their_place(
    app: GuiApp, kernel: Kernel, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gui_app, "WEB_SESSION_LIMIT", 1)
    primero = ClienteGui(app)
    assert primero.entrar(ADMIN_USER, ADMIN_PASSWORD).estado == 200
    kernel.security.sessions.close_all(ADMIN_USER)
    segundo = ClienteGui(app)
    assert segundo.entrar(ADMIN_USER, ADMIN_PASSWORD).estado == 200
    assert primero.pedir("GET", "/api/panel").estado == 401
    assert segundo.pedir("GET", "/api/panel").estado == 200


def test_login_is_refused_until_the_installation_is_complete(kernel: Kernel) -> None:
    # Sin el fixture admin la plataforma sigue pendiente de instalar.
    cliente = ClienteGui(GuiApp(kernel, PORT))
    inicial = cliente.pedir("GET", "/api/sesion")
    assert inicial.datos["instalacion_pendiente"] is True
    respuesta = cliente.entrar(ADMIN_USER, ADMIN_PASSWORD)
    assert respuesta.estado == 409
    assert respuesta.codigo == "instalacion_pendiente"


# --- Preferencias --------------------------------------------------------------------------------


def test_preferences_are_saved_and_reported(entrada: ClienteGui, tmp_path: Path) -> None:
    respuesta = entrada.pedir(
        "POST", "/api/preferencias", datos={"tema": "claro", "densidad": "compacta"}
    )
    assert respuesta.estado == 200
    assert respuesta.datos["preferencias"]["tema"] == "claro"
    configuracion = entrada.pedir("GET", "/api/configuracion")
    assert configuracion.datos["preferencias"]["densidad"] == "compacta"
    assert configuracion.datos["opciones"]["temas"] == list(preferences.THEMES)


@pytest.mark.parametrize(
    "datos",
    [{"tema": "neón"}, {"actualizacion_segundos": 45}, {"admin": True}, {"filas_por_pagina": "25"}],
)
def test_invalid_preferences_are_refused_with_a_validation_error(
    entrada: ClienteGui, datos: dict[str, object]
) -> None:
    respuesta = entrada.pedir("POST", "/api/preferencias", datos=datos)
    assert respuesta.estado == 422
    assert respuesta.codigo == "validacion"


# --- Errores y cabeceras -------------------------------------------------------------------------


def test_internal_errors_do_not_reveal_details(
    entrada: ClienteGui, app: GuiApp, monkeypatch
) -> None:
    def fallo(_token: str) -> object:
        raise RuntimeError("detalle interno que no debe salir")

    monkeypatch.setattr(app._reads, "dashboard", fallo)
    respuesta = entrada.pedir("GET", "/api/panel")
    assert respuesta.estado == 500
    assert respuesta.codigo == "interno"
    assert b"detalle interno" not in respuesta.cuerpo
    assert b"Traceback" not in respuesta.cuerpo


def test_security_headers_are_declared_for_every_response() -> None:
    cabeceras = dict(security_headers())
    assert cabeceras["Content-Security-Policy"] == CONTENT_SECURITY_POLICY
    assert "script-src 'self'" in CONTENT_SECURITY_POLICY
    assert "style-src 'self'" in CONTENT_SECURITY_POLICY
    assert "default-src 'none'" in CONTENT_SECURITY_POLICY
    assert cabeceras["X-Frame-Options"] == "DENY"
    assert cabeceras["X-Content-Type-Options"] == "nosniff"
    assert cabeceras["Cache-Control"] == "no-store"


# --- Información del sistema según la cuenta -----------------------------------------------------

CAMPOS_TECNICOS = ("estado_nucleo", "servicios", "python", "sqlite", "sistema")


def test_a_company_account_sees_only_the_version_of_the_system(app: GuiApp, kernel: Kernel) -> None:
    kernel.security.companies.create("acme", "Acme S.A.")
    kernel.security.create_account("auditor_acme", "contraseña-de-prueba-7", ["auditor"], "acme")
    empresa = ClienteGui(app)
    assert empresa.entrar("auditor_acme", "contraseña-de-prueba-7").estado == 200
    datos = empresa.pedir("GET", "/api/configuracion").datos
    assert datos["restringido"] is True
    assert "version" in datos
    for campo in CAMPOS_TECNICOS:
        assert campo not in datos


def test_a_platform_account_sees_the_technical_detail(entrada: ClienteGui) -> None:
    datos = entrada.pedir("GET", "/api/configuracion").datos
    assert datos["restringido"] is False
    assert set(CAMPOS_TECNICOS) <= set(datos)
