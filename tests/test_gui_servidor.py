"""Servidor local de la interfaz y opciones de arranque de la aplicación.

El servidor atiende en el mismo hilo que lo creó; el cliente HTTP corre en un hilo auxiliar y
se llama a handle_request() una vez por petición.
"""

from __future__ import annotations

import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from natxajo_auditor import main as main_module
from natxajo_auditor.interfaces.gui.http_security import CONTENT_SECURITY_POLICY
from natxajo_auditor.interfaces.gui.server import GuiServer
from natxajo_auditor.kernel.kernel import Kernel


def _peticion(
    servidor: GuiServer,
    metodo: str,
    ruta: str,
    *,
    cabeceras: dict[str, str] | None = None,
    cuerpo: bytes | None = None,
) -> dict[str, Any]:
    resultado: dict[str, Any] = {}

    def cliente() -> None:
        peticion = urllib.request.Request(
            servidor.url.rstrip("/") + ruta, method=metodo, headers=cabeceras or {}, data=cuerpo
        )
        try:
            with urllib.request.urlopen(peticion, timeout=10) as respuesta:
                resultado.update(
                    estado=respuesta.status,
                    cabeceras=dict(respuesta.headers),
                    cuerpo=respuesta.read(),
                )
        except urllib.error.HTTPError as error:
            resultado.update(estado=error.code, cabeceras=dict(error.headers), cuerpo=error.read())

    hilo = threading.Thread(target=cliente)
    hilo.start()
    servidor.timeout = 10
    servidor.handle_request()
    hilo.join(15)
    return resultado


@pytest.fixture
def servidor(kernel: Kernel) -> GuiServer:
    instancia = GuiServer(0, kernel)
    yield instancia
    instancia.server_close()


def test_the_server_listens_only_on_the_loopback_interface(servidor: GuiServer) -> None:
    assert servidor.server_address[0] == "127.0.0.1"
    assert servidor.url == f"http://127.0.0.1:{servidor.server_port}/"


def test_the_start_page_carries_the_security_headers(servidor: GuiServer) -> None:
    respuesta = _peticion(servidor, "GET", "/")
    assert respuesta["estado"] == 200
    cabeceras = {clave.lower(): valor for clave, valor in respuesta["cabeceras"].items()}
    assert cabeceras["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert cabeceras["x-frame-options"] == "DENY"
    assert cabeceras["x-content-type-options"] == "nosniff"
    assert cabeceras["cache-control"] == "no-store"
    assert cabeceras["content-type"].startswith("text/html")
    assert b'<div id="app"' in respuesta["cuerpo"]


def test_static_scripts_are_served_with_their_type(servidor: GuiServer) -> None:
    respuesta = _peticion(servidor, "GET", "/static/app.js")
    assert respuesta["estado"] == 200
    cabeceras = {clave.lower(): valor for clave, valor in respuesta["cabeceras"].items()}
    assert cabeceras["content-type"].startswith("text/javascript")


def test_paths_outside_the_static_list_are_not_served(servidor: GuiServer) -> None:
    respuesta = _peticion(servidor, "GET", "/static/../server.py")
    assert respuesta["estado"] == 404


def test_a_foreign_host_is_refused_by_the_server(servidor: GuiServer) -> None:
    respuesta = _peticion(servidor, "GET", "/api/sesion", cabeceras={"Host": "evil.example"})
    assert respuesta["estado"] == 403


def test_an_oversized_body_is_refused_before_it_is_read(servidor: GuiServer) -> None:
    respuesta = _peticion(
        servidor,
        "POST",
        "/api/preferencias",
        cabeceras={"Content-Type": "application/json", "Content-Length": "99999"},
        cuerpo=b"{}",
    )
    assert respuesta["estado"] == 413


def test_unsupported_methods_get_405(servidor: GuiServer) -> None:
    respuesta = _peticion(servidor, "PUT", "/api/sesion", cuerpo=b"{}")
    assert respuesta["estado"] == 405


def test_sin_navegador_without_gui_is_a_usage_error(
    tmp_path: Path,
) -> None:
    with pytest.raises(SystemExit) as salida:
        main_module.main(["--sin-navegador"], project_root=tmp_path)
    assert salida.value.code == 2


@pytest.mark.parametrize(
    ("argumentos", "abre_navegador"),
    [(["--gui"], True), (["--gui", "--sin-navegador"], False)],
)
def test_gui_flag_chooses_the_interface_and_the_browser_behaviour(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    argumentos: list[str],
    abre_navegador: bool,
) -> None:
    llamadas: list[bool] = []

    def falsa_gui(_kernel: Kernel, *, open_browser: bool) -> int:
        llamadas.append(open_browser)
        return 0

    monkeypatch.setattr(main_module, "run_gui", falsa_gui)
    monkeypatch.setattr(main_module, "run_terminal", lambda _kernel: pytest.fail("terminal"))
    assert main_module.main(argumentos, project_root=tmp_path) == 0
    assert llamadas == [abre_navegador]


def test_without_the_gui_flag_the_terminal_is_started(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(main_module, "run_terminal", lambda _kernel: 7)
    monkeypatch.setattr(main_module, "run_gui", lambda *_a, **_k: pytest.fail("gui"))
    assert main_module.main([], project_root=tmp_path) == 7
