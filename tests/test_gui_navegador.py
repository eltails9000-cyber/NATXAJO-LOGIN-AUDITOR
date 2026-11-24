"""Prueba de navegador: la interfaz real en Chromium, recorrida página a página.

Comprueba que no hay excepciones, errores de consola ni infracciones de la política de contenido,
que el acceso y el cierre de sesión funcionan y que ninguna página se queda cargando.

Se omite si Playwright no está instalado o si no hay Chromium. Para guardar capturas, defina
NATXAJO_CAPTURAS con una carpeta existente.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from natxajo_auditor.core.exceptions import NatxajoError
from natxajo_auditor.interfaces.gui.server import GuiServer
from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.kernel import Kernel
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER, install_administrator

sync_api = pytest.importorskip("playwright.sync_api")

PAGINAS = (
    "panel",
    "auditoria",
    "usuarios",
    "sesiones",
    "plugins",
    "modulos",
    "reportes",
    "eventos",
    "seguridad",
    "mantenimiento",
    "configuracion",
)


@contextmanager
def interfaz_en_hilo(raiz: Path) -> Iterator[str]:
    """Arranca la plataforma y la interfaz en un hilo propio: el kernel y su SQLite se crean y
    se usan en ese hilo, como en la aplicación real."""
    estado: dict[str, object] = {}
    listo = threading.Event()

    def servir() -> None:
        kernel = Kernel(RuntimeContext(project_root=raiz), password_iterations=1_000)
        kernel.start()
        servidor: GuiServer | None = None
        try:
            install_administrator(kernel)
            servidor = GuiServer(0, kernel)
            estado["servidor"] = servidor
            estado["url"] = servidor.url
            listo.set()
            servidor.serve_forever(poll_interval=0.05)
        except (NatxajoError, OSError) as error:
            estado["error"] = error
            listo.set()
        finally:
            if servidor is not None:
                servidor.server_close()
            kernel.stop()

    hilo = threading.Thread(target=servir, daemon=True)
    hilo.start()
    listo.wait(60)
    if "error" in estado or "url" not in estado:
        pytest.fail(f"La interfaz no arrancó: {estado.get('error')}")
    try:
        yield str(estado["url"])
    finally:
        servidor = estado["servidor"]
        assert isinstance(servidor, GuiServer)
        servidor.shutdown()
        hilo.join(30)


def test_every_page_loads_without_errors_in_chromium(tmp_path: Path) -> None:
    capturas = os.environ.get("NATXAJO_CAPTURAS")
    with interfaz_en_hilo(tmp_path / "proyecto") as url, sync_api.sync_playwright() as navegador_pw:
        try:
            navegador = navegador_pw.chromium.launch()
        except sync_api.Error as error:  # Chromium no instalado o no lanzable aquí.
            pytest.skip(f"Chromium no disponible: {error}")
        problemas: list[str] = []
        try:
            pagina = navegador.new_page(viewport={"width": 1440, "height": 900})
            pagina.on("pageerror", lambda error: problemas.append(f"excepción: {error}"))
            pagina.on(
                "console",
                lambda mensaje: (
                    problemas.append(f"consola: {mensaje.text}")
                    if mensaje.type == "error"
                    else None
                ),
            )
            pagina.goto(url)
            pagina.wait_for_selector("#usuario")
            pagina.fill("#usuario", ADMIN_USER)
            pagina.fill("#contrasena", ADMIN_PASSWORD)
            pagina.click("button[type=submit]")
            pagina.wait_for_selector(".app", timeout=15_000)
            for indice, nombre in enumerate(PAGINAS):
                pagina.evaluate(f"location.hash = '#/{nombre}'")
                pagina.wait_for_selector("h1", timeout=15_000)
                pagina.wait_for_function(
                    "() => !document.querySelector('.esqueleto')", timeout=15_000
                )
                if capturas:
                    pagina.screenshot(path=str(Path(capturas) / f"{indice:02d}-{nombre}.png"))
            pagina.get_by_role("button", name="Cerrar sesión").click()
            pagina.wait_for_selector("#usuario", timeout=10_000)
        finally:
            navegador.close()
    assert problemas == [], "\n".join(problemas)
