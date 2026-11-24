"""Servidor local de la interfaz gráfica.

Escucha solo en 127.0.0.1 y atiende las peticiones en un único hilo. Es obligatorio: la conexión
SQLite del núcleo se creó en el hilo principal y no puede usarse desde otro. Cada conexión tiene
un tiempo máximo, para que un cliente lento no bloquee a los demás.
"""

from __future__ import annotations

import webbrowser
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import cast

from natxajo_auditor.interfaces.gui.app import GuiApp
from natxajo_auditor.interfaces.gui.http_security import (
    MAX_BODY_BYTES,
    Request,
    Response,
    error_response,
    security_headers,
)
from natxajo_auditor.kernel.kernel import Kernel

HOST = "127.0.0.1"


class GuiServer(HTTPServer):
    allow_reuse_address = False

    def __init__(self, port: int, kernel: Kernel) -> None:
        super().__init__((HOST, port), GuiRequestHandler)
        self.app = GuiApp(kernel, self.server_port)

    @property
    def url(self) -> str:
        return f"http://{HOST}:{self.server_port}/"


class GuiRequestHandler(BaseHTTPRequestHandler):
    server_version = "NatxajoGUI"
    sys_version = ""
    protocol_version = "HTTP/1.0"
    timeout = 10

    def do_GET(self) -> None:
        self._serve()

    def do_POST(self) -> None:
        self._serve()

    def do_PUT(self) -> None:
        self._serve()

    def do_DELETE(self) -> None:
        self._serve()

    def do_PATCH(self) -> None:
        self._serve()

    def do_HEAD(self) -> None:
        self._serve()

    def do_OPTIONS(self) -> None:
        self._serve()

    def log_message(self, format: str, *args: object) -> None:
        # El registro de acceso se omite: las rutas no deben quedar en la consola.
        return

    def _serve(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send(error_response(400, "longitud", "Longitud del cuerpo no válida"))
            return
        if length < 0 or length > MAX_BODY_BYTES:
            self._send(
                error_response(413, "tamano", "El cuerpo de la petición es demasiado grande")
            )
            return
        body = self.rfile.read(length) if length else b""
        headers = {key.lower(): value for key, value in self.headers.items()}
        request = Request(method=self.command, target=self.path, headers=headers, body=body)
        app = cast(GuiServer, self.server).app
        self._send(app.handle(request))

    def _send(self, response: Response) -> None:
        self.send_response(response.status)
        for name, value in security_headers():
            self.send_header(name, value)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body)))
        for name, value in response.headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(response.body)


def run_gui(
    kernel: Kernel,
    *,
    open_browser: bool,
    port: int = 0,
    out: Callable[[str], None] = print,
) -> int:
    """Sirve la interfaz hasta Ctrl+C. El puerto 0 elige uno libre."""
    server = GuiServer(port, kernel)
    try:
        out(f"Interfaz gráfica en {server.url}")
        out("Pulse Ctrl+C para detenerla.")
        if open_browser:
            webbrowser.open(server.url)
        server.serve_forever()
    except KeyboardInterrupt:
        out("Interfaz detenida.")
    finally:
        server.server_close()
    return 0
