"""Cliente en memoria para probar GuiApp sin abrir sockets.

Guarda la cookie de sesión y la ficha CSRF como lo haría un navegador: la cookie se toma de
Set-Cookie y la ficha de la última respuesta JSON que la incluya.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from natxajo_auditor.interfaces.gui.app import GuiApp
from natxajo_auditor.interfaces.gui.http_security import SESSION_COOKIE, Request

PORT = 8765


@dataclass(frozen=True)
class Respuesta:
    estado: int
    datos: Any
    cabeceras: tuple[tuple[str, str], ...]
    cuerpo: bytes

    @property
    def codigo(self) -> str | None:
        """Código de error estable de la respuesta, si lo hay."""
        if isinstance(self.datos, dict) and isinstance(self.datos.get("error"), dict):
            value = self.datos["error"].get("codigo")
            return value if isinstance(value, str) else None
        return None

    @property
    def mensaje(self) -> str:
        if isinstance(self.datos, dict) and isinstance(self.datos.get("error"), dict):
            value = self.datos["error"].get("mensaje")
            return value if isinstance(value, str) else ""
        return ""


class ClienteGui:
    def __init__(self, app: GuiApp, port: int = PORT) -> None:
        self.app = app
        self.port = port
        self.cookie: str | None = None
        self.csrf = ""

    def pedir(
        self,
        metodo: str,
        ruta: str,
        *,
        datos: object = None,
        cabeceras: dict[str, str] | None = None,
        cuerpo: bytes | None = None,
        tipo: str | None = None,
    ) -> Respuesta:
        headers: dict[str, str] = {"host": f"127.0.0.1:{self.port}"}
        if self.cookie is not None:
            headers["cookie"] = f"{SESSION_COOKIE}={self.cookie}"
        if metodo == "POST":
            headers["x-csrf-token"] = self.csrf
        body = b""
        if datos is not None:
            body = json.dumps(datos).encode("utf-8")
            headers["content-type"] = "application/json"
        if cuerpo is not None:
            body = cuerpo
        if tipo is not None:
            headers["content-type"] = tipo
        headers.update(cabeceras or {})
        respuesta = self.app.handle(Request(metodo, ruta, headers, body))
        for nombre, valor in respuesta.headers:
            if nombre == "Set-Cookie":
                self.cookie = valor.split(";", 1)[0].split("=", 1)[1]
        parsed: Any = None
        if respuesta.content_type.startswith("application/json"):
            parsed = json.loads(respuesta.body)
            if isinstance(parsed, dict) and isinstance(parsed.get("csrf"), str):
                self.csrf = parsed["csrf"]
        return Respuesta(respuesta.status, parsed, respuesta.headers, respuesta.body)

    def entrar(self, usuario: str, contrasena: str) -> Respuesta:
        """Pide la ficha inicial y envía el acceso, como hace la pantalla de acceso."""
        self.pedir("GET", "/api/sesion")
        return self.pedir(
            "POST", "/api/sesion/entrar", datos={"usuario": usuario, "contrasena": contrasena}
        )
