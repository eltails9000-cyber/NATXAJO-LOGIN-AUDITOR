"""Cliente HTTP mínimo para formularios de autenticación, solo con biblioteca estándar.

No sigue redirecciones: la siguiente petición la decide el motor, de modo que nunca se contacta un
host que no esté registrado como objetivo. Las cookies viven en una Sesion, solo en memoria, y las
respuestas exponen únicamente el nombre y los atributos de cada cookie, nunca su valor.
"""

from __future__ import annotations

import http.client
import ssl
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final
from urllib.parse import urlencode

from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.pruebas.modelo import RUTA
from natxajo_auditor.pruebas.objetivos import Origen

MAX_CUERPO_BYTES: Final = 262_144
USER_AGENT: Final = "NATXAJO-LOGIN-AUDITOR/pruebas"
_METODOS: Final = frozenset({"GET", "POST"})


@dataclass(frozen=True)
class CookieInfo:
    """Atributos de una cookie de sesión. El valor no se incluye en ningún tipo de este módulo."""

    nombre: str
    httponly: bool
    secure: bool
    samesite: str | None


@dataclass(frozen=True)
class Respuesta:
    codigo: int
    ubicacion: str | None
    cuerpo: str = field(repr=False)
    duracion_ms: int
    cookies: tuple[CookieInfo, ...]
    error: str | None = None


@dataclass
class Sesion:
    """Cookies de una secuencia de peticiones. Se descartan al terminar el caso."""

    valores: dict[str, str] = field(default_factory=dict, repr=False)


class ClienteHttp:
    """Envía peticiones a un único origen. No guarda estado entre peticiones: es seguro en hilos."""

    def __init__(self, origen: Origen, timeout_s: float) -> None:
        self._origen = origen
        self._timeout = timeout_s

    @property
    def origen(self) -> Origen:
        return self._origen

    def enviar(
        self,
        metodo: str,
        ruta: str,
        campos: Mapping[str, str] | None,
        sesion: Sesion,
    ) -> Respuesta:
        if metodo not in _METODOS:
            raise ValidationError("método HTTP no admitido")
        if RUTA.fullmatch(ruta) is None:
            raise ValidationError("ruta no válida para una petición de prueba")
        cabeceras = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/json;q=0.8",
            "Connection": "close",
        }
        cuerpo: bytes | None = None
        if metodo == "POST":
            cabeceras["Content-Type"] = "application/x-www-form-urlencoded"
            cuerpo = urlencode(dict(campos or {})).encode("utf-8")
        if sesion.valores:
            cabeceras["Cookie"] = "; ".join(f"{n}={v}" for n, v in sesion.valores.items())

        codigo = 0
        ubicacion: str | None = None
        crudo = b""
        cookies: tuple[CookieInfo, ...] = ()
        error: str | None = None
        inicio = time.perf_counter()
        conexion = self._conexion()
        try:
            conexion.request(metodo, ruta, body=cuerpo, headers=cabeceras)
            respuesta = conexion.getresponse()
            crudo = respuesta.read(MAX_CUERPO_BYTES)
            codigo = respuesta.status
            ubicacion = respuesta.getheader("Location")
            cookies = _procesar_cookies(respuesta.headers.get_all("Set-Cookie") or [], sesion)
        except TimeoutError:
            error = "tiempo máximo de la petición agotado"
        except (OSError, http.client.HTTPException) as exc:
            error = f"error de conexión ({type(exc).__name__})"
        finally:
            conexion.close()
        duracion = int((time.perf_counter() - inicio) * 1000)
        return Respuesta(
            codigo=codigo,
            ubicacion=ubicacion,
            cuerpo=crudo.decode("utf-8", errors="replace"),
            duracion_ms=duracion,
            cookies=cookies,
            error=error,
        )

    def _conexion(self) -> http.client.HTTPConnection:
        if self._origen.https:
            return http.client.HTTPSConnection(
                self._origen.host,
                self._origen.puerto,
                timeout=self._timeout,
                context=ssl.create_default_context(),
            )
        return http.client.HTTPConnection(
            self._origen.host, self._origen.puerto, timeout=self._timeout
        )


def _procesar_cookies(cabeceras: Sequence[str], sesion: Sesion) -> tuple[CookieInfo, ...]:
    infos: list[CookieInfo] = []
    for linea in cabeceras:
        partes = [parte.strip() for parte in linea.split(";")]
        nombre, _, valor = partes[0].partition("=")
        nombre = nombre.strip()
        if not nombre:
            continue
        atributos: dict[str, str] = {}
        for parte in partes[1:]:
            clave, _, dato = parte.partition("=")
            atributos[clave.strip().lower()] = dato.strip()
        if valor == "" or atributos.get("max-age") == "0":
            sesion.valores.pop(nombre, None)
        else:
            sesion.valores[nombre] = valor.strip()
        samesite = atributos.get("samesite", "")
        infos.append(
            CookieInfo(
                nombre=nombre,
                httponly="httponly" in atributos,
                secure="secure" in atributos,
                samesite=samesite.capitalize() if samesite else None,
            )
        )
    return tuple(infos)
