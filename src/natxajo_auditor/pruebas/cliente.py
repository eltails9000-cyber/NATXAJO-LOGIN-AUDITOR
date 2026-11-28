"""Cliente HTTP mínimo para formularios de autenticación, solo con biblioteca estándar.

No sigue redirecciones: la siguiente petición la decide el motor, de modo que nunca se contacta un
host que no esté registrado como objetivo.

Vigilancia de DNS: la ejecución fija las direcciones del objetivo al empezar. Cada conexión va a una
de ellas (no se vuelve a resolver el nombre al conectar), y antes de cada petición se vuelve a
resolver el nombre. Si las direcciones actuales no tienen ninguna en común con las fijadas, se lanza
CambioDnsError y la ejecución se detiene. Un fallo transitorio de resolución solo afecta a esa petición.

Las cookies viven en una Sesion, solo en memoria, y las respuestas exponen únicamente el nombre y los
atributos de cada cookie, nunca su valor. De las cabeceras de respuesta solo se conservan las de
seguridad, con su valor, porque no contienen datos de sesión.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final
from urllib.parse import urlencode

from natxajo_auditor.core.exceptions import ServiceError, ValidationError
from natxajo_auditor.pruebas.modelo import RUTA
from natxajo_auditor.pruebas.objetivos import Origen

MAX_CUERPO_BYTES: Final = 262_144
USER_AGENT: Final = "NATXAJO-LOGIN-AUDITOR/pruebas"
CABECERAS_DE_SEGURIDAD: Final = frozenset(
    {
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    }
)
_METODOS: Final = frozenset({"GET", "POST"})

Resolver = Callable[[str, int], frozenset[str]]


class CambioDnsError(ServiceError):
    """El nombre del objetivo apunta a otra dirección durante la ejecución. Se detiene todo."""


def resolver_del_sistema(host: str, puerto: int) -> frozenset[str]:
    """Direcciones IP a las que resuelve el nombre. Lanza OSError si no resuelve."""
    entradas = socket.getaddrinfo(host, puerto, type=socket.SOCK_STREAM)
    return frozenset(str(entrada[4][0]) for entrada in entradas)


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
    seguridad: tuple[tuple[str, str], ...] = ()

    def cabecera_de_seguridad(self, nombre: str) -> str | None:
        """Valor de una cabecera de seguridad (nombre en minúsculas), o None si no viene."""
        return dict(self.seguridad).get(nombre)


@dataclass(frozen=True)
class InformeTls:
    """Resultado de la conexión TLS. `motivo` es None solo si el certificado se verificó."""

    protocolo: str | None
    cifrado: str | None
    dias_restantes: int | None
    motivo: str | None

    @property
    def verificado(self) -> bool:
        return self.motivo is None


@dataclass
class Sesion:
    """Cookies de una secuencia de peticiones. Se descartan al terminar el caso."""

    valores: dict[str, str] = field(default_factory=dict, repr=False)


class _HttpFijada(http.client.HTTPConnection):
    """Conexión HTTP a la dirección fijada por la ejecución. El nombre viaja en la cabecera Host."""

    def __init__(self, host: str, puerto: int, direccion: str, timeout: float) -> None:
        super().__init__(host, puerto, timeout=timeout)
        self._direccion = direccion

    def connect(self) -> None:
        self.sock = socket.create_connection((self._direccion, self.port), self.timeout)


class _HttpsFijada(http.client.HTTPSConnection):
    """Conexión TLS a la dirección fijada. El certificado se verifica contra el nombre del objetivo."""

    def __init__(
        self,
        host: str,
        puerto: int,
        direccion: str,
        timeout: float,
        contexto: ssl.SSLContext,
    ) -> None:
        super().__init__(host, puerto, timeout=timeout)
        self._direccion = direccion
        self._contexto_tls = contexto

    def connect(self) -> None:
        crudo = socket.create_connection((self._direccion, self.port), self.timeout)
        self.sock = self._contexto_tls.wrap_socket(crudo, server_hostname=self.host)


class ClienteHttp:
    """Envía peticiones a un único origen. No guarda estado entre peticiones: es seguro en hilos.

    `contexto_tls` solo lo cambian las pruebas (para confiar en una autoridad de laboratorio). En
    ejecución real es None y se usa la verificación TLS por defecto del sistema.
    """

    def __init__(
        self,
        origen: Origen,
        timeout_s: float,
        *,
        resolver: Resolver = resolver_del_sistema,
        contexto_tls: ssl.SSLContext | None = None,
    ) -> None:
        self._origen = origen
        self._timeout = timeout_s
        self._resolver = resolver
        self._contexto_tls = contexto_tls
        self._direcciones: frozenset[str] | None = None

    @property
    def origen(self) -> Origen:
        return self._origen

    @property
    def direcciones(self) -> frozenset[str]:
        if self._direcciones is None:
            raise ValidationError("la ejecución no ha fijado la dirección del objetivo")
        return self._direcciones

    def fijar_direcciones(self) -> frozenset[str]:
        """Resuelve el objetivo al empezar la ejecución. Si no resuelve, no hay plan válido."""
        try:
            direcciones = self._resolver(self._origen.host, self._origen.puerto)
        except OSError as exc:
            raise ValidationError(
                f"el objetivo no se puede resolver ({type(exc).__name__})"
            ) from None
        if not direcciones:
            raise ValidationError("el objetivo no resuelve a ninguna dirección")
        self._direcciones = direcciones
        return direcciones

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

        inicio = time.perf_counter()
        direccion = self._direccion_vigilada()
        if direccion is None:
            return _respuesta_de_error("el nombre del objetivo no resuelve en este momento", inicio)

        codigo = 0
        ubicacion: str | None = None
        crudo = b""
        cookies: tuple[CookieInfo, ...] = ()
        seguridad: tuple[tuple[str, str], ...] = ()
        error: str | None = None
        conexion = self._conexion(direccion)
        try:
            conexion.request(metodo, ruta, body=cuerpo, headers=cabeceras)
            respuesta = conexion.getresponse()
            crudo = respuesta.read(MAX_CUERPO_BYTES)
            codigo = respuesta.status
            ubicacion = respuesta.getheader("Location")
            cookies = _procesar_cookies(respuesta.headers.get_all("Set-Cookie") or [], sesion)
            seguridad = _cabeceras_de_seguridad(respuesta.getheaders())
        except TimeoutError:
            error = "tiempo máximo de la petición agotado"
        except ConnectionRefusedError:
            error = "conexión rechazada por el objetivo"
        except ssl.SSLError as exc:
            error = f"error TLS ({exc.reason or type(exc).__name__})"
        except socket.gaierror:
            error = "no se pudo resolver el nombre del objetivo"
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
            seguridad=seguridad,
        )

    def informe_tls(self, *, ahora: float | None = None) -> InformeTls:
        """Conecta por TLS y describe el protocolo, el cifrado y el certificado. Nunca desactiva la
        verificación: un certificado no verificable se informa como motivo, no se acepta."""
        if not self._origen.https:
            return InformeTls(
                None, None, None, "el objetivo no usa HTTPS: el tráfico no está cifrado"
            )
        direccion = self._direccion_vigilada()
        if direccion is None:
            return InformeTls(
                None, None, None, "el nombre del objetivo no resuelve en este momento"
            )
        contexto = self._contexto_tls or ssl.create_default_context()
        try:
            with (
                socket.create_connection((direccion, self._origen.puerto), self._timeout) as crudo,
                contexto.wrap_socket(crudo, server_hostname=self._origen.host) as canal,
            ):
                protocolo = canal.version()
                datos_cifrado = canal.cipher()
                cifrado = datos_cifrado[0] if datos_cifrado else None
                certificado = canal.getpeercert() or {}
        except ssl.SSLCertVerificationError as exc:
            detalle = exc.verify_message or exc.reason or "verificación fallida"
            return InformeTls(None, None, None, f"certificado no verificable ({detalle})")
        except ssl.SSLError as exc:
            return InformeTls(None, None, None, f"error TLS ({exc.reason or type(exc).__name__})")
        except (OSError, TimeoutError) as exc:
            return InformeTls(None, None, None, f"error de conexión ({type(exc).__name__})")
        expira = certificado.get("notAfter")
        dias = _dias_hasta(expira, ahora) if isinstance(expira, str) else None
        return InformeTls(protocolo, cifrado, dias, None)

    def _direccion_vigilada(self) -> str | None:
        """Dirección a la que conectar, o None si el nombre no resuelve en este momento.

        Lanza CambioDnsError si el nombre apunta a direcciones sin ninguna en común con las fijadas.
        """
        fijadas = self.direcciones
        try:
            actuales = self._resolver(self._origen.host, self._origen.puerto)
        except OSError:
            return None
        if actuales.isdisjoint(fijadas):
            raise CambioDnsError(
                "el nombre del objetivo apunta a otra dirección durante la ejecución"
            )
        return min(fijadas)

    def _conexion(self, direccion: str) -> http.client.HTTPConnection:
        if self._origen.https:
            return _HttpsFijada(
                self._origen.host,
                self._origen.puerto,
                direccion,
                self._timeout,
                self._contexto_tls or ssl.create_default_context(),
            )
        return _HttpFijada(self._origen.host, self._origen.puerto, direccion, self._timeout)


def _respuesta_de_error(motivo: str, inicio: float) -> Respuesta:
    return Respuesta(
        codigo=0,
        ubicacion=None,
        cuerpo="",
        duracion_ms=int((time.perf_counter() - inicio) * 1000),
        cookies=(),
        error=motivo,
    )


def _cabeceras_de_seguridad(cabeceras: Sequence[tuple[str, str]]) -> tuple[tuple[str, str], ...]:
    return tuple(
        (nombre.lower(), valor)
        for nombre, valor in cabeceras
        if nombre.lower() in CABECERAS_DE_SEGURIDAD
    )


def _dias_hasta(fecha: str, ahora: float | None) -> int:
    """Días completos entre el momento actual y la fecha de caducidad del certificado."""
    instante = ssl.cert_time_to_seconds(fecha)
    referencia = time.time() if ahora is None else ahora
    return int((instante - referencia) // 86_400)


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
