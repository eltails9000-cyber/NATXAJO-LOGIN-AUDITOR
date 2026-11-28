"""Servidor HTTP local de pruebas: cuentas sintéticas y escenarios controlados.

Solo usa biblioteca estándar y escucha en 127.0.0.1 con un puerto libre. Las cuentas y sus
contraseñas son valores fijos de prueba, sin relación con personas reales. El servidor reproduce
rutas de login, validación, CSRF, MFA, límite de intentos y errores, y cada escenario se activa
con `Escenario` para que las pruebas comprueben que el motor clasifica cada comportamiento bien.
"""

from __future__ import annotations

import json
import secrets
import shutil
import ssl
import subprocess
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Final, Self
from urllib.parse import parse_qs, urlsplit

CLAVE_A: Final = "clave-sintetica-a-0001"
CLAVE_B: Final = "clave-sintetica-b-0002"
CODIGO_MFA_A: Final = "424242"
VAR_CLAVE_A: Final = "NATXAJO_PRUEBA_CONTRASENA_A"
VAR_CLAVE_B: Final = "NATXAJO_PRUEBA_CONTRASENA_B"
VAR_MFA_A: Final = "NATXAJO_PRUEBA_MFA_A"
MAX_CUERPO: Final = 65_536
LONGITUD_USUARIO: Final = (2, 32)
LONGITUD_CORREO: Final = 64
LONGITUD_CLAVE: Final = 64

MENSAJE_CREDENCIALES: Final = "Credenciales incorrectas."
MENSAJE_BLOQUEO: Final = "Demasiados intentos fallidos. Espere antes de volver a intentarlo."
MENSAJE_RETRO: Final = (
    "El usuario no existe en el sistema de autenticación de la aplicación de prueba, "
    "así que la respuesta difiere de la de una cuenta existente."
)


@dataclass(frozen=True)
class CuentaLab:
    usuario: str
    correo: str
    clave: str
    mfa: str | None = None


CUENTAS_LAB: Final[tuple[CuentaLab, ...]] = (
    CuentaLab("prueba-a", "prueba-a@example.com", CLAVE_A, CODIGO_MFA_A),
    CuentaLab("prueba-b", "prueba-b@example.com", CLAVE_B),
)


@dataclass
class Escenario:
    """Comportamiento del servidor. Por defecto es un servidor correcto."""

    csrf: bool = True
    csrf_obligatorio: bool = True
    cookie_httponly: bool = True
    revelar_usuario: bool = False
    umbral_bloqueo: int = 1000
    fallar_500: bool = False
    retardo_s: float = 0.0
    # Cabeceras de seguridad en todas las respuestas, sin ellas el servidor es vulnerable a propósito.
    cabeceras_seguridad: bool = False
    # Atributo Secure en la cookie de sesión (solo tiene sentido con HTTPS).
    cookie_secure: bool = False
    # Retardo solo para cuentas existentes: permite detectar diferencias de tiempo entre cuentas.
    retardo_cuenta_existente_s: float = 0.0
    # (certificado, clave) en PEM. Si se indica, el servidor sirve HTTPS.
    certificado: tuple[Path, Path] | None = None


class LaboratorioHttp:
    """Servidor en un hilo aparte. Usar como contexto: al salir se detiene y libera el puerto."""

    def __init__(self, escenario: Escenario | None = None) -> None:
        self.escenario = escenario or Escenario()
        self._cerrojo = threading.Lock()
        self._tokens: set[str] = set()
        self._sesiones: dict[str, str] = {}
        self._pendientes: dict[str, str] = {}
        self._fallidos: dict[str, int] = {}
        self._en_vuelo = 0
        self.peticiones = 0
        self.maximo_simultaneas = 0
        self.rutas_visitadas: list[str] = []
        self._servidor = ThreadingHTTPServer(("127.0.0.1", 0), _manejador_para(self))
        self._servidor.daemon_threads = True
        if self.escenario.certificado is not None:
            certificado, clave = self.escenario.certificado
            contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            contexto.load_cert_chain(certificado, clave)
            # El handshake se hace en el hilo de cada petición, no en el bucle de aceptación.
            self._servidor.socket = contexto.wrap_socket(
                self._servidor.socket, server_side=True, do_handshake_on_connect=False
            )
        self._hilo = threading.Thread(target=self._servidor.serve_forever, daemon=True)

    @property
    def origen(self) -> str:
        esquema = "https" if self.escenario.certificado is not None else "http"
        return f"{esquema}://127.0.0.1:{self._servidor.server_address[1]}"

    def _cabeceras_fijas(self) -> tuple[tuple[str, str], ...]:
        if not self.escenario.cabeceras_seguridad:
            return ()
        return CABECERAS_SEGURAS

    def __enter__(self) -> Self:
        self._hilo.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._servidor.shutdown()
        self._servidor.server_close()

    # ----- Enrutado -------------------------------------------------------------------------

    def _atender(self, manejador: BaseHTTPRequestHandler, metodo: str) -> None:
        ruta = urlsplit(manejador.path).path
        with self._cerrojo:
            self.peticiones += 1
            self.rutas_visitadas.append(ruta)
            if metodo == "POST":
                self._en_vuelo += 1
                self.maximo_simultaneas = max(self.maximo_simultaneas, self._en_vuelo)
        try:
            self._despachar(manejador, metodo, ruta)
        finally:
            if metodo == "POST":
                with self._cerrojo:
                    self._en_vuelo -= 1

    def _despachar(self, manejador: BaseHTTPRequestHandler, metodo: str, ruta: str) -> None:
        if metodo == "GET" and ruta == "/login":
            self._pagina_login(manejador)
        elif metodo == "POST" and ruta == "/login":
            self._entrar(manejador, correo=False, con_csrf=True)
        elif metodo == "POST" and ruta == "/acceso":
            self._entrar(manejador, correo=True, con_csrf=False)
        elif metodo == "POST" and ruta == "/login-mfa":
            self._entrar_mfa(manejador)
        elif metodo == "POST" and ruta == "/verificar":
            self._verificar(manejador)
        elif metodo == "GET" and ruta == "/inicio":
            _enviar(manejador, 200, "Bienvenido a la aplicación de prueba.")
        else:
            _enviar(manejador, 404, "Página no encontrada.")

    # ----- Rutas ----------------------------------------------------------------------------

    def _pagina_login(self, manejador: BaseHTTPRequestHandler) -> None:
        oculto = ""
        if self.escenario.csrf:
            token = secrets.token_urlsafe(16)
            with self._cerrojo:
                self._tokens.add(token)
            oculto = f'<input type="hidden" name="csrf_token" value="{token}">'
        html = (
            '<!doctype html><html><body><form method="post" action="/login">'
            '<input name="usuario" type="text"><input name="clave" type="password">'
            f"{oculto}<button>Entrar</button></form></body></html>"
        )
        _enviar(manejador, 200, html)

    def _entrar(self, manejador: BaseHTTPRequestHandler, *, correo: bool, con_csrf: bool) -> None:
        campos = _campos(manejador)
        if self.escenario.fallar_500:
            _enviar(manejador, 500, "Error interno del servidor de prueba.")
            return
        if self.escenario.retardo_s > 0:
            time.sleep(self.escenario.retardo_s)
        if con_csrf and self.escenario.csrf and not self._csrf_aceptable(campos):
            _enviar(manejador, 403, "Solicitud rechazada: token CSRF no válido.")
            return
        identidad = campos.get("correo" if correo else "usuario") or ""
        clave = campos.get("clave") or ""
        error = _validar(identidad, clave, correo)
        if error is not None:
            codigo, mensaje = error
            _enviar(manejador, codigo, mensaje)
            return
        if self._bloqueado(identidad):
            _enviar(manejador, 429, MENSAJE_BLOQUEO)
            return
        cuenta = self._buscar(identidad, correo)
        if cuenta is not None and self.escenario.retardo_cuenta_existente_s > 0:
            time.sleep(self.escenario.retardo_cuenta_existente_s)
        if cuenta is None or cuenta.clave != clave:
            self._registrar_fallo(identidad)
            if cuenta is None and self.escenario.revelar_usuario:
                _enviar(manejador, 200, MENSAJE_RETRO)
            else:
                _enviar(manejador, 200, MENSAJE_CREDENCIALES)
            return
        with self._cerrojo:
            self._fallidos.pop(identidad, None)
        self._abrir_sesion(manejador, cuenta.usuario)

    def _entrar_mfa(self, manejador: BaseHTTPRequestHandler) -> None:
        campos = _campos(manejador)
        identidad = campos.get("usuario") or ""
        clave = campos.get("clave") or ""
        error = _validar(identidad, clave, correo=False)
        if error is not None:
            codigo, mensaje = error
            _enviar(manejador, codigo, mensaje)
            return
        if self._bloqueado(identidad):
            _enviar(manejador, 429, MENSAJE_BLOQUEO)
            return
        cuenta = self._buscar(identidad, correo=False)
        if cuenta is None or cuenta.clave != clave:
            self._registrar_fallo(identidad)
            _enviar(manejador, 200, MENSAJE_CREDENCIALES)
            return
        if cuenta.mfa is None:
            self._abrir_sesion(manejador, cuenta.usuario)
            return
        pendiente = secrets.token_urlsafe(16)
        with self._cerrojo:
            self._pendientes[pendiente] = cuenta.usuario
        _enviar(
            manejador,
            200,
            "Introduzca el código de verificación de su aplicación de autenticación.",
            [("Set-Cookie", self._cookie("pendiente", pendiente))],
        )

    def _verificar(self, manejador: BaseHTTPRequestHandler) -> None:
        pendiente = _cookie(manejador, "pendiente")
        with self._cerrojo:
            usuario = self._pendientes.get(pendiente) if pendiente else None
        if usuario is None:
            _enviar(manejador, 403, "Sesión de verificación no válida.")
            return
        codigo = _campos(manejador).get("codigo")
        if not codigo:
            _enviar(manejador, 400, "El código es obligatorio.")
            return
        cuenta = self._buscar(usuario, correo=False)
        if cuenta is None or codigo != cuenta.mfa:
            _enviar(manejador, 200, "Código incorrecto. Vuelva a intentarlo.")
            return
        with self._cerrojo:
            self._pendientes.pop(pendiente or "", None)
        self._abrir_sesion(manejador, usuario)

    # ----- Estado ---------------------------------------------------------------------------

    def _csrf_aceptable(self, campos: Mapping[str, str]) -> bool:
        token = campos.get("csrf_token")
        if token is None and not self.escenario.csrf_obligatorio:
            return True
        with self._cerrojo:
            return token is not None and token in self._tokens

    def _bloqueado(self, identidad: str) -> bool:
        with self._cerrojo:
            return self._fallidos.get(identidad, 0) >= self.escenario.umbral_bloqueo

    def _registrar_fallo(self, identidad: str) -> None:
        with self._cerrojo:
            self._fallidos[identidad] = self._fallidos.get(identidad, 0) + 1

    def _buscar(self, identidad: str, correo: bool) -> CuentaLab | None:
        for cuenta in CUENTAS_LAB:
            if (correo and cuenta.correo == identidad) or (
                not correo and cuenta.usuario == identidad
            ):
                return cuenta
        return None

    def _abrir_sesion(self, manejador: BaseHTTPRequestHandler, usuario: str) -> None:
        sid = secrets.token_urlsafe(16)
        with self._cerrojo:
            self._sesiones[sid] = usuario
        _enviar(
            manejador,
            302,
            "",
            [("Location", "/inicio"), ("Set-Cookie", self._cookie("sid", sid))],
        )

    def _cookie(self, nombre: str, valor: str) -> str:
        atributos = f"{nombre}={valor}; Path=/; SameSite=Lax"
        if self.escenario.cookie_httponly:
            atributos += "; HttpOnly"
        if self.escenario.cookie_secure:
            atributos += "; Secure"
        return atributos


def _manejador_para(laboratorio: LaboratorioHttp) -> type[BaseHTTPRequestHandler]:
    class Manejador(BaseHTTPRequestHandler):
        cabeceras_fijas = laboratorio._cabeceras_fijas()

        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            laboratorio._atender(self, "GET")

        def do_POST(self) -> None:
            laboratorio._atender(self, "POST")

    return Manejador


def _validar(identidad: str, clave: str, correo: bool) -> tuple[int, str] | None:
    if not identidad:
        return 400, ("El correo es obligatorio." if correo else "El usuario es obligatorio.")
    if correo:
        if len(identidad) > LONGITUD_CORREO or "@" not in identidad:
            return 422, "El correo no es válido."
    elif not LONGITUD_USUARIO[0] <= len(identidad) <= LONGITUD_USUARIO[1]:
        return 422, "El usuario no es válido."
    if not clave:
        return 400, "La contraseña es obligatoria."
    if len(clave) > LONGITUD_CLAVE:
        return 422, "La contraseña no es válida."
    return None


def _campos(manejador: BaseHTTPRequestHandler) -> dict[str, str]:
    longitud = int(manejador.headers.get("Content-Length", "0") or 0)
    cuerpo = manejador.rfile.read(min(longitud, MAX_CUERPO)).decode("utf-8", errors="replace")
    return {
        clave: valores[0] for clave, valores in parse_qs(cuerpo, keep_blank_values=True).items()
    }


def _cookie(manejador: BaseHTTPRequestHandler, nombre: str) -> str | None:
    for linea in manejador.headers.get_all("Cookie") or []:
        for parte in linea.split(";"):
            clave, _, valor = parte.strip().partition("=")
            if clave == nombre:
                return valor
    return None


def _enviar(
    manejador: BaseHTTPRequestHandler,
    codigo: int,
    cuerpo: str,
    cabeceras: list[tuple[str, str]] | None = None,
) -> None:
    datos = cuerpo.encode("utf-8")
    manejador.send_response(codigo)
    # Las cabeceras fijas las aporta el manejador del escenario (vacío salvo cabeceras_seguridad).
    fijas: tuple[tuple[str, str], ...] = getattr(manejador, "cabeceras_fijas", ())
    for nombre, valor in [*fijas, *(cabeceras or [])]:
        manejador.send_header(nombre, valor)
    manejador.send_header("Content-Type", "text/html; charset=utf-8")
    manejador.send_header("Content-Length", str(len(datos)))
    manejador.end_headers()
    if datos:
        manejador.wfile.write(datos)


CABECERAS_SEGURAS: Final[tuple[tuple[str, str], ...]] = (
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=(), microphone=()"),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
)


class OpensslNoDisponible(RuntimeError):
    """No hay openssl en el PATH: las pruebas de HTTPS no pueden generar su certificado."""


def generar_certificado(directorio: Path, dias: int = 365) -> tuple[Path, Path]:
    """Certificado autofirmado para 127.0.0.1 con openssl. Su clave solo vive en el directorio temporal.

    El certificado se marca como autoridad para que el cliente pueda confiar en él explícitamente.
    Nunca se usa el almacén del sistema: las pruebas confían solo en este certificado.
    """
    openssl = shutil.which("openssl")
    if openssl is None:
        raise OpensslNoDisponible("no se encontró openssl en el PATH")
    certificado = directorio / "laboratorio-cert.pem"
    clave = directorio / "laboratorio-clave.pem"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            str(clave),
            "-out",
            str(certificado),
            "-days",
            str(dias),
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )
    return certificado, clave


# ----- Configuración de prueba -----------------------------------------------------------------

FORMULARIOS_PRUEBA: Final[dict[str, Any]] = {
    "version": 1,
    "formularios": [
        {
            "id": "login",
            "tipo": "usuario_contrasena",
            "ruta": "/login",
            "campos": {"identidad": "usuario", "contrasena": "clave"},
            "longitudes": {"identidad": [2, 32], "contrasena": [1, 64]},
            "extra": {},
            "csrf": {"campo": "csrf_token", "pagina": "/login"},
            "respuesta": {
                "exito": ["Bienvenido"],
                "fallo": [
                    "Credenciales incorrectas",
                    "es obligatorio",
                    "no es válido",
                    "no es válida",
                    "token CSRF",
                    "no existe en el sistema",
                ],
                "bloqueo": ["Demasiados intentos fallidos"],
                "ruta_login": "/login",
            },
        },
        {
            "id": "acceso",
            "tipo": "correo_contrasena",
            "ruta": "/acceso",
            "campos": {"identidad": "correo", "contrasena": "clave"},
            "longitudes": {"identidad": [5, 64], "contrasena": [1, 64]},
            "extra": {"origen": "web"},
            "respuesta": {
                "exito": ["Bienvenido"],
                "fallo": [
                    "Credenciales incorrectas",
                    "es obligatorio",
                    "no es válido",
                    "no es válida",
                ],
                "bloqueo": [],
                "ruta_login": "/acceso",
            },
        },
        {
            "id": "mfa",
            "tipo": "usuario_contrasena_mfa",
            "ruta": "/login-mfa",
            "campos": {"identidad": "usuario", "contrasena": "clave"},
            "longitudes": {"identidad": [2, 32], "contrasena": [1, 64]},
            "extra": {},
            "mfa": {
                "campo": "codigo",
                "ruta": "/verificar",
                "marcador": "Introduzca el código de verificación",
            },
            "respuesta": {
                "exito": ["Bienvenido"],
                "fallo": [
                    "Credenciales incorrectas",
                    "es obligatorio",
                    "no es válida",
                    "Código incorrecto",
                    "Sesión de verificación no válida",
                ],
                "bloqueo": ["Demasiados intentos fallidos"],
                "ruta_login": "/login-mfa",
            },
        },
    ],
}

CUENTAS_PRUEBA: Final[dict[str, Any]] = {
    "version": 1,
    "cuentas": [
        {
            "id": "a",
            "usuario": "prueba-a",
            "variable_contrasena": VAR_CLAVE_A,
            "variable_mfa": VAR_MFA_A,
            "correo": "prueba-a@example.com",
        },
        {
            "id": "b",
            "usuario": "prueba-b",
            "variable_contrasena": VAR_CLAVE_B,
            "correo": "prueba-b@example.com",
        },
    ],
}

LIMITES_PRUEBA: Final[dict[str, Any]] = {
    "version": 1,
    "max_solicitudes": 200,
    "max_cuentas": 5,
    "concurrencia": 1,
    "pausa_ms": 0,
    "timeout_s": 2,
    "max_intentos": 6,
}


def entorno_de_prueba() -> dict[str, str]:
    """Variables de entorno con las contraseñas y el código MFA sintéticos de las cuentas."""
    return {VAR_CLAVE_A: CLAVE_A, VAR_CLAVE_B: CLAVE_B, VAR_MFA_A: CODIGO_MFA_A}


def escribir_configuracion(
    config_dir: Path,
    *,
    formularios: Mapping[str, Any] | None = None,
    cuentas: Mapping[str, Any] | None = None,
    limites: Mapping[str, Any] | None = None,
) -> Path:
    """Escribe formularios.json, cuentas.json y limites.json en config_dir/pruebas."""
    carpeta = config_dir / "pruebas"
    carpeta.mkdir(parents=True, exist_ok=True)
    (carpeta / "formularios.json").write_text(
        json.dumps(dict(formularios or FORMULARIOS_PRUEBA), ensure_ascii=False), encoding="utf-8"
    )
    (carpeta / "cuentas.json").write_text(
        json.dumps(dict(cuentas or CUENTAS_PRUEBA), ensure_ascii=False), encoding="utf-8"
    )
    (carpeta / "limites.json").write_text(
        json.dumps(dict(limites or LIMITES_PRUEBA)), encoding="utf-8"
    )
    return carpeta
