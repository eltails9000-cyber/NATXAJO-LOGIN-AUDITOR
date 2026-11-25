"""Capa HTTP de la interfaz: cabeceras, orígenes, cookies, cuerpos y respuestas.

Todo lo que llega del navegador se trata como no fiable. La interfaz solo escucha en 127.0.0.1 y:
- rechaza Host distinto de localhost o 127.0.0.1 con el puerto propio (protege frente a la
  reasignación de DNS);
- rechaza peticiones de la API que el navegador marca como de otro sitio (Sec-Fetch-Site);
- exige Origin correcto y la ficha CSRF en cada POST;
- limita el tamaño del cuerpo y exige JSON;
- sirve solo los archivos estáticos de una lista cerrada, sin rutas de disco ni sustituciones.
"""

from __future__ import annotations

import hmac
import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass

SESSION_COOKIE = "natxajo_gui"
CSRF_HEADER = "x-csrf-token"
MAX_BODY_BYTES = 16 * 1024
MAX_TARGET_CHARS = 2048
MAX_TEXT = 500
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; "
    "object-src 'none'"
)
STATIC_TYPES: dict[str, str] = {
    "index.html": "text/html; charset=utf-8",
    "app.css": "text/css; charset=utf-8",
    "core.js": "text/javascript; charset=utf-8",
    "components.js": "text/javascript; charset=utf-8",
    "pages.js": "text/javascript; charset=utf-8",
    "app.js": "text/javascript; charset=utf-8",
}


@dataclass(frozen=True)
class Request:
    method: str
    target: str
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    content_type: str
    headers: tuple[tuple[str, str], ...] = ()


class GuiError(Exception):
    """Error que se devuelve al navegador con un código estable y un mensaje en español."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def security_headers() -> tuple[tuple[str, str], ...]:
    return (
        ("Content-Security-Policy", CONTENT_SECURITY_POLICY),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Cross-Origin-Resource-Policy", "same-origin"),
        ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=()"),
        ("Cache-Control", "no-store"),
    )


def json_response(
    status: int, payload: object, extra: tuple[tuple[str, str], ...] = ()
) -> Response:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)
    return Response(status, body.encode("utf-8"), "application/json; charset=utf-8", extra)


def error_response(status: int, code: str, message: str) -> Response:
    return json_response(status, {"error": {"codigo": code, "mensaje": message}})


def allowed_hosts(port: int) -> frozenset[str]:
    return frozenset({f"127.0.0.1:{port}", f"localhost:{port}"})


def allowed_origins(port: int) -> frozenset[str]:
    return frozenset({f"http://127.0.0.1:{port}", f"http://localhost:{port}"})


def check_host(request: Request, port: int) -> bool:
    return request.headers.get("host") in allowed_hosts(port)


def check_origin(request: Request, port: int) -> bool:
    origin = request.headers.get("origin")
    return origin is None or origin in allowed_origins(port)


def check_fetch_site(request: Request) -> bool:
    site = request.headers.get("sec-fetch-site")
    return site is None or site in ("same-origin", "none")


def new_secret() -> str:
    return secrets.token_urlsafe(32)


def same_secret(expected: str, given: str | None) -> bool:
    return given is not None and hmac.compare_digest(expected.encode(), given.encode())


def read_cookie(request: Request, name: str) -> str | None:
    raw = request.headers.get("cookie")
    if not raw:
        return None
    for part in raw.split(";"):
        key, separator, value = part.strip().partition("=")
        if separator and key == name:
            return value
    return None


def session_cookie(value: str) -> tuple[str, str]:
    return ("Set-Cookie", f"{SESSION_COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict")


def parse_json_body(request: Request) -> dict[str, object]:
    media_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if media_type != "application/json":
        raise GuiError(415, "tipo", "Se esperaba un cuerpo application/json")
    if len(request.body) > MAX_BODY_BYTES:
        raise GuiError(413, "tamano", "El cuerpo de la petición es demasiado grande")
    try:
        data = json.loads(request.body.decode("utf-8") or "{}")
    except (UnicodeDecodeError, ValueError) as exc:
        raise GuiError(400, "json", "El cuerpo no es JSON válido") from exc
    if not isinstance(data, dict):
        raise GuiError(400, "json", "El cuerpo debe ser un objeto JSON")
    return data


def text_field(
    params: Mapping[str, object], key: str, *, required: bool = True, maximum: int = MAX_TEXT
) -> str:
    value = params.get(key, "")
    if not isinstance(value, str):
        raise GuiError(422, "validacion", f"El campo {key} debe ser texto")
    if len(value) > maximum:
        raise GuiError(422, "validacion", f"El campo {key} es demasiado largo")
    text = value.strip()
    if required and not text:
        raise GuiError(422, "validacion", f"Falta el campo {key}")
    return text


def secret_field(params: Mapping[str, object], key: str) -> str:
    """Contraseñas: no se recortan ni se registran. Solo se comprueba que existan."""
    value = params.get(key)
    if not isinstance(value, str) or not value or len(value) > 256:
        raise GuiError(422, "validacion", f"Falta el campo {key}")
    return value


def flag_field(params: Mapping[str, object], key: str) -> bool:
    value = params.get(key, False)
    if not isinstance(value, bool):
        raise GuiError(422, "validacion", f"El campo {key} debe ser verdadero o falso")
    return value


def int_field(params: Mapping[str, object], key: str, allowed: tuple[int, ...]) -> int:
    value = params.get(key)
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or value not in allowed:
        raise GuiError(422, "validacion", f"Valor no permitido para {key}")
    return value
