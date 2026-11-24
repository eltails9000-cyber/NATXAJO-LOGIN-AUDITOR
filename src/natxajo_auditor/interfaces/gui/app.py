"""Aplicación de la interfaz: rutas, sesiones web y traducción de errores a respuestas HTTP.

Una sesión web vive en memoria del proceso y se asocia al navegador con una cookie HttpOnly. Guarda
la ficha de la sesión de la plataforma y una ficha CSRF propia. La ficha de la plataforma nunca
llega al navegador. Al entrar y al salir la cookie y la ficha CSRF se renuevan (evita la fijación
de sesión).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs

from natxajo_auditor.core.contracts import (
    ACCOUNT_READ_PERMISSION,
    DIAGNOSTIC_PERMISSION,
    EVENT_READ_PERMISSION,
    MODULE_READ_PERMISSION,
    PLATFORM_COMPANY,
    PLUGIN_READ_PERMISSION,
    REPORT_READ_PERMISSION,
    SCOPE_DENIED,
    SESSION_READ_PERMISSION,
)
from natxajo_auditor.core.exceptions import (
    AuthorizationError,
    NatxajoError,
    SessionError,
    SessionLimitError,
)
from natxajo_auditor.interfaces.gui.actions import Actions
from natxajo_auditor.interfaces.gui.http_security import (
    CSRF_HEADER,
    MAX_TARGET_CHARS,
    SESSION_COOKIE,
    STATIC_TYPES,
    GuiError,
    Request,
    Response,
    check_fetch_site,
    check_host,
    check_origin,
    error_response,
    flag_field,
    int_field,
    json_response,
    new_secret,
    parse_json_body,
    read_cookie,
    same_secret,
    secret_field,
    session_cookie,
    text_field,
)
from natxajo_auditor.interfaces.gui.preferences import (
    DENSITIES,
    FILE_NAME,
    MOTION,
    PAGE_SIZES,
    REFRESH_SECONDS,
    START_PAGES,
    THEMES,
)
from natxajo_auditor.interfaces.gui.preferences import (
    from_mapping as preferences_from_mapping,
)
from natxajo_auditor.interfaces.gui.preferences import (
    load as load_preferences,
)
from natxajo_auditor.interfaces.gui.preferences import (
    save as save_preferences,
)
from natxajo_auditor.interfaces.gui.readmodels import ReadModels
from natxajo_auditor.kernel.kernel import Kernel

LOG = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).resolve().parent / "static"
WEB_SESSION_LIMIT = 64
CREDENTIALS_MESSAGE = "Usuario o contraseña incorrectos."
REPORT_FORMATS = ("json", "csv", "html", "txt")
DEFAULT_EVENT_LIMIT = 200
MAX_HOURS = 720
PLATFORM_ONLY = "solo_plataforma"
# página -> (permiso de lectura o None, solo plataforma)
PAGE_RULES: dict[str, tuple[str | None, bool]] = {
    "panel": (None, False),
    "auditoria": (EVENT_READ_PERMISSION, False),
    "usuarios": (ACCOUNT_READ_PERMISSION, False),
    "sesiones": (SESSION_READ_PERMISSION, False),
    "plugins": (PLUGIN_READ_PERMISSION, True),
    "modulos": (MODULE_READ_PERMISSION, True),
    "reportes": (REPORT_READ_PERMISSION, False),
    "eventos": (EVENT_READ_PERMISSION, False),
    "seguridad": (EVENT_READ_PERMISSION, False),
    "mantenimiento": (DIAGNOSTIC_PERMISSION, True),
    "configuracion": (None, False),
}


@dataclass
class WebSession:
    sid: str
    csrf: str
    token: str | None = None


@dataclass
class Context:
    request: Request
    params: dict[str, object]
    web: WebSession

    def token(self) -> str:
        if self.web.token is None:
            raise GuiError(401, "no_autenticado", "Inicie sesión para continuar")
        return self.web.token


@dataclass(frozen=True)
class Route:
    handler: Callable[[Context], Response | dict[str, object]]
    auth: bool = True


class GuiApp:
    def __init__(self, kernel: Kernel, port: int) -> None:
        self._kernel = kernel
        self._port = port
        self._reads = ReadModels(kernel)
        self._actions = Actions(kernel)
        self._sessions: dict[str, WebSession] = {}
        self._routes: dict[tuple[str, str], Route] = {
            ("GET", "/api/sesion"): Route(self._session_state, auth=False),
            ("POST", "/api/sesion/entrar"): Route(self._login, auth=False),
            ("POST", "/api/sesion/salir"): Route(self._logout, auth=False),
            ("POST", "/api/sesion/reautenticar"): Route(self._reauthenticate),
            ("GET", "/api/panel"): Route(lambda c: self._reads.dashboard(c.token())),
            ("GET", "/api/auditoria/eventos"): Route(self._events),
            ("GET", "/api/auditoria/evaluaciones"): Route(
                lambda c: self._reads.evaluations(c.token(), _optional(c.params, "empresa"))
            ),
            ("GET", "/api/auditoria/evaluacion"): Route(self._evaluation),
            ("GET", "/api/usuarios"): Route(
                lambda c: self._reads.accounts(c.token(), _optional(c.params, "empresa"))
            ),
            ("GET", "/api/usuarios/detalle"): Route(
                lambda c: self._reads.account_detail(
                    c.token(), text_field(c.params, "usuario", maximum=40)
                )
            ),
            ("GET", "/api/sesiones"): Route(
                lambda c: self._reads.sessions(c.token(), _optional(c.params, "empresa"))
            ),
            ("GET", "/api/plugins"): Route(lambda c: self._reads.plugins(c.token())),
            ("GET", "/api/modulos"): Route(lambda c: self._reads.modules(c.token())),
            ("GET", "/api/informes"): Route(
                lambda c: self._reads.reports(c.token(), _optional(c.params, "empresa"))
            ),
            ("GET", "/api/eventos/catalogo"): Route(
                lambda c: self._reads.catalog(c.token(), _optional(c.params, "empresa"))
            ),
            ("GET", "/api/seguridad"): Route(
                lambda c: self._reads.security_overview(c.token(), _optional(c.params, "empresa"))
            ),
            ("GET", "/api/mantenimiento"): Route(lambda c: self._reads.maintenance(c.token())),
            ("GET", "/api/mantenimiento/limpieza"): Route(
                lambda c: self._reads.cleanup_plan(c.token(), _hours(c.params))
            ),
            ("GET", "/api/mantenimiento/diagnostico"): Route(self._diagnostic_download),
            ("GET", "/api/empresas"): Route(lambda c: self._reads.companies(c.token())),
            ("GET", "/api/configuracion"): Route(self._configuration),
            ("POST", "/api/preferencias"): Route(self._save_preferences),
            ("POST", "/api/acciones/plugins/cuarentena"): Route(self._quarantine),
            ("POST", "/api/acciones/plugins/liberar"): Route(self._release),
            ("POST", "/api/acciones/plugins/actualizar"): Route(self._update),
            ("POST", "/api/acciones/plugins/revertir"): Route(self._rollback),
            ("POST", "/api/acciones/modulos/habilitar"): Route(self._enable_module),
            ("POST", "/api/acciones/modulos/deshabilitar"): Route(self._disable_module),
            ("POST", "/api/acciones/informes/exportar"): Route(self._export_report),
            ("POST", "/api/acciones/informes/verificar"): Route(self._verify_reports),
            ("POST", "/api/acciones/mantenimiento/limpiar"): Route(self._apply_cleanup),
        }

    def handle(self, request: Request) -> Response:
        try:
            return self._dispatch(request)
        except GuiError as exc:
            return error_response(exc.status, exc.code, exc.message)
        except SessionError as exc:
            return error_response(401, "sesion", str(exc))
        except AuthorizationError as exc:
            return error_response(403, _denial_code(str(exc)), str(exc))
        except NatxajoError as exc:
            return error_response(422, "validacion", str(exc))
        except Exception:
            LOG.exception("Error interno al atender %s", request.method)
            return error_response(
                500, "interno", "Error interno. Revise la consola donde se ejecuta la interfaz."
            )

    def _dispatch(self, request: Request) -> Response:
        if not check_host(request, self._port):
            return error_response(403, "host", "Host no permitido")
        if len(request.target) > MAX_TARGET_CHARS:
            return error_response(414, "destino", "La ruta es demasiado larga")
        path, _, query = request.target.partition("?")
        if request.method == "GET" and path in ("/", "/index.html"):
            return _static("index.html")
        if request.method == "GET" and path.startswith("/static/"):
            name = path.removeprefix("/static/")
            if name not in STATIC_TYPES:
                return error_response(404, "no_encontrada", "Archivo no encontrado")
            return _static(name)
        route = self._routes.get((request.method, path))
        if route is None:
            if request.method not in ("GET", "POST"):
                return error_response(405, "metodo", "Método no permitido")
            return error_response(404, "no_encontrada", "Ruta no encontrada")
        if not check_fetch_site(request):
            return error_response(403, "origen", "Petición de otro sitio rechazada")
        if request.method == "POST" and not check_origin(request, self._port):
            return error_response(403, "origen", "Origen no permitido")
        web = self._web_session(request)
        ctx = Context(request=request, params=_params(request, query), web=web)
        if request.method == "POST" and not same_secret(web.csrf, request.headers.get(CSRF_HEADER)):
            return error_response(403, "csrf", "Ficha de seguridad no válida. Recargue la página.")
        if route.auth and web.token is None:
            return error_response(401, "no_autenticado", "Inicie sesión para continuar")
        try:
            result = route.handler(ctx)
        except SessionError:
            web.token = None
            return error_response(401, "sesion", "La sesión ha caducado. Inicie sesión de nuevo.")
        response = result if isinstance(result, Response) else json_response(200, result)
        return self._with_cookie(response, ctx)

    # --- sesiones web -----------------------------------------------------------------------

    def _web_session(self, request: Request) -> WebSession:
        sid = read_cookie(request, SESSION_COOKIE)
        if sid is not None and sid in self._sessions:
            return self._sessions[sid]
        return self._new_web()

    def _new_web(self) -> WebSession:
        if len(self._sessions) >= WEB_SESSION_LIMIT:
            oldest = next(iter(self._sessions))
            evicted = self._sessions.pop(oldest)
            if evicted.token is not None:
                self._kernel.security.logout(evicted.token)
        web = WebSession(sid=new_secret(), csrf=new_secret())
        self._sessions[web.sid] = web
        return web

    def _forget(self, web: WebSession) -> None:
        self._sessions.pop(web.sid, None)

    def _with_cookie(self, response: Response, ctx: Context) -> Response:
        if read_cookie(ctx.request, SESSION_COOKIE) == ctx.web.sid:
            return response
        return Response(
            response.status,
            response.body,
            response.content_type,
            response.headers + (session_cookie(ctx.web.sid),),
        )

    # --- sesión y acceso ----------------------------------------------------------------------

    def _session_state(self, ctx: Context) -> dict[str, object]:
        security = self._kernel.security
        pending = security.installer.is_pending()
        web = ctx.web
        if web.token is None:
            return self._anonymous(web, pending)
        try:
            session = security.sessions.validate(web.token)
        except SessionError:
            web.token = None
            return self._anonymous(web, pending)
        company = security.accounts.company_of(session.username)
        platform = company == PLATFORM_COMPANY
        return {
            "autenticado": True,
            "csrf": web.csrf,
            "usuario": session.username,
            "empresa": company,
            "plataforma": platform,
            "reautenticada": security.sessions.recently_reauthenticated(session),
            "instalacion_pendiente": pending,
            "version": self._kernel.kernel_version,
            "paginas": self._page_access(session.username, platform),
            **self._preferences_payload(),
        }

    def _anonymous(self, web: WebSession, pending: bool) -> dict[str, object]:
        return {
            "autenticado": False,
            "csrf": web.csrf,
            "instalacion_pendiente": pending,
            "version": self._kernel.kernel_version,
            **self._preferences_payload(),
        }

    def _page_access(self, username: str, platform: bool) -> dict[str, str]:
        authorizer = self._kernel.security.authorizer
        access: dict[str, str] = {}
        for page, (permission, platform_only) in PAGE_RULES.items():
            if platform_only and not platform:
                access[page] = PLATFORM_ONLY
            elif permission is not None and not authorizer.is_allowed(username, permission):
                access[page] = "sin_permiso"
            else:
                access[page] = "ok"
        return access

    def _login(self, ctx: Context) -> dict[str, object]:
        usuario = text_field(ctx.params, "usuario", maximum=40)
        contrasena = secret_field(ctx.params, "contrasena")
        security = self._kernel.security
        if security.installer.is_pending():
            raise GuiError(
                409,
                "instalacion_pendiente",
                "La instalación inicial no está completa. Complétela en la terminal.",
            )
        try:
            token = security.login(usuario, contrasena)
        except SessionLimitError as exc:
            raise GuiError(409, "sesiones_maximas", str(exc)) from exc
        except AuthorizationError as exc:
            # Mensaje único para todo fallo de acceso: no se revela si la cuenta existe, está
            # bloqueada o deshabilitada.
            raise GuiError(401, "credenciales", CREDENTIALS_MESSAGE) from exc
        previous = ctx.web
        if previous.token is not None:
            security.logout(previous.token)
        self._forget(previous)
        ctx.web = self._new_web()
        ctx.web.token = token
        return self._session_state(ctx)

    def _logout(self, ctx: Context) -> dict[str, object]:
        if ctx.web.token is not None:
            self._kernel.security.logout(ctx.web.token)
        self._forget(ctx.web)
        ctx.web = self._new_web()
        return self._anonymous(ctx.web, self._kernel.security.installer.is_pending())

    def _reauthenticate(self, ctx: Context) -> dict[str, object]:
        password = secret_field(ctx.params, "contrasena")
        try:
            self._kernel.security.reauthenticate(ctx.token(), password)
        except SessionError:
            raise
        except AuthorizationError as exc:
            raise GuiError(401, "credenciales", CREDENTIALS_MESSAGE) from exc
        return {"reautenticada": True}

    # --- preferencias y configuración ---------------------------------------------------------

    def _preferences_path(self) -> Path:
        return self._kernel.context.config_dir / FILE_NAME

    def _preferences_payload(self) -> dict[str, object]:
        loaded = load_preferences(self._preferences_path())
        return {
            "preferencias": loaded.preferences.as_dict(),
            "aviso_preferencias": loaded.warning,
        }

    def _configuration(self, ctx: Context) -> dict[str, object]:
        return {
            **self._reads.system_info(),
            **self._preferences_payload(),
            "opciones": {
                "temas": list(THEMES),
                "densidades": list(DENSITIES),
                "movimientos": list(MOTION),
                "paginas": list(START_PAGES),
                "actualizaciones": list(REFRESH_SECONDS),
                "filas": list(PAGE_SIZES),
            },
        }

    def _save_preferences(self, ctx: Context) -> dict[str, object]:
        current = load_preferences(self._preferences_path()).preferences
        merged: dict[str, object] = {**current.as_dict(), **ctx.params}
        updated = preferences_from_mapping(merged)
        try:
            save_preferences(self._preferences_path(), updated)
        except OSError as exc:
            raise GuiError(
                500, "almacenamiento", "No se pudieron guardar las preferencias"
            ) from exc
        return {"preferencias": updated.as_dict(), "aviso_preferencias": None}

    # --- lecturas con parámetros --------------------------------------------------------------

    def _events(self, ctx: Context) -> dict[str, object]:
        params = ctx.params
        return self._reads.events(
            ctx.token(),
            category=_choice(params, "categoria", ("", "operativo", "seguridad")) or None,
            severity=_choice(params, "gravedad", ("", "alta", "media", "baja")) or None,
            event_type=_optional(params, "tipo"),
            company=_optional(params, "empresa"),
            limit=_bounded(params, "limite", 1, 500, DEFAULT_EVENT_LIMIT),
        )

    def _evaluation(self, ctx: Context) -> dict[str, object]:
        return self._reads.evaluation(
            ctx.token(),
            _optional(ctx.params, "empresa"),
            text_field(ctx.params, "id", maximum=64),
        )

    def _diagnostic_download(self, ctx: Context) -> Response:
        report = self._reads.diagnostic_export(ctx.token())
        return json_response(
            200,
            report,
            (("Content-Disposition", 'attachment; filename="diagnostico-natxajo.json"'),),
        )

    # --- acciones -------------------------------------------------------------------------------

    def _quarantine(self, ctx: Context) -> dict[str, object]:
        return self._actions.quarantine_plugin(
            ctx.token(),
            text_field(ctx.params, "plugin_id", maximum=100),
            text_field(ctx.params, "motivo", maximum=200),
        )

    def _release(self, ctx: Context) -> dict[str, object]:
        return self._actions.release_plugin(
            ctx.token(),
            text_field(ctx.params, "plugin_id", maximum=100),
            confirmed=flag_field(ctx.params, "confirmado"),
        )

    def _update(self, ctx: Context) -> dict[str, object]:
        return self._actions.update_plugin(
            ctx.token(),
            Path(text_field(ctx.params, "carpeta", maximum=500)),
            confirmed=flag_field(ctx.params, "confirmado"),
        )

    def _rollback(self, ctx: Context) -> dict[str, object]:
        return self._actions.rollback_plugin(
            ctx.token(),
            text_field(ctx.params, "plugin_id", maximum=100),
            confirmed=flag_field(ctx.params, "confirmado"),
        )

    def _enable_module(self, ctx: Context) -> dict[str, object]:
        return self._actions.enable_module(
            ctx.token(),
            text_field(ctx.params, "modulo_id", maximum=100),
            confirmed=flag_field(ctx.params, "confirmado"),
        )

    def _disable_module(self, ctx: Context) -> dict[str, object]:
        return self._actions.disable_module(
            ctx.token(),
            text_field(ctx.params, "modulo_id", maximum=100),
            confirmed=flag_field(ctx.params, "confirmado"),
        )

    def _export_report(self, ctx: Context) -> dict[str, object]:
        company = self._required_company(ctx)
        fmt = _choice(ctx.params, "formato", REPORT_FORMATS)
        return self._actions.export_report(
            ctx.token(), company, text_field(ctx.params, "evaluacion", maximum=64), fmt
        )

    def _verify_reports(self, ctx: Context) -> dict[str, object]:
        return self._actions.verify_reports(ctx.token(), self._required_company(ctx))

    def _apply_cleanup(self, ctx: Context) -> dict[str, object]:
        return self._actions.apply_cleanup(
            ctx.token(), _hours(ctx.params), confirmed=flag_field(ctx.params, "confirmado")
        )

    def _required_company(self, ctx: Context) -> str:
        viewer = self._reads.viewer(ctx.token())
        scope = self._reads.scope(viewer, _optional(ctx.params, "empresa"))
        if scope is None:
            raise GuiError(422, "validacion", "Indique la empresa")
        return scope


def _static(name: str) -> Response:
    return Response(200, (STATIC_DIR / name).read_bytes(), STATIC_TYPES[name])


def _params(request: Request, query: str) -> dict[str, object]:
    if request.method == "POST":
        return parse_json_body(request)
    return {key: values[0] for key, values in parse_qs(query, keep_blank_values=True).items()}


def _optional(params: dict[str, object], key: str) -> str | None:
    return text_field(params, key, required=False, maximum=120) or None


def _choice(params: dict[str, object], key: str, allowed: tuple[str, ...]) -> str:
    value = text_field(params, key, required=False, maximum=20)
    if value not in allowed:
        raise GuiError(422, "validacion", f"Valor no permitido para {key}")
    return value


def _bounded(params: dict[str, object], key: str, low: int, high: int, default: int) -> int:
    if params.get(key) in (None, ""):
        return default
    value = params[key]
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise GuiError(422, "validacion", f"{key} debe estar entre {low} y {high}")
    return value


def _hours(params: dict[str, object]) -> int:
    if params.get("horas") in (None, ""):
        return 24
    return int_field(params, "horas", tuple(range(1, MAX_HOURS + 1)))


def _denial_code(message: str) -> str:
    if message.startswith("operación crítica: reautentique"):
        return "reautenticacion_requerida"
    if message.startswith("operación crítica: se requiere confirmación"):
        return "confirmacion_requerida"
    if message.startswith("sin permiso"):
        return "sin_permiso"
    if message == SCOPE_DENIED:
        return "ambito"
    return "denegado"
