"""Interfaz de terminal. Instala la plataforma si hace falta, pide inicio de sesión y muestra solo las
opciones que la cuenta puede usar.

La terminal presenta datos y pide confirmaciones. No decide permisos ni empresas: cada acción pasa
por el guardián de operaciones del núcleo, que vuelve a comprobar el permiso y el ámbito de empresa.

Ámbito de cada opción:
- plataforma: solo cuentas de la empresa `plataforma` (infraestructura y empresas).
- propia: la cuenta actúa sobre su empresa. Una cuenta de la plataforma actúa sobre todas.
- ninguno: no requiere empresa (la comprobación la hace la propia acción).
"""

from __future__ import annotations

import getpass
import json
from collections.abc import Callable
from dataclasses import dataclass

from natxajo_auditor.core.contracts import APPROVE_PERMISSION, PLATFORM_COMPANY, SCOPE_DENIED
from natxajo_auditor.core.exceptions import (
    AuthorizationError,
    NatxajoError,
    SessionError,
    ValidationError,
)
from natxajo_auditor.kernel.kernel import Kernel

PENDING_FEATURES = (
    "Gestión de plugins desde la terminal (fase 6)",
    "Motor de automatización (fase 8)",
    "Motor de auditoría defensiva (fase 9)",
    "Interfaz de escritorio (fase 10)",
    "Diagnósticos, informes y mantenimiento (fases 11 y 12)",
    "Ejecución de módulos y plugins (sin fase asignada)",
)
MAX_LOGIN_ATTEMPTS = 3
CONFIRMATIONS = frozenset({"sí", "si", "s"})
CREATE_ACCOUNT_PERMISSION = "seguridad:nucleo:cuenta:administrar"
COMPANY_ADMIN_PERMISSION = "seguridad:nucleo:empresa:administrar"
COMPANY_READ_PERMISSION = "seguridad:nucleo:empresa:leer"
SCOPE_NONE = "ninguno"
SCOPE_OWN = "propia"
SCOPE_PLATFORM = "plataforma"
_EXIT = "salir"
_EXPIRED = "caducada"

Read = Callable[[str], str]
Write = Callable[[str], None]


@dataclass
class Console:
    kernel: Kernel
    read: Read
    read_secret: Read
    write: Write
    token: str = ""
    username: str = ""
    company: str = ""


@dataclass(frozen=True)
class Option:
    key: str
    label: str
    permission: str | None
    critical: bool
    action: Callable[[Console], None]
    scope: str = SCOPE_NONE


def run_terminal(
    kernel: Kernel,
    read: Read = input,
    write: Write = print,
    read_secret: Read = getpass.getpass,
) -> int:
    """Bucle principal. Devuelve 0 al salir o al cerrarse la entrada, 1 si no se pudo entrar."""
    console = Console(kernel=kernel, read=read, read_secret=read_secret, write=write)
    try:
        if kernel.security.installer.is_pending() and not _install(console):
            return 1
        while True:
            if not _login(console):
                write("Demasiados intentos fallidos. Saliendo.")
                return 1
            if _session(console) == _EXIT:
                return 0
            write("La sesión ha caducado. Inicie sesión de nuevo.")
    except EOFError:
        write("")
        return 0


def _install(console: Console) -> bool:
    """Instalación del primer administrador. El código se muestra una vez y solo sirve una vez."""
    installer = console.kernel.security.installer
    code = installer.issue_code()
    minutes = int(installer.code_ttl.total_seconds() // 60)
    console.write("No hay cuentas en la plataforma. Instalación del primer administrador.")
    console.write(f"Código de instalación de un solo uso (válido {minutes} minutos):")
    console.write(f"  código: {code}")
    console.write("Guárdelo ahora: no volverá a mostrarse.")
    for _ in range(installer.max_code_attempts):
        typed = console.read_secret("Código de instalación: ").strip()
        username = console.read("Usuario administrador: ").strip()
        password = console.read_secret("Contraseña: ")
        confirmation = console.read_secret("Repita la contraseña: ")
        try:
            if password != confirmation:
                raise ValidationError("las contraseñas no coinciden")
            installer.complete(typed, username, password)
        except AuthorizationError as exc:
            # Código incorrecto: se cuenta el intento y se puede volver a escribir.
            console.write(f"Error: {exc}")
            continue
        except NatxajoError as exc:
            console.write(f"Error: {exc}")
            return False
        console.write(f"Cuenta de administrador creada: {username}. La instalación queda cerrada.")
        return True
    return False


def _login(console: Console) -> bool:
    for _ in range(MAX_LOGIN_ATTEMPTS):
        username = console.read("Usuario: ").strip()
        password = console.read_secret("Contraseña: ")
        try:
            console.token = console.kernel.security.login(username, password)
        except NatxajoError as exc:
            console.write(f"Error: {exc}")
            continue
        console.username = username
        console.company = console.kernel.security.accounts.company_of(username)
        return True
    return False


def _session(console: Console) -> str:
    _show_menu(console)
    while True:
        try:
            choice = console.read("\nSeleccione una opción: ").strip().lower()
        except EOFError:
            console.kernel.security.logout(console.token)
            return _EXIT
        if choice == "0":
            console.kernel.security.logout(console.token)
            return _EXIT
        try:
            _dispatch(console, choice)
        except SessionError:
            return _EXPIRED
        except NatxajoError as exc:
            console.write(f"Error: {exc}")


def _dispatch(console: Console, choice: str) -> None:
    if choice == "m":
        _show_menu(console)
        return
    option = _OPTIONS.get(choice)
    if option is None:
        console.write("Opción no válida")
        return
    security = console.kernel.security
    security.sessions.validate(console.token)
    if option.permission is None:
        option.action(console)
        return
    if not security.authorizer.is_allowed(console.username, option.permission):
        console.write("Opción no disponible para su cuenta")
        return
    company = _scope_company(console, option)
    if company is not None:
        # Se comprueba antes de pedir confirmación: una denegación no debe pedir nada más.
        security.guard.check_scope(console.token, company, option.permission)
    if option.critical and not _confirm(console):
        console.write("Operación cancelada")
        return
    security.guard.run(
        console.token,
        option.permission,
        lambda: option.action(console),
        confirmed=option.critical,
        company_id=company,
    )


def _scope_company(console: Console, option: Option) -> str | None:
    if option.scope == SCOPE_PLATFORM:
        return PLATFORM_COMPANY
    if option.scope == SCOPE_OWN:
        return console.company
    return None


def _visible(console: Console, option: Option) -> bool:
    security = console.kernel.security
    if option.permission is not None and not security.authorizer.is_allowed(
        console.username, option.permission
    ):
        return False
    return option.scope != SCOPE_PLATFORM or console.company == PLATFORM_COMPANY


def _confirm(console: Console) -> bool:
    answer = console.read("¿Confirma la operación? (sí/no): ").strip().lower()
    return answer in CONFIRMATIONS


def _show_menu(console: Console) -> None:
    lines = ["", "NATXAJO-LOGIN-AUDITOR", f"  Sesión: {console.username} ({console.company})"]
    for option in _OPTIONS.values():
        if _visible(console, option):
            lines.append(f"{option.key:>3}. {option.label}")
    lines.append("  m. Mostrar menú")
    lines.append("  0. Salir")
    console.write("\n".join(lines))


def _show_status(kernel: Kernel, write: Write) -> None:
    health = kernel.health()
    active = kernel.versions.active or "ninguna"
    write(f"Estado: {health['state']} ({health['status']})")
    write(f"Núcleo: {health['kernel_version']}")
    write(f"Versión activa: {active}")
    write("Servicios: " + ", ".join(health["services"]))


def _show_versions(kernel: Kernel, write: Write) -> None:
    statuses = kernel.versions.available()
    if not statuses:
        write("No hay versiones disponibles en la carpeta versions/")
        return
    for status in statuses:
        manifest = status.manifest
        flags = [
            "activa" if status.active else "",
            "compatible" if status.compatible else "no compatible",
        ]
        flag_text = ", ".join(flag for flag in flags if flag)
        write(
            f"- {manifest.version} | {manifest.channel.value} | "
            f"núcleo {manifest.compatible_kernel} | {flag_text}"
        )


def _show_detail(kernel: Kernel, read: Read, write: Write) -> None:
    version = read("Versión: ").strip()
    status = kernel.versions.status(version)
    manifest = status.manifest
    write(f"Nombre: {manifest.name}")
    write(f"Descripción: {manifest.description}")
    write(f"Canal: {manifest.channel.value}")
    write(f"Núcleo compatible: {manifest.compatible_kernel}")
    write("Dependencias: " + (", ".join(manifest.dependencies) or "ninguna"))
    write(f"Activa: {'sí' if status.active else 'no'}")
    if status.problems:
        write("Problemas: " + "; ".join(status.problems))
    else:
        write("Problemas: ninguno")


def _load_version(kernel: Kernel, read: Read, write: Write) -> None:
    version = read("Versión a cargar: ").strip()
    manifest = kernel.versions.load(version)
    write(f"Versión activa: {manifest.version}")


def _rollback(kernel: Kernel, write: Write) -> None:
    manifest = kernel.versions.rollback()
    write(f"Versión activa tras revertir: {manifest.version}")


def _show_history(kernel: Kernel, write: Write) -> None:
    history = kernel.versions.history()
    write("Historial: " + (" -> ".join(history) if history else "vacío"))


def _show_audit(console: Console) -> None:
    """Eventos recientes. Una cuenta de empresa solo ve los de su empresa."""
    company = None if console.company == PLATFORM_COMPANY else console.company
    events = console.kernel.audit.list_events(limit=20, company_id=company)
    if not events:
        console.write("Sin eventos de auditoría")
        return
    for event in events:
        payload = json.dumps(event["payload"], ensure_ascii=False, sort_keys=True)
        console.write(f"{event['created_at']} | {event['event_type']} | {payload}")


def _show_integrity(kernel: Kernel, write: Write) -> None:
    result = kernel.backups.integrity()
    write(f"Integridad de copias: {result['status']}")
    problems = result["problems"]
    if isinstance(problems, list):
        for problem in problems:
            write(f"  - {problem}")


def _show_pending(write: Write) -> None:
    write("Funciones pendientes (no implementadas todavía):")
    for feature in PENDING_FEATURES:
        write(f"  - {feature}")


def _show_modules(kernel: Kernel, write: Write) -> None:
    statuses = kernel.modules.list_modules()
    if not statuses:
        write("No hay módulos instalados en la carpeta modules/")
        return
    for status in statuses:
        manifest = status.manifest
        state = "habilitado" if status.enabled else "deshabilitado"
        requires = ", ".join(manifest.requires) or "ninguna"
        permissions = ", ".join(manifest.permissions) or "ninguno"
        write(
            f"- {manifest.module_id} {manifest.version} | {state} | requiere: {requires} "
            f"| permisos: {permissions}"
        )
        for problem in status.problems:
            write(f"    problema: {problem}")


def _enable_module(kernel: Kernel, read: Read, write: Write) -> None:
    module_id = read("Módulo a habilitar: ").strip()
    changed = kernel.modules.enable(module_id)
    if not changed:
        write(f"{module_id} ya estaba habilitado")
        return
    write("Habilitados: " + ", ".join(changed))


def _disable_module(kernel: Kernel, read: Read, write: Write) -> None:
    module_id = read("Módulo a deshabilitar: ").strip()
    kernel.modules.disable(module_id)
    write(f"Deshabilitado: {module_id}")


def _show_module_diagnostics(kernel: Kernel, write: Write) -> None:
    report = kernel.modules.diagnose()
    if not report:
        write("No hay módulos que diagnosticar")
        return
    for module_id, problems in sorted(report.items()):
        if not problems:
            write(f"- {module_id}: correcto")
            continue
        write(f"- {module_id}: {len(problems)} problema(s)")
        for problem in problems:
            write(f"    {problem}")


def _account_company(console: Console) -> str:
    """Una cuenta de empresa solo crea cuentas en su empresa. La plataforma elige la empresa."""
    if console.company != PLATFORM_COMPANY:
        return console.company
    chosen = console.read(f"Empresa (Enter para {PLATFORM_COMPANY}): ").strip()
    return chosen or PLATFORM_COMPANY


def _create_account(console: Console) -> None:
    security = console.kernel.security
    company = _account_company(console)
    security.guard.check_scope(console.token, company, CREATE_ACCOUNT_PERMISSION)
    username = console.read("Usuario nuevo: ").strip()
    password = console.read_secret("Contraseña: ")
    confirmation = console.read_secret("Repita la contraseña: ")
    if password != confirmation:
        raise ValidationError("las contraseñas no coinciden")
    roles = [
        role.strip()
        for role in console.read("Roles (separados por comas): ").split(",")
        if role.strip()
    ]
    account = security.create_account(username, password, roles, company)
    console.write(
        f"Cuenta creada: {account.username} | empresa: {account.company_id} "
        f"| roles: {', '.join(account.roles)}"
    )


def _create_company(console: Console) -> None:
    company_id = console.read("Identificador de la empresa: ").strip()
    name = console.read("Nombre de la empresa: ").strip()
    company = console.kernel.security.companies.create(company_id, name)
    console.write(f"Empresa creada: {company.company_id} | {company.name}")


def _list_companies(console: Console) -> None:
    companies = console.kernel.security.companies.list_companies()
    for company in companies:
        console.write(f"- {company.company_id} | {company.name} | creada: {company.created_at}")


def _request_grant(console: Console) -> None:
    security = console.kernel.security
    username = console.read("Usuario que recibirá el permiso: ").strip()
    permission = console.read("Permiso (subsistema:modulo:recurso:accion): ").strip()
    minutes_text = console.read("Duración en minutos (1 a 240): ").strip()
    reason = console.read("Motivo: ").strip()
    try:
        minutes = int(minutes_text)
    except ValueError as exc:
        raise ValidationError("la duración debe ser un número entero") from exc
    try:
        target = security.accounts.company_of(username)
    except ValidationError as exc:
        # Fuera de la plataforma, una cuenta inexistente y una ajena dan el mismo mensaje.
        if console.company == PLATFORM_COMPANY:
            raise
        raise AuthorizationError(SCOPE_DENIED) from exc
    security.guard.check_scope(console.token, target, permission)
    grant_id = security.grants.request(console.username, username, permission, minutes, reason)
    console.write(f"Solicitud {grant_id} registrada. Queda pendiente de aprobación.")


def _resolve_grant(console: Console) -> None:
    security = console.kernel.security
    scope = None if console.company == PLATFORM_COMPANY else console.company
    pending = [
        grant
        for grant in security.grants.list_grants(company_id=scope)
        if grant.status == "pending"
    ]
    if not pending:
        console.write("No hay solicitudes pendientes")
        return
    for grant in pending:
        console.write(
            f"- {grant.grant_id} | {grant.username} | {grant.permission} | {grant.minutes} min "
            f"| {grant.reason} | solicita: {grant.requested_by}"
        )
    try:
        grant_id = int(console.read("Número de solicitud: ").strip())
    except ValueError as exc:
        raise ValidationError("el número de solicitud no es válido") from exc
    decision = console.read("Aprobar (a) o rechazar (r): ").strip().lower()
    if decision not in ("a", "r"):
        raise ValidationError("decisión no válida: use a o r")
    record = security.grants.get(grant_id)
    target = security.accounts.company_of(record.username)
    security.guard.check_scope(console.token, target, APPROVE_PERMISSION)
    if decision == "a":
        approved = security.grants.approve(
            console.username, grant_id, security.authorizer.is_allowed
        )
        console.write(f"Permiso aprobado hasta: {approved.expires_at}")
    else:
        security.grants.reject(console.username, grant_id, security.authorizer.is_allowed)
        console.write("Solicitud rechazada")


def _reauthenticate(console: Console) -> None:
    password = console.read_secret("Contraseña: ")
    console.kernel.security.reauthenticate(console.token, password)
    console.write("Sesión reautenticada")


_OPTIONS: dict[str, Option] = {
    option.key: option
    for option in (
        Option(
            "1",
            "Estado del sistema",
            "nucleo:plataforma:estado:leer",
            False,
            lambda c: _show_status(c.kernel, c.write),
            scope=SCOPE_PLATFORM,
        ),
        Option(
            "2",
            "Versiones disponibles",
            "versiones:nucleo:version:leer",
            False,
            lambda c: _show_versions(c.kernel, c.write),
            scope=SCOPE_PLATFORM,
        ),
        Option(
            "3",
            "Detalle y compatibilidad de una versión",
            "versiones:nucleo:version:leer",
            False,
            lambda c: _show_detail(c.kernel, c.read, c.write),
            scope=SCOPE_PLATFORM,
        ),
        Option(
            "4",
            "Cargar una versión",
            "versiones:nucleo:version:ejecutar",
            True,
            lambda c: _load_version(c.kernel, c.read, c.write),
            scope=SCOPE_PLATFORM,
        ),
        Option(
            "5",
            "Revertir a la versión anterior",
            "versiones:nucleo:version:ejecutar",
            True,
            lambda c: _rollback(c.kernel, c.write),
            scope=SCOPE_PLATFORM,
        ),
        Option(
            "6",
            "Historial de activaciones",
            "versiones:nucleo:version:leer",
            False,
            lambda c: _show_history(c.kernel, c.write),
            scope=SCOPE_PLATFORM,
        ),
        Option(
            "7",
            "Eventos de auditoría recientes",
            "auditoria:nucleo:evento:leer",
            False,
            _show_audit,
            scope=SCOPE_OWN,
        ),
        Option(
            "8",
            "Verificar integridad de copias",
            "almacenamiento:nucleo:copia:leer",
            False,
            lambda c: _show_integrity(c.kernel, c.write),
            scope=SCOPE_PLATFORM,
        ),
        Option("9", "Funciones pendientes", None, False, lambda c: _show_pending(c.write)),
        Option(
            "10",
            "Módulos instalados",
            "modulos:nucleo:modulo:leer",
            False,
            lambda c: _show_modules(c.kernel, c.write),
            scope=SCOPE_PLATFORM,
        ),
        Option(
            "11",
            "Habilitar un módulo",
            "modulos:nucleo:modulo:ejecutar",
            True,
            lambda c: _enable_module(c.kernel, c.read, c.write),
            scope=SCOPE_PLATFORM,
        ),
        Option(
            "12",
            "Deshabilitar un módulo",
            "modulos:nucleo:modulo:ejecutar",
            True,
            lambda c: _disable_module(c.kernel, c.read, c.write),
            scope=SCOPE_PLATFORM,
        ),
        Option(
            "13",
            "Diagnóstico de módulos",
            "modulos:nucleo:modulo:leer",
            False,
            lambda c: _show_module_diagnostics(c.kernel, c.write),
            scope=SCOPE_PLATFORM,
        ),
        Option(
            "14",
            "Crear cuenta",
            CREATE_ACCOUNT_PERMISSION,
            True,
            _create_account,
            scope=SCOPE_OWN,
        ),
        Option("15", "Solicitar permiso temporal", None, False, _request_grant),
        Option(
            "16",
            "Aprobar o rechazar un permiso temporal",
            APPROVE_PERMISSION,
            True,
            _resolve_grant,
            scope=SCOPE_OWN,
        ),
        Option("17", "Reautenticar la sesión", None, False, _reauthenticate),
        Option(
            "18",
            "Crear empresa",
            COMPANY_ADMIN_PERMISSION,
            True,
            _create_company,
            scope=SCOPE_PLATFORM,
        ),
        Option(
            "19",
            "Listar empresas",
            COMPANY_READ_PERMISSION,
            False,
            _list_companies,
            scope=SCOPE_PLATFORM,
        ),
    )
}
