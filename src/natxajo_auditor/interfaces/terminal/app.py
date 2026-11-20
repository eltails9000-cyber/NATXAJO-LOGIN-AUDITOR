"""Interfaz de terminal. Pide inicio de sesión y muestra solo las opciones que la cuenta puede usar.

La terminal presenta datos y pide confirmaciones. No decide permisos: cada acción pasa por el
guardián de operaciones del núcleo, que vuelve a comprobarlos.
"""

from __future__ import annotations

import getpass
import json
from collections.abc import Callable
from dataclasses import dataclass

from natxajo_auditor.core.exceptions import NatxajoError, ValidationError
from natxajo_auditor.kernel.kernel import Kernel
from natxajo_auditor.security.sessions import SessionError

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


@dataclass(frozen=True)
class Option:
    key: str
    label: str
    permission: str | None
    critical: bool
    action: Callable[[Console], None]


def run_terminal(
    kernel: Kernel,
    read: Read = input,
    write: Write = print,
    read_secret: Read = getpass.getpass,
) -> int:
    """Bucle principal. Devuelve 0 al salir o al cerrarse la entrada, 1 si no se pudo entrar."""
    console = Console(kernel=kernel, read=read, read_secret=read_secret, write=write)
    try:
        if not kernel.security.has_accounts() and not _bootstrap(console):
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


def _bootstrap(console: Console) -> bool:
    console.write("No hay cuentas en la plataforma. Cree la cuenta de administrador inicial.")
    username = console.read("Usuario administrador: ").strip()
    password = console.read_secret("Contraseña: ")
    confirmation = console.read_secret("Repita la contraseña: ")
    try:
        if password != confirmation:
            raise ValidationError("las contraseñas no coinciden")
        console.kernel.security.bootstrap_administrator(username, password)
    except NatxajoError as exc:
        console.write(f"Error: {exc}")
        return False
    console.write(f"Cuenta de administrador creada: {username}")
    return True


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
    if option.critical and not _confirm(console):
        console.write("Operación cancelada")
        return
    security.guard.run(
        console.token,
        option.permission,
        lambda: option.action(console),
        confirmed=option.critical,
    )


def _confirm(console: Console) -> bool:
    answer = console.read("¿Confirma la operación? (sí/no): ").strip().lower()
    return answer in CONFIRMATIONS


def _show_menu(console: Console) -> None:
    security = console.kernel.security
    lines = ["", "NATXAJO-LOGIN-AUDITOR", f"  Sesión: {console.username}"]
    for option in _OPTIONS.values():
        if option.permission is None or security.authorizer.is_allowed(
            console.username, option.permission
        ):
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


def _show_audit(kernel: Kernel, write: Write) -> None:
    events = kernel.audit.list_events(limit=20)
    if not events:
        write("Sin eventos de auditoría")
        return
    for event in events:
        payload = json.dumps(event["payload"], ensure_ascii=False, sort_keys=True)
        write(f"{event['created_at']} | {event['event_type']} | {payload}")


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


def _create_account(console: Console) -> None:
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
    account = console.kernel.security.create_account(username, password, roles)
    console.write(f"Cuenta creada: {account.username} | roles: {', '.join(account.roles)}")


def _request_grant(console: Console) -> None:
    username = console.read("Usuario que recibirá el permiso: ").strip()
    permission = console.read("Permiso (subsistema:modulo:recurso:accion): ").strip()
    minutes_text = console.read("Duración en minutos (1 a 240): ").strip()
    reason = console.read("Motivo: ").strip()
    try:
        minutes = int(minutes_text)
    except ValueError as exc:
        raise ValidationError("la duración debe ser un número entero") from exc
    grant_id = console.kernel.security.grants.request(
        console.username, username, permission, minutes, reason
    )
    console.write(f"Solicitud {grant_id} registrada. Queda pendiente de aprobación.")


def _resolve_grant(console: Console) -> None:
    security = console.kernel.security
    pending = [grant for grant in security.grants.list_grants() if grant.status == "pending"]
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
    if decision == "a":
        record = security.grants.approve(console.username, grant_id, security.authorizer.is_allowed)
        console.write(f"Permiso aprobado hasta: {record.expires_at}")
    elif decision == "r":
        security.grants.reject(console.username, grant_id, security.authorizer.is_allowed)
        console.write("Solicitud rechazada")
    else:
        raise ValidationError("decisión no válida: use a o r")


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
        ),
        Option(
            "2",
            "Versiones disponibles",
            "versiones:nucleo:version:leer",
            False,
            lambda c: _show_versions(c.kernel, c.write),
        ),
        Option(
            "3",
            "Detalle y compatibilidad de una versión",
            "versiones:nucleo:version:leer",
            False,
            lambda c: _show_detail(c.kernel, c.read, c.write),
        ),
        Option(
            "4",
            "Cargar una versión",
            "versiones:nucleo:version:ejecutar",
            True,
            lambda c: _load_version(c.kernel, c.read, c.write),
        ),
        Option(
            "5",
            "Revertir a la versión anterior",
            "versiones:nucleo:version:ejecutar",
            True,
            lambda c: _rollback(c.kernel, c.write),
        ),
        Option(
            "6",
            "Historial de activaciones",
            "versiones:nucleo:version:leer",
            False,
            lambda c: _show_history(c.kernel, c.write),
        ),
        Option(
            "7",
            "Eventos de auditoría recientes",
            "auditoria:nucleo:evento:leer",
            False,
            lambda c: _show_audit(c.kernel, c.write),
        ),
        Option(
            "8",
            "Verificar integridad de copias",
            "almacenamiento:nucleo:copia:leer",
            False,
            lambda c: _show_integrity(c.kernel, c.write),
        ),
        Option("9", "Funciones pendientes", None, False, lambda c: _show_pending(c.write)),
        Option(
            "10",
            "Módulos instalados",
            "modulos:nucleo:modulo:leer",
            False,
            lambda c: _show_modules(c.kernel, c.write),
        ),
        Option(
            "11",
            "Habilitar un módulo",
            "modulos:nucleo:modulo:ejecutar",
            True,
            lambda c: _enable_module(c.kernel, c.read, c.write),
        ),
        Option(
            "12",
            "Deshabilitar un módulo",
            "modulos:nucleo:modulo:ejecutar",
            True,
            lambda c: _disable_module(c.kernel, c.read, c.write),
        ),
        Option(
            "13",
            "Diagnóstico de módulos",
            "modulos:nucleo:modulo:leer",
            False,
            lambda c: _show_module_diagnostics(c.kernel, c.write),
        ),
        Option("14", "Crear cuenta", "seguridad:nucleo:cuenta:administrar", True, _create_account),
        Option("15", "Solicitar permiso temporal", None, False, _request_grant),
        Option(
            "16",
            "Aprobar o rechazar un permiso temporal",
            "seguridad:nucleo:permiso:aprobar",
            True,
            _resolve_grant,
        ),
        Option("17", "Reautenticar la sesión", None, False, _reauthenticate),
    )
}
