"""Interfaz de terminal. Solo presenta datos y delega cada acción en los servicios del núcleo."""

from __future__ import annotations

import json
from collections.abc import Callable

from natxajo_auditor.core.exceptions import NatxajoError
from natxajo_auditor.kernel.kernel import Kernel

PENDING_FEATURES = (
    "Módulos y plugins (fases 5 y 6)",
    "Seguridad, RBAC y sesiones (fase 7)",
    "Motor de automatización (fase 8)",
    "Motor de auditoría defensiva (fase 9)",
    "Interfaz de escritorio (fase 10)",
    "Diagnósticos, informes y mantenimiento (fases 11 y 12)",
)

MENU = """
NATXAJO-LOGIN-AUDITOR
  1. Estado del sistema
  2. Versiones disponibles
  3. Detalle y compatibilidad de una versión
  4. Cargar una versión
  5. Revertir a la versión anterior
  6. Historial de activaciones
  7. Eventos de auditoría recientes
  8. Verificar integridad de copias
  9. Funciones pendientes
  m. Mostrar menú
  0. Salir"""

Read = Callable[[str], str]
Write = Callable[[str], None]


def run_terminal(kernel: Kernel, read: Read = input, write: Write = print) -> int:
    """Bucle principal. Devuelve 0 al salir o al cerrarse la entrada."""
    write(MENU)
    while True:
        try:
            choice = read("\nSeleccione una opción: ").strip().lower()
        except EOFError:
            write("")
            return 0
        if choice == "0":
            return 0
        try:
            _dispatch(kernel, choice, read, write)
        except NatxajoError as exc:
            write(f"Error: {exc}")


def _dispatch(kernel: Kernel, choice: str, read: Read, write: Write) -> None:
    actions: dict[str, Callable[[], None]] = {
        "1": lambda: _show_status(kernel, write),
        "2": lambda: _show_versions(kernel, write),
        "3": lambda: _show_detail(kernel, read, write),
        "4": lambda: _load_version(kernel, read, write),
        "5": lambda: _rollback(kernel, write),
        "6": lambda: _show_history(kernel, write),
        "7": lambda: _show_audit(kernel, write),
        "8": lambda: _show_integrity(kernel, write),
        "9": lambda: _show_pending(write),
        "m": lambda: write(MENU),
    }
    action = actions.get(choice)
    if action is None:
        write("Opción no válida")
        return
    action()


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
