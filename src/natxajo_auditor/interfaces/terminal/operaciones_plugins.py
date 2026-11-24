"""Acciones de terminal para plugins: estado, cuarentena, actualización y reversión.

Cada acción pide los datos, llama al gestor de plugins y muestra el resultado. El gestor aplica la
puerta de operaciones (sesión, permiso, confirmación y reautenticación) y registra la operación, así
que estas acciones no la repiten.

Las opciones de cambio son `guarded`: la terminal no pide confirmación por ellas. Por eso las
acciones críticas piden la confirmación aquí, antes de llamar al servicio.
"""

from __future__ import annotations

from pathlib import Path

from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.interfaces.terminal.console import Console, confirm


def _plugin_id(console: Console) -> str:
    value = console.read("Identificador del plugin: ").strip()
    if not value:
        raise ValidationError("indique el identificador del plugin")
    return value


def _folder(console: Console) -> Path:
    # Las rutas copiadas como «Copiar como ruta» en Windows llegan entre comillas.
    text = console.read("Carpeta del paquete del plugin: ").strip().strip('"').strip()
    if not text:
        raise ValidationError("indique la carpeta del paquete")
    return Path(text)


def _names(items: list[str]) -> str:
    return ", ".join(items) if items else "ninguno"


def plugin_status(console: Console) -> None:
    records = console.kernel.plugins.status(console.token)
    if not records:
        console.write("No hay plugins instalados")
        return
    for record in records:
        state = "habilitado" if record.enabled else "deshabilitado"
        details = [f"editor {record.publisher_key_id} ({record.trust_level})"]
        if record.quarantined:
            details.append("en cuarentena")
        if record.previous_version is not None:
            details.append(f"versión anterior {record.previous_version}")
        console.write(f"- {record.plugin_id} {record.version} | {state} | {' | '.join(details)}")


def plugin_quarantine(console: Console) -> None:
    plugin_id = _plugin_id(console)
    reason = console.read("Motivo (1 a 200 caracteres): ").strip()
    disabled = console.kernel.plugins.quarantine(console.token, plugin_id, reason)
    console.write(f"{plugin_id} queda en cuarentena. Deshabilitados: {_names(disabled)}")


def plugin_release(console: Console) -> None:
    plugin_id = _plugin_id(console)
    if not confirm(console):
        console.write("Operación cancelada")
        return
    console.kernel.plugins.release_quarantine(console.token, plugin_id, confirmed=True)
    console.write(f"Cuarentena liberada: {plugin_id}. Puede volver a habilitarse.")


def plugin_update(console: Console) -> None:
    folder = _folder(console)
    if not confirm(console):
        console.write("Operación cancelada")
        return
    record = console.kernel.plugins.update_package(console.token, folder, confirmed=True)
    console.write(
        f"{record.plugin_id} actualizado a {record.version}. "
        f"Versión anterior conservada: {record.previous_version}. Queda deshabilitado."
    )


def plugin_rollback(console: Console) -> None:
    plugin_id = _plugin_id(console)
    if not confirm(console):
        console.write("Operación cancelada")
        return
    record = console.kernel.plugins.rollback(console.token, plugin_id, confirmed=True)
    console.write(
        f"{record.plugin_id} vuelve a la versión {record.version}. "
        f"Versión anterior conservada: {record.previous_version}. Queda deshabilitado."
    )
