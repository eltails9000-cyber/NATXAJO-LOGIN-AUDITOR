"""Gestor de módulos: registro, habilitación persistente, protección de dependencias y diagnóstico.

Invariante: todo módulo habilitado tiene sus dependencias habilitadas. Habilitar un módulo
habilita antes sus dependencias; deshabilitar uno se rechaza si otro módulo habilitado lo requiere.
Cada cambio de estado se registra en la auditoría, en la misma transacción.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from natxajo_auditor.core.exceptions import ModuleError, ValidationError
from natxajo_auditor.modules.dependency_graph import dependents_of, resolve_load_order
from natxajo_auditor.modules.discovery import Discovery, discover_modules
from natxajo_auditor.modules.manifest import ModuleManifest
from natxajo_auditor.storage.audit import AuditLog
from natxajo_auditor.storage.database import Database

ENABLED_EVENT = "module.enabled"
DISABLED_EVENT = "module.disabled"


@dataclass(frozen=True)
class ModuleStatus:
    manifest: ModuleManifest
    enabled: bool
    problems: tuple[str, ...]


class ModuleManager:
    def __init__(self, modules_dir: Path, database: Database, audit: AuditLog) -> None:
        self._modules_dir = modules_dir
        self._database = database
        self._audit = audit

    def discovery(self) -> Discovery:
        """Relee la carpeta en cada llamada, para ver módulos añadidos o corregidos."""
        return discover_modules(self._modules_dir)

    def enabled_ids(self) -> set[str]:
        rows = self._database.fetchall("SELECT module_id FROM module_states WHERE enabled = 1")
        return {str(row[0]) for row in rows}

    def is_enabled(self, module_id: str) -> bool:
        return module_id in self.enabled_ids()

    def list_modules(self) -> list[ModuleStatus]:
        discovery = self.discovery()
        enabled = self.enabled_ids()
        return [
            ModuleStatus(
                manifest=manifest,
                enabled=manifest.module_id in enabled,
                problems=tuple(_graph_problems(manifest.module_id, discovery.manifests)),
            )
            for manifest in sorted(discovery.manifests.values(), key=lambda item: item.module_id)
        ]

    def enable(self, module_id: str) -> list[str]:
        """Habilita un módulo y, antes, sus dependencias. Devuelve los que cambiaron de estado."""
        discovery = self.discovery()
        if module_id not in discovery.manifests:
            raise ModuleError(_not_installed_message(module_id, discovery))
        try:
            order = resolve_load_order(discovery.manifests, module_id)
        except ValidationError as exc:
            raise ModuleError(str(exc)) from exc

        enabled = self.enabled_ids()
        changed = [item for item in order if item not in enabled]
        if not changed:
            return []
        with self._database.transaction() as connection:
            for item in changed:
                connection.execute(
                    "INSERT INTO module_states (module_id, enabled) VALUES (?, 1) "
                    "ON CONFLICT(module_id) DO UPDATE SET enabled = 1, "
                    "updated_at = CURRENT_TIMESTAMP",
                    (item,),
                )
                self._audit.record(ENABLED_EVENT, {"module": item}, connection=connection)
        return changed

    def disable(self, module_id: str) -> None:
        enabled = self.enabled_ids()
        discovery = self.discovery()
        if module_id not in enabled:
            if module_id not in discovery.manifests:
                raise ModuleError(_not_installed_message(module_id, discovery))
            return
        # Los dependientes se buscan entre los módulos habilitados que aún tienen manifiesto válido.
        blocking = [
            item for item in dependents_of(discovery.manifests, module_id) if item in enabled
        ]
        if blocking:
            raise ModuleError(
                f"no se puede deshabilitar {module_id}: lo requieren {', '.join(blocking)}"
            )
        with self._database.transaction() as connection:
            connection.execute(
                "UPDATE module_states SET enabled = 0, updated_at = CURRENT_TIMESTAMP "
                "WHERE module_id = ?",
                (module_id,),
            )
            self._audit.record(DISABLED_EVENT, {"module": module_id}, connection=connection)

    def diagnose(self) -> dict[str, list[str]]:
        """Problemas por módulo. Incluye carpetas con manifiesto inválido y habilitados sin manifiesto."""
        discovery = self.discovery()
        enabled = self.enabled_ids()
        report: dict[str, list[str]] = {
            folder: [reason] for folder, reason in discovery.errors.items()
        }
        for module_id in sorted(discovery.manifests):
            problems = _graph_problems(module_id, discovery.manifests)
            manifest = discovery.manifests[module_id]
            if module_id in enabled:
                disabled_deps = [dep for dep in manifest.requires if dep not in enabled]
                if disabled_deps:
                    problems.append(
                        "habilitado con dependencias deshabilitadas: " + ", ".join(disabled_deps)
                    )
            report[module_id] = problems
        for module_id in sorted(enabled - set(discovery.manifests)):
            report[module_id] = ["habilitado pero sin manifiesto válido"]
        return report


def _graph_problems(module_id: str, manifests: dict[str, ModuleManifest]) -> list[str]:
    try:
        resolve_load_order(manifests, module_id)
    except ValidationError as exc:
        return [str(exc)]
    return []


def _not_installed_message(module_id: str, discovery: Discovery) -> str:
    reason = discovery.errors.get(module_id)
    if reason is not None:
        return f"el módulo {module_id} tiene un manifiesto inválido: {reason}"
    return f"módulo no instalado: {module_id}"
