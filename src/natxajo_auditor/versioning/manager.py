"""Gestor de versiones: consulta, validación, carga manual, cambio y reversión.

Solo una versión está activa a la vez. La versión activa se guarda en la base de datos y cada
activación se registra en la auditoría dentro de la misma transacción.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from natxajo_auditor.core.exceptions import VersionError
from natxajo_auditor.storage.audit import AuditLog
from natxajo_auditor.storage.database import Database
from natxajo_auditor.versioning.manifest import VersionManifest
from natxajo_auditor.versioning.registry import VersionRegistry

ACTIVE_KEY = "active_version"
ACTIVATION_EVENT = "version.activated"


@dataclass(frozen=True)
class VersionStatus:
    manifest: VersionManifest
    active: bool
    compatible: bool
    problems: tuple[str, ...]


class VersionManager:
    def __init__(
        self,
        registry: VersionRegistry,
        database: Database,
        audit: AuditLog,
        kernel_version: str,
        module_enabled: Callable[[str], bool] | None = None,
    ) -> None:
        self._registry = registry
        self._database = database
        self._audit = audit
        self._kernel_version = kernel_version
        # Sin sistema de módulos, ninguna dependencia está disponible.
        self._module_enabled: Callable[[str], bool] = module_enabled or (lambda _: False)

    @property
    def active(self) -> str | None:
        rows = self._database.fetchall(
            "SELECT value FROM platform_metadata WHERE key = ?", (ACTIVE_KEY,)
        )
        return str(rows[0][0]) if rows else None

    def available(self) -> list[VersionStatus]:
        return [self.status(manifest.version) for manifest in self._registry.available()]

    def status(self, version: str) -> VersionStatus:
        manifest = self._registry.get(version)
        compatible = manifest.is_compatible_with(self._kernel_version)
        return VersionStatus(
            manifest=manifest,
            active=self.active == version,
            compatible=compatible,
            problems=tuple(self._problems(manifest)),
        )

    def load(self, version: str) -> VersionManifest:
        """Valida y activa una versión. Si ya estaba activa, no hace nada."""
        status = self.status(version)
        if status.problems:
            raise VersionError(f"No se puede cargar {version}: " + "; ".join(status.problems))
        previous = self.active
        if previous != version:
            self._activate(version, previous, reason="carga")
        return status.manifest

    def rollback(self) -> VersionManifest:
        """Vuelve a la versión activa anterior según el historial de activaciones."""
        current = self.active
        if current is None:
            raise VersionError("No hay ninguna versión activa")
        target = self._previous_version(current)
        if target is None:
            raise VersionError("No existe una versión anterior para revertir")
        status = self.status(target)
        if status.problems:
            raise VersionError(f"No se puede revertir a {target}: " + "; ".join(status.problems))
        self._activate(target, current, reason="rollback")
        return status.manifest

    def history(self) -> list[str]:
        """Versiones activadas en orden cronológico (puede repetir versiones)."""
        return [
            str(event["payload"]["to"]) for event in self._audit.events_of_type(ACTIVATION_EVENT)
        ]

    def _previous_version(self, current: str) -> str | None:
        sequence = self.history()
        if current not in sequence:
            return None
        last_index = len(sequence) - 1 - sequence[::-1].index(current)
        for version in reversed(sequence[:last_index]):
            if version != current:
                return version
        return None

    def _problems(self, manifest: VersionManifest) -> list[str]:
        problems: list[str] = []
        if not manifest.is_compatible_with(self._kernel_version):
            problems.append(
                f"requiere núcleo {manifest.compatible_kernel}; "
                f"el núcleo actual es {self._kernel_version}"
            )
        missing = [dep for dep in manifest.dependencies if not self._module_enabled(dep)]
        if missing:
            problems.append("módulos requeridos no habilitados: " + ", ".join(missing))
        return problems

    def _activate(self, version: str, previous: str | None, reason: str) -> None:
        with self._database.transaction() as connection:
            connection.execute(
                "INSERT INTO platform_metadata (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
                "updated_at = CURRENT_TIMESTAMP",
                (ACTIVE_KEY, version),
            )
            self._audit.record(
                ACTIVATION_EVENT,
                {"from": previous, "to": version, "reason": reason},
                connection=connection,
            )
