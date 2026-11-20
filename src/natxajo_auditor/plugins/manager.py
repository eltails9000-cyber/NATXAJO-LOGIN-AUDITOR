"""Ciclo de vida de los plugins: instalación verificada, revisión, habilitación y desinstalación.

Estados de un plugin instalado:
- deshabilitado: paquete verificado y copiado al almacén. No hace nada.
- habilitado: se verifica de nuevo la copia almacenada y todas sus dependencias están habilitadas.

Reglas:
- Un paquete se verifica (firma, integridad, API y núcleo) antes de copiarse al almacén.
- Un plugin de un editor de terceros solo se habilita con una revisión aprobada de su versión.
- Un editor revocado no puede instalar ni habilitar. Revocarlo deshabilita sus plugins y los que
  dependen de ellos.
- Habilitar no ejecuta el plugin. La ejecución aislada aún no existe.
- Cada cambio de estado se registra en la auditoría, en la misma transacción.
"""

from __future__ import annotations

import json
import shutil
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from natxajo_auditor.core.exceptions import PluginError, ValidationError
from natxajo_auditor.core.graph import dependents_of, resolve_load_order
from natxajo_auditor.plugins.package import copy_package
from natxajo_auditor.plugins.repository import CatalogEntry, LocalRepository
from natxajo_auditor.plugins.review import InventoryItem, ReviewLog, inventory
from natxajo_auditor.plugins.store import PluginStore
from natxajo_auditor.plugins.trust import REVOKED, THIRD_PARTY, TrustStore
from natxajo_auditor.plugins.verifier import VerifiedPackage, verify_package
from natxajo_auditor.storage.audit import AuditLog
from natxajo_auditor.storage.database import Database

INSTALLED_EVENT = "plugin.installed"
REJECTED_EVENT = "plugin.rejected"
ENABLED_EVENT = "plugin.enabled"
DISABLED_EVENT = "plugin.disabled"
UNINSTALLED_EVENT = "plugin.uninstalled"
REVIEWED_EVENT = "plugin.reviewed"
REVOKED_EVENT = "plugin.publisher_revoked"


@dataclass(frozen=True)
class PluginRecord:
    plugin_id: str
    version: str
    enabled: bool
    publisher_key_id: str
    trust_level: str
    integrity_sha256: str
    dependencies: tuple[str, ...]
    approved_review: bool


class PluginManager:
    def __init__(
        self,
        plugins_dir: Path,
        database: Database,
        audit: AuditLog,
        kernel_version: str,
    ) -> None:
        self._database = database
        self._audit = audit
        self._kernel_version = kernel_version
        self._store = PluginStore(plugins_dir / "store")
        self._work_dir = plugins_dir / "work"
        self.trust = TrustStore(database)
        self.reviews = ReviewLog(database)

    # Instalación

    def install_package(self, source: Path) -> PluginRecord:
        """Copia un paquete a un área de trabajo, lo verifica y lo guarda si es válido."""
        with self._staging() as work:
            target = work / "package"
            try:
                copy_package(source, target)
                return self._install_verified(target, expected=None)
            except ValidationError as exc:
                self._audit.record(REJECTED_EVENT, {"source": source.name, "reason": str(exc)})
                raise

    def install_from_repository(
        self, repository: LocalRepository, plugin_id: str, version: str
    ) -> PluginRecord:
        entry = repository.find(plugin_id, version)
        with self._staging() as work:
            try:
                fetched = repository.fetch(entry, work)
                return self._install_verified(fetched, expected=entry)
            except ValidationError as exc:
                self._audit.record(
                    REJECTED_EVENT, {"source": f"{plugin_id} {version}", "reason": str(exc)}
                )
                raise

    def inspect_package(self, source: Path) -> tuple[VerifiedPackage, list[InventoryItem]]:
        """Verifica un paquete y lista su contenido sin instalarlo."""
        with self._staging() as work:
            target = work / "package"
            copy_package(source, target)
            verified = verify_package(target, self.trust, self._kernel_version)
            return verified, inventory(target)

    # Consulta

    def list_plugins(self) -> list[PluginRecord]:
        rows = self._database.fetchall(
            "SELECT i.plugin_id, i.version, i.enabled, i.publisher_key_id, p.trust_level, "
            "i.integrity_sha256, i.dependencies "
            "FROM plugin_installs i JOIN plugin_publishers p ON p.key_id = i.publisher_key_id "
            "ORDER BY i.plugin_id"
        )
        records: list[PluginRecord] = []
        for row in rows:
            plugin_id, version = str(row[0]), str(row[1])
            records.append(
                PluginRecord(
                    plugin_id=plugin_id,
                    version=version,
                    enabled=bool(row[2]),
                    publisher_key_id=str(row[3]),
                    trust_level=str(row[4]),
                    integrity_sha256=str(row[5]),
                    dependencies=tuple(json.loads(str(row[6]))),
                    approved_review=self.reviews.is_approved(plugin_id, version),
                )
            )
        return records

    def get(self, plugin_id: str) -> PluginRecord:
        for record in self.list_plugins():
            if record.plugin_id == plugin_id:
                return record
        raise PluginError(f"plugin no instalado: {plugin_id}")

    def enabled_ids(self) -> set[str]:
        return {record.plugin_id for record in self.list_plugins() if record.enabled}

    # Habilitación

    def enable(self, plugin_id: str) -> list[str]:
        """Habilita un plugin y, antes, sus dependencias. Devuelve los que cambiaron de estado."""
        records = {record.plugin_id: record for record in self.list_plugins()}
        if plugin_id not in records:
            raise PluginError(f"plugin no instalado: {plugin_id}")
        try:
            order = resolve_load_order(
                lambda item: records[item].dependencies if item in records else None,
                plugin_id,
                noun="plugin",
            )
        except ValidationError as exc:
            raise PluginError(str(exc)) from exc

        changed = [item for item in order if not records[item].enabled]
        for item in changed:
            self._check_enableable(records[item])
        if not changed:
            return []
        with self._database.transaction() as connection:
            for item in changed:
                connection.execute(
                    "UPDATE plugin_installs SET enabled = 1, updated_at = CURRENT_TIMESTAMP "
                    "WHERE plugin_id = ?",
                    (item,),
                )
                self._audit.record(
                    ENABLED_EVENT,
                    {"plugin": item, "version": records[item].version},
                    connection=connection,
                )
        return changed

    def disable(self, plugin_id: str) -> None:
        records = {record.plugin_id: record for record in self.list_plugins()}
        if plugin_id not in records:
            raise PluginError(f"plugin no instalado: {plugin_id}")
        if not records[plugin_id].enabled:
            return
        enabled_requirements = {
            item: record.dependencies for item, record in records.items() if record.enabled
        }
        blocking = dependents_of(enabled_requirements, plugin_id)
        if blocking:
            raise PluginError(
                f"no se puede deshabilitar {plugin_id}: lo requieren {', '.join(blocking)}"
            )
        with self._database.transaction() as connection:
            connection.execute(
                "UPDATE plugin_installs SET enabled = 0, updated_at = CURRENT_TIMESTAMP "
                "WHERE plugin_id = ?",
                (plugin_id,),
            )
            self._audit.record(DISABLED_EVENT, {"plugin": plugin_id}, connection=connection)

    # Desinstalación, revisión y revocación

    def uninstall(self, plugin_id: str) -> None:
        record = self.get(plugin_id)
        if record.enabled:
            raise PluginError(f"deshabilite {plugin_id} antes de desinstalarlo")
        dependents = [
            other.plugin_id for other in self.list_plugins() if plugin_id in other.dependencies
        ]
        if dependents:
            raise PluginError(
                f"no se puede desinstalar {plugin_id}: lo requieren {', '.join(dependents)}"
            )
        with self._database.transaction() as connection:
            connection.execute("DELETE FROM plugin_installs WHERE plugin_id = ?", (plugin_id,))
            self._audit.record(
                UNINSTALLED_EVENT,
                {"plugin": plugin_id, "version": record.version},
                connection=connection,
            )
        self._store.remove(plugin_id, record.version)

    def record_review(self, plugin_id: str, reviewer: str, decision: str, findings: str) -> None:
        record = self.get(plugin_id)
        self.reviews.record(plugin_id, record.version, reviewer, decision, findings)
        self._audit.record(
            REVIEWED_EVENT,
            {
                "plugin": plugin_id,
                "version": record.version,
                "reviewer": reviewer,
                "decision": decision,
            },
        )

    def revoke_publisher(self, key_id: str) -> list[str]:
        """Revoca un editor y deshabilita sus plugins habilitados y los que dependen de ellos."""
        self.trust.get_publisher(key_id)
        records = {record.plugin_id: record for record in self.list_plugins()}
        affected = {
            item
            for item, record in records.items()
            if record.enabled and record.publisher_key_id == key_id
        }
        grew = True
        while grew:
            grew = False
            for item, record in records.items():
                if (
                    record.enabled
                    and item not in affected
                    and any(dependency in affected for dependency in record.dependencies)
                ):
                    affected.add(item)
                    grew = True
        with self._database.transaction() as connection:
            self.trust.revoke(key_id)
            for item in sorted(affected):
                connection.execute(
                    "UPDATE plugin_installs SET enabled = 0, updated_at = CURRENT_TIMESTAMP "
                    "WHERE plugin_id = ?",
                    (item,),
                )
                self._audit.record(
                    DISABLED_EVENT,
                    {"plugin": item, "reason": f"editor revocado: {key_id}"},
                    connection=connection,
                )
            self._audit.record(
                REVOKED_EVENT,
                {"publisher": key_id, "disabled": sorted(affected)},
                connection=connection,
            )
        return sorted(affected)

    # Internos

    def _install_verified(self, root: Path, expected: CatalogEntry | None) -> PluginRecord:
        verified = verify_package(root, self.trust, self._kernel_version)
        manifest = verified.manifest
        if expected is not None and (manifest.plugin_id, manifest.version) != (
            expected.plugin_id,
            expected.version,
        ):
            raise ValidationError("el paquete no corresponde a la entrada del catálogo")
        if self._is_installed(manifest.plugin_id):
            raise PluginError(
                f"ya hay una versión instalada de {manifest.plugin_id}; "
                "desinstálela antes de instalar otra"
            )
        self._store.copy_in(root, manifest.plugin_id, manifest.version)
        try:
            with self._database.transaction() as connection:
                connection.execute(
                    "INSERT INTO plugin_installs (plugin_id, version, enabled, publisher_key_id, "
                    "integrity_sha256, dependencies) VALUES (?, ?, 0, ?, ?, ?)",
                    (
                        manifest.plugin_id,
                        manifest.version,
                        verified.publisher_key_id,
                        verified.integrity_sha256,
                        json.dumps(list(manifest.dependencies)),
                    ),
                )
                self._audit.record(
                    INSTALLED_EVENT,
                    {
                        "plugin": manifest.plugin_id,
                        "version": manifest.version,
                        "publisher": verified.publisher_key_id,
                        "trust_level": verified.trust_level,
                    },
                    connection=connection,
                )
        except BaseException:
            self._store.remove(manifest.plugin_id, manifest.version)
            raise
        return self.get(manifest.plugin_id)

    def _check_enableable(self, record: PluginRecord) -> None:
        if record.trust_level == REVOKED:
            raise PluginError(f"el editor de {record.plugin_id} está revocado")
        root = self._store.path_for(record.plugin_id, record.version)
        if not root.is_dir():
            raise PluginError(f"falta la copia almacenada de {record.plugin_id} {record.version}")
        try:
            verified = verify_package(root, self.trust, self._kernel_version)
        except ValidationError as exc:
            raise PluginError(
                f"la copia almacenada de {record.plugin_id} no es válida: {exc}"
            ) from exc
        if verified.integrity_sha256 != record.integrity_sha256:
            raise PluginError(
                f"la copia almacenada de {record.plugin_id} cambió desde su instalación"
            )
        if record.trust_level == THIRD_PARTY and not record.approved_review:
            raise PluginError(
                f"{record.plugin_id} {record.version} requiere una revisión aprobada "
                "antes de habilitarse"
            )

    def _is_installed(self, plugin_id: str) -> bool:
        rows = self._database.fetchall(
            "SELECT 1 FROM plugin_installs WHERE plugin_id = ?", (plugin_id,)
        )
        return bool(rows)

    @contextmanager
    def _staging(self) -> Iterator[Path]:
        """Área de trabajo temporal, eliminada al terminar aunque haya fallos."""
        self._work_dir.mkdir(parents=True, exist_ok=True)
        work = self._work_dir / uuid.uuid4().hex
        work.mkdir()
        try:
            yield work
        finally:
            shutil.rmtree(work, ignore_errors=True)
