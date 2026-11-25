"""Ciclo de vida de los plugins: instalación verificada, revisión, habilitación, cuarentena,
actualización y reversión.

Estados de un plugin instalado:
- deshabilitado: paquete verificado y copiado al almacén. No hace nada.
- habilitado: se verifica de nuevo la copia almacenada y todas sus dependencias están habilitadas.
- en cuarentena: su versión activa no puede habilitarse hasta liberarla. Ponerla en cuarentena
  deshabilita el plugin y los habilitados que dependen de él.

Reglas:
- Un paquete se verifica (firma, integridad, API y núcleo) antes de copiarse al almacén.
- Un plugin de un editor de terceros solo se habilita con una revisión aprobada de su versión.
- Un editor revocado no puede instalar, actualizar ni habilitar. Revocarlo deshabilita sus plugins
  y los que dependen de ellos.
- Actualizar solo sube de versión, con el mismo editor y con el plugin deshabilitado. La versión
  anterior se conserva en el almacén. Solo se conserva una: la siguiente actualización retira la
  que había.
- Revertir intercambia la versión activa con la anterior. Revertir otra vez devuelve la versión
  que se acaba de revertir.
- Habilitar no ejecuta el plugin. La ejecución aislada aún no existe.
- Cada cambio de estado se registra en la auditoría, en la misma transacción.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import uuid
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from natxajo_auditor.core.contracts import (
    PLUGIN_QUARANTINE_PERMISSION,
    PLUGIN_QUARANTINE_RELEASE_PERMISSION,
    PLUGIN_READ_PERMISSION,
    PLUGIN_VERSION_PERMISSION,
    OperationGate,
)
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
PUBLISHER_REGISTERED_EVENT = "plugin.publisher_registered"
QUARANTINED_EVENT = "plugin.quarantined"
QUARANTINE_RELEASED_EVENT = "plugin.quarantine_released"
UPDATED_EVENT = "plugin.updated"
ROLLED_BACK_EVENT = "plugin.rolled_back"
# Confianza global: solo la cuenta de la plataforma, con confirmación y reautenticación.
PUBLISHER_PERMISSION = "plugins:nucleo:editor:administrar"
REVIEW_PERMISSION = "plugins:nucleo:revision:administrar"
MAX_REASON = 200


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
    previous_version: str | None = None
    quarantined: bool = False


@dataclass(frozen=True)
class StoredVersion:
    """Una versión con copia en el almacén: la activa, o la anterior que permite revertir."""

    plugin_id: str
    version: str
    publisher_key_id: str
    integrity_sha256: str
    dependencies: tuple[str, ...]


class PluginManager:
    def __init__(
        self,
        plugins_dir: Path,
        database: Database,
        audit: AuditLog,
        kernel_version: str,
        gate: OperationGate,
    ) -> None:
        self._database = database
        self._audit = audit
        self._kernel_version = kernel_version
        self._gate = gate
        self._store = PluginStore(plugins_dir / "store")
        self._work_dir = plugins_dir / "work"
        # Lectura pública. Las altas y revocaciones solo se hacen con register_publisher y
        # revoke_publisher, que pasan por la puerta de operaciones.
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
            "i.integrity_sha256, i.dependencies, h.version, q.plugin_id IS NOT NULL "
            "FROM plugin_installs i "
            "JOIN plugin_publishers p ON p.key_id = i.publisher_key_id "
            "LEFT JOIN plugin_history h ON h.plugin_id = i.plugin_id "
            "LEFT JOIN plugin_quarantine q ON q.plugin_id = i.plugin_id AND q.version = i.version "
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
                    previous_version=None if row[7] is None else str(row[7]),
                    quarantined=bool(row[8]),
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

    def status(self, token: str) -> list[PluginRecord]:
        """Estado de los plugins instalados. Requiere el permiso de lectura de plugins."""
        return self._gate.run(token, PLUGIN_READ_PERMISSION, self.list_plugins)

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
        previous = self._previous(plugin_id)
        with self._database.transaction() as connection:
            connection.execute("DELETE FROM plugin_quarantine WHERE plugin_id = ?", (plugin_id,))
            connection.execute("DELETE FROM plugin_history WHERE plugin_id = ?", (plugin_id,))
            connection.execute("DELETE FROM plugin_installs WHERE plugin_id = ?", (plugin_id,))
            self._audit.record(
                UNINSTALLED_EVENT,
                {"plugin": plugin_id, "version": record.version},
                connection=connection,
            )
        self._store.remove(plugin_id, record.version)
        if previous is not None:
            self._store.remove(plugin_id, previous.version)

    # Cuarentena: la versión activa no se habilita hasta que se libere

    def quarantine(self, token: str, plugin_id: str, reason: str) -> list[str]:
        """Pone la versión activa en cuarentena. Devuelve los plugins que se deshabilitaron."""
        username = self._gate.username_for(token)
        clean = _reason(reason)

        def operation() -> list[str]:
            with self._database.transaction() as connection:
                records = {record.plugin_id: record for record in self.list_plugins()}
                if plugin_id not in records:
                    raise PluginError(f"plugin no instalado: {plugin_id}")
                record = records[plugin_id]
                if record.quarantined:
                    raise PluginError(f"{plugin_id} {record.version} ya está en cuarentena")
                affected = _enabled_closure(records, {plugin_id})
                connection.execute(
                    "INSERT INTO plugin_quarantine (plugin_id, version, reason, username) "
                    "VALUES (?, ?, ?, ?)",
                    (plugin_id, record.version, clean, username),
                )
                for item in affected:
                    connection.execute(
                        "UPDATE plugin_installs SET enabled = 0, updated_at = CURRENT_TIMESTAMP "
                        "WHERE plugin_id = ?",
                        (item,),
                    )
                    self._audit.record(
                        DISABLED_EVENT,
                        {"plugin": item, "reason": f"en cuarentena: {plugin_id}"},
                        connection=connection,
                    )
                self._audit.record(
                    QUARANTINED_EVENT,
                    {
                        "plugin": plugin_id,
                        "version": record.version,
                        "reason": clean,
                        "username": username,
                    },
                    connection=connection,
                )
                return affected

        return self._gate.run(token, PLUGIN_QUARANTINE_PERMISSION, operation)

    def release_quarantine(self, token: str, plugin_id: str, *, confirmed: bool = False) -> None:
        username = self._gate.username_for(token)

        def operation() -> None:
            with self._database.transaction() as connection:
                record = self.get(plugin_id)
                if not record.quarantined:
                    raise PluginError(f"{plugin_id} no está en cuarentena")
                cursor = connection.execute(
                    "DELETE FROM plugin_quarantine WHERE plugin_id = ? AND version = ?",
                    (plugin_id, record.version),
                )
                if cursor.rowcount != 1:
                    raise PluginError(f"la cuarentena de {plugin_id} cambió durante la operación")
                self._audit.record(
                    QUARANTINE_RELEASED_EVENT,
                    {"plugin": plugin_id, "version": record.version, "username": username},
                    connection=connection,
                )

        self._gate.run(token, PLUGIN_QUARANTINE_RELEASE_PERMISSION, operation, confirmed=confirmed)

    # Actualización y reversión: cambian la versión activa; siempre con la puerta de operaciones

    def update_package(self, token: str, source: Path, *, confirmed: bool = False) -> PluginRecord:
        """Actualiza un plugin instalado a una versión más nueva del mismo editor."""
        username = self._gate.username_for(token)

        def operation() -> PluginRecord:
            with self._staging() as work:
                target = work / "package"
                copy_package(source, target)
                try:
                    verified = verify_package(target, self.trust, self._kernel_version)
                except ValidationError as exc:
                    self._audit.record(REJECTED_EVENT, {"source": source.name, "reason": str(exc)})
                    raise
                return self._apply_update(verified, target, username)

        return self._gate.run(token, PLUGIN_VERSION_PERMISSION, operation, confirmed=confirmed)

    def rollback(self, token: str, plugin_id: str, *, confirmed: bool = False) -> PluginRecord:
        """Intercambia la versión activa con la anterior conservada. Exige el plugin deshabilitado."""
        username = self._gate.username_for(token)

        def operation() -> PluginRecord:
            current = self.get(plugin_id)
            if current.enabled:
                raise PluginError(f"deshabilite {plugin_id} antes de revertirlo")
            if current.trust_level == REVOKED:
                raise PluginError(f"el editor de {plugin_id} está revocado")
            previous = self._previous(plugin_id)
            if previous is None:
                raise PluginError(f"{plugin_id} no tiene una versión anterior a la que revertir")
            self._check_stored_copy(plugin_id, previous.version, previous.integrity_sha256)
            with self._database.transaction() as connection:
                connection.execute("DELETE FROM plugin_history WHERE plugin_id = ?", (plugin_id,))
                _insert_history(connection, _as_stored(current))
                _set_active(connection, plugin_id, current.version, previous)
                self._audit.record(
                    ROLLED_BACK_EVENT,
                    {
                        "plugin": plugin_id,
                        "from": current.version,
                        "to": previous.version,
                        "username": username,
                    },
                    connection=connection,
                )
            return self.get(plugin_id)

        return self._gate.run(token, PLUGIN_VERSION_PERMISSION, operation, confirmed=confirmed)

    # Confianza: cada operación pasa por la puerta (sesión, permiso, ámbito de plataforma,
    # confirmación y reautenticación) y su escritura y auditoría van en una sola transacción.

    def register_publisher(
        self,
        token: str,
        *,
        key_id: str,
        display_name: str,
        public_key: bytes,
        trust_level: str,
        confirmed: bool = False,
    ) -> None:
        """Da de alta un editor de confianza. Solo la cuenta de la plataforma, con permiso."""
        username = self._gate.username_for(token)

        def operation() -> None:
            with self._database.transaction() as connection:
                self.trust._insert(connection, key_id, display_name, public_key, trust_level)
                self._audit.record(
                    PUBLISHER_REGISTERED_EVENT,
                    {"publisher": key_id, "trust_level": trust_level, "username": username},
                    connection=connection,
                )

        self._gate.run(token, PUBLISHER_PERMISSION, operation, confirmed=confirmed)

    def revoke_publisher(self, token: str, key_id: str, *, confirmed: bool = False) -> list[str]:
        """Revoca un editor y deshabilita sus plugins habilitados y los que dependen de ellos."""
        username = self._gate.username_for(token)

        def operation() -> list[str]:
            with self._database.transaction() as connection:
                records = {record.plugin_id: record for record in self.list_plugins()}
                affected = _disabled_by_revocation(records, key_id)
                self.trust._revoke(connection, key_id)
                for item in affected:
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
                    {"publisher": key_id, "disabled": affected, "username": username},
                    connection=connection,
                )
                return affected

        return self._gate.run(token, PUBLISHER_PERMISSION, operation, confirmed=confirmed)

    def record_review(
        self,
        token: str,
        plugin_id: str,
        decision: str,
        findings: str,
        *,
        confirmed: bool = False,
    ) -> None:
        """Registra una decisión de revisión. El revisor es la cuenta de la sesión."""
        username = self._gate.username_for(token)

        def operation() -> None:
            with self._database.transaction() as connection:
                record = self.get(plugin_id)
                self.reviews.record(plugin_id, record.version, username, decision, findings)
                self._audit.record(
                    REVIEWED_EVENT,
                    {
                        "plugin": plugin_id,
                        "version": record.version,
                        "reviewer": username,
                        "decision": decision,
                    },
                    connection=connection,
                )

        self._gate.run(token, REVIEW_PERMISSION, operation, confirmed=confirmed)

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

    def _apply_update(self, verified: VerifiedPackage, root: Path, username: str) -> PluginRecord:
        manifest = verified.manifest
        plugin_id = manifest.plugin_id
        current = self.get(plugin_id)
        if current.enabled:
            raise PluginError(f"deshabilite {plugin_id} antes de actualizarlo")
        if current.trust_level == REVOKED:
            raise PluginError(f"el editor de {plugin_id} está revocado")
        if verified.publisher_key_id != current.publisher_key_id:
            raise PluginError(f"el paquete no es del editor instalado de {plugin_id}")
        if _semver_key(manifest.version) <= _semver_key(current.version):
            raise PluginError(
                f"{manifest.version} no es más nueva que la versión instalada {current.version}"
            )
        if self._store.path_for(plugin_id, manifest.version).exists():
            raise PluginError(
                f"la versión {manifest.version} ya está en el almacén; "
                "revierta o desinstale el plugin antes de instalarla"
            )
        previous = self._previous(plugin_id)
        incoming = StoredVersion(
            plugin_id=plugin_id,
            version=manifest.version,
            publisher_key_id=verified.publisher_key_id,
            integrity_sha256=verified.integrity_sha256,
            dependencies=tuple(manifest.dependencies),
        )
        self._store.copy_in(root, plugin_id, manifest.version)
        try:
            with self._database.transaction() as connection:
                if previous is not None:
                    connection.execute(
                        "DELETE FROM plugin_history WHERE plugin_id = ?", (plugin_id,)
                    )
                    connection.execute(
                        "DELETE FROM plugin_quarantine WHERE plugin_id = ? AND version = ?",
                        (plugin_id, previous.version),
                    )
                _insert_history(connection, _as_stored(current))
                _set_active(connection, plugin_id, current.version, incoming)
                self._audit.record(
                    UPDATED_EVENT,
                    {
                        "plugin": plugin_id,
                        "from": current.version,
                        "to": manifest.version,
                        "publisher": verified.publisher_key_id,
                        "username": username,
                    },
                    connection=connection,
                )
        except BaseException:
            self._store.remove(plugin_id, manifest.version)
            raise
        if previous is not None:
            self._store.remove(plugin_id, previous.version)
        return self.get(plugin_id)

    def _previous(self, plugin_id: str) -> StoredVersion | None:
        rows = self._database.fetchall(
            "SELECT version, publisher_key_id, integrity_sha256, dependencies "
            "FROM plugin_history WHERE plugin_id = ?",
            (plugin_id,),
        )
        if not rows:
            return None
        row = rows[0]
        return StoredVersion(
            plugin_id=plugin_id,
            version=str(row[0]),
            publisher_key_id=str(row[1]),
            integrity_sha256=str(row[2]),
            dependencies=tuple(json.loads(str(row[3]))),
        )

    def _check_enableable(self, record: PluginRecord) -> None:
        if record.trust_level == REVOKED:
            raise PluginError(f"el editor de {record.plugin_id} está revocado")
        if record.quarantined:
            raise PluginError(
                f"{record.plugin_id} {record.version} está en cuarentena; "
                "libérela antes de habilitarla"
            )
        self._check_stored_copy(record.plugin_id, record.version, record.integrity_sha256)
        if record.trust_level == THIRD_PARTY and not record.approved_review:
            raise PluginError(
                f"{record.plugin_id} {record.version} requiere una revisión aprobada "
                "antes de habilitarse"
            )

    def _check_stored_copy(self, plugin_id: str, version: str, integrity: str) -> None:
        """La copia del almacén debe verificar, corresponder a su versión y no haber cambiado."""
        root = self._store.path_for(plugin_id, version)
        if not root.is_dir():
            raise PluginError(f"falta la copia almacenada de {plugin_id} {version}")
        try:
            verified = verify_package(root, self.trust, self._kernel_version)
        except ValidationError as exc:
            raise PluginError(f"la copia almacenada de {plugin_id} no es válida: {exc}") from exc
        if (verified.manifest.plugin_id, verified.manifest.version) != (plugin_id, version):
            raise PluginError(
                f"la copia almacenada de {plugin_id} no corresponde a la versión {version}"
            )
        if verified.integrity_sha256 != integrity:
            raise PluginError(f"la copia almacenada de {plugin_id} cambió desde su instalación")

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


def _as_stored(record: PluginRecord) -> StoredVersion:
    return StoredVersion(
        plugin_id=record.plugin_id,
        version=record.version,
        publisher_key_id=record.publisher_key_id,
        integrity_sha256=record.integrity_sha256,
        dependencies=record.dependencies,
    )


def _insert_history(connection: sqlite3.Connection, version: StoredVersion) -> None:
    connection.execute(
        "INSERT INTO plugin_history (plugin_id, version, publisher_key_id, integrity_sha256, "
        "dependencies) VALUES (?, ?, ?, ?, ?)",
        (
            version.plugin_id,
            version.version,
            version.publisher_key_id,
            version.integrity_sha256,
            json.dumps(list(version.dependencies)),
        ),
    )


def _set_active(
    connection: sqlite3.Connection,
    plugin_id: str,
    expected_version: str,
    target: StoredVersion,
) -> None:
    """Cambia la versión activa solo si sigue siendo la esperada y el plugin está deshabilitado."""
    cursor = connection.execute(
        "UPDATE plugin_installs SET version = ?, publisher_key_id = ?, integrity_sha256 = ?, "
        "dependencies = ?, updated_at = CURRENT_TIMESTAMP "
        "WHERE plugin_id = ? AND version = ? AND enabled = 0",
        (
            target.version,
            target.publisher_key_id,
            target.integrity_sha256,
            json.dumps(list(target.dependencies)),
            plugin_id,
            expected_version,
        ),
    )
    if cursor.rowcount != 1:
        raise PluginError(f"{plugin_id} cambió durante la operación; repítala")


def _reason(text: str) -> str:
    clean = text.strip()
    if not 1 <= len(clean) <= MAX_REASON:
        raise ValidationError(f"el motivo debe tener entre 1 y {MAX_REASON} caracteres")
    return clean


def _semver_key(version: str) -> tuple[int, int, int]:
    """Versiones ya validadas por el manifiesto: MAJOR.MINOR.PATCH sin ceros a la izquierda."""
    major, minor, patch = (int(part) for part in version.split("."))
    return major, minor, patch


def _enabled_closure(records: dict[str, PluginRecord], seeds: Iterable[str]) -> list[str]:
    """Las semillas y, en cascada, los que dependen de ellas. Solo se devuelven los habilitados."""
    affected = set(seeds)
    grew = True
    while grew:
        grew = False
        for item, record in records.items():
            if item not in affected and any(dep in affected for dep in record.dependencies):
                affected.add(item)
                grew = True
    return sorted(item for item in affected if records[item].enabled)


def _disabled_by_revocation(records: dict[str, PluginRecord], key_id: str) -> list[str]:
    """Plugins habilitados de un editor y, en cascada, los habilitados que dependen de ellos."""
    seeds = [item for item, record in records.items() if record.publisher_key_id == key_id]
    return _enabled_closure(records, seeds)
