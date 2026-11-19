"""Núcleo permanente: arranque, parada y acceso a servicios.

El núcleo no depende de una versión concreta de la plataforma. Las versiones son un
servicio más, que se consulta y se carga a petición.
"""

from __future__ import annotations

from typing import Any, cast

from natxajo_auditor import __version__
from natxajo_auditor.configuration.manager import ConfigurationManager
from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.event_bus import EventBus
from natxajo_auditor.kernel.lifecycle import Lifecycle, LifecycleState
from natxajo_auditor.kernel.service_container import ServiceContainer
from natxajo_auditor.storage.audit import AuditLog
from natxajo_auditor.storage.backups import BackupManager
from natxajo_auditor.storage.database import Database
from natxajo_auditor.storage.migrations import apply_migrations
from natxajo_auditor.versioning.manager import VersionManager
from natxajo_auditor.versioning.registry import VersionRegistry

SERVICE_CONFIGURATION = "configuration"
SERVICE_DATABASE = "database"
SERVICE_AUDIT = "audit"
SERVICE_BACKUPS = "backups"
SERVICE_VERSIONS = "versions"


class Kernel:
    def __init__(self, context: RuntimeContext, kernel_version: str = __version__) -> None:
        self.context = context
        self.kernel_version = kernel_version
        self.services = ServiceContainer()
        self.events = EventBus()
        self._lifecycle = Lifecycle()

    @property
    def state(self) -> LifecycleState:
        return self._lifecycle.state

    def start(self) -> None:
        """Arranca los servicios en orden. Si algo falla, el núcleo queda en estado FAILED."""
        self._lifecycle.transition(LifecycleState.STARTING)
        try:
            self.context.config_dir.mkdir(parents=True, exist_ok=True)
            self.context.storage_dir.mkdir(parents=True, exist_ok=True)

            database = Database(self.context.storage_dir / "natxajo.db")
            database.open()
            self.services.register(SERVICE_DATABASE, database)
            apply_migrations(database)

            audit = AuditLog(database)
            self.services.register(SERVICE_AUDIT, audit)
            self.services.register(
                SERVICE_CONFIGURATION, ConfigurationManager(self.context.config_dir)
            )
            self.services.register(
                SERVICE_BACKUPS, BackupManager(self.context.storage_dir / "backups")
            )
            self.services.register(
                SERVICE_VERSIONS,
                VersionManager(
                    registry=VersionRegistry(self.context.versions_dir),
                    database=database,
                    audit=audit,
                    kernel_version=self.kernel_version,
                ),
            )
        except Exception:
            self._lifecycle.transition(LifecycleState.FAILED)
            self._close_services()
            raise
        self.events.publish("kernel.started", None)
        self._lifecycle.transition(LifecycleState.RUNNING)

    def stop(self) -> None:
        """Detiene el núcleo. Es seguro llamarlo varias veces."""
        if self.state is LifecycleState.STOPPED:
            return
        if self.state is LifecycleState.CREATED:
            self._lifecycle.transition(LifecycleState.STOPPED)
            return
        self._lifecycle.transition(LifecycleState.STOPPING)
        self._close_services()
        self.events.publish("kernel.stopped", None)
        self._lifecycle.transition(LifecycleState.STOPPED)

    def health(self) -> dict[str, Any]:
        healthy = self.state is LifecycleState.RUNNING
        return {
            "status": "healthy" if healthy else "degraded",
            "state": self.state.value,
            "kernel_version": self.kernel_version,
            "services": self.services.names(),
        }

    @property
    def configuration(self) -> ConfigurationManager:
        return cast(ConfigurationManager, self.services.get(SERVICE_CONFIGURATION))

    @property
    def audit(self) -> AuditLog:
        return cast(AuditLog, self.services.get(SERVICE_AUDIT))

    @property
    def backups(self) -> BackupManager:
        return cast(BackupManager, self.services.get(SERVICE_BACKUPS))

    @property
    def versions(self) -> VersionManager:
        return cast(VersionManager, self.services.get(SERVICE_VERSIONS))

    def _close_services(self) -> None:
        if self.services.has(SERVICE_DATABASE):
            database = cast(Database, self.services.get(SERVICE_DATABASE))
            database.close()
        self.services.clear()
