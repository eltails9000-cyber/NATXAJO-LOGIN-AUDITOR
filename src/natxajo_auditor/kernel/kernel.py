"""Núcleo permanente: arranque, parada y acceso a servicios.

El núcleo no depende de una versión concreta de la plataforma. Las versiones son un
servicio más, que se consulta y se carga a petición.

Al arrancar, si la base de datos ya existía y tiene migraciones pendientes, se guarda una copia
consistente en storage/migraciones/ antes de migrar. Después se entregan los eventos pendientes del
bus, antes de atender cualquier otra operación. El arranque y la parada quedan en la auditoría.
"""

from __future__ import annotations

from typing import Any, cast

from natxajo_auditor import __version__
from natxajo_auditor.configuration.manager import ConfigurationManager
from natxajo_auditor.core.utilities import Clock, utc_now, utc_stamp
from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.event_bus import EventBus
from natxajo_auditor.kernel.lifecycle import Lifecycle, LifecycleState
from natxajo_auditor.kernel.service_container import ServiceContainer
from natxajo_auditor.modules.manager import ModuleManager
from natxajo_auditor.plugins.manager import PluginManager
from natxajo_auditor.security.passwords import DEFAULT_ITERATIONS, MIN_ITERATIONS
from natxajo_auditor.security.service import SecurityService
from natxajo_auditor.storage.audit import AuditConsumer, AuditLog
from natxajo_auditor.storage.backups import BackupManager
from natxajo_auditor.storage.database import Database
from natxajo_auditor.storage.migrations import apply_migrations, pending_versions
from natxajo_auditor.storage.outbox import EventOutbox
from natxajo_auditor.versioning.manager import VersionManager
from natxajo_auditor.versioning.registry import VersionRegistry

SERVICE_CONFIGURATION = "configuration"
SERVICE_DATABASE = "database"
SERVICE_OUTBOX = "outbox"
SERVICE_AUDIT = "audit"
SERVICE_BACKUPS = "backups"
SERVICE_MODULES = "modules"
SERVICE_VERSIONS = "versions"
SERVICE_PLUGINS = "plugins"
SERVICE_SECURITY = "security"
MIGRATION_COPIES_DIR = "migraciones"


class Kernel:
    def __init__(
        self,
        context: RuntimeContext,
        kernel_version: str = __version__,
        *,
        password_iterations: int = DEFAULT_ITERATIONS,
        clock: Clock = utc_now,
    ) -> None:
        if password_iterations < MIN_ITERATIONS:
            raise ValueError(f"password_iterations debe ser al menos {MIN_ITERATIONS}")
        self.context = context
        self.kernel_version = kernel_version
        self._password_iterations = password_iterations
        self._clock = clock
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

            database_path = self.context.storage_dir / "natxajo.db"
            existed = database_path.exists()
            database = Database(database_path)
            database.open()
            self.services.register(SERVICE_DATABASE, database)
            pending = pending_versions(database)
            if existed and pending:
                # Copia previa a la migración: si la migración falla, la base anterior sigue ahí.
                copies = self.context.storage_dir / MIGRATION_COPIES_DIR
                database.snapshot(copies / f"natxajo-previa-v{pending[0]}-{utc_stamp()}.db")
            apply_migrations(database)

            outbox = EventOutbox(database, self._clock)
            outbox.register(AuditConsumer())
            self.services.register(SERVICE_OUTBOX, outbox)
            audit = AuditLog(database, outbox)
            self.services.register(SERVICE_AUDIT, audit)
            # Eventos que quedaron pendientes en una parada anterior: se entregan antes de seguir.
            outbox.dispatch_pending()

            self.services.register(
                SERVICE_CONFIGURATION, ConfigurationManager(self.context.config_dir)
            )
            self.services.register(
                SERVICE_BACKUPS, BackupManager(self.context.storage_dir / "backups")
            )
            modules = ModuleManager(self.context.modules_dir, database, audit)
            self.services.register(SERVICE_MODULES, modules)
            self.services.register(
                SERVICE_VERSIONS,
                VersionManager(
                    registry=VersionRegistry(self.context.versions_dir),
                    database=database,
                    audit=audit,
                    kernel_version=self.kernel_version,
                    module_enabled=modules.is_enabled,
                ),
            )
            security = SecurityService(
                database=database,
                audit=audit,
                clock=self._clock,
                password_iterations=self._password_iterations,
            )
            self.services.register(SERVICE_SECURITY, security)
            self.services.register(
                SERVICE_PLUGINS,
                PluginManager(
                    plugins_dir=self.context.plugins_dir,
                    database=database,
                    audit=audit,
                    kernel_version=self.kernel_version,
                    gate=security.guard,
                ),
            )
            audit.record("kernel.started", {"version": self.kernel_version})
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
        try:
            # La parada se registra antes de cerrar la base de datos.
            if self.services.has(SERVICE_AUDIT):
                self.audit.record("kernel.stopped", {})
        finally:
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
    def outbox(self) -> EventOutbox:
        return cast(EventOutbox, self.services.get(SERVICE_OUTBOX))

    @property
    def audit(self) -> AuditLog:
        return cast(AuditLog, self.services.get(SERVICE_AUDIT))

    @property
    def backups(self) -> BackupManager:
        return cast(BackupManager, self.services.get(SERVICE_BACKUPS))

    @property
    def modules(self) -> ModuleManager:
        return cast(ModuleManager, self.services.get(SERVICE_MODULES))

    @property
    def versions(self) -> VersionManager:
        return cast(VersionManager, self.services.get(SERVICE_VERSIONS))

    @property
    def plugins(self) -> PluginManager:
        return cast(PluginManager, self.services.get(SERVICE_PLUGINS))

    @property
    def security(self) -> SecurityService:
        return cast(SecurityService, self.services.get(SERVICE_SECURITY))

    def _close_services(self) -> None:
        if self.services.has(SERVICE_DATABASE):
            database = cast(Database, self.services.get(SERVICE_DATABASE))
            database.close()
        self.services.clear()
