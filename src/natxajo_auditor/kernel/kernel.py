"""Núcleo permanente: arranque, parada y acceso tipado a servicios.

El núcleo no depende de una versión concreta de la plataforma. Las versiones son un
servicio más, que se consulta y se carga a petición.

El núcleo no importa subsistemas concretos en tiempo de ejecución. Los construye
`kernel.composition.compose`, y sus accesores leen los servicios con claves tipadas. Las clases
concretas solo se nombran en las anotaciones, bajo TYPE_CHECKING.

Al arrancar, si la base de datos ya existía y tiene migraciones pendientes, se guarda una copia
consistente antes de migrar. Después se entregan los eventos pendientes del outbox, antes de
atender cualquier otra operación. El arranque y la parada quedan en la auditoría.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from natxajo_auditor import __version__
from natxajo_auditor.core.utilities import Clock, utc_now
from natxajo_auditor.kernel.composition import (
    AUDIT,
    BACKUPS,
    CONFIGURATION,
    DATABASE,
    DEFAULT_PASSWORD_ITERATIONS,
    MIN_PASSWORD_ITERATIONS,
    MODULES,
    OUTBOX,
    PLUGINS,
    SECURITY,
    SERVICE_AUDIT,
    SERVICE_BACKUPS,
    SERVICE_CONFIGURATION,
    SERVICE_DATABASE,
    SERVICE_MODULES,
    SERVICE_OUTBOX,
    SERVICE_PLUGINS,
    SERVICE_SECURITY,
    SERVICE_VERSIONS,
    VERSIONS,
    compose,
)
from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.event_bus import EventBus
from natxajo_auditor.kernel.lifecycle import Lifecycle, LifecycleState
from natxajo_auditor.kernel.service_container import ServiceContainer

if TYPE_CHECKING:
    from natxajo_auditor.configuration.manager import ConfigurationManager
    from natxajo_auditor.modules.manager import ModuleManager
    from natxajo_auditor.plugins.manager import PluginManager
    from natxajo_auditor.security.service import SecurityService
    from natxajo_auditor.storage.audit import AuditLog
    from natxajo_auditor.storage.backups import BackupManager
    from natxajo_auditor.storage.outbox import EventOutbox
    from natxajo_auditor.versioning.manager import VersionManager

__all__ = [
    "SERVICE_AUDIT",
    "SERVICE_BACKUPS",
    "SERVICE_CONFIGURATION",
    "SERVICE_DATABASE",
    "SERVICE_MODULES",
    "SERVICE_OUTBOX",
    "SERVICE_PLUGINS",
    "SERVICE_SECURITY",
    "SERVICE_VERSIONS",
    "Kernel",
]


class Kernel:
    def __init__(
        self,
        context: RuntimeContext,
        kernel_version: str = __version__,
        *,
        password_iterations: int = DEFAULT_PASSWORD_ITERATIONS,
        clock: Clock = utc_now,
    ) -> None:
        if password_iterations < MIN_PASSWORD_ITERATIONS:
            raise ValueError(f"password_iterations debe ser al menos {MIN_PASSWORD_ITERATIONS}")
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
            compose(
                self.services,
                self.context,
                kernel_version=self.kernel_version,
                clock=self._clock,
                password_iterations=self._password_iterations,
            )
            self.audit.record("kernel.started", {"version": self.kernel_version})
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
        return self.services.fetch(CONFIGURATION)

    @property
    def outbox(self) -> EventOutbox:
        return self.services.fetch(OUTBOX)

    @property
    def audit(self) -> AuditLog:
        return self.services.fetch(AUDIT)

    @property
    def backups(self) -> BackupManager:
        return self.services.fetch(BACKUPS)

    @property
    def modules(self) -> ModuleManager:
        return self.services.fetch(MODULES)

    @property
    def versions(self) -> VersionManager:
        return self.services.fetch(VERSIONS)

    @property
    def plugins(self) -> PluginManager:
        return self.services.fetch(PLUGINS)

    @property
    def security(self) -> SecurityService:
        return self.services.fetch(SECURITY)

    def _close_services(self) -> None:
        if self.services.has(SERVICE_DATABASE):
            self.services.fetch(DATABASE).close()
        self.services.clear()
