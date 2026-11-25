"""Composición del núcleo: el único módulo del núcleo que conoce los subsistemas concretos.

`compose` construye los servicios en el orden que el núcleo garantiza y los registra en el
contenedor en cuanto existen. Así, si una construcción falla a mitad de camino, lo ya abierto
(la base de datos, por ejemplo) sigue registrado y el núcleo puede cerrarlo.

Orden de construcción:

1. Carpetas de configuración y de datos.
2. Base de datos: se abre y se registra.
3. Si la base ya existía y tiene migraciones pendientes, copia previa consistente.
4. Migraciones.
5. Outbox con el consumidor de auditoría, y auditoría.
6. Entrega de los eventos pendientes de una parada anterior.
7. Servicios de dominio: configuración, copias, módulos, versiones, seguridad y plugins.

La seguridad se construye antes que los plugins porque el gestor de plugins necesita el guardián
de operaciones. El núcleo registra `kernel.started` solo después de llamar a `compose`.
"""

from __future__ import annotations

from natxajo_auditor.auditing.service import AuditingService
from natxajo_auditor.configuration.manager import ConfigurationManager
from natxajo_auditor.core.utilities import Clock, utc_stamp
from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.service_container import ServiceContainer, ServiceKey
from natxajo_auditor.maintenance.service import MaintenanceService
from natxajo_auditor.modules.manager import ModuleManager
from natxajo_auditor.plugins.manager import PluginManager
from natxajo_auditor.reporting.service import ReportService
from natxajo_auditor.security.passwords import DEFAULT_ITERATIONS, MIN_ITERATIONS
from natxajo_auditor.security.service import SecurityService
from natxajo_auditor.storage.audit import AuditConsumer, AuditLog
from natxajo_auditor.storage.backups import BackupManager
from natxajo_auditor.storage.database import Database
from natxajo_auditor.storage.migrations import apply_migrations, pending_versions
from natxajo_auditor.storage.outbox import EventOutbox
from natxajo_auditor.versioning.manager import VersionManager
from natxajo_auditor.versioning.registry import VersionRegistry

DEFAULT_PASSWORD_ITERATIONS: int = DEFAULT_ITERATIONS
MIN_PASSWORD_ITERATIONS: int = MIN_ITERATIONS

SERVICE_CONFIGURATION = "configuration"
SERVICE_DATABASE = "database"
SERVICE_OUTBOX = "outbox"
SERVICE_AUDIT = "audit"
SERVICE_BACKUPS = "backups"
SERVICE_MODULES = "modules"
SERVICE_VERSIONS = "versions"
SERVICE_PLUGINS = "plugins"
SERVICE_SECURITY = "security"
SERVICE_AUDITING = "auditing"
SERVICE_REPORTS = "reports"
SERVICE_MAINTENANCE = "maintenance"
MIGRATION_COPIES_DIR = "migraciones"

DATABASE: ServiceKey[Database] = ServiceKey(SERVICE_DATABASE, Database)
OUTBOX: ServiceKey[EventOutbox] = ServiceKey(SERVICE_OUTBOX, EventOutbox)
AUDIT: ServiceKey[AuditLog] = ServiceKey(SERVICE_AUDIT, AuditLog)
CONFIGURATION: ServiceKey[ConfigurationManager] = ServiceKey(
    SERVICE_CONFIGURATION, ConfigurationManager
)
BACKUPS: ServiceKey[BackupManager] = ServiceKey(SERVICE_BACKUPS, BackupManager)
MODULES: ServiceKey[ModuleManager] = ServiceKey(SERVICE_MODULES, ModuleManager)
VERSIONS: ServiceKey[VersionManager] = ServiceKey(SERVICE_VERSIONS, VersionManager)
SECURITY: ServiceKey[SecurityService] = ServiceKey(SERVICE_SECURITY, SecurityService)
PLUGINS: ServiceKey[PluginManager] = ServiceKey(SERVICE_PLUGINS, PluginManager)
AUDITING: ServiceKey[AuditingService] = ServiceKey(SERVICE_AUDITING, AuditingService)
REPORTS: ServiceKey[ReportService] = ServiceKey(SERVICE_REPORTS, ReportService)
MAINTENANCE: ServiceKey[MaintenanceService] = ServiceKey(SERVICE_MAINTENANCE, MaintenanceService)


def compose(
    services: ServiceContainer,
    context: RuntimeContext,
    *,
    kernel_version: str,
    clock: Clock,
    password_iterations: int,
) -> None:
    """Construye y registra los servicios del núcleo en el orden descrito en este módulo."""
    context.config_dir.mkdir(parents=True, exist_ok=True)
    context.storage_dir.mkdir(parents=True, exist_ok=True)

    database_path = context.storage_dir / "natxajo.db"
    existed = database_path.exists()
    database = Database(database_path)
    database.open()
    services.put(DATABASE, database)
    pending = pending_versions(database)
    if existed and pending:
        # Copia previa a la migración: si la migración falla, la base anterior sigue ahí.
        copies = context.storage_dir / MIGRATION_COPIES_DIR
        database.snapshot(copies / f"natxajo-previa-v{pending[0]}-{utc_stamp()}.db")
    apply_migrations(database)

    outbox = EventOutbox(database, clock)
    outbox.register(AuditConsumer())
    services.put(OUTBOX, outbox)
    audit = AuditLog(database, outbox)
    services.put(AUDIT, audit)
    # Eventos que quedaron pendientes en una parada anterior: se entregan antes de seguir.
    outbox.dispatch_pending()

    services.put(CONFIGURATION, ConfigurationManager(context.config_dir))
    backups = BackupManager(context.storage_dir / "backups")
    services.put(BACKUPS, backups)
    modules = ModuleManager(context.modules_dir, database, audit)
    services.put(MODULES, modules)
    services.put(
        VERSIONS,
        VersionManager(
            registry=VersionRegistry(context.versions_dir),
            database=database,
            audit=audit,
            kernel_version=kernel_version,
            module_enabled=modules.is_enabled,
        ),
    )
    security = SecurityService(
        database=database,
        audit=audit,
        clock=clock,
        password_iterations=password_iterations,
    )
    services.put(SECURITY, security)
    services.put(
        PLUGINS,
        PluginManager(
            plugins_dir=context.plugins_dir,
            database=database,
            audit=audit,
            kernel_version=kernel_version,
            gate=security.guard,
        ),
    )
    # Etapa 4: auditoría, informes y mantenimiento. Todos reciben el mismo guardián.
    services.put(
        AUDITING,
        AuditingService(
            database=database,
            audit=audit,
            gate=security.guard,
            clock=clock,
            engine_version=kernel_version,
        ),
    )
    services.put(
        REPORTS,
        ReportService(
            database=database,
            audit=audit,
            gate=security.guard,
            clock=clock,
            reports_dir=context.reports_dir,
            platform_version=kernel_version,
        ),
    )
    services.put(
        MAINTENANCE,
        MaintenanceService(
            database=database,
            outbox=outbox,
            backups=backups,
            audit=audit,
            gate=security.guard,
            clock=clock,
            managed_dirs=(context.config_dir, context.storage_dir, context.reports_dir),
        ),
    )
