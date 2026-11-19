from pathlib import Path

from natxajo_auditor.configuration.configuration_manager import ConfigurationManager
from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.event_bus import EventBus
from natxajo_auditor.kernel.command_bus import CommandBus
from natxajo_auditor.kernel.lifecycle import LifecycleState
from natxajo_auditor.kernel.service_container import ServiceContainer
from natxajo_auditor.storage.database_manager import DatabaseManager
from natxajo_auditor.versioning.version_manager import VersionManager
from natxajo_auditor.versioning.version_registry import VersionRegistry


class Kernel:
    def __init__(self, context: RuntimeContext) -> None:
        self.context = context
        self.container = ServiceContainer()
        self.events = EventBus()
        self.commands = CommandBus()
        self.state = LifecycleState.CREATED

    def startup(self) -> None:
        self.state = LifecycleState.STARTING
        for directory in (
            self.context.data_dir,
            self.context.config_dir,
            self.context.log_dir,
            self.context.report_dir,
            self.context.storage_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)

        configuration = ConfigurationManager(self.context.config_dir / "app.json")
        database = DatabaseManager(self.context.storage_dir / "natxajo.db")
        database.initialize()
        versions = VersionManager(VersionRegistry())

        self.container.replace("configuration", configuration)
        self.container.replace("database", database)
        self.container.replace("versions", versions)
        self.events.publish("kernel.starting", {"environment": self.context.environment})
        self.state = LifecycleState.RUNNING
        self.events.publish("kernel.started", None)

    def shutdown(self) -> None:
        self.state = LifecycleState.STOPPING
        database = self.container.get("database") if self.container.has("database") else None
        if database:
            database.close()
        self.events.publish("kernel.stopped", None)
        self.state = LifecycleState.STOPPED

    def health(self) -> dict[str, object]:
        return {
            "status": "healthy" if self.state == LifecycleState.RUNNING else "degraded",
            "state": self.state.value,
            "environment": self.context.environment,
        }
