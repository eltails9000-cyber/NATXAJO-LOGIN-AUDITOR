"""Caracterización del ciclo de vida del núcleo, anterior a la composición de la etapa 3.

Fijan el orden de arranque y de parada que el núcleo garantiza hoy. Comprueban relaciones de
precedencia y no una secuencia exacta de llamadas: la factoría de la etapa 3 puede reorganizar la
construcción mientras se conserve el orden que importa.

El rastro se obtiene envolviendo métodos existentes con monkeypatch. Las envolturas solo añaden
una entrada a la lista y llaman al original.
"""

from pathlib import Path
from typing import Any

import pytest

from natxajo_auditor.kernel import composition as composition_module
from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.kernel import Kernel
from natxajo_auditor.kernel.lifecycle import LifecycleState
from natxajo_auditor.kernel.service_container import ServiceContainer
from natxajo_auditor.storage.audit import AuditLog
from natxajo_auditor.storage.database import Database
from natxajo_auditor.storage.outbox import EventOutbox

# Servicios que el núcleo construye después de la auditoría y antes de declararse en marcha.
DOMAIN_SERVICES = (
    "configuration",
    "backups",
    "modules",
    "versions",
    "security",
    "plugins",
)
ALL_SERVICES = {"database", "outbox", "audit", *DOMAIN_SERVICES}


@pytest.fixture
def trace(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Rastro ordenado de los pasos del núcleo: registros, migraciones, copias, cierre y eventos."""
    steps: list[str] = []

    original_register = ServiceContainer.register

    def register(self: ServiceContainer, name: str, service: Any) -> None:
        steps.append(f"register:{name}")
        original_register(self, name, service)

    original_record = AuditLog.record

    def record(self: AuditLog, event_type: str, *args: Any, **kwargs: Any) -> Any:
        steps.append(f"record:{event_type}")
        return original_record(self, event_type, *args, **kwargs)

    original_dispatch = EventOutbox.dispatch_pending

    def dispatch_pending(self: EventOutbox) -> Any:
        steps.append("dispatch")
        return original_dispatch(self)

    original_snapshot = Database.snapshot

    def snapshot(self: Database, target: Path) -> None:
        steps.append("snapshot")
        original_snapshot(self, target)

    original_close = Database.close

    def close(self: Database) -> None:
        steps.append("close")
        original_close(self)

    original_migrate = composition_module.apply_migrations

    def migrate(database: Database) -> list[int]:
        steps.append("migrate")
        return original_migrate(database)

    monkeypatch.setattr(ServiceContainer, "register", register)
    monkeypatch.setattr(AuditLog, "record", record)
    monkeypatch.setattr(EventOutbox, "dispatch_pending", dispatch_pending)
    monkeypatch.setattr(Database, "snapshot", snapshot)
    monkeypatch.setattr(Database, "close", close)
    monkeypatch.setattr(composition_module, "apply_migrations", migrate)
    return steps


def _kernel(context: RuntimeContext) -> Kernel:
    return Kernel(context, password_iterations=1_000)


def test_a_new_installation_builds_the_services_in_dependency_order(
    context: RuntimeContext, trace: list[str]
) -> None:
    kernel = _kernel(context)
    kernel.start()
    try:
        assert trace.index("register:database") < trace.index("migrate")
        assert "snapshot" not in trace, "una base nueva no tiene nada que copiar"
        assert trace.index("migrate") < trace.index("register:outbox")
        assert trace.index("register:outbox") < trace.index("register:audit")
        assert trace.index("register:audit") < trace.index("dispatch")
        for name in DOMAIN_SERVICES:
            assert trace.index("dispatch") < trace.index(f"register:{name}"), name
        assert trace.index("register:security") < trace.index("register:plugins")
        last_registration = max(trace.index(f"register:{name}") for name in DOMAIN_SERVICES)
        assert last_registration < trace.index("record:kernel.started")
    finally:
        kernel.stop()


def test_an_existing_database_with_pending_migrations_is_copied_before_migrating(
    context: RuntimeContext, trace: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    first = _kernel(context)
    first.start()
    first.stop()
    trace.clear()
    monkeypatch.setattr(composition_module, "pending_versions", lambda database: [9])

    second = _kernel(context)
    second.start()
    second.stop()

    assert trace.index("snapshot") < trace.index("migrate")
    copies = list((context.storage_dir / "migraciones").glob("natxajo-previa-v9-*.db"))
    assert len(copies) == 1


def test_stopping_records_the_shutdown_before_closing_the_database(
    context: RuntimeContext, trace: list[str]
) -> None:
    kernel = _kernel(context)
    kernel.start()
    trace.clear()
    kernel.stop()

    assert trace.index("record:kernel.stopped") < trace.index("close")
    assert kernel.services.names() == []
    assert kernel.state is LifecycleState.STOPPED


def test_a_failed_start_closes_the_database_and_builds_nothing_after_the_failure(
    context: RuntimeContext, trace: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken_security(**_: object) -> None:
        raise RuntimeError("fallo simulado al construir la seguridad")

    monkeypatch.setattr(composition_module, "SecurityService", broken_security)
    kernel = _kernel(context)

    with pytest.raises(RuntimeError, match="fallo simulado"):
        kernel.start()

    assert kernel.state is LifecycleState.FAILED
    assert kernel.services.names() == []
    assert "register:plugins" not in trace
    assert "record:kernel.started" not in trace
    assert trace[-1] == "close"
    kernel.stop()
    assert kernel.state is LifecycleState.STOPPED


def test_every_start_builds_the_same_set_of_services(context: RuntimeContext) -> None:
    first = _kernel(context)
    first.start()
    names = first.services.names()
    first.stop()

    second = _kernel(context)
    second.start()
    try:
        assert second.services.names() == names
        assert set(names) == ALL_SERVICES
    finally:
        second.stop()


def test_stopping_a_kernel_that_never_started_touches_no_storage(context: RuntimeContext) -> None:
    kernel = _kernel(context)
    kernel.stop()

    assert kernel.state is LifecycleState.STOPPED
    assert not (context.storage_dir / "natxajo.db").exists()


def test_the_accessors_return_the_services_registered_under_their_names(
    context: RuntimeContext,
) -> None:
    kernel = _kernel(context)
    kernel.start()
    try:
        assert kernel.audit is kernel.services.get("audit")
        assert kernel.security is kernel.services.get("security")
        assert kernel.plugins is kernel.services.get("plugins")
        assert kernel.outbox is kernel.services.get("outbox")
    finally:
        kernel.stop()
