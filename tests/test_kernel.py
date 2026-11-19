from pathlib import Path

import pytest

from natxajo_auditor.core.exceptions import LifecycleError, ServiceError
from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.event_bus import EventBus
from natxajo_auditor.kernel.kernel import SERVICE_VERSIONS, Kernel
from natxajo_auditor.kernel.lifecycle import Lifecycle, LifecycleState
from natxajo_auditor.kernel.service_container import ServiceContainer


def test_kernel_starts_and_stops(context: RuntimeContext) -> None:
    kernel = Kernel(context)
    assert kernel.state is LifecycleState.CREATED
    kernel.start()
    assert kernel.state is LifecycleState.RUNNING
    assert kernel.health()["status"] == "healthy"
    assert SERVICE_VERSIONS in kernel.services.names()
    kernel.stop()
    assert kernel.state is LifecycleState.STOPPED
    assert kernel.health()["status"] == "degraded"


def test_start_twice_is_rejected(kernel: Kernel) -> None:
    with pytest.raises(LifecycleError):
        kernel.start()


def test_stop_is_idempotent(kernel: Kernel) -> None:
    kernel.stop()
    kernel.stop()
    assert kernel.state is LifecycleState.STOPPED


def test_failed_start_marks_kernel_failed(tmp_path: Path) -> None:
    # Un archivo donde debe ir el directorio de configuración impide el arranque.
    (tmp_path / "config").write_text("bloqueo", encoding="utf-8")
    kernel = Kernel(RuntimeContext(project_root=tmp_path))
    with pytest.raises(OSError):
        kernel.start()
    assert kernel.state is LifecycleState.FAILED
    assert kernel.services.names() == []
    kernel.stop()
    assert kernel.state is LifecycleState.STOPPED


def test_lifecycle_rejects_invalid_transition() -> None:
    lifecycle = Lifecycle()
    with pytest.raises(LifecycleError):
        lifecycle.transition(LifecycleState.RUNNING)


def test_service_container_rejects_duplicates_and_missing() -> None:
    container = ServiceContainer()
    container.register("a", 1)
    with pytest.raises(ServiceError):
        container.register("a", 2)
    with pytest.raises(ServiceError):
        container.get("b")
    assert container.get("a") == 1


def test_event_bus_runs_handlers_once_in_order() -> None:
    bus = EventBus()
    calls: list[tuple[str, object]] = []

    def handler(name: str, payload: object) -> None:
        calls.append((name, payload))

    bus.subscribe("evento", handler)
    bus.subscribe("evento", handler)
    bus.publish("evento", 7)
    assert calls == [("evento", 7)]
