import importlib.util
from pathlib import Path

import pytest

from natxajo_auditor.core.exceptions import LifecycleError, ServiceError
from natxajo_auditor.kernel.context import RuntimeContext
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


def test_the_kernel_has_no_second_event_bus(context: RuntimeContext) -> None:
    # El bus en memoria del núcleo se retiró. Los eventos del núcleo se registran en el outbox
    # transaccional y en la auditoría. Esta prueba impide reintroducir el atributo o el módulo.
    kernel = Kernel(context)
    kernel.start()
    try:
        assert not hasattr(kernel, "events")
        assert importlib.util.find_spec("natxajo_auditor.kernel.event_bus") is None
        assert kernel.audit.events_of_type("kernel.started")
    finally:
        kernel.stop()
