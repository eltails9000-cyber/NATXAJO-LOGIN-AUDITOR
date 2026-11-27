"""Reencolado controlado de eventos fallidos.

- Solo la plataforma puede reencolar, con confirmación y reautenticación reciente.
- El evento no se borra: pasa a pendiente, con su contador de reencolados.
- Quien ya recibió el evento no lo recibe otra vez.
- Cada reencolado queda en la auditoría con el usuario que lo hizo.
"""

from __future__ import annotations

import sqlite3
from typing import cast

import pytest

from natxajo_auditor.core.contracts import PLATFORM_COMPANY
from natxajo_auditor.core.events import Event
from natxajo_auditor.core.exceptions import AuthorizationError, ValidationError
from natxajo_auditor.kernel.kernel import SERVICE_DATABASE, Kernel
from natxajo_auditor.security.roles import OPERATOR
from natxajo_auditor.storage.database import Database
from natxajo_auditor.storage.outbox import MAX_ATTEMPTS
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER, install_administrator

PASSWORD = "contraseña-de-prueba-9"


class Sano:
    """Consumidor que siempre entrega y guarda cuántas veces recibió cada evento."""

    name = "sano_prueba"

    def __init__(self) -> None:
        self.recibidos: list[str] = []

    def accepts(self, event: Event) -> bool:
        return event.name == "module.enabled"

    def handle(self, event: Event, connection: sqlite3.Connection) -> None:
        self.recibidos.append(event.event_id)


class Bloqueado(Sano):
    """Consumidor que falla mientras `fallando` sea verdadero."""

    name = "bloqueado_prueba"

    def __init__(self) -> None:
        super().__init__()
        self.fallando = True

    def handle(self, event: Event, connection: sqlite3.Connection) -> None:
        if self.fallando:
            raise RuntimeError("sin acceso al destino")
        super().handle(event, connection)


def _dead_event(kernel: Kernel) -> tuple[Sano, Bloqueado, str]:
    """Registra dos consumidores y deja un evento fallido: el primero entrega, el segundo no."""
    sano = Sano()
    bloqueado = Bloqueado()
    kernel.outbox.register(sano)
    kernel.outbox.register(bloqueado)
    event = kernel.outbox.emit("module.enabled", {"module": "alfa"})
    # La primera entrega ocurre al confirmar el evento; las siguientes completan los intentos.
    for _ in range(MAX_ATTEMPTS - 1):
        kernel.outbox.dispatch_pending()
    assert [item["event_id"] for item in kernel.outbox.dead_events()] == [event.event_id]
    return sano, bloqueado, event.event_id


def _database(kernel: Kernel) -> Database:
    return cast(Database, kernel.services.get(SERVICE_DATABASE))


@pytest.fixture
def world(kernel: Kernel) -> Kernel:
    install_administrator(kernel)
    kernel.security.companies.create("acme", "Acme S.A.")
    kernel.security.create_account("admin_acme", PASSWORD, ["administrador"], "acme")
    kernel.security.create_account("operador_plataforma", PASSWORD, [OPERATOR], PLATFORM_COMPANY)
    return kernel


def test_a_platform_administrator_requeues_a_dead_event_with_a_trace(
    world: Kernel, platform_token: str
) -> None:
    _, bloqueado, event_id = _dead_event(world)
    bloqueado.fallando = False

    world.maintenance.requeue_event(platform_token, event_id, confirmed=True)

    # Entregado al confirmarse el reencolado, sin llamadas posteriores.
    assert bloqueado.recibidos == [event_id]
    assert world.outbox.pending_count() == 0
    assert world.outbox.dead_events() == []
    # El evento no se borra: sigue en el outbox con su contador de reencolados.
    rows = _database(world).fetchall(
        "SELECT status, requeues FROM event_outbox WHERE event_id = ?", (event_id,)
    )
    assert rows == [("delivered", 1)]
    # La constancia queda en la auditoría, con el evento y el usuario que lo reencoló.
    requeued = world.audit.events_of_type("event.requeued")
    assert [(item["payload"], item["actor"]) for item in requeued] == [
        ({"event_id": event_id, "name": "module.enabled"}, ADMIN_USER)
    ]


def test_a_requeued_event_does_not_reach_the_consumer_that_already_received_it(
    world: Kernel, platform_token: str
) -> None:
    sano, bloqueado, event_id = _dead_event(world)
    assert sano.recibidos == [event_id]
    bloqueado.fallando = False

    world.maintenance.requeue_event(platform_token, event_id, confirmed=True)

    assert sano.recibidos == [event_id]
    assert bloqueado.recibidos == [event_id]


def test_requeueing_needs_confirmation_and_leaves_the_event_dead(
    world: Kernel, platform_token: str
) -> None:
    _, bloqueado, event_id = _dead_event(world)
    bloqueado.fallando = False

    with pytest.raises(AuthorizationError, match="confirmación"):
        world.maintenance.requeue_event(platform_token, event_id, confirmed=False)

    assert [item["event_id"] for item in world.outbox.dead_events()] == [event_id]
    assert bloqueado.recibidos == []
    assert world.audit.events_of_type("event.requeued") == []


def test_requeueing_needs_a_recent_reauthentication(world: Kernel) -> None:
    _, bloqueado, event_id = _dead_event(world)
    bloqueado.fallando = False
    token = world.security.login(ADMIN_USER, ADMIN_PASSWORD)

    with pytest.raises(AuthorizationError, match="reautentique"):
        world.maintenance.requeue_event(token, event_id, confirmed=True)

    assert [item["event_id"] for item in world.outbox.dead_events()] == [event_id]


def test_only_dead_events_can_be_requeued(world: Kernel, platform_token: str) -> None:
    event = world.outbox.emit("module.enabled", {"module": "alfa"})

    with pytest.raises(ValidationError, match="solo se reencolan eventos fallidos"):
        world.maintenance.requeue_event(platform_token, event.event_id, confirmed=True)
    with pytest.raises(ValidationError, match="evento no encontrado"):
        world.maintenance.requeue_event(platform_token, "no-existe", confirmed=True)
    assert world.audit.events_of_type("event.requeued") == []


@pytest.mark.parametrize("event_id", ["", "x" * 65])
def test_the_event_identifier_is_checked_before_anything_runs(
    world: Kernel, platform_token: str, event_id: str
) -> None:
    with pytest.raises(ValidationError, match="identificador del evento"):
        world.maintenance.requeue_event(platform_token, event_id, confirmed=True)


def test_operators_and_company_administrators_cannot_requeue(world: Kernel) -> None:
    _, bloqueado, event_id = _dead_event(world)
    bloqueado.fallando = False
    for username in ("operador_plataforma", "admin_acme"):
        token = world.security.login(username, PASSWORD)
        world.security.reauthenticate(token, PASSWORD)
        with pytest.raises(AuthorizationError):
            world.maintenance.requeue_event(token, event_id, confirmed=True)
    assert [item["event_id"] for item in world.outbox.dead_events()] == [event_id]
    assert bloqueado.recibidos == []
