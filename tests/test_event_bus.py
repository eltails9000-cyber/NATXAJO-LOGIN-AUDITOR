"""Bus de eventos: contratos tipados, outbox transaccional, consumidores idempotentes y fallos."""

import json
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from natxajo_auditor.core.events import Event, build_event
from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.kernel import Kernel
from natxajo_auditor.storage.audit import AuditConsumer, AuditLog
from natxajo_auditor.storage.database import Database
from natxajo_auditor.storage.migrations import apply_migrations
from natxajo_auditor.storage.outbox import EventOutbox

NOW = datetime(2026, 1, 1, 9, 0, tzinfo=UTC)


def _clock() -> datetime:
    return NOW


class Recorder:
    """Consumidor de prueba. Escribe una fila por entrega y puede fallar un número de veces."""

    def __init__(self, name: str = "contador", failures: int = 0) -> None:
        self.name = name
        self.failures = failures
        self.calls = 0

    def accepts(self, event: Event) -> bool:
        return True

    def handle(self, event: Event, connection: sqlite3.Connection) -> None:
        connection.execute(
            "INSERT INTO pruebas_entregas (consumer, event_id) VALUES (?, ?)",
            (self.name, event.event_id),
        )
        self.calls += 1
        if self.failures > 0:
            self.failures -= 1
            raise RuntimeError("fallo simulado")


class FlakyFirst:
    """Falla dos veces con el primer evento de un módulo, para comprobar el orden de entrega."""

    name = "orden"

    def __init__(self, module: str) -> None:
        self.module = module
        self.remaining = 2
        self.order: list[str] = []

    def accepts(self, event: Event) -> bool:
        return True

    def handle(self, event: Event, connection: sqlite3.Connection) -> None:
        if event.payload.get("module") == self.module and self.remaining > 0:
            self.remaining -= 1
            raise RuntimeError("bloqueo temporal")
        self.order.append(str(event.payload["module"]))


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    db = Database(tmp_path / "bus.db")
    db.open()
    apply_migrations(db)
    db.execute("CREATE TABLE pruebas_entregas (consumer TEXT NOT NULL, event_id TEXT NOT NULL)")
    yield db
    db.close()


def _deliveries(database: Database, consumer: str) -> int:
    rows = database.fetchall(
        "SELECT COUNT(*) FROM pruebas_entregas WHERE consumer = ?", (consumer,)
    )
    return int(rows[0][0])


def test_undeclared_events_are_refused(database: Database) -> None:
    audit = AuditLog(database)
    with pytest.raises(ValidationError, match="no declarado"):
        audit.record("prueba", {})
    with pytest.raises(ValidationError, match="faltan claves"):
        audit.record("module.enabled", {})
    with pytest.raises(ValidationError, match="no declaradas"):
        audit.record("module.enabled", {"module": "alfa", "extra": "x"})
    # Una clave con apariencia de secreto nunca se acepta, esté o no en el catálogo.
    with pytest.raises(ValidationError, match="no declaradas"):
        audit.record("module.enabled", {"module": "alfa", "password": "x"})


def test_payload_values_must_be_scalars_or_text_lists(database: Database) -> None:
    audit = AuditLog(database)
    with pytest.raises(ValidationError, match="valor no admitido"):
        audit.record("module.enabled", {"module": {"id": "alfa"}})
    with pytest.raises(ValidationError, match="valor no admitido"):
        audit.record("grant.requested", {"grant": 1, "username": "a", "permission": ["x", 2]})


def test_company_identifiers_are_checked_when_emitted(database: Database) -> None:
    outbox = EventOutbox(database, _clock)
    with pytest.raises(ValidationError, match="identificador de empresa"):
        outbox.emit("module.enabled", {"module": "alfa"}, company_id="Empresa Mala")


def test_events_disappear_with_a_rolled_back_transaction(database: Database) -> None:
    audit = AuditLog(database)
    with pytest.raises(RuntimeError), database.transaction() as connection:
        audit.record("module.enabled", {"module": "alfa"}, connection=connection)
        raise RuntimeError("cambio revertido")
    assert audit.list_events() == []
    assert database.fetchall("SELECT COUNT(*) FROM event_outbox")[0][0] == 0


def test_committed_events_keep_their_category_and_company(database: Database) -> None:
    audit = AuditLog(database)
    audit.record("module.enabled", {"module": "alfa"})
    audit.record("account.login_failed", {"username": "nadie", "locked": False})
    audit.record("module.enabled", {"module": "beta"}, company_id="acme")
    categories = {event["event_type"]: event["category"] for event in audit.list_events(limit=10)}
    assert categories == {"module.enabled": "operativo", "account.login_failed": "seguridad"}
    assert [e["event_type"] for e in audit.list_events(category="seguridad")] == [
        "account.login_failed"
    ]
    acme = audit.list_events(company_id="acme")
    assert [(e["event_type"], e["company_id"]) for e in acme] == [("module.enabled", "acme")]


def test_consumers_handle_each_event_only_once(database: Database) -> None:
    outbox = EventOutbox(database, _clock)
    recorder = Recorder()
    outbox.register(recorder)
    outbox.emit("module.enabled", {"module": "alfa"})
    assert recorder.calls == 1
    assert outbox.dispatch_pending().delivered == 0
    assert outbox.dispatch_pending().delivered == 0
    assert recorder.calls == 1
    assert _deliveries(database, "contador") == 1
    assert outbox.pending_count() == 0


def test_the_audit_consumer_is_idempotent(database: Database) -> None:
    event = build_event(
        "module.enabled", {"module": "alfa"}, event_id="evento-fijo", occurred_at=NOW
    )
    with database.transaction() as connection:
        AuditConsumer().handle(event, connection)
        AuditConsumer().handle(event, connection)
    rows = database.fetchall("SELECT COUNT(*) FROM audit_events WHERE event_id = 'evento-fijo'")
    assert rows[0][0] == 1


def test_a_retry_does_not_repeat_consumers_that_already_succeeded(database: Database) -> None:
    healthy = Recorder(name="sano")
    flaky = Recorder(name="inestable", failures=1)
    outbox = EventOutbox(database, _clock)
    outbox.register(healthy)
    outbox.register(flaky)
    outbox.emit("module.enabled", {"module": "alfa"})
    assert healthy.calls == 1
    assert outbox.pending_count() == 1
    outbox.dispatch_pending()
    # El reintento solo vuelve a llamar al consumidor que falló.
    assert healthy.calls == 1
    assert flaky.calls == 2
    assert _deliveries(database, "sano") == 1
    assert _deliveries(database, "inestable") == 1
    assert outbox.pending_count() == 0


def test_a_failing_consumer_is_retried_then_dead_lettered(database: Database) -> None:
    outbox = EventOutbox(database, _clock, max_attempts=3)
    outbox.register(Recorder(failures=10))
    outbox.emit("module.enabled", {"module": "alfa"})
    assert outbox.pending_count() == 1
    outbox.dispatch_pending()
    report = outbox.dispatch_pending()
    assert report.dead == 1
    assert outbox.pending_count() == 0
    dead = outbox.dead_events()
    assert len(dead) == 1
    assert dead[0]["attempts"] == 3
    assert "contador: RuntimeError: fallo simulado" in str(dead[0]["last_error"])
    # El efecto parcial del consumidor fallido se revirtió con su transacción.
    assert _deliveries(database, "contador") == 0


def test_dead_events_are_delivered_after_requeue_once_the_consumer_recovers(
    database: Database,
) -> None:
    outbox = EventOutbox(database, _clock, max_attempts=3)
    outbox.register(Recorder(failures=3))
    outbox.register(AuditConsumer())
    # La auditoría comparte el bus: un segundo bus sobre la misma tabla entregaría los eventos
    # sin pasar por el consumidor de prueba.
    audit = AuditLog(database, outbox)
    outbox.emit("module.enabled", {"module": "alfa"})
    outbox.dispatch_pending()
    outbox.dispatch_pending()
    [dead] = outbox.dead_events()
    assert outbox.requeue_dead(audit=audit, actor="operador_prueba") == 1
    # La entrega ocurre al confirmarse el reencolado: no hace falta una llamada posterior.
    assert outbox.pending_count() == 0
    assert outbox.dead_events() == []
    rows = database.fetchall(
        "SELECT COUNT(*) FROM pruebas_entregas WHERE consumer = 'contador' AND event_id = ?",
        (dead["event_id"],),
    )
    assert rows[0][0] == 1
    # La constancia del reencolado queda en la auditoría, con el evento y el operador.
    requeued = audit.events_of_type("event.requeued")
    assert [event["payload"] for event in requeued] == [
        {"event_id": dead["event_id"], "name": "module.enabled"}
    ]
    assert [event["actor"] for event in requeued] == ["operador_prueba"]


def test_later_events_wait_behind_a_pending_failure(database: Database) -> None:
    flaky = FlakyFirst(module="primero")
    outbox = EventOutbox(database, _clock)
    outbox.register(flaky)
    outbox.emit("module.enabled", {"module": "primero"})
    outbox.emit("module.enabled", {"module": "segundo"})
    assert flaky.order == []
    assert outbox.pending_count() == 2
    outbox.dispatch_pending()
    assert flaky.order == ["primero", "segundo"]
    assert outbox.pending_count() == 0


def test_a_consumer_name_can_be_registered_only_once(database: Database) -> None:
    outbox = EventOutbox(database, _clock)
    outbox.register(Recorder())
    with pytest.raises(ValidationError, match="ya está registrado"):
        outbox.register(Recorder())


def test_the_kernel_records_its_start_and_stop_durably(context: RuntimeContext) -> None:
    kernel = Kernel(context, password_iterations=1_000)
    kernel.start()
    kernel.stop()
    database = Database(context.storage_dir / "natxajo.db")
    database.open()
    try:
        types = [
            row[0] for row in database.fetchall("SELECT event_type FROM audit_events ORDER BY id")
        ]
        assert types[0] == "kernel.started"
        assert types[-1] == "kernel.stopped"
        started = database.fetchall(
            "SELECT payload FROM audit_events WHERE event_type = 'kernel.started'"
        )
        assert json.loads(str(started[0][0])) == {"version": kernel.kernel_version}
    finally:
        database.close()


def test_the_kernel_delivers_events_left_pending_by_a_previous_run(context: RuntimeContext) -> None:
    first = Kernel(context, password_iterations=1_000)
    first.start()
    first.stop()
    database = Database(context.storage_dir / "natxajo.db")
    database.open()
    database.execute(
        "INSERT INTO event_outbox (event_id, name, category, company_id, actor, occurred_at, "
        "payload, status) VALUES ('pendiente01', 'module.enabled', 'operativo', NULL, NULL, "
        "'2026-01-01T09:00:00+00:00', '{\"module\": \"huerfano\"}', 'pending')"
    )
    database.close()
    restarted = Kernel(context, password_iterations=1_000)
    restarted.start()
    try:
        events = restarted.audit.events_of_type("module.enabled")
        assert [event["payload"] for event in events] == [{"module": "huerfano"}]
        assert restarted.outbox.pending_count() == 0
    finally:
        restarted.stop()
