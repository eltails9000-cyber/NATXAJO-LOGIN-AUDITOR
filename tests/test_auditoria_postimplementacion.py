"""Regresiones de la auditoría posterior a la etapa 2.

Cada prueba reproduce de forma determinista una carrera o un fallo de contrato. La segunda
operación se ejecuta justo en el punto en que la primera todavía no ha escrito: durante una
verificación de contraseña, entre una comprobación y su escritura, o antes de abrir una transacción.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

import natxajo_auditor.security.accounts as accounts_module
from natxajo_auditor.core.events import Event
from natxajo_auditor.core.exceptions import AuthorizationError, ValidationError
from natxajo_auditor.core.utilities import utc_now
from natxajo_auditor.kernel.kernel import SERVICE_DATABASE, Kernel
from natxajo_auditor.security.accounts import MAX_FAILED_ATTEMPTS, AccountStore
from natxajo_auditor.security.installer import Installer
from natxajo_auditor.security.sessions import MAX_CONCURRENT_SESSIONS
from natxajo_auditor.security.tenancy import SCOPE_DENIED
from natxajo_auditor.storage.audit import AuditLog
from natxajo_auditor.storage.database import Database
from natxajo_auditor.storage.migrations import apply_migrations
from natxajo_auditor.storage.outbox import EventOutbox
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER, install_administrator

PASSWORD = "contraseña-de-prueba-3"
WRONG_PASSWORD = "contraseña-incorrecta-x"
GRANT_PERMISSION = "versiones:nucleo:version:leer"
NOW = datetime(2026, 1, 1, 9, 0, tzinfo=UTC)


def _clock() -> datetime:
    return NOW


def _database(kernel: Kernel) -> Database:
    return cast(Database, kernel.services.get(SERVICE_DATABASE))


def _count(database: Database, sql: str, params: tuple[Any, ...] = ()) -> int:
    return int(database.fetchall(sql, params)[0][0])


@pytest.fixture
def plataforma(kernel: Kernel) -> Kernel:
    """Plataforma instalada, una empresa y una cuenta administradora y otra operadora de ella."""
    install_administrator(kernel)
    security = kernel.security
    security.companies.create("acme", "Acme S.A.")
    security.create_account("admin_acme", PASSWORD, ["administrador"], "acme")
    security.create_account("operador_acme", PASSWORD, ["operador"], "acme")
    return kernel


# --- Guardián: una operación sin empresa indicada es de plataforma -----------------------------


def test_an_operation_without_company_is_platform_only(plataforma: Kernel) -> None:
    guard = plataforma.security.guard
    token = plataforma.security.login("admin_acme", PASSWORD)
    executed: list[str] = []
    with pytest.raises(AuthorizationError, match=SCOPE_DENIED):
        guard.run(token, GRANT_PERMISSION, lambda: executed.append("leída"))
    assert executed == []


def test_a_company_operation_is_limited_to_its_own_company(plataforma: Kernel) -> None:
    security = plataforma.security
    security.companies.create("globex", "Globex S.A.")
    token = security.login("admin_acme", PASSWORD)
    assert (
        security.guard.run(token, GRANT_PERMISSION, lambda: "propia", company_id="acme") == "propia"
    )
    with pytest.raises(AuthorizationError, match=SCOPE_DENIED):
        security.guard.run(token, GRANT_PERMISSION, lambda: "ajena", company_id="globex")
    platform_token = security.login(ADMIN_USER, ADMIN_PASSWORD)
    assert security.guard.run(platform_token, GRANT_PERMISSION, lambda: "plataforma") == (
        "plataforma"
    )


# --- Bloqueo por fallos: el contador y el bloqueo se deciden dentro de la escritura -------------


def test_concurrent_failed_attempts_are_all_counted(
    plataforma: Kernel, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un fallo registrado mientras otro intento verifica su contraseña también cuenta."""
    accounts = plataforma.security.accounts
    original = accounts_module.verify_password
    interleaved = False

    def verify_with_interleaved_failure(password: str, stored: str) -> bool:
        nonlocal interleaved
        if not interleaved:
            interleaved = True
            with pytest.raises(AuthorizationError):
                accounts.check_password(ADMIN_USER, WRONG_PASSWORD)
        return original(password, stored)

    monkeypatch.setattr(accounts_module, "verify_password", verify_with_interleaved_failure)
    with pytest.raises(AuthorizationError):
        accounts.check_password(ADMIN_USER, "contraseña-incorrecta-y")
    monkeypatch.undo()
    failed = _count(
        _database(plataforma),
        "SELECT failed_attempts FROM accounts WHERE username = ?",
        (ADMIN_USER,),
    )
    assert failed == 2


def test_a_lock_set_while_the_correct_password_is_checked_still_applies(
    plataforma: Kernel, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Si el bloqueo se fija mientras se verifica la contraseña correcta, el acierto no lo salta."""
    accounts = plataforma.security.accounts
    original = accounts_module.verify_password
    racing = False

    def verify_while_others_fail(password: str, stored: str) -> bool:
        nonlocal racing
        if not racing:
            racing = True
            for _ in range(MAX_FAILED_ATTEMPTS):
                with pytest.raises(AuthorizationError):
                    accounts.check_password(ADMIN_USER, WRONG_PASSWORD)
        return original(password, stored)

    monkeypatch.setattr(accounts_module, "verify_password", verify_while_others_fail)
    with pytest.raises(AuthorizationError):
        accounts.check_password(ADMIN_USER, ADMIN_PASSWORD)
    monkeypatch.undo()
    locked = _count(
        _database(plataforma),
        "SELECT COUNT(*) FROM accounts WHERE username = ? AND locked_until IS NOT NULL",
        (ADMIN_USER,),
    )
    assert locked == 1


# --- Permisos temporales: una solicitud se resuelve una sola vez --------------------------------


def test_a_grant_is_decided_only_once(plataforma: Kernel) -> None:
    grants = plataforma.security.grants
    grant_id = grants.request("operador_acme", "operador_acme", GRANT_PERMISSION, 30, "revisión")
    raced = False

    def can_with_racing_approval(actor: str, permission: str) -> bool:
        nonlocal raced
        if not raced:
            raced = True
            # Otro aprobador resuelve la solicitud mientras este comprueba sus permisos.
            grants.approve(ADMIN_USER, grant_id, lambda _actor, _permission: True)
        return True

    with pytest.raises(ValidationError, match="ya no está pendiente"):
        grants.approve("admin_acme", grant_id, can_with_racing_approval)
    approvals = _count(
        _database(plataforma),
        "SELECT COUNT(*) FROM audit_events WHERE event_type = ?",
        ("grant.approved",),
    )
    assert approvals == 1
    assert grants.get(grant_id).approved_by == ADMIN_USER


# --- Sesiones: el límite se comprueba dentro de la transacción de escritura --------------------


def test_the_session_limit_is_checked_inside_the_write_transaction(
    plataforma: Kernel, monkeypatch: pytest.MonkeyPatch
) -> None:
    sessions = plataforma.security.sessions
    database = _database(plataforma)
    sessions.open(ADMIN_USER)
    sessions.open(ADMIN_USER)
    real_transaction = database.transaction
    racing = False

    def transaction_with_racing_open() -> Any:
        nonlocal racing
        if not racing:
            racing = True
            # Otro inicio de sesión se confirma antes de que empiece esta transacción.
            sessions.open(ADMIN_USER)
        return real_transaction()

    monkeypatch.setattr(database, "transaction", transaction_with_racing_open)
    with pytest.raises(AuthorizationError, match="máximo"):
        sessions.open(ADMIN_USER)
    monkeypatch.undo()
    live = _count(
        database,
        "SELECT COUNT(*) FROM sessions WHERE username = ? AND revoked_at IS NULL",
        (ADMIN_USER,),
    )
    assert live == MAX_CONCURRENT_SESSIONS


# --- Bus de eventos: una entrega confirmada por otro despachador no se repite -------------------


class Contador:
    """Consumidor de prueba: una fila por entrega."""

    name = "contador"

    def __init__(self) -> None:
        self.calls = 0

    def accepts(self, event: Event) -> bool:
        return True

    def handle(self, event: Event, connection: Any) -> None:
        self.calls += 1
        connection.execute(
            "INSERT INTO pruebas_entregas (consumer, event_id) VALUES (?, ?)",
            (self.name, event.event_id),
        )


@pytest.fixture
def bus_database(tmp_path: Path) -> Iterator[Database]:
    database = Database(tmp_path / "bus.db")
    database.open()
    apply_migrations(database)
    database.execute(
        "CREATE TABLE pruebas_entregas (consumer TEXT NOT NULL, event_id TEXT NOT NULL)"
    )
    yield database
    database.close()


def test_a_delivery_committed_by_another_dispatcher_is_not_repeated(
    bus_database: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    outbox = EventOutbox(bus_database, _clock)
    event = outbox.emit("module.enabled", {"module": "alfa"})
    # Sin consumidores el evento se marca entregado al confirmarse; se devuelve a pendiente.
    bus_database.execute(
        "UPDATE event_outbox SET status = ? WHERE event_id = ?", ("pending", event.event_id)
    )
    consumer = Contador()
    outbox.register(consumer)
    real_transaction = bus_database.transaction
    racing = False

    def transaction_with_racing_delivery() -> Any:
        nonlocal racing
        if not racing:
            racing = True
            # Otro despachador registra la entrega y la confirma antes de esta transacción.
            with real_transaction() as connection:
                connection.execute(
                    "INSERT INTO event_deliveries (event_id, consumer, delivered_at) "
                    "VALUES (?, ?, ?)",
                    (event.event_id, consumer.name, "2026-01-01T09:00:00Z"),
                )
        return real_transaction()

    monkeypatch.setattr(bus_database, "transaction", transaction_with_racing_delivery)
    outbox.dispatch_pending()
    monkeypatch.undo()
    assert consumer.calls == 0
    assert (
        _count(
            bus_database,
            "SELECT COUNT(*) FROM event_deliveries WHERE event_id = ?",
            (event.event_id,),
        )
        == 1
    )


# --- Bus de eventos: un consumidor no altera la plataforma ni el historial ----------------------


class Intruso:
    """Consumidor que ejecuta una sentencia que no le corresponde."""

    name = "intruso"

    def __init__(self, sql: str) -> None:
        self.sql = sql

    def accepts(self, event: Event) -> bool:
        return True

    def handle(self, event: Event, connection: Any) -> None:
        connection.execute(self.sql)


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE audit_events SET event_type = 'alterado'",
        "DELETE FROM audit_events",
        "DELETE FROM event_outbox",
        "UPDATE installation SET state = 'pending'",
        "DELETE FROM accounts",
        "UPDATE sessions SET revoked_at = '2026-01-01T00:00:00Z'",
        "CREATE TABLE robado (x INTEGER)",
        "PRAGMA writable_schema = ON",
    ],
)
def test_a_consumer_cannot_alter_the_platform_or_its_history(
    bus_database: Database, sql: str
) -> None:
    AuditLog(bus_database).record("module.enabled", {"module": "alfa"})
    before = _count(bus_database, "SELECT COUNT(*) FROM audit_events")
    outbox = EventOutbox(bus_database, _clock, max_attempts=1)
    outbox.register(Intruso(sql))
    outbox.emit("module.enabled", {"module": "beta"})
    dead = outbox.dead_events()
    assert len(dead) == 1
    assert "not authorized" in str(dead[0]["last_error"])
    assert _count(bus_database, "SELECT COUNT(*) FROM audit_events") == before
    assert (
        _count(
            bus_database, "SELECT COUNT(*) FROM event_deliveries WHERE consumer = ?", ("intruso",)
        )
        == 0
    )


def test_the_restriction_ends_with_the_consumer_run(bus_database: Database) -> None:
    """Tras ejecutar un consumidor, la conexión vuelve a aceptar escrituras normales."""
    outbox = EventOutbox(bus_database, _clock)
    outbox.register(Contador())
    outbox.emit("module.enabled", {"module": "alfa"})
    AuditLog(bus_database).record("module.enabled", {"module": "beta"})
    assert _count(bus_database, "SELECT COUNT(*) FROM audit_events") == 1


# --- Instalador: el código y el estado viven en la base de datos, no en el proceso ------------


def test_the_installation_code_is_single_use_across_connections(kernel: Kernel) -> None:
    installer = kernel.security.installer
    code = installer.issue_code()
    installer.complete(code, ADMIN_USER, ADMIN_PASSWORD)
    # Un segundo proceso abre su propia conexión al mismo archivo y encuentra la instalación cerrada.
    second = Database(_database(kernel).path)
    second.open()
    try:
        audit = AuditLog(second)
        accounts = AccountStore(second, audit, utc_now, 1_000)
        other = Installer(second, audit, utc_now, 1_000, accounts)
        with pytest.raises(ValidationError):
            other.issue_code()
        with pytest.raises(ValidationError):
            other.complete(code, "otro_admin", PASSWORD)
    finally:
        second.close()
    assert _count(_database(kernel), "SELECT COUNT(*) FROM accounts") == 1
