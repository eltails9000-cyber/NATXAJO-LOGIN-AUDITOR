"""Instalador del primer administrador: código de un solo uso, almacenamiento seguro y bloqueo."""

import json
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from natxajo_auditor.core.exceptions import AuthorizationError, ValidationError
from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.kernel import SERVICE_DATABASE, Kernel
from natxajo_auditor.security.installer import CODE_TTL, MAX_CODE_ATTEMPTS
from natxajo_auditor.security.passwords import verify_password
from natxajo_auditor.storage.database import Database
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER


class FakeClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, 9, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def fresh(context: RuntimeContext, clock: FakeClock) -> Iterator[Kernel]:
    """Plataforma recién creada: sin cuentas, instalación pendiente."""
    instance = Kernel(context, password_iterations=1_000, clock=clock)
    instance.start()
    yield instance
    instance.stop()


def _database(kernel: Kernel) -> Database:
    return cast(Database, kernel.services.get(SERVICE_DATABASE))


def _all_text(kernel: Kernel) -> str:
    """Todo el contenido de las tablas que podrían guardar secretos o trazas."""
    database = _database(kernel)
    rows = (
        database.fetchall("SELECT * FROM installation")
        + database.fetchall("SELECT * FROM audit_events")
        + database.fetchall("SELECT * FROM event_outbox")
    )
    return json.dumps(rows, default=str)


def test_a_fresh_platform_is_pending_and_refuses_accounts(fresh: Kernel) -> None:
    assert fresh.security.installer.is_pending()
    assert not fresh.security.has_accounts()
    with pytest.raises(ValidationError, match="instalación inicial"):
        fresh.security.create_account("usuario_uno", ADMIN_PASSWORD, ["operador"])


def test_the_code_is_stored_only_as_a_hash_and_never_in_the_audit(fresh: Kernel) -> None:
    code = fresh.security.installer.issue_code()
    stored = str(_database(fresh).fetchall("SELECT code_hash FROM installation WHERE id = 1")[0][0])
    assert code not in stored
    assert verify_password(code, stored)
    assert code not in _all_text(fresh)


def test_completing_creates_the_platform_administrator_and_locks_the_installation(
    fresh: Kernel,
) -> None:
    installer = fresh.security.installer
    account = installer.complete(installer.issue_code(), ADMIN_USER, ADMIN_PASSWORD)
    assert account.roles == ("administrador",)
    assert account.company_id == "plataforma"
    assert not installer.is_pending()
    state, code_hash, expires, completed_at = _database(fresh).fetchall(
        "SELECT state, code_hash, code_expires_at, completed_at FROM installation WHERE id = 1"
    )[0]
    assert state == "completed"
    assert code_hash is None
    assert expires is None
    assert completed_at is not None
    completed = fresh.audit.events_of_type("installation.completed")
    assert completed[-1]["payload"] == {"username": ADMIN_USER}


def test_the_code_works_only_once(fresh: Kernel) -> None:
    installer = fresh.security.installer
    code = installer.issue_code()
    installer.complete(code, ADMIN_USER, ADMIN_PASSWORD)
    with pytest.raises(ValidationError, match="ya existen cuentas"):
        installer.complete(code, "otro_admin", ADMIN_PASSWORD)
    with pytest.raises(ValidationError, match="completada"):
        installer.issue_code()
    assert [a.username for a in fresh.security.accounts.accounts()] == [ADMIN_USER]


def test_a_wrong_code_is_counted_and_the_count_survives_the_error(fresh: Kernel) -> None:
    installer = fresh.security.installer
    installer.issue_code()
    with pytest.raises(AuthorizationError, match="intentos restantes"):
        installer.complete("codigo-erroneo", ADMIN_USER, ADMIN_PASSWORD)
    attempts = _database(fresh).fetchall(
        "SELECT code_failed_attempts FROM installation WHERE id = 1"
    )[0][0]
    assert attempts == 1
    rejected = fresh.audit.events_of_type("installation.code_rejected")
    assert rejected[-1]["payload"] == {"intentos": 1}
    assert "codigo-erroneo" not in _all_text(fresh)
    assert installer.is_pending()


def test_the_attempt_limit_blocks_even_the_right_code(fresh: Kernel) -> None:
    installer = fresh.security.installer
    code = installer.issue_code()
    for _ in range(MAX_CODE_ATTEMPTS):
        with pytest.raises(AuthorizationError):
            installer.complete("codigo-erroneo", ADMIN_USER, ADMIN_PASSWORD)
    with pytest.raises(ValidationError, match="demasiados intentos"):
        installer.complete(code, ADMIN_USER, ADMIN_PASSWORD)
    assert installer.is_pending()


def test_an_expired_code_is_refused(fresh: Kernel, clock: FakeClock) -> None:
    installer = fresh.security.installer
    code = installer.issue_code()
    clock.advance(CODE_TTL + timedelta(seconds=1))
    with pytest.raises(ValidationError, match="caducado"):
        installer.complete(code, ADMIN_USER, ADMIN_PASSWORD)
    assert installer.is_pending()


def test_a_new_code_replaces_the_previous_one(fresh: Kernel) -> None:
    installer = fresh.security.installer
    first = installer.issue_code()
    second = installer.issue_code()
    with pytest.raises(AuthorizationError):
        installer.complete(first, ADMIN_USER, ADMIN_PASSWORD)
    account = installer.complete(second, ADMIN_USER, ADMIN_PASSWORD)
    assert account.username == ADMIN_USER


def test_the_completed_installation_is_locked_at_database_level(fresh: Kernel) -> None:
    installer = fresh.security.installer
    installer.complete(installer.issue_code(), ADMIN_USER, ADMIN_PASSWORD)
    connection = _database(fresh).connection
    with pytest.raises(sqlite3.Error):
        connection.execute("UPDATE installation SET state = 'pending' WHERE id = 1")
    with pytest.raises(sqlite3.Error):
        connection.execute("DELETE FROM installation WHERE id = 1")
    state = _database(fresh).fetchall("SELECT state FROM installation WHERE id = 1")[0][0]
    assert state == "completed"
