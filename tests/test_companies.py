"""Aislamiento entre empresas: ámbito de cada operación, cuentas, permisos temporales, auditoría,
permisos administrativos y la terminal.
"""

import sqlite3
from collections.abc import Callable, Iterable
from typing import cast

import pytest

from natxajo_auditor.core.contracts import PLATFORM_COMPANY, SCOPE_DENIED
from natxajo_auditor.core.exceptions import AuthorizationError, ValidationError
from natxajo_auditor.interfaces.terminal.app import run_terminal
from natxajo_auditor.kernel.kernel import SERVICE_DATABASE, Kernel
from natxajo_auditor.security.guard import CRITICAL_PERMISSIONS
from natxajo_auditor.storage.database import Database
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER, install_administrator

PASSWORD = "contraseña-de-prueba-2"
COMPANY_ADMIN_PERMISSION = "seguridad:nucleo:empresa:administrar"
CREATE_ACCOUNT_PERMISSION = "seguridad:nucleo:cuenta:administrar"
GRANT_PERMISSION = "versiones:nucleo:version:leer"


def _scripted(answers: Iterable[str]) -> Callable[[str], str]:
    iterator = iter(answers)

    def read(prompt: str) -> str:
        try:
            return next(iterator)
        except StopIteration:
            raise EOFError from None

    return read


def _database(kernel: Kernel) -> Database:
    return cast(Database, kernel.services.get(SERVICE_DATABASE))


@pytest.fixture
def world(kernel: Kernel) -> Kernel:
    """Plataforma instalada, dos empresas y dos cuentas administradoras y una operadora."""
    install_administrator(kernel)
    security = kernel.security
    security.companies.create("acme", "Acme S.A.")
    security.companies.create("globex", "Globex S.A.")
    security.create_account("admin_acme", PASSWORD, ["administrador"], "acme")
    security.create_account("operador_acme", PASSWORD, ["operador"], "acme")
    security.create_account("admin_globex", PASSWORD, ["administrador"], "globex")
    return kernel


def _token(kernel: Kernel, username: str) -> str:
    return kernel.security.login(username, PASSWORD)


def test_company_identifiers_and_names_are_validated(world: Kernel) -> None:
    companies = world.security.companies
    assert {c.company_id for c in companies.list_companies()} == {
        "plataforma",
        "acme",
        "globex",
    }
    for bad_id in ("Acme", "a", "plataforma", "acme"):
        with pytest.raises(ValidationError):
            companies.create(bad_id, "Nombre")
    with pytest.raises(ValidationError):
        companies.create("nueva", "   ")
    with pytest.raises(ValidationError):
        companies.create("nueva", "x" * 121)


def test_an_account_keeps_its_company_and_no_one_can_change_it(world: Kernel) -> None:
    connection = _database(world).connection
    with pytest.raises(sqlite3.Error):
        connection.execute(
            "UPDATE accounts SET company_id = 'globex' WHERE username = 'admin_acme'"
        )
    assert world.security.accounts.company_of("admin_acme") == "acme"
    with pytest.raises(sqlite3.Error):
        connection.execute(
            "INSERT INTO accounts (username, password_hash, status, company_id) "
            "VALUES ('fantasma_x', 'h', 'active', 'inexistente')"
        )
    with pytest.raises(ValidationError, match="la empresa no existe"):
        world.security.create_account("nuevo_x", PASSWORD, ["operador"], "inexistente")


def test_companies_with_accounts_and_the_platform_cannot_be_deleted(world: Kernel) -> None:
    connection = _database(world).connection
    with pytest.raises(sqlite3.Error):
        connection.execute("DELETE FROM companies WHERE id = 'acme'")
    with pytest.raises(sqlite3.Error):
        connection.execute("DELETE FROM companies WHERE id = 'plataforma'")
    assert world.security.companies.exists("acme")


def test_a_company_administrator_cannot_act_on_another_company(world: Kernel) -> None:
    guard = world.security.guard
    token = _token(world, "admin_acme")
    with pytest.raises(AuthorizationError, match=SCOPE_DENIED):
        guard.check_scope(token, "globex", CREATE_ACCOUNT_PERMISSION)
    executed: list[str] = []
    with pytest.raises(AuthorizationError, match=SCOPE_DENIED):
        guard.run(
            token,
            CREATE_ACCOUNT_PERMISSION,
            lambda: executed.append("ejecutada"),
            confirmed=True,
            company_id="globex",
        )
    assert executed == []
    denied = world.audit.events_of_type("operation.denied")[-1]
    assert denied["company_id"] == "acme"
    assert denied["payload"]["empresa_destino"] == "globex"


def test_platform_only_operations_are_closed_to_every_company(world: Kernel) -> None:
    guard = world.security.guard
    token = _token(world, "admin_acme")
    executed: list[str] = []
    with pytest.raises(AuthorizationError, match=SCOPE_DENIED):
        guard.run(
            token,
            COMPANY_ADMIN_PERMISSION,
            lambda: executed.append("ejecutada"),
            confirmed=True,
            company_id=PLATFORM_COMPANY,
        )
    assert executed == []


def test_company_creation_is_critical(world: Kernel) -> None:
    assert COMPANY_ADMIN_PERMISSION in CRITICAL_PERMISSIONS
    world.security.create_account("admin_plataforma", PASSWORD, ["administrador"])
    token = _token(world, "admin_plataforma")
    with pytest.raises(AuthorizationError, match="reautentique"):
        world.security.guard.run(
            token,
            COMPANY_ADMIN_PERMISSION,
            lambda: None,
            confirmed=True,
            company_id=PLATFORM_COMPANY,
        )


def test_the_platform_administrator_acts_on_every_company(world: Kernel) -> None:
    guard = world.security.guard
    token = world.security.login(ADMIN_USER, ADMIN_PASSWORD)
    assert guard.check_scope(token, "acme", CREATE_ACCOUNT_PERMISSION).is_platform
    assert guard.check_scope(token, "globex", CREATE_ACCOUNT_PERMISSION).is_platform


def test_operator_and_auditor_cannot_run_administrative_operations(world: Kernel) -> None:
    world.security.create_account("auditor_acme", PASSWORD, ["auditor"], "acme")
    guard = world.security.guard
    for username in ("operador_acme", "auditor_acme"):
        token = _token(world, username)
        with pytest.raises(AuthorizationError):
            guard.run(
                token,
                CREATE_ACCOUNT_PERMISSION,
                lambda: None,
                confirmed=True,
                company_id="acme",
            )


def test_accounts_and_grants_are_listed_per_company(world: Kernel) -> None:
    accounts = world.security.accounts
    assert {a.username for a in accounts.accounts(company_id="acme")} == {
        "admin_acme",
        "operador_acme",
    }
    grants = world.security.grants
    own = grants.request("admin_acme", "operador_acme", GRANT_PERMISSION, 5, "revisión")
    other = grants.request("admin_globex", "admin_globex", GRANT_PERMISSION, 5, "revisión")
    assert {g.grant_id for g in grants.list_grants(company_id="acme")} == {own}
    assert {g.grant_id for g in grants.list_grants(company_id="globex")} == {other}
    assert len(grants.list_grants()) == 2


def test_a_temporary_grant_cannot_cross_companies(world: Kernel) -> None:
    security = world.security
    grants = security.grants
    with pytest.raises(AuthorizationError, match=SCOPE_DENIED):
        grants.request("admin_acme", "admin_globex", GRANT_PERMISSION, 5, "motivo")
    own = grants.request("admin_acme", "operador_acme", GRANT_PERMISSION, 5, "motivo")
    security.create_account("admin_acme_dos", PASSWORD, ["administrador"], "acme")
    with pytest.raises(AuthorizationError, match=SCOPE_DENIED):
        grants.approve("admin_globex", own, security.authorizer.is_allowed)
    with pytest.raises(AuthorizationError, match=SCOPE_DENIED):
        grants.reject("admin_globex", own, security.authorizer.is_allowed)
    approved = grants.approve("admin_acme_dos", own, security.authorizer.is_allowed)
    assert approved.status == "active"
    with pytest.raises(AuthorizationError, match=SCOPE_DENIED):
        grants.revoke("admin_globex", own, security.authorizer.is_allowed)


def test_audit_events_are_filtered_by_company(world: Kernel) -> None:
    world.security.login("admin_acme", PASSWORD)
    world.security.login("admin_globex", PASSWORD)
    acme_events = world.audit.list_events(limit=500, company_id="acme")
    assert acme_events
    assert all(event["company_id"] == "acme" for event in acme_events)
    assert not any("admin_globex" in str(event["payload"]) for event in acme_events)
    everything = {event["event_type"] for event in world.audit.list_events(limit=500)}
    assert "kernel.started" in everything
    assert "kernel.started" not in {event["event_type"] for event in acme_events}


def test_company_administrator_menu_hides_platform_options(world: Kernel) -> None:
    lines: list[str] = []
    run_terminal(
        world,
        read=_scripted(["admin_acme", "0"]),
        write=lines.append,
        read_secret=_scripted([PASSWORD]),
    )
    menu = "\n".join(lines)
    assert "Crear cuenta" in menu
    assert "Eventos de auditoría recientes" in menu
    assert "Estado del sistema" not in menu
    assert "Crear empresa" not in menu
    assert "Listar empresas" not in menu


def test_terminal_creates_accounts_only_in_the_company_of_the_session(world: Kernel) -> None:
    lines: list[str] = []
    run_terminal(
        world,
        read=_scripted(["admin_acme", "17", "14", "sí", "nuevo_acme", "operador", "0"]),
        write=lines.append,
        read_secret=_scripted([PASSWORD, PASSWORD, PASSWORD, PASSWORD]),
    )
    assert world.security.accounts.get("nuevo_acme").company_id == "acme"
    assert any(line.startswith("Cuenta creada: nuevo_acme | empresa: acme") for line in lines)


def test_terminal_company_administrator_cannot_create_a_company(world: Kernel) -> None:
    lines: list[str] = []
    run_terminal(
        world,
        read=_scripted(["admin_acme", "18", "0"]),
        write=lines.append,
        read_secret=_scripted([PASSWORD]),
    )
    assert f"Error: {SCOPE_DENIED}" in lines
    assert not world.security.companies.exists("intruso")
    assert world.audit.events_of_type("operation.denied")[-1]["company_id"] == "acme"


def test_terminal_refuses_grants_outside_the_company_without_revealing_accounts(
    world: Kernel,
) -> None:
    lines: list[str] = []
    for target in ("admin_globex", "nadie_en_ninguna_parte"):
        run_terminal(
            world,
            read=_scripted(["admin_acme", "15", target, GRANT_PERMISSION, "5", "motivo", "0"]),
            write=lines.append,
            read_secret=_scripted([PASSWORD]),
        )
    assert lines.count(f"Error: {SCOPE_DENIED}") == 2


def test_terminal_platform_administrator_manages_companies(
    kernel: Kernel, admin: tuple[str, str]
) -> None:
    lines: list[str] = []
    run_terminal(
        kernel,
        read=_scripted(
            [
                ADMIN_USER,
                "17",
                "18",
                "sí",
                "initech",
                "Initech S.A.",
                "19",
                "14",
                "sí",
                "initech",
                "nuevo_initech",
                "administrador",
                "0",
            ]
        ),
        write=lines.append,
        read_secret=_scripted([ADMIN_PASSWORD] * 4),
    )
    assert kernel.security.companies.exists("initech")
    assert kernel.security.accounts.get("nuevo_initech").company_id == "initech"
    assert any(line.startswith("- initech | Initech S.A. | creada: ") for line in lines)
