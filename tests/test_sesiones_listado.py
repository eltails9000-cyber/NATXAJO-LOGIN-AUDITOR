"""Listado de sesiones vigentes para la interfaz: filtro por empresa, exclusión de sesiones cerradas
o caducadas, ausencia de secretos y ninguna renovación de la actividad al consultar."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import fields
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.kernel import Kernel
from natxajo_auditor.security.sessions import MAX_LISTED_SESSIONS, SessionInfo
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER, install_administrator

PASSWORD = "contraseña-de-prueba-6"
INICIO = datetime(2026, 11, 1, 9, 0, tzinfo=UTC)


@pytest.fixture
def reloj(tmp_path: Path) -> Iterator[tuple[Kernel, dict[str, datetime]]]:
    ahora = {"t": INICIO}
    kernel = Kernel(
        RuntimeContext(project_root=tmp_path), password_iterations=1_000, clock=lambda: ahora["t"]
    )
    kernel.start()
    install_administrator(kernel)
    kernel.security.companies.create("acme", "Acme S.A.")
    kernel.security.create_account("auditor_acme", PASSWORD, ["auditor"], "acme")
    yield kernel, ahora
    kernel.stop()


def test_listing_returns_every_live_session_and_can_filter_by_company(
    reloj: tuple[Kernel, dict[str, datetime]],
) -> None:
    kernel, _ = reloj
    kernel.security.login(ADMIN_USER, ADMIN_PASSWORD)
    kernel.security.login("auditor_acme", PASSWORD)
    sesiones = kernel.security.sessions
    cuentas = kernel.security.accounts
    assert {s.username for s in sesiones.list_live(cuentas)} == {ADMIN_USER, "auditor_acme"}
    solo_acme = sesiones.list_live(cuentas, company_id="acme")
    assert [s.username for s in solo_acme] == ["auditor_acme"]
    assert all(s.company_id == "acme" for s in solo_acme)


def test_closed_sessions_are_not_listed(reloj: tuple[Kernel, dict[str, datetime]]) -> None:
    kernel, _ = reloj
    token = kernel.security.login("auditor_acme", PASSWORD)
    kernel.security.logout(token)
    assert kernel.security.sessions.list_live(kernel.security.accounts) == []


def test_expired_sessions_are_not_listed(reloj: tuple[Kernel, dict[str, datetime]]) -> None:
    kernel, ahora = reloj
    kernel.security.login(ADMIN_USER, ADMIN_PASSWORD)
    assert len(kernel.security.sessions.list_live(kernel.security.accounts)) == 1
    ahora["t"] = INICIO + timedelta(days=3)
    assert kernel.security.sessions.list_live(kernel.security.accounts) == []


def test_listing_does_not_renew_the_activity_of_a_session(
    reloj: tuple[Kernel, dict[str, datetime]],
) -> None:
    kernel, ahora = reloj
    kernel.security.login(ADMIN_USER, ADMIN_PASSWORD)
    primera = kernel.security.sessions.list_live(kernel.security.accounts)[0]
    ahora["t"] = INICIO + timedelta(minutes=10)
    segunda = kernel.security.sessions.list_live(kernel.security.accounts)[0]
    assert segunda.last_activity == primera.last_activity


def test_session_info_carries_no_secrets() -> None:
    nombres = {campo.name for campo in fields(SessionInfo)}
    assert nombres == {
        "username",
        "company_id",
        "created_at",
        "last_activity",
        "expires_at",
        "reauthenticated",
    }
    assert not any("token" in nombre or "hash" in nombre for nombre in nombres)


def test_the_listing_is_bounded() -> None:
    assert MAX_LISTED_SESSIONS == 500
