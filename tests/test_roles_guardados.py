"""Cambio de roles a través del guardián.

- Solo la plataforma cambia roles, con confirmación y reautenticación reciente. Una empresa no
  puede conceder roles, ni siquiera dentro de su propia empresa.
- El cambio queda en la auditoría con el usuario que lo hizo.
"""

from __future__ import annotations

import pytest

from natxajo_auditor.core.contracts import PLATFORM_COMPANY
from natxajo_auditor.core.exceptions import AuthorizationError, ValidationError
from natxajo_auditor.kernel.kernel import Kernel
from natxajo_auditor.security.roles import ADMINISTRATOR, AUDITOR, OPERATOR
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER, install_administrator

PASSWORD = "contraseña-de-prueba-9"


@pytest.fixture
def world(kernel: Kernel) -> Kernel:
    install_administrator(kernel)
    kernel.security.companies.create("acme", "Acme S.A.")
    kernel.security.create_account("admin_acme", PASSWORD, [ADMINISTRATOR], "acme")
    kernel.security.create_account("operador_plataforma", PASSWORD, [OPERATOR], PLATFORM_COMPANY)
    kernel.security.create_account("usuario_acme", PASSWORD, [OPERATOR], "acme")
    return kernel


def _roles(kernel: Kernel, username: str) -> tuple[str, ...]:
    return tuple(sorted(kernel.security.accounts.get(username).roles))


def test_a_platform_administrator_changes_roles_with_a_trace(
    world: Kernel, platform_token: str
) -> None:
    world.security.change_roles(platform_token, "usuario_acme", [AUDITOR], confirmed=True)

    assert _roles(world, "usuario_acme") == (AUDITOR,)
    registros = world.audit.events_of_type("account.roles_changed")
    assert [(item["payload"], item["actor"]) for item in registros] == [
        ({"username": "usuario_acme", "roles": [AUDITOR]}, ADMIN_USER)
    ]


def test_changing_roles_needs_confirmation(world: Kernel, platform_token: str) -> None:
    with pytest.raises(AuthorizationError, match="confirmación"):
        world.security.change_roles(platform_token, "usuario_acme", [AUDITOR], confirmed=False)

    assert _roles(world, "usuario_acme") == (OPERATOR,)


def test_changing_roles_needs_a_recent_reauthentication(world: Kernel) -> None:
    token = world.security.login(ADMIN_USER, ADMIN_PASSWORD)

    with pytest.raises(AuthorizationError, match="reautentique"):
        world.security.change_roles(token, "usuario_acme", [AUDITOR], confirmed=True)

    assert _roles(world, "usuario_acme") == (OPERATOR,)


def test_a_company_administrator_cannot_grant_roles_even_in_its_own_company(world: Kernel) -> None:
    token = world.security.login("admin_acme", PASSWORD)
    world.security.reauthenticate(token, PASSWORD)

    with pytest.raises(AuthorizationError):
        world.security.change_roles(token, "usuario_acme", [ADMINISTRATOR], confirmed=True)

    assert _roles(world, "usuario_acme") == (OPERATOR,)
    assert world.audit.events_of_type("account.roles_changed") == []


def test_an_operator_cannot_change_roles(world: Kernel) -> None:
    token = world.security.login("operador_plataforma", PASSWORD)
    world.security.reauthenticate(token, PASSWORD)

    with pytest.raises(AuthorizationError):
        world.security.change_roles(token, "usuario_acme", [AUDITOR], confirmed=True)

    assert _roles(world, "usuario_acme") == (OPERATOR,)


def test_an_unknown_role_is_refused_and_changes_nothing(world: Kernel, platform_token: str) -> None:
    with pytest.raises(ValidationError, match="rol no existe"):
        world.security.change_roles(platform_token, "usuario_acme", ["inventado"], confirmed=True)

    assert _roles(world, "usuario_acme") == (OPERATOR,)
