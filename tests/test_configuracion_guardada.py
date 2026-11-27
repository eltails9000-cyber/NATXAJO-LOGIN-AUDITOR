"""Restauración de configuración a través del guardián.

- Es una operación crítica de plataforma: exige confirmación y reautenticación reciente.
- Una copia que no verifica su hash no se aplica, y la configuración no cambia.
- La restauración queda en la auditoría con el archivo y el usuario que la hizo.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from natxajo_auditor.core.contracts import PLATFORM_COMPANY
from natxajo_auditor.core.exceptions import AuthorizationError, ConfigurationError
from natxajo_auditor.kernel.kernel import Kernel
from natxajo_auditor.security.roles import OPERATOR
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER, install_administrator

PASSWORD = "contraseña-de-prueba-9"


@pytest.fixture
def world(kernel: Kernel) -> Kernel:
    install_administrator(kernel)
    kernel.security.companies.create("acme", "Acme S.A.")
    kernel.security.create_account("admin_acme", PASSWORD, ["administrador"], "acme")
    kernel.security.create_account("operador_plataforma", PASSWORD, [OPERATOR], PLATFORM_COMPANY)
    return kernel


def _copia_del_tema_claro(kernel: Kernel) -> Path:
    """Guarda una copia con el tema claro y deja la configuración con el tema de contraste."""
    config = kernel.configuration
    config.set("general", "theme", "light")
    copia = config.backup()
    config.set("general", "theme", "contrast")
    return copia


def _tema(kernel: Kernel) -> str:
    return str(kernel.configuration.get("general", "theme"))


def test_a_platform_administrator_restores_a_verified_copy_with_a_trace(
    world: Kernel, platform_token: str
) -> None:
    copia = _copia_del_tema_claro(world)

    world.configuration_service.restore(platform_token, copia, confirmed=True)

    assert _tema(world) == "light"
    eventos = world.audit.events_of_type("configuration.restored")
    assert [(item["payload"], item["actor"]) for item in eventos] == [
        ({"archivo": copia.name}, ADMIN_USER)
    ]


def test_restoring_needs_confirmation(world: Kernel, platform_token: str) -> None:
    copia = _copia_del_tema_claro(world)

    with pytest.raises(AuthorizationError, match="confirmación"):
        world.configuration_service.restore(platform_token, copia, confirmed=False)

    assert _tema(world) == "contrast"
    assert world.audit.events_of_type("configuration.restored") == []


def test_restoring_needs_a_recent_reauthentication(world: Kernel) -> None:
    copia = _copia_del_tema_claro(world)
    token = world.security.login(ADMIN_USER, ADMIN_PASSWORD)

    with pytest.raises(AuthorizationError, match="reautentique"):
        world.configuration_service.restore(token, copia, confirmed=True)

    assert _tema(world) == "contrast"


def test_company_administrators_and_operators_cannot_restore(world: Kernel) -> None:
    copia = _copia_del_tema_claro(world)
    for username in ("admin_acme", "operador_plataforma"):
        token = world.security.login(username, PASSWORD)
        world.security.reauthenticate(token, PASSWORD)
        with pytest.raises(AuthorizationError):
            world.configuration_service.restore(token, copia, confirmed=True)

    assert _tema(world) == "contrast"
    assert world.audit.events_of_type("configuration.restored") == []


def test_a_copy_that_does_not_verify_is_not_applied(world: Kernel, platform_token: str) -> None:
    copia = _copia_del_tema_claro(world)
    copia.write_text('{"general": {"theme": "light"}}', encoding="utf-8")

    with pytest.raises(ConfigurationError, match="no válida"):
        world.configuration_service.restore(platform_token, copia, confirmed=True)

    assert _tema(world) == "contrast"
    assert world.audit.events_of_type("configuration.restored") == []
