"""Terminal de plugins (etapa 4, fase 6): estado, cuarentena, actualización y reversión.

Las respuestas se simulan con listas. Las cuentas son ficticias y los paquetes viven en carpetas
temporales. Las acciones de cambio reciben sus datos y confirmaciones desde la lista de respuestas.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path

import pytest

from natxajo_auditor.core.exceptions import PluginError
from natxajo_auditor.interfaces.terminal.app import run_terminal
from natxajo_auditor.kernel.kernel import Kernel
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER

PASSWORD = "contraseña-de-prueba-8"
PLUGIN = "plugin_ejemplo"
OPERATOR = "operador_terminal"
COMPANY_ADMIN = "admin_acme"


def _scripted(answers: Iterable[str]) -> Callable[[str], str]:
    iterator = iter(answers)

    def read(prompt: str) -> str:
        try:
            return next(iterator)
        except StopIteration:
            raise EOFError from None

    return read


def _run(kernel: Kernel, reads: list[str], secrets: list[str], lines: list[str]) -> None:
    run_terminal(
        kernel,
        read=_scripted(reads),
        write=lines.append,
        read_secret=_scripted(secrets),
    )


@pytest.fixture
def make_package(tmp_path: Path, make_plugin_source: Callable[..., Path]) -> Callable[..., Path]:
    def _make(name: str, version: str = "0.1.0") -> Path:
        return make_plugin_source(tmp_path / name, version=version)

    return _make


@pytest.fixture
def plugins(
    kernel: Kernel,
    platform_token: str,
    register_publisher: Callable[..., None],
    make_package: Callable[..., Path],
) -> Kernel:
    """Plataforma con un editor oficial y plugin_ejemplo 0.1.0 instalado y deshabilitado."""
    register_publisher(kernel, trust_level="official")
    kernel.plugins.install_package(make_package("base"))
    return kernel


def test_status_lists_each_plugin_with_its_state_and_publisher(plugins: Kernel) -> None:
    lines: list[str] = []
    _run(plugins, [ADMIN_USER, "29", "0"], [ADMIN_PASSWORD], lines)
    assert "- plugin_ejemplo 0.1.0 | deshabilitado | editor editor_pruebas (official)" in lines


def test_quarantine_from_the_terminal_is_recorded_and_asks_no_extra_confirmation(
    plugins: Kernel,
) -> None:
    lines: list[str] = []
    # Sin «sí» de confirmación: la opción es guardada y el servicio aplica la puerta.
    _run(plugins, [ADMIN_USER, "30", PLUGIN, "motivo de prueba", "0"], [ADMIN_PASSWORD], lines)
    assert f"{PLUGIN} queda en cuarentena. Deshabilitados: ninguno" in lines
    assert len(plugins.audit.events_of_type("plugin.quarantined")) == 1
    with pytest.raises(PluginError, match="en cuarentena"):
        plugins.plugins.enable(PLUGIN)


def test_release_needs_confirmation_and_recent_reauthentication(
    plugins: Kernel, platform_token: str
) -> None:
    plugins.plugins.quarantine(platform_token, PLUGIN, "motivo")
    lines: list[str] = []
    _run(plugins, [ADMIN_USER, "31", PLUGIN, "sí", "0"], [ADMIN_PASSWORD], lines)
    assert "Error: operación crítica: reautentique la sesión" in lines
    assert plugins.plugins.get(PLUGIN).quarantined

    lines = []
    _run(
        plugins,
        [ADMIN_USER, "17", "31", PLUGIN, "sí", "0"],
        [ADMIN_PASSWORD, ADMIN_PASSWORD],
        lines,
    )
    assert f"Cuarentena liberada: {PLUGIN}. Puede volver a habilitarse." in lines
    assert not plugins.plugins.get(PLUGIN).quarantined


def test_update_from_a_folder_with_spaces_after_confirmation(
    plugins: Kernel, make_package: Callable[..., Path]
) -> None:
    folder = make_package("Paquete nuevo ñ", "0.2.0")
    lines: list[str] = []
    # Ruta entre comillas, como la copia «Copiar como ruta» de Windows.
    _run(
        plugins,
        [ADMIN_USER, "17", "32", f'"{folder}"', "sí", "0"],
        [ADMIN_PASSWORD, ADMIN_PASSWORD],
        lines,
    )
    assert (
        f"{PLUGIN} actualizado a 0.2.0. Versión anterior conservada: 0.1.0. Queda deshabilitado."
        in lines
    )
    assert len(plugins.audit.events_of_type("plugin.updated")) == 1


def test_rollback_from_the_terminal_after_an_update(
    plugins: Kernel, platform_token: str, make_package: Callable[..., Path]
) -> None:
    plugins.plugins.update_package(platform_token, make_package("v2", "0.2.0"), confirmed=True)
    lines: list[str] = []
    _run(
        plugins,
        [ADMIN_USER, "17", "33", PLUGIN, "sí", "0"],
        [ADMIN_PASSWORD, ADMIN_PASSWORD],
        lines,
    )
    assert (
        f"{PLUGIN} vuelve a la versión 0.1.0. Versión anterior conservada: 0.2.0. Queda deshabilitado."
        in lines
    )
    assert plugins.plugins.get(PLUGIN).version == "0.1.0"


def test_a_cancelled_rollback_changes_nothing(
    plugins: Kernel, platform_token: str, make_package: Callable[..., Path]
) -> None:
    plugins.plugins.update_package(platform_token, make_package("v2", "0.2.0"), confirmed=True)
    lines: list[str] = []
    _run(
        plugins,
        [ADMIN_USER, "17", "33", PLUGIN, "no", "0"],
        [ADMIN_PASSWORD, ADMIN_PASSWORD],
        lines,
    )
    assert "Operación cancelada" in lines
    assert plugins.plugins.get(PLUGIN).version == "0.2.0"


def test_an_operator_can_read_the_status_but_gets_no_change_option(plugins: Kernel) -> None:
    plugins.security.create_account(OPERATOR, PASSWORD, ["operador"])
    lines: list[str] = []
    _run(plugins, [OPERATOR, "30", "0"], [PASSWORD], lines)
    assert "Opción no disponible para su cuenta" in lines
    assert plugins.audit.events_of_type("plugin.quarantined") == []

    status: list[str] = []
    _run(plugins, [OPERATOR, "29", "0"], [PASSWORD], status)
    assert any(line.startswith("- plugin_ejemplo 0.1.0") for line in status)


def test_company_accounts_do_not_see_the_plugin_options(plugins: Kernel) -> None:
    plugins.security.companies.create("acme", "Acme S.A.")
    plugins.security.create_account(COMPANY_ADMIN, PASSWORD, ["administrador"], "acme")
    lines: list[str] = []
    _run(plugins, [COMPANY_ADMIN, "0"], [PASSWORD], lines)
    assert not any("cuarentena" in line or "Estado de los plugins" in line for line in lines)
