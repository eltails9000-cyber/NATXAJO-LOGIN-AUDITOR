"""Acciones de la interfaz: cada una llama a una operación existente y pasa por la confirmación,
la reautenticación y los permisos que esa operación exige."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import timedelta
from pathlib import Path

import pytest

from natxajo_auditor.interfaces.gui.app import GuiApp
from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.kernel import Kernel
from natxajo_auditor.security import sessions as sessions_module
from tests.auditoria_datos import GOOD, copy_of
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER, install_administrator
from tests.gui_cliente import PORT, ClienteGui

PASSWORD = "contraseña-de-prueba-5"
AUTH = "Autorización escrita AUT-2026-005"
MODULO = "modulo_interfaz"


@pytest.fixture
def mundo(tmp_path: Path, make_module: Callable[..., Path]) -> Iterator[Kernel]:
    # El módulo debe existir antes de arrancar: el descubrimiento corre al iniciar la plataforma.
    make_module(tmp_path / "modules", MODULO)
    kernel = Kernel(RuntimeContext(project_root=tmp_path), password_iterations=1_000)
    kernel.start()
    install_administrator(kernel)
    kernel.security.companies.create("acme", "Acme S.A.")
    kernel.security.create_account("auditor_plataforma", PASSWORD, ["auditor"])
    yield kernel
    kernel.stop()


@pytest.fixture
def admin(mundo: Kernel) -> ClienteGui:
    cliente = ClienteGui(GuiApp(mundo, PORT))
    assert cliente.entrar(ADMIN_USER, ADMIN_PASSWORD).estado == 200
    return cliente


# --- Confirmación y reautenticación ---------------------------------------------------------------


def test_a_critical_action_without_confirmation_is_refused(admin: ClienteGui) -> None:
    respuesta = admin.pedir("POST", "/api/acciones/mantenimiento/limpiar", datos={"horas": 24})
    assert respuesta.estado == 403
    assert respuesta.codigo == "confirmacion_requerida"


def test_a_critical_action_asks_for_reauthentication_when_the_window_has_passed(
    admin: ClienteGui, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sessions_module, "REAUTH_WINDOW", timedelta(0))
    respuesta = admin.pedir(
        "POST", "/api/acciones/mantenimiento/limpiar", datos={"horas": 24, "confirmado": True}
    )
    assert respuesta.estado == 403
    assert respuesta.codigo == "reautenticacion_requerida"


def test_reauthentication_then_the_critical_action_succeeds(admin: ClienteGui) -> None:
    reautenticado = admin.pedir(
        "POST", "/api/sesion/reautenticar", datos={"contrasena": ADMIN_PASSWORD}
    )
    assert reautenticado.estado == 200
    assert reautenticado.datos == {"reautenticada": True}
    respuesta = admin.pedir(
        "POST", "/api/acciones/mantenimiento/limpiar", datos={"horas": 24, "confirmado": True}
    )
    assert respuesta.estado == 200
    assert {"planeados", "eliminados"} <= set(respuesta.datos)


def test_a_wrong_password_does_not_reauthenticate(admin: ClienteGui) -> None:
    respuesta = admin.pedir("POST", "/api/sesion/reautenticar", datos={"contrasena": "incorrecta"})
    assert respuesta.estado == 401
    assert respuesta.codigo == "credenciales"


def test_enabling_a_module_without_confirmation_is_refused(admin: ClienteGui) -> None:
    respuesta = admin.pedir("POST", "/api/acciones/modulos/habilitar", datos={"modulo_id": MODULO})
    assert respuesta.estado == 403
    assert respuesta.codigo == "confirmacion_requerida"


# --- Permisos ------------------------------------------------------------------------------------


def test_a_read_only_auditor_cannot_apply_the_cleanup(mundo: Kernel) -> None:
    cliente = ClienteGui(GuiApp(mundo, PORT))
    assert cliente.entrar("auditor_plataforma", PASSWORD).estado == 200
    respuesta = cliente.pedir(
        "POST", "/api/acciones/mantenimiento/limpiar", datos={"horas": 24, "confirmado": True}
    )
    assert respuesta.estado == 403
    assert respuesta.codigo == "sin_permiso"


def test_a_read_only_auditor_cannot_enable_modules(mundo: Kernel) -> None:
    cliente = ClienteGui(GuiApp(mundo, PORT))
    assert cliente.entrar("auditor_plataforma", PASSWORD).estado == 200
    respuesta = cliente.pedir(
        "POST", "/api/acciones/modulos/habilitar", datos={"modulo_id": MODULO, "confirmado": True}
    )
    assert respuesta.estado == 403
    assert respuesta.codigo == "sin_permiso"


# --- Mantenimiento -------------------------------------------------------------------------------


def test_the_cleanup_plan_is_read_only(admin: ClienteGui, mundo: Kernel) -> None:
    antes = sorted(path.name for path in mundo.context.project_root.rglob("*"))
    respuesta = admin.pedir("GET", "/api/mantenimiento/limpieza?horas=24")
    assert respuesta.estado == 200
    assert isinstance(respuesta.datos["archivos"], list)
    despues = sorted(path.name for path in mundo.context.project_root.rglob("*"))
    assert antes == despues


def test_the_cleanup_age_must_be_a_known_value(admin: ClienteGui) -> None:
    respuesta = admin.pedir("GET", "/api/mantenimiento/limpieza?horas=0")
    assert respuesta.estado == 422
    assert respuesta.codigo == "validacion"


# --- Módulos -------------------------------------------------------------------------------------


def test_a_module_can_be_enabled_and_disabled_through_the_gui(admin: ClienteGui) -> None:
    # El inicio de sesión no reautentica: las operaciones críticas piden la contraseña antes.
    assert (
        admin.pedir("POST", "/api/sesion/reautenticar", datos={"contrasena": ADMIN_PASSWORD}).estado
        == 200
    )
    habilitado = admin.pedir(
        "POST", "/api/acciones/modulos/habilitar", datos={"modulo_id": MODULO, "confirmado": True}
    )
    assert habilitado.estado == 200
    modulos = {m["id"]: m for m in admin.pedir("GET", "/api/modulos").datos["modulos"]}
    assert modulos[MODULO]["habilitado"] is True
    deshabilitado = admin.pedir(
        "POST",
        "/api/acciones/modulos/deshabilitar",
        datos={"modulo_id": MODULO, "confirmado": True},
    )
    assert deshabilitado.estado == 200
    modulos = {m["id"]: m for m in admin.pedir("GET", "/api/modulos").datos["modulos"]}
    assert modulos[MODULO]["habilitado"] is False


def test_an_unknown_module_is_a_controlled_error(admin: ClienteGui) -> None:
    respuesta = admin.pedir(
        "POST",
        "/api/acciones/modulos/habilitar",
        datos={"modulo_id": "no_existe", "confirmado": True},
    )
    assert respuesta.estado >= 400
    assert respuesta.estado != 500
    assert respuesta.codigo != "interno"


# --- Plugins -------------------------------------------------------------------------------------


def test_an_unknown_plugin_is_a_controlled_error(admin: ClienteGui) -> None:
    respuesta = admin.pedir(
        "POST",
        "/api/acciones/plugins/cuarentena",
        datos={"plugin_id": "no_existe", "motivo": "prueba"},
    )
    assert respuesta.estado >= 400
    assert respuesta.estado != 500
    assert respuesta.codigo != "interno"


# --- Informes ------------------------------------------------------------------------------------


def test_a_report_is_exported_listed_and_verified(admin: ClienteGui, mundo: Kernel) -> None:
    token = mundo.security.login(ADMIN_USER, ADMIN_PASSWORD)
    registro = mundo.auditing.run_document(
        token, "acme", copy_of(GOOD), authorization_reference=AUTH
    )
    run_id = str(registro["id"])

    exportado = admin.pedir(
        "POST",
        "/api/acciones/informes/exportar",
        datos={"empresa": "acme", "evaluacion": run_id, "formato": "json"},
    )
    assert exportado.estado == 200
    assert str(exportado.datos["informe"]["ruta"]).endswith(".json")

    listado = admin.pedir("GET", "/api/informes?empresa=acme").datos
    assert [item["evaluacion"] for item in listado["informes"]] == [run_id]

    verificado = admin.pedir("POST", "/api/acciones/informes/verificar", datos={"empresa": "acme"})
    assert verificado.estado == 200
    assert "verificacion" in verificado.datos


def test_an_export_format_outside_the_list_is_refused(admin: ClienteGui) -> None:
    respuesta = admin.pedir(
        "POST",
        "/api/acciones/informes/exportar",
        datos={"empresa": "acme", "evaluacion": "x", "formato": "pdf"},
    )
    assert respuesta.estado == 422
    assert respuesta.codigo == "validacion"


def test_the_platform_must_name_the_company_of_a_report(admin: ClienteGui) -> None:
    respuesta = admin.pedir("POST", "/api/acciones/informes/verificar", datos={})
    assert respuesta.estado == 422
    assert respuesta.codigo == "validacion"
