"""Lecturas de la interfaz: alcance por empresa, páginas de plataforma, sesiones sin fichas,
filtros de eventos y gravedad fija. Todo se comprueba a través de la API HTTP en memoria."""

from __future__ import annotations

import pytest

from natxajo_auditor.interfaces.gui.app import GuiApp
from natxajo_auditor.interfaces.gui.readmodels import severity_of
from natxajo_auditor.kernel.kernel import Kernel
from tests.auditoria_datos import GOOD, copy_of
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER, install_administrator
from tests.gui_cliente import PORT, ClienteGui

PASSWORD = "contraseña-de-prueba-3"
AUTH = "Autorización escrita AUT-2026-003"


@pytest.fixture
def mundo(kernel: Kernel) -> Kernel:
    install_administrator(kernel)
    seguridad = kernel.security
    seguridad.companies.create("acme", "Acme S.A.")
    seguridad.companies.create("globex", "Globex S.A.")
    seguridad.create_account("auditor_acme", PASSWORD, ["auditor"], "acme")
    seguridad.create_account("operador_acme", PASSWORD, ["operador"], "acme")
    seguridad.create_account("auditor_globex", PASSWORD, ["auditor"], "globex")
    seguridad.create_account("auditor_plataforma", PASSWORD, ["auditor"])
    return kernel


def _cliente(kernel: Kernel, usuario: str, contrasena: str) -> ClienteGui:
    cliente = ClienteGui(GuiApp(kernel, PORT))
    assert cliente.entrar(usuario, contrasena).estado == 200
    return cliente


@pytest.fixture
def admin_gui(mundo: Kernel) -> ClienteGui:
    return _cliente(mundo, ADMIN_USER, ADMIN_PASSWORD)


@pytest.fixture
def empresa_gui(mundo: Kernel) -> ClienteGui:
    return _cliente(mundo, "auditor_acme", PASSWORD)


# --- Páginas y permisos --------------------------------------------------------------------------


def test_the_platform_administrator_can_open_every_page(admin_gui: ClienteGui) -> None:
    paginas = admin_gui.pedir("GET", "/api/sesion").datos["paginas"]
    assert set(paginas.values()) == {"ok"}
    assert paginas["plugins"] == "ok"
    assert paginas["mantenimiento"] == "ok"


def test_company_accounts_do_not_get_platform_pages(empresa_gui: ClienteGui) -> None:
    datos = empresa_gui.pedir("GET", "/api/sesion").datos
    assert datos["plataforma"] is False
    assert datos["paginas"]["plugins"] == "solo_plataforma"
    assert datos["paginas"]["modulos"] == "solo_plataforma"
    assert datos["paginas"]["mantenimiento"] == "solo_plataforma"
    assert datos["paginas"]["auditoria"] == "ok"


def test_a_read_only_auditor_reads_maintenance_but_is_not_gated_out(mundo: Kernel) -> None:
    # El rol auditor tiene lectura en todo; lo que no puede hacer es aplicar cambios
    # (véase tests/test_gui_acciones.py).
    cliente = _cliente(mundo, "auditor_plataforma", PASSWORD)
    paginas = cliente.pedir("GET", "/api/sesion").datos["paginas"]
    assert paginas["mantenimiento"] == "ok"
    assert paginas["plugins"] == "ok"


def test_platform_only_reads_are_refused_to_company_accounts(empresa_gui: ClienteGui) -> None:
    respuesta = empresa_gui.pedir("GET", "/api/plugins")
    assert respuesta.estado == 403
    assert respuesta.codigo == "solo_plataforma"


# --- Alcance por empresa -------------------------------------------------------------------------


def test_company_accounts_list_only_their_own_accounts(empresa_gui: ClienteGui) -> None:
    cuentas = empresa_gui.pedir("GET", "/api/usuarios").datos["cuentas"]
    nombres = {cuenta["usuario"] for cuenta in cuentas}
    assert nombres == {"auditor_acme", "operador_acme"}
    assert ADMIN_USER not in nombres
    assert "auditor_globex" not in nombres


def test_account_detail_outside_the_company_does_not_exist(empresa_gui: ClienteGui) -> None:
    # Una cuenta de otra empresa responde igual que una cuenta inexistente.
    otra = empresa_gui.pedir("GET", "/api/usuarios/detalle?usuario=" + ADMIN_USER)
    inexistente = empresa_gui.pedir("GET", "/api/usuarios/detalle?usuario=no_existe")
    assert otra.estado == 404
    assert inexistente.estado == 404


def test_a_company_cannot_ask_for_another_company(empresa_gui: ClienteGui) -> None:
    respuesta = empresa_gui.pedir("GET", "/api/usuarios?empresa=globex")
    assert respuesta.estado == 403
    assert respuesta.codigo == "ambito"


def test_company_sessions_are_filtered_by_company(
    mundo: Kernel, admin_gui: ClienteGui, empresa_gui: ClienteGui
) -> None:
    de_plataforma = admin_gui.pedir("GET", "/api/sesiones").datos["sesiones"]
    assert {sesion["usuario"] for sesion in de_plataforma} >= {ADMIN_USER, "auditor_acme"}
    de_empresa = empresa_gui.pedir("GET", "/api/sesiones").datos["sesiones"]
    assert {sesion["usuario"] for sesion in de_empresa} == {"auditor_acme"}
    assert all(sesion["empresa"] == "acme" for sesion in de_empresa)


def test_session_views_never_carry_tokens_or_digests(admin_gui: ClienteGui) -> None:
    for sesion in admin_gui.pedir("GET", "/api/sesiones").datos["sesiones"]:
        assert set(sesion) == {
            "usuario",
            "empresa",
            "creada",
            "ultima_actividad",
            "expira",
            "reautenticada",
        }
        for clave in sesion:
            assert "token" not in clave.lower()
            assert "hash" not in clave.lower()


# --- Auditoría y eventos -------------------------------------------------------------------------


def test_events_can_be_filtered_by_category_and_severity(
    mundo: Kernel, admin_gui: ClienteGui
) -> None:
    mundo.auditing.run_document(
        mundo.security.login(ADMIN_USER, ADMIN_PASSWORD),
        "acme",
        copy_of(GOOD),
        authorization_reference=AUTH,
    )
    todos = admin_gui.pedir("GET", "/api/auditoria/eventos").datos
    assert todos["analizados"] > 0
    seguridad = admin_gui.pedir("GET", "/api/auditoria/eventos?categoria=seguridad").datos[
        "eventos"
    ]
    assert seguridad and all(evento["categoria"] == "seguridad" for evento in seguridad)
    media = admin_gui.pedir("GET", "/api/auditoria/eventos?gravedad=media").datos["eventos"]
    assert all(evento["gravedad"] == "media" for evento in media)


def test_an_invalid_filter_is_refused(admin_gui: ClienteGui) -> None:
    respuesta = admin_gui.pedir("GET", "/api/auditoria/eventos?categoria=todo")
    assert respuesta.estado == 422
    assert respuesta.codigo == "validacion"


def test_severity_is_a_fixed_display_rule() -> None:
    assert severity_of("operation.denied", "seguridad") == "alta"
    assert severity_of("account.login_blocked", "seguridad") == "alta"
    assert severity_of("account.login_failed", "seguridad") == "media"
    assert severity_of("kernel.started", "operativo") == "baja"


def test_the_event_catalogue_lists_every_declared_type(admin_gui: ClienteGui) -> None:
    datos = admin_gui.pedir("GET", "/api/eventos/catalogo").datos
    tipos = {entrada["tipo"] for entrada in datos["tipos"]}
    assert "account.login_failed" in tipos
    assert all("obligatorias" in entrada for entrada in datos["tipos"])


def test_the_dashboard_reports_every_section(admin_gui: ClienteGui) -> None:
    datos = admin_gui.pedir("GET", "/api/panel").datos
    for seccion in ("estado", "plugins", "modulos", "sesiones", "alertas", "actividad", "gravedad"):
        assert seccion in datos, seccion
    assert datos["plataforma"] is True
    assert datos["sesiones"]["disponible"] is True


def test_security_overview_responds_for_the_platform(admin_gui: ClienteGui) -> None:
    respuesta = admin_gui.pedir("GET", "/api/seguridad")
    assert respuesta.estado == 200
