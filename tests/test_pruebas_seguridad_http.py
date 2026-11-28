"""Controles HTTP de seguridad contra el laboratorio: cabeceras, TLS, cookies y tiempos de respuesta.

Cada control se prueba en los dos sentidos: un servidor correcto debe pasar y uno vulnerable a
propósito debe fallar. La confianza TLS se limita al certificado generado para el laboratorio; el
motor nunca desactiva la verificación, y eso también se comprueba.
"""

from __future__ import annotations

import ssl
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from natxajo_auditor.core.exceptions import AuthorizationError
from natxajo_auditor.kernel.kernel import Kernel
from tests.laboratorio_http import (
    Escenario,
    LaboratorioHttp,
    OpensslNoDisponible,
    generar_certificado,
)
from tests.test_pruebas_http import _admin, _estados, _objetivo, _procedimiento


@pytest.fixture(scope="module")
def certificado(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    try:
        return generar_certificado(tmp_path_factory.mktemp("tls-laboratorio"))
    except OpensslNoDisponible as exc:
        pytest.skip(str(exc))


@pytest.fixture
def certificado_proximo(tmp_path: Path) -> tuple[Path, Path]:
    """Certificado que caduca en diez días: debe producir FAIL aunque esté verificado."""
    try:
        return generar_certificado(tmp_path, dias=10)
    except OpensslNoDisponible as exc:
        pytest.skip(str(exc))


def _confiar_en(kernel: Kernel, monkeypatch: pytest.MonkeyPatch, certificado: Path) -> None:
    """Confía solo en el certificado del laboratorio, nunca en el almacén del sistema."""
    contexto = ssl.create_default_context(cafile=str(certificado))
    monkeypatch.setattr(kernel.pruebas, "_contexto_tls", contexto)


def _controles(ejecucion: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(r["caso"]): r for r in ejecucion["resultados"]}


def _por_control(ejecucion: dict[str, Any]) -> dict[str, str]:
    return {caso: str(r["resultado"]) for caso, r in _controles(ejecucion).items()}


# ----- Cabeceras de seguridad -----------------------------------------------------------------


def test_cabeceras_ausentes_son_FAIL(arrancar: Callable[..., Kernel]) -> None:
    kernel = arrancar()
    with LaboratorioHttp() as lab:
        token = _objetivo(kernel, lab)
        ejecucion = _procedimiento(kernel, token, lab, "security-headers", formulario="login")

    assert ejecucion["estado"] == "completada"
    assert _por_control(ejecucion) == {
        "cabecera-csp": "FAIL",
        "cabecera-nosniff": "FAIL",
        "cabecera-encuadre": "FAIL",
        "cabecera-referrer": "FAIL",
        "cabecera-hsts": "FAIL",
    }


def test_cabeceras_correctas_pasan_salvo_hsts_sin_https(arrancar: Callable[..., Kernel]) -> None:
    kernel = arrancar()
    with LaboratorioHttp(Escenario(cabeceras_seguridad=True)) as lab:
        token = _objetivo(kernel, lab)
        ejecucion = _procedimiento(kernel, token, lab, "security-headers", formulario="login")

    controles = _controles(ejecucion)
    assert [controles[c]["resultado"] for c in controles if c != "cabecera-hsts"] == ["PASS"] * 4
    assert controles["cabecera-hsts"]["resultado"] == "FAIL"
    assert "no usa HTTPS" in controles["cabecera-hsts"]["motivo"]


def test_cabeceras_correctas_por_https_pasan_todas(
    arrancar: Callable[..., Kernel],
    certificado: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = arrancar()
    _confiar_en(kernel, monkeypatch, certificado[0])
    with LaboratorioHttp(Escenario(cabeceras_seguridad=True, certificado=certificado)) as lab:
        token = _objetivo(kernel, lab)
        ejecucion = _procedimiento(kernel, token, lab, "security-headers", formulario="login")

    assert set(_estados(ejecucion)) == {"PASS"}
    assert len(ejecucion["resultados"]) == 5


# ----- TLS -------------------------------------------------------------------------------------


def test_tls_verificado_con_protocolo_y_caducidad_correctos(
    arrancar: Callable[..., Kernel],
    certificado: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = arrancar()
    _confiar_en(kernel, monkeypatch, certificado[0])
    with LaboratorioHttp(Escenario(certificado=certificado)) as lab:
        token = _objetivo(kernel, lab)
        ejecucion = _procedimiento(kernel, token, lab, "tls", formulario="login")

    assert _por_control(ejecucion) == {
        "tls-verificacion": "PASS",
        "tls-protocolo": "PASS",
        "tls-caducidad": "PASS",
    }
    assert "TLSv1" in _controles(ejecucion)["tls-protocolo"]["motivo"]


def test_tls_sin_https_es_FAIL_y_no_analiza_lo_demas(arrancar: Callable[..., Kernel]) -> None:
    kernel = arrancar()
    with LaboratorioHttp() as lab:
        token = _objetivo(kernel, lab)
        ejecucion = _procedimiento(kernel, token, lab, "tls", formulario="login")

    controles = _controles(ejecucion)
    assert controles["tls-verificacion"]["resultado"] == "FAIL"
    assert "no usa HTTPS" in controles["tls-verificacion"]["motivo"]
    assert controles["tls-protocolo"]["resultado"] == "SKIPPED"
    assert controles["tls-caducidad"]["resultado"] == "SKIPPED"


def test_certificado_no_confiable_no_se_acepta(
    arrancar: Callable[..., Kernel],
    certificado: Path,
) -> None:
    """Sin confianza explícita, un certificado autofirmado falla: la verificación no se desactiva."""
    kernel = arrancar()
    with LaboratorioHttp(Escenario(certificado=certificado)) as lab:
        token = _objetivo(kernel, lab)
        ejecucion = _procedimiento(kernel, token, lab, "tls", formulario="login")

    controles = _controles(ejecucion)
    assert controles["tls-verificacion"]["resultado"] == "FAIL"
    assert "certificado no verificable" in controles["tls-verificacion"]["motivo"]
    assert controles["tls-protocolo"]["resultado"] == "SKIPPED"


def test_certificado_que_caduca_pronto_es_FAIL(
    arrancar: Callable[..., Kernel],
    certificado_proximo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = arrancar()
    _confiar_en(kernel, monkeypatch, certificado_proximo[0])
    with LaboratorioHttp(Escenario(certificado=certificado_proximo)) as lab:
        token = _objetivo(kernel, lab)
        ejecucion = _procedimiento(kernel, token, lab, "tls", formulario="login")

    controles = _controles(ejecucion)
    assert controles["tls-verificacion"]["resultado"] == "PASS"
    assert controles["tls-caducidad"]["resultado"] == "FAIL"
    assert "caduca en" in controles["tls-caducidad"]["motivo"]


# ----- Cookies de sesión sobre HTTPS -----------------------------------------------------------


def test_cookie_secure_pasa_cuando_el_objetivo_usa_https(
    arrancar: Callable[..., Kernel],
    certificado: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = arrancar()
    _confiar_en(kernel, monkeypatch, certificado[0])
    with LaboratorioHttp(Escenario(cookie_secure=True, certificado=certificado)) as lab:
        token = _objetivo(kernel, lab)
        ejecucion = _procedimiento(kernel, token, lab, "sessions", formulario="login")

    controles = _controles(ejecucion)
    assert controles["sesion-cookie-1-secure"]["resultado"] == "PASS"
    assert controles["sesion-cookie-1-httponly"]["resultado"] == "PASS"


def test_cookie_sin_secure_por_https_es_FAIL(
    arrancar: Callable[..., Kernel],
    certificado: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = arrancar()
    _confiar_en(kernel, monkeypatch, certificado[0])
    with LaboratorioHttp(Escenario(cookie_secure=False, certificado=certificado)) as lab:
        token = _objetivo(kernel, lab)
        ejecucion = _procedimiento(kernel, token, lab, "sessions", formulario="login")

    assert _controles(ejecucion)["sesion-cookie-1-secure"]["resultado"] == "FAIL"


# ----- Tiempos de respuesta --------------------------------------------------------------------


def test_tiempos_parecidos_entre_cuentas_pasan(arrancar: Callable[..., Kernel]) -> None:
    kernel = arrancar()
    with LaboratorioHttp() as lab:
        token = _objetivo(kernel, lab)
        ejecucion = _procedimiento(kernel, token, lab, "timing", formulario="login")

    assert _por_control(ejecucion) == {"tiempos-diferencia": "PASS"}


def test_diferencia_de_tiempo_entre_cuentas_es_FAIL(arrancar: Callable[..., Kernel]) -> None:
    """Una cuenta existente tarda más: el tiempo revela qué cuentas existen aunque el mensaje sea igual."""
    kernel = arrancar()
    with LaboratorioHttp(Escenario(retardo_cuenta_existente_s=0.25)) as lab:
        token = _objetivo(kernel, lab)
        ejecucion = _procedimiento(kernel, token, lab, "timing", formulario="login")

    control = _controles(ejecucion)["tiempos-diferencia"]
    assert control["resultado"] == "FAIL"
    assert "diferencia" in control["motivo"]


def test_procedimientos_de_seguridad_requieren_objetivo_registrado(
    arrancar: Callable[..., Kernel],
) -> None:
    kernel = arrancar()
    token = _admin(kernel)
    with LaboratorioHttp() as lab, pytest.raises(AuthorizationError, match="no está registrado"):
        _procedimiento(kernel, token, lab, "security-headers", formulario="login")
