"""Submenú de pruebas HTTP en la terminal: menús, ayuda, confirmaciones y equivalencia con el servicio.

Las respuestas se simulan con listas. Cada prueba envía solicitudes reales al servidor de laboratorio,
así que la terminal y el servicio se comparan sobre el mismo comportamiento.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

import pytest

from natxajo_auditor.interfaces.terminal.app import run_terminal
from natxajo_auditor.kernel.kernel import Kernel
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER
from tests.laboratorio_http import CLAVE_A, CLAVE_B, LaboratorioHttp
from tests.test_pruebas_fiabilidad import _ejecucion_huerfana
from tests.test_pruebas_http import (
    CLAVE_OPERADOR,
    OPERADOR,
    _admin,
    _estados,
    _objetivo,
    _observados,
    _suite,
)

FIN = "0"  # Vuelve del submenú; después la terminal principal espera la siguiente opción.


def _scripted(answers: Iterable[str]) -> Callable[[str], str]:
    iterator = iter(answers)

    def read(prompt: str) -> str:
        try:
            return next(iterator)
        except StopIteration:
            raise EOFError from None

    return read


def _terminal(kernel: Kernel, lecturas: list[str], secretos: list[str]) -> list[str]:
    """Ejecuta la terminal con respuestas fijas. Devuelve todo lo que escribió."""
    lineas: list[str] = []
    codigo = run_terminal(
        kernel,
        read=_scripted(lecturas),
        write=lineas.append,
        read_secret=_scripted(secretos),
    )
    assert codigo == 0
    return lineas


def _texto(lineas: list[str]) -> str:
    return "\n".join(lineas)


# ----- Menús y ayuda --------------------------------------------------------------------------


def test_el_submenu_lista_formularios_y_cuentas_sin_mostrar_contrasenas(
    arrancar: Callable[..., Kernel],
) -> None:
    kernel = arrancar()
    lineas = _terminal(kernel, [ADMIN_USER, "34", "1", "2", FIN], [ADMIN_PASSWORD])

    salida = _texto(lineas)
    assert "PRUEBAS HTTP Y FORMULARIOS" in salida
    assert "login" in salida
    assert "acceso" in salida
    assert CLAVE_A not in salida
    assert CLAVE_B not in salida


def test_la_ayuda_contextual_explica_cada_opcion(arrancar: Callable[..., Kernel]) -> None:
    kernel = arrancar()
    lineas = _terminal(kernel, [ADMIN_USER, "34", "?6", "?99", FIN], [ADMIN_PASSWORD])

    salida = _texto(lineas)
    assert "Envía las solicitudes de una suite" in salida
    assert "Indique el número de una opción" in salida


def test_una_opcion_inexistente_no_cierra_el_submenu(arrancar: Callable[..., Kernel]) -> None:
    kernel = arrancar()
    lineas = _terminal(kernel, [ADMIN_USER, "34", "999", "4", FIN], [ADMIN_PASSWORD])

    salida = _texto(lineas)
    assert "Opción no válida" in salida
    assert "No hay objetivos registrados" in salida


# ----- Operaciones críticas --------------------------------------------------------------------


def test_registrar_un_objetivo_se_cancela_sin_confirmacion(arrancar: Callable[..., Kernel]) -> None:
    kernel = arrancar()
    with LaboratorioHttp() as lab:
        lineas = _terminal(kernel, [ADMIN_USER, "34", "5", lab.origen, "no", FIN], [ADMIN_PASSWORD])
        token = _admin(kernel)
        registrados = kernel.pruebas.objetivos(token)

    assert "Operación cancelada" in lineas
    assert registrados == []


def test_registrar_un_objetivo_con_confirmacion_lo_autoriza(
    arrancar: Callable[..., Kernel],
) -> None:
    kernel = arrancar()
    with LaboratorioHttp() as lab:
        lineas = _terminal(
            kernel,
            [ADMIN_USER, "34", "5", lab.origen, "sí", FIN],
            [ADMIN_PASSWORD, ADMIN_PASSWORD],
        )
        token = _admin(kernel)
        origenes = [o["origen"] for o in kernel.pruebas.objetivos(token)]

    assert f"Objetivo registrado: {lab.origen}" in lineas
    assert origenes == [lab.origen]


def test_una_suite_desde_la_terminal_da_los_mismos_resultados_que_el_servicio(
    arrancar: Callable[..., Kernel],
) -> None:
    kernel = arrancar()
    with LaboratorioHttp() as lab:
        token = _objetivo(kernel, lab)
        esperada = _suite(kernel, token, lab, "validation")
        lineas = _terminal(
            kernel,
            [ADMIN_USER, "34", "6", "validation", lab.origen, "login", "a", "sí", FIN],
            [ADMIN_PASSWORD, ADMIN_PASSWORD],
        )
        ejecutada = kernel.pruebas.inspeccionar(token, kernel.pruebas.historial(token)[0]["id"])

    assert _estados(ejecutada) == _estados(esperada)
    assert _observados(ejecutada) == _observados(esperada)
    totales = next(l for l in _texto(lineas).splitlines() if l.startswith("Totales: "))
    assert f"PASS={_estados(esperada).count('PASS')}" in totales
    assert f"SKIPPED={_estados(esperada).count('SKIPPED')}" in totales


def test_un_procedimiento_desde_la_terminal_registra_su_ejecucion(
    arrancar: Callable[..., Kernel],
) -> None:
    kernel = arrancar()
    with LaboratorioHttp() as lab:
        token = _objetivo(kernel, lab)
        lineas = _terminal(
            kernel,
            [ADMIN_USER, "34", "7", "security-headers", lab.origen, "login", "a", "sí", FIN],
            [ADMIN_PASSWORD, ADMIN_PASSWORD],
        )
        ejecucion: dict[str, Any] = kernel.pruebas.historial(token)[0]

    assert ejecucion["suite"] == "security-headers"
    assert any(linea.startswith("Ejecución ") for linea in lineas)


def test_una_entrada_vacia_muestra_el_error_y_no_abre_ejecucion(
    arrancar: Callable[..., Kernel],
) -> None:
    kernel = arrancar()
    with LaboratorioHttp() as lab:
        token = _objetivo(kernel, lab)
        lineas = _terminal(
            kernel,
            [ADMIN_USER, "34", "6", "validation", lab.origen, "login", "", FIN],
            [ADMIN_PASSWORD],
        )
        ejecuciones = kernel.pruebas.historial(token)

    assert "Error: falta el valor de «Cuentas sintéticas, separadas por comas»" in _texto(lineas)
    assert ejecuciones == []


def test_recuperar_desde_la_terminal_cierra_la_ejecucion_huerfana(
    arrancar: Callable[..., Kernel],
) -> None:
    kernel = arrancar()
    token = _admin(kernel)
    run_id = _ejecucion_huerfana(kernel, resultados=1, solicitudes=1)

    lineas = _terminal(
        kernel, [ADMIN_USER, "34", "12", "sí", FIN], [ADMIN_PASSWORD, ADMIN_PASSWORD]
    )

    ejecucion = kernel.pruebas.inspeccionar(token, run_id)
    assert ejecucion["estado"] == "cancelada"
    assert ejecucion["motivo_cierre"] == "interrumpida_recuperada"
    assert _estados(ejecucion) == ["PASS"]
    assert any(run_id in linea for linea in lineas)


# ----- Exportación y permisos ------------------------------------------------------------------


def test_exportar_y_verificar_desde_la_terminal(arrancar: Callable[..., Kernel]) -> None:
    kernel = arrancar()
    with LaboratorioHttp() as lab:
        token = _objetivo(kernel, lab)
        ejecucion = _suite(kernel, token, lab, "validation")
        lineas = _terminal(
            kernel,
            [ADMIN_USER, "34", "10", ejecucion["id"], "txt", "11", FIN],
            [ADMIN_PASSWORD],
        )

    salida = _texto(lineas)
    assert "Informe exportado:" in salida
    assert "estado" in salida
    assert "correcto" in salida


def test_un_operador_ve_el_submenu_pero_no_ejecuta(arrancar: Callable[..., Kernel]) -> None:
    kernel = arrancar()
    kernel.security.accounts.create(OPERADOR, CLAVE_OPERADOR, roles=["operador"])
    with LaboratorioHttp() as lab:
        token = _admin(kernel)
        kernel.pruebas.registrar_objetivo(token, lab.origen, confirmed=True)
        lineas = _terminal(
            kernel,
            [OPERADOR, "34", "6", FIN],
            [CLAVE_OPERADOR],
        )

    salida = _texto(lineas)
    assert "Formularios configurados" in salida
    assert "Ejecutar una suite" not in salida
    assert "Opción no disponible para su cuenta" in salida


@pytest.mark.parametrize("opcion", ["1", "2", "3", "4", "8", "9", "11"])
def test_las_consultas_no_piden_confirmacion(arrancar: Callable[..., Kernel], opcion: str) -> None:
    kernel = arrancar()
    lineas = _terminal(kernel, [ADMIN_USER, "34", opcion, FIN], [ADMIN_PASSWORD])

    assert "¿Confirma la operación?" not in _texto(lineas)
