"""CLI `natxajo` contra el motor real y el servidor de laboratorio.

Se invoca el mismo punto de entrada que usa PowerShell o CMD (`ejecutar_cli` y `main`), con
argumentos, contraseña leída de la entrada y salida capturada. Así se comprueban códigos de salida,
formatos, confirmación obligatoria, valores por defecto y el manejo de Ctrl+C.
"""

from __future__ import annotations

import io
import json
import signal
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from natxajo_auditor.interfaces.cli.app import construir_parser, ejecutar_cli
from natxajo_auditor.interfaces.cli.comandos import FORMATOS, SUITES_CUENTAS, SUITES_FORMULARIOS
from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.kernel import Kernel
from natxajo_auditor.main import main
from natxajo_auditor.pruebas.informes import FORMATOS as FORMATOS_MOTOR
from natxajo_auditor.pruebas.modelo import PROCEDURES, SUITES
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER, install_administrator
from tests.laboratorio_http import (
    CLAVE_A,
    LIMITES_PRUEBA,
    Escenario,
    LaboratorioHttp,
    entorno_de_prueba,
    escribir_configuracion,
)


@pytest.fixture
def cli_kernel(context: RuntimeContext, monkeypatch: pytest.MonkeyPatch) -> Iterator[Kernel]:
    for nombre, valor in entorno_de_prueba().items():
        monkeypatch.setenv(nombre, valor)
    escribir_configuracion(context.config_dir, limites={**LIMITES_PRUEBA})
    kernel = Kernel(context, password_iterations=1_000)
    kernel.start()
    install_administrator(kernel)
    yield kernel
    kernel.stop()


class Ejecucion:
    """Resultado de una invocación de la CLI: código, salida estándar y errores."""

    def __init__(self, codigo: int, salida: str, errores: str, pidio_contrasena: bool) -> None:
        self.codigo = codigo
        self.salida = salida
        self.errores = errores
        self.pidio_contrasena = pidio_contrasena


def _cli(
    kernel: Kernel,
    *argv: str,
    contrasena: str = ADMIN_PASSWORD,
    usuario: bool = True,
) -> Ejecucion:
    pidio: list[bool] = []

    def leer(_pregunta: str) -> str:
        pidio.append(True)
        return contrasena

    argumentos = list(argv)
    if usuario:
        argumentos += ["--usuario", ADMIN_USER]
    salida = io.StringIO()
    errores = io.StringIO()
    codigo = ejecutar_cli(
        kernel,
        argumentos,
        salida=salida,
        errores=errores,
        entrada=io.StringIO(""),
        leer_contrasena=leer,
    )
    return Ejecucion(codigo, salida.getvalue(), errores.getvalue(), bool(pidio))


def _registrar(kernel: Kernel, origen: str) -> None:
    resultado = _cli(kernel, "targets", "add", origen, "--confirmar")
    assert resultado.codigo == 0, resultado.errores


# ----- Catálogo y lectura ----------------------------------------------------------------------


def test_los_catalogos_de_la_cli_coinciden_con_el_motor() -> None:
    assert set(SUITES_FORMULARIOS) <= set(SUITES)
    assert set(SUITES_CUENTAS) <= set(SUITES)
    assert set(FORMATOS) == set(FORMATOS_MOTOR)
    assert {
        "rate-limit",
        "csrf",
        "mfa",
        "sessions",
        "response-check",
        "security-headers",
        "tls",
        "timing",
    } == set(PROCEDURES)


def test_forms_list_muestra_los_formularios_configurados(cli_kernel: Kernel) -> None:
    resultado = _cli(cli_kernel, "forms", "list")

    assert resultado.codigo == 0
    for formulario in ("login", "acceso", "mfa"):
        assert formulario in resultado.salida


def test_json_devuelve_datos_utilizables_por_scripts(cli_kernel: Kernel) -> None:
    resultado = _cli(cli_kernel, "forms", "list", "--json")

    datos = json.loads(resultado.salida)
    assert resultado.codigo == 0
    assert {f["id"] for f in datos} == {"login", "acceso", "mfa"}


def test_forms_validate_comprueba_variables_sin_enviar_nada(cli_kernel: Kernel) -> None:
    resultado = _cli(cli_kernel, "forms", "validate", "login")

    assert resultado.codigo == 0
    assert "contrasenas-en-entorno" in resultado.salida
    assert "FAIL" not in resultado.salida


def test_la_contrasena_nunca_aparece_en_la_salida(cli_kernel: Kernel) -> None:
    resultado = _cli(cli_kernel, "accounts", "list")

    assert resultado.codigo == 0
    assert CLAVE_A not in resultado.salida
    assert CLAVE_A not in resultado.errores
    assert "prueba-a" in resultado.salida


def test_test_suites_list_muestra_suites_y_procedimientos(cli_kernel: Kernel) -> None:
    resultado = _cli(cli_kernel, "test", "suites", "list")

    assert resultado.codigo == 0
    assert "login-validation" in resultado.salida
    assert "response-check" in resultado.salida


# ----- Errores y códigos de salida -------------------------------------------------------------


def test_una_operacion_critica_sin_confirmar_no_pide_contrasena(cli_kernel: Kernel) -> None:
    resultado = _cli(cli_kernel, "forms", "test", "--suite", "validation")

    assert resultado.codigo == 2
    assert "--confirmar" in resultado.errores
    assert resultado.pidio_contrasena is False


def test_contrasena_incorrecta_devuelve_3(cli_kernel: Kernel) -> None:
    resultado = _cli(cli_kernel, "forms", "list", contrasena="contraseña-equivocada-1")

    assert resultado.codigo == 3
    assert "contraseña-equivocada-1" not in resultado.errores


def test_suite_que_no_corresponde_al_comando_devuelve_2(cli_kernel: Kernel) -> None:
    resultado = _cli(cli_kernel, "forms", "test", "--suite", "credentials", "--confirmar")

    assert resultado.codigo == 2
    assert "acepta" in resultado.errores


def test_sin_objetivo_registrado_se_indica_como_registrarlo(cli_kernel: Kernel) -> None:
    resultado = _cli(cli_kernel, "forms", "test", "--suite", "validation", "--confirmar")

    assert resultado.codigo == 2
    assert "targets add" in resultado.errores


def test_varios_objetivos_obligan_a_indicar_uno(cli_kernel: Kernel) -> None:
    with LaboratorioHttp() as uno, LaboratorioHttp() as dos:
        _registrar(cli_kernel, uno.origen)
        _registrar(cli_kernel, dos.origen)
        resultado = _cli(cli_kernel, "forms", "test", "--suite", "validation", "--confirmar")

    assert resultado.codigo == 2
    assert "varios objetivos" in resultado.errores


def test_error_en_json_se_entrega_como_objeto(cli_kernel: Kernel) -> None:
    resultado = _cli(cli_kernel, "forms", "inspect", "no-existe", "--json")

    datos = json.loads(resultado.salida)
    assert resultado.codigo == 2
    assert datos["codigo"] == 2
    assert "no encontrado" in datos["error"]


# ----- Ejecuciones reales ----------------------------------------------------------------------


def test_suite_de_validacion_por_cli_contra_el_servidor(cli_kernel: Kernel) -> None:
    with LaboratorioHttp() as lab:
        _registrar(cli_kernel, lab.origen)
        resultado = _cli(
            cli_kernel, "forms", "test", "--suite", "validation", "--confirmar", "--json"
        )

    datos = json.loads(resultado.salida)
    assert resultado.codigo == 0, resultado.errores
    assert [r["resultado"] for r in datos["resultados"]] == ["PASS"] * 6
    assert datos["estado"] == "completada"


def test_un_unico_objetivo_se_usa_por_defecto(cli_kernel: Kernel) -> None:
    with LaboratorioHttp() as lab:
        _registrar(cli_kernel, lab.origen)
        resultado = _cli(cli_kernel, "test", "suites", "run", "format", "--confirmar")

    assert resultado.codigo == 0, resultado.errores
    assert "suite format" in resultado.salida


def test_un_resultado_fallido_devuelve_1(cli_kernel: Kernel) -> None:
    with LaboratorioHttp(Escenario(fallar_500=True)) as lab:
        _registrar(cli_kernel, lab.origen)
        resultado = _cli(cli_kernel, "forms", "test", "--suite", "validation", "--confirmar")

    assert resultado.codigo == 1
    assert "ERROR" in resultado.salida


def test_csrf_permisivo_por_cli_devuelve_1(cli_kernel: Kernel) -> None:
    with LaboratorioHttp(Escenario(csrf_obligatorio=False)) as lab:
        _registrar(cli_kernel, lab.origen)
        resultado = _cli(cli_kernel, "security", "csrf", "test", "--confirmar")

    assert resultado.codigo == 1
    assert "FAIL" in resultado.salida


def test_limite_de_frecuencia_por_cli_muestra_el_bloqueo(cli_kernel: Kernel) -> None:
    with LaboratorioHttp(Escenario(umbral_bloqueo=3)) as lab:
        _registrar(cli_kernel, lab.origen)
        resultado = _cli(cli_kernel, "security", "rate-limit", "test", "--confirmar")

    assert resultado.codigo == 0, resultado.errores
    assert "BLOCKED" in resultado.salida


def test_mfa_por_cli_completa_los_dos_factores(cli_kernel: Kernel) -> None:
    with LaboratorioHttp() as lab:
        _registrar(cli_kernel, lab.origen)
        resultado = _cli(cli_kernel, "auth", "mfa", "test", "--confirmar", "--json")

    datos = json.loads(resultado.salida)
    assert resultado.codigo == 0, resultado.errores
    assert [r["resultado"] for r in datos["resultados"]] == ["PASS"] * 3


def test_solo_una_cuenta_en_los_procedimientos(cli_kernel: Kernel) -> None:
    with LaboratorioHttp() as lab:
        _registrar(cli_kernel, lab.origen)
        resultado = _cli(
            cli_kernel,
            "auth",
            "sessions",
            "inspect",
            "--cuenta",
            "a",
            "--cuenta",
            "b",
            "--confirmar",
        )

    assert resultado.codigo == 2
    assert "una sola cuenta" in resultado.errores


def test_informes_se_generan_se_verifican_y_una_alteracion_se_detecta(
    cli_kernel: Kernel, context: RuntimeContext
) -> None:
    with LaboratorioHttp() as lab:
        _registrar(cli_kernel, lab.origen)
        _cli(cli_kernel, "forms", "test", "--suite", "validation", "--confirmar")

    generado = _cli(cli_kernel, "reports", "generate", "--json")
    datos = json.loads(generado.salida)
    assert generado.codigo == 0
    assert {d["formato"] for d in datos} == {"json", "csv", "html", "txt"}

    verificado = _cli(cli_kernel, "reports", "verify")
    assert verificado.codigo == 0
    assert verificado.salida.count("correcto") == 4

    Path(datos[0]["ruta"]).write_bytes(b"manipulado")
    alterado = _cli(cli_kernel, "reports", "verify")
    assert alterado.codigo == 1
    assert "alterado" in alterado.salida


def test_reports_export_escribe_un_solo_formato(cli_kernel: Kernel) -> None:
    with LaboratorioHttp() as lab:
        _registrar(cli_kernel, lab.origen)
        _cli(cli_kernel, "forms", "test", "--suite", "validation", "--confirmar")

    resultado = _cli(cli_kernel, "reports", "export", "--format", "json", "--json")

    datos = json.loads(resultado.salida)
    assert resultado.codigo == 0
    assert datos["formato"] == "json"
    assert Path(datos["ruta"]).is_file()


def test_formato_de_informe_desconocido_se_rechaza_al_analizar(cli_kernel: Kernel) -> None:
    resultado = _cli(cli_kernel, "reports", "export", "--format", "pdf")

    assert resultado.codigo == 2
    assert "pdf" in resultado.errores


def test_requests_inspect_sin_identificador_usa_la_ultima_ejecucion(cli_kernel: Kernel) -> None:
    with LaboratorioHttp() as lab:
        _registrar(cli_kernel, lab.origen)
        _cli(cli_kernel, "test", "suites", "run", "validation", "--confirmar")

    historial = _cli(cli_kernel, "requests", "history", "--json")
    inspeccion = _cli(cli_kernel, "requests", "inspect")

    assert historial.codigo == 0
    assert len(json.loads(historial.salida)) == 1
    assert inspeccion.codigo == 0
    assert "estado completada" in inspeccion.salida


def test_una_cancelacion_con_ctrl_c_conserva_lo_evaluado(cli_kernel: Kernel) -> None:
    previo = signal.getsignal(signal.SIGINT)
    with LaboratorioHttp(Escenario(retardo_s=0.3)) as lab:
        _registrar(cli_kernel, lab.origen)
        disparo = threading.Timer(0.5, lambda: signal.raise_signal(signal.SIGINT))
        disparo.start()
        try:
            resultado = _cli(cli_kernel, "forms", "test", "--suite", "validation", "--confirmar")
        finally:
            disparo.cancel()

    assert resultado.codigo == 4
    assert signal.getsignal(signal.SIGINT) == previo
    historial = _cli(cli_kernel, "requests", "history", "--json")
    assert json.loads(historial.salida)[0]["estado"] == "cancelada"


def test_el_punto_de_entrada_principal_enruta_los_comandos(
    context: RuntimeContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for nombre, valor in entorno_de_prueba().items():
        monkeypatch.setenv(nombre, valor)
    monkeypatch.setattr(
        "natxajo_auditor.interfaces.cli.app.getpass.getpass",
        lambda _pregunta: "no-se-usa",
    )
    monkeypatch.setattr(sys, "stdin", io.StringIO("contraseña-equivocada-1\n"))
    codigo = main(
        ["accounts", "list", "--usuario", ADMIN_USER, "--contrasena-desde-entrada"],
        project_root=context.project_root,
    )
    assert codigo == 3


def test_el_parser_expone_los_grupos_de_comandos() -> None:
    parser = construir_parser()
    args: Any = parser.parse_args(["security", "response-check", "--confirmar", "--usuario", "x"])
    assert args.grupo == "security"
    assert args.ejecuta is True
    assert args.critico is True


@pytest.mark.parametrize(
    "argumentos",
    [
        ["forms", "test"],
        ["targets", "add"],
        ["requests", "history", "--limite", "0"],
    ],
)
def test_argumentos_incompletos_se_rechazan(cli_kernel: Kernel, argumentos: list[str]) -> None:
    resultado = _cli(cli_kernel, *argumentos)
    assert resultado.codigo == 2
    assert resultado.errores


def test_sin_argumentos_se_muestra_la_ayuda(cli_kernel: Kernel) -> None:
    salida = io.StringIO()
    codigo = ejecutar_cli(cli_kernel, [], salida=salida, errores=io.StringIO())
    assert codigo == 2
    assert "grupo" in salida.getvalue()
