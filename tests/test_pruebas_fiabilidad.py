"""Fiabilidad del motor HTTP: persistencia parcial, recuperación, cambios de DNS y exportación atómica.

Las pruebas usan el servidor de laboratorio en 127.0.0.1. Cuando hace falta forzar un fallo, un
cambio de resolución o un error de base de datos, se sustituye solo ese punto. Lo demás es el motor
real, con sus solicitudes reales y su base de datos.
"""

from __future__ import annotations

import socket
import sqlite3
import uuid
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.kernel.composition import DATABASE
from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.kernel import Kernel
from natxajo_auditor.pruebas import motor
from natxajo_auditor.pruebas.cliente import CambioDnsError
from natxajo_auditor.pruebas.modelo import Resultado, ResultadoCaso
from natxajo_auditor.pruebas.repositorio import RepositorioPruebas
from tests.conftest import ADMIN_USER, install_administrator
from tests.laboratorio_http import (
    LIMITES_PRUEBA,
    LaboratorioHttp,
    entorno_de_prueba,
    escribir_configuracion,
)
from tests.test_pruebas_http import _admin, _ejecuciones, _estados, _objetivo, _suite

ORIGEN_HUERFANO = "http://127.0.0.1:9"


@pytest.fixture
def entorno(monkeypatch: pytest.MonkeyPatch) -> None:
    for nombre, valor in entorno_de_prueba().items():
        monkeypatch.setenv(nombre, valor)


@pytest.fixture
def arrancar(context: RuntimeContext, entorno: None) -> Iterator[Callable[..., Kernel]]:
    kernels: list[Kernel] = []

    def _crear(**limites: Any) -> Kernel:
        escribir_configuracion(context.config_dir, limites={**LIMITES_PRUEBA, **limites})
        kernel = Kernel(context, password_iterations=1_000)
        kernel.start()
        install_administrator(kernel)
        kernels.append(kernel)
        return kernel

    yield _crear
    for kernel in kernels:
        kernel.stop()


def _resultado(posicion: int, resultado: Resultado = Resultado.PASS) -> ResultadoCaso:
    return ResultadoCaso(
        posicion=posicion,
        caso_id=f"caso-{posicion}",
        formulario_id="login",
        tipo="login",
        cuenta="a",
        resultado=resultado,
        esperado="ACEPTADA",
        observado="ACEPTADA",
        codigo_http=302,
        duracion_ms=5,
        motivo="prueba",
    )


def _ejecucion_huerfana(kernel: Kernel, resultados: int, solicitudes: int) -> str:
    """Deja una ejecución en curso, como la dejaría un proceso que se detuvo sin cerrarla."""
    run_id = str(uuid.uuid4())
    database = kernel.services.fetch(DATABASE)
    repo = RepositorioPruebas(database)
    with database.transaction() as conexion:
        # La ejecución referencia un objetivo registrado: se registra como lo haría el operador.
        repo.registrar_objetivo(conexion, ORIGEN_HUERFANO, ADMIN_USER, "2026-11-27T09:00:00Z")
        repo.abrir_ejecucion(
            conexion,
            run_id=run_id,
            suite="validation",
            origen=ORIGEN_HUERFANO,
            esquema_sha256="0" * 64,
            usuario=ADMIN_USER,
            iniciado_en="2026-11-27T10:00:00Z",
            casos=6,
        )
    for posicion in range(1, resultados + 1):
        with database.transaction() as conexion:
            repo.registrar_resultado(conexion, run_id, _resultado(posicion))
    with database.transaction() as conexion:
        repo.progreso(conexion, run_id, solicitudes)
    return run_id


def _eventos(kernel: Kernel, tipo: str) -> int:
    filas = kernel.services.fetch(DATABASE).fetchall(
        "SELECT COUNT(*) FROM audit_events WHERE event_type = ?", (tipo,)
    )
    return int(filas[0][0])


# ----- Persistencia de resultados ya obtenidos -------------------------------------------------


def test_un_fallo_a_mitad_conserva_lo_ya_registrado(
    arrancar: Callable[..., Kernel], monkeypatch: pytest.MonkeyPatch
) -> None:
    kernel = arrancar(concurrencia=1)
    clasificar_original = motor.clasificar
    llamadas = {"n": 0}

    def clasificar_con_fallo(respuesta: Any, reglas: Any) -> Any:
        llamadas["n"] += 1
        if llamadas["n"] == 3:
            raise RuntimeError("fallo simulado")
        return clasificar_original(respuesta, reglas)

    monkeypatch.setattr(motor, "clasificar", clasificar_con_fallo)
    with LaboratorioHttp() as lab:
        token = _objetivo(kernel, lab)
        with pytest.raises(RuntimeError, match="fallo simulado"):
            _suite(kernel, token, lab, "validation")

    run_id = kernel.pruebas.historial(token)[0]["id"]
    ejecucion = kernel.pruebas.inspeccionar(token, run_id)
    assert ejecucion["estado"] == "cancelada"
    assert ejecucion["motivo_cierre"] == "fallo_tecnico"
    estados = _estados(ejecucion)
    assert estados[:2] == ["PASS", "PASS"]
    assert estados[2:] == ["SKIPPED"] * 4
    assert [r["posicion"] for r in ejecucion["resultados"]] == [1, 2, 3, 4, 5, 6]
    assert all("no registrado" in r["motivo"] for r in ejecucion["resultados"][2:])


def test_un_resultado_no_se_puede_insertar_dos_veces(kernel: Kernel) -> None:
    """La clave (ejecución, posición) impide duplicar un resultado aunque se reintente la escritura."""
    database = kernel.services.fetch(DATABASE)
    repo = RepositorioPruebas(database)
    run_id = _ejecucion_huerfana(kernel, resultados=1, solicitudes=1)
    with (
        pytest.raises(sqlite3.IntegrityError),
        database.transaction() as conexion,
    ):
        repo.registrar_resultado(conexion, run_id, _resultado(1))


# ----- Cambios de DNS y errores de resolución --------------------------------------------------


def test_un_cambio_de_dns_cierra_la_ejecucion_y_conserva_lo_evaluado(
    arrancar: Callable[..., Kernel], monkeypatch: pytest.MonkeyPatch
) -> None:
    kernel = arrancar(concurrencia=1)
    llamadas = {"n": 0}

    def resolver(host: str, puerto: int) -> frozenset[str]:
        # 1 al fijar la dirección y luego una por petición: la sexta petición ya apunta a otra IP.
        llamadas["n"] += 1
        return frozenset({"10.0.0.9"}) if llamadas["n"] >= 6 else frozenset({"127.0.0.1"})

    monkeypatch.setattr(kernel.pruebas, "_resolver", resolver)
    with LaboratorioHttp() as lab:
        token = _objetivo(kernel, lab)
        with pytest.raises(CambioDnsError, match="otra dirección"):
            _suite(kernel, token, lab, "validation")

    run_id = kernel.pruebas.historial(token)[0]["id"]
    ejecucion = kernel.pruebas.inspeccionar(token, run_id)
    assert ejecucion["estado"] == "cancelada"
    assert ejecucion["motivo_cierre"] == "cambio_dns"
    estados = _estados(ejecucion)
    assert len(estados) == 6
    assert estados[:2] == ["PASS", "PASS"]
    assert estados[2:] == ["SKIPPED"] * 4
    assert all("cambio de dirección" in r["motivo"] for r in ejecucion["resultados"][2:])


def test_un_objetivo_que_no_resuelve_no_abre_ejecucion(
    arrancar: Callable[..., Kernel], monkeypatch: pytest.MonkeyPatch
) -> None:
    kernel = arrancar()

    def sin_resolucion(host: str, puerto: int) -> frozenset[str]:
        raise socket.gaierror("sin resolución")

    monkeypatch.setattr(kernel.pruebas, "_resolver", sin_resolucion)
    with LaboratorioHttp() as lab:
        token = _objetivo(kernel, lab)
        with pytest.raises(ValidationError, match="no se puede resolver"):
            _suite(kernel, token, lab, "validation")
    assert _ejecuciones(kernel) == 0


def test_un_fallo_de_resolucion_durante_la_ejecucion_produce_ERROR(
    arrancar: Callable[..., Kernel], monkeypatch: pytest.MonkeyPatch
) -> None:
    kernel = arrancar(concurrencia=1)
    llamadas = {"n": 0}

    def resolver_intermitente(host: str, puerto: int) -> frozenset[str]:
        llamadas["n"] += 1
        if llamadas["n"] == 1:
            return frozenset({"127.0.0.1"})
        raise socket.gaierror("fallo temporal del DNS")

    monkeypatch.setattr(kernel.pruebas, "_resolver", resolver_intermitente)
    with LaboratorioHttp() as lab:
        token = _objetivo(kernel, lab)
        ejecucion = _suite(kernel, token, lab, "validation")
        peticiones = lab.peticiones

    assert _estados(ejecucion) == ["ERROR"] * 6
    assert peticiones == 0
    assert ejecucion["estado"] == "completada"
    assert ejecucion["motivo_cierre"] is None


# ----- Recuperación de ejecuciones interrumpidas -----------------------------------------------


def test_recuperar_cierra_las_ejecuciones_huerfanas_sin_perder_resultados(
    arrancar: Callable[..., Kernel],
) -> None:
    kernel = arrancar()
    token = _admin(kernel)
    run_id = _ejecucion_huerfana(kernel, resultados=1, solicitudes=2)

    recuperadas = kernel.pruebas.recuperar_interrumpidas(token, confirmed=True)

    assert recuperadas == [{"run_id": run_id, "resultados": 1, "solicitudes": 2}]
    ejecucion = kernel.pruebas.inspeccionar(token, run_id)
    assert ejecucion["estado"] == "cancelada"
    assert ejecucion["motivo_cierre"] == "interrumpida_recuperada"
    assert ejecucion["solicitudes"] == 2
    assert _estados(ejecucion) == ["PASS"]
    assert _eventos(kernel, "pruebas.ejecucion_recuperada") == 1


def test_recuperar_no_cierra_dos_veces_una_ejecucion(arrancar: Callable[..., Kernel]) -> None:
    kernel = arrancar()
    token = _admin(kernel)
    _ejecucion_huerfana(kernel, resultados=0, solicitudes=0)

    assert len(kernel.pruebas.recuperar_interrumpidas(token, confirmed=True)) == 1
    assert kernel.pruebas.recuperar_interrumpidas(token, confirmed=True) == []
    assert _eventos(kernel, "pruebas.ejecucion_recuperada") == 1


def test_el_informe_de_una_ejecucion_recuperada_muestra_el_motivo(
    arrancar: Callable[..., Kernel],
) -> None:
    kernel = arrancar()
    token = _admin(kernel)
    run_id = _ejecucion_huerfana(kernel, resultados=1, solicitudes=1)
    kernel.pruebas.recuperar_interrumpidas(token, confirmed=True)

    informe = kernel.pruebas.exportar(token, run_id, "txt")

    contenido = _leer(informe["ruta"])
    assert "motivo_cierre: interrumpida_recuperada" in contenido
    assert kernel.pruebas.verificar_informes(token)[0]["estado"] == "correcto"


# ----- Exportación atómica ---------------------------------------------------------------------


def test_una_exportacion_que_no_se_registra_no_deja_archivo(
    arrancar: Callable[..., Kernel],
    context: RuntimeContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = arrancar()
    with LaboratorioHttp() as lab:
        token = _objetivo(kernel, lab)
        ejecucion = _suite(kernel, token, lab, "validation")

    def registro_fallido(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("base de datos no disponible")

    monkeypatch.setattr(kernel.pruebas, "_registrar_exportacion_en_db", registro_fallido)
    with pytest.raises(RuntimeError, match="no disponible"):
        kernel.pruebas.exportar(token, ejecucion["id"], "json")

    carpeta = context.reports_dir / "pruebas"
    archivos = list(carpeta.glob("*")) if carpeta.exists() else []
    assert archivos == []
    assert kernel.pruebas.verificar_informes(token) == []


def _leer(ruta: str) -> str:
    with open(ruta, encoding="utf-8") as fichero:
        return fichero.read()
