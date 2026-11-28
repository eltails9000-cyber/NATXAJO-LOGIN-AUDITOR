"""Motor de pruebas HTTP contra el servidor de laboratorio, con red real en 127.0.0.1.

Cada prueba envía solicitudes reales, recibe respuestas reales y comprueba el resultado que el motor
registra. Los escenarios activan un comportamiento concreto del servidor (CSRF permisivo, límite de
intentos, mensajes que revelan usuarios, errores 500, latencia) para que el motor deba detectarlo.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from natxajo_auditor.core.exceptions import AuthorizationError, ValidationError
from natxajo_auditor.kernel.composition import DATABASE
from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.kernel import Kernel
from natxajo_auditor.pruebas.repositorio import RepositorioPruebas
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER, install_administrator
from tests.laboratorio_http import (
    CLAVE_A,
    CLAVE_B,
    LIMITES_PRUEBA,
    Escenario,
    LaboratorioHttp,
    entorno_de_prueba,
    escribir_configuracion,
)

OPERADOR = "operador-prueba"
CLAVE_OPERADOR = "contraseña-de-operador-1"


@pytest.fixture
def entorno(monkeypatch: pytest.MonkeyPatch) -> None:
    for nombre, valor in entorno_de_prueba().items():
        monkeypatch.setenv(nombre, valor)


@pytest.fixture
def arrancar(context: RuntimeContext, entorno: None) -> Iterator[Callable[..., Kernel]]:
    """Arranca la plataforma con configuración de prueba y la detiene al terminar la prueba."""
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


@pytest.fixture
def plataforma(arrancar: Callable[..., Kernel]) -> Kernel:
    return arrancar()


def _admin(kernel: Kernel) -> str:
    token = kernel.security.login(ADMIN_USER, ADMIN_PASSWORD)
    kernel.security.reauthenticate(token, ADMIN_PASSWORD)
    return token


def _objetivo(kernel: Kernel, lab: LaboratorioHttp) -> str:
    token = _admin(kernel)
    kernel.pruebas.registrar_objetivo(token, lab.origen, confirmed=True)
    return token


def _suite(
    kernel: Kernel,
    token: str,
    lab: LaboratorioHttp,
    suite: str,
    *,
    formulario: str = "login",
    cuentas: tuple[str, ...] = ("a",),
    cancelacion: threading.Event | None = None,
) -> dict[str, Any]:
    return kernel.pruebas.ejecutar_suite(
        token,
        suite=suite,
        objetivo=lab.origen,
        formulario_id=formulario,
        cuentas=list(cuentas),
        confirmed=True,
        cancelacion=cancelacion,
    )


def _procedimiento(
    kernel: Kernel,
    token: str,
    lab: LaboratorioHttp,
    nombre: str,
    *,
    formulario: str,
    cuenta: str = "a",
) -> dict[str, Any]:
    return kernel.pruebas.ejecutar_procedimiento(
        token,
        nombre=nombre,
        objetivo=lab.origen,
        formulario_id=formulario,
        cuenta=cuenta,
        confirmed=True,
    )


def _estados(ejecucion: dict[str, Any]) -> list[str]:
    return [str(r["resultado"]) for r in ejecucion["resultados"]]


def _observados(ejecucion: dict[str, Any]) -> list[str]:
    return [str(r["observado"]) for r in ejecucion["resultados"]]


def _ejecuciones(kernel: Kernel) -> int:
    filas = kernel.services.fetch(DATABASE).fetchall("SELECT COUNT(*) FROM http_runs")
    return int(filas[0][0])


# ----- Configuración y solo lectura ------------------------------------------------------------


def test_formularios_y_cuentas_se_leen_sin_exponer_contrasenas(plataforma: Kernel) -> None:
    token = _admin(plataforma)

    formularios = plataforma.pruebas.formularios(token)
    cuentas = plataforma.pruebas.cuentas(token)

    assert {f["id"] for f in formularios} == {"login", "acceso", "mfa"}
    assert [c["id"] for c in cuentas] == ["a", "b"]
    assert all(c["contrasena_en_entorno"] for c in cuentas)
    assert CLAVE_A not in repr(cuentas)
    assert CLAVE_B not in repr(formularios)


def test_validar_comprueba_entorno_csrf_y_mfa_sin_enviar_nada(plataforma: Kernel) -> None:
    token = _admin(plataforma)

    controles = {c["control"]: c["estado"] for c in plataforma.pruebas.validar(token, "login")}
    controles_mfa = {c["control"]: c["estado"] for c in plataforma.pruebas.validar(token, "mfa")}

    assert controles["cuentas-sinteticas"] == "PASS"
    assert controles["contrasenas-en-entorno"] == "PASS"
    assert controles["csrf"] == "PASS"
    assert controles["codigo-mfa"] == "SKIPPED"
    assert controles_mfa["codigo-mfa"] == "PASS"
    assert controles_mfa["csrf"] == "SKIPPED"
    assert plataforma.pruebas.historial(token) == []


# ----- Suites contra el servidor real ----------------------------------------------------------


def test_validacion_de_campos_se_evalua_contra_respuestas_reales(plataforma: Kernel) -> None:
    with LaboratorioHttp() as lab:
        token = _objetivo(plataforma, lab)
        ejecucion = _suite(plataforma, token, lab, "validation")

    assert ejecucion["estado"] == "completada"
    assert _estados(ejecucion) == ["PASS"] * 6
    assert {r["codigo_http"] for r in ejecucion["resultados"]} == {400}
    assert set(_observados(ejecucion)) == {"rechazada"}
    assert all(r["duracion_ms"] is not None for r in ejecucion["resultados"])


def test_formato_y_longitudes_se_rechazan_con_422(plataforma: Kernel) -> None:
    with LaboratorioHttp() as lab:
        token = _objetivo(plataforma, lab)
        login = _suite(plataforma, token, lab, "format", formulario="login")
        acceso = _suite(plataforma, token, lab, "format", formulario="acceso")

    assert _estados(login) == ["PASS"] * 4
    assert _estados(acceso) == ["PASS"] * 5
    # Tres casos rechazados por formato (422). Los caracteres especiales llegan al servidor como
    # un usuario inexistente: responde 200 con credenciales incorrectas, y eso también es PASS.
    assert sorted(r["codigo_http"] for r in login["resultados"]) == [200, 422, 422, 422]


def test_credenciales_validas_e_incorrectas_se_distinguen(plataforma: Kernel) -> None:
    with LaboratorioHttp() as lab:
        token = _objetivo(plataforma, lab)
        ejecucion = _suite(plataforma, token, lab, "credentials")
        acceso = _suite(plataforma, token, lab, "credentials", formulario="acceso")

    assert _estados(ejecucion) == ["PASS", "PASS", "PASS"]
    assert _observados(ejecucion) == ["aceptada", "rechazada", "rechazada"]
    assert [r["codigo_http"] for r in ejecucion["resultados"]] == [302, 200, 200]
    assert _observados(acceso) == ["aceptada", "rechazada", "rechazada"]


def test_formulario_mfa_acepta_el_primer_factor_con_su_marcador(plataforma: Kernel) -> None:
    with LaboratorioHttp() as lab:
        token = _objetivo(plataforma, lab)
        ejecucion = _suite(plataforma, token, lab, "credentials", formulario="mfa")

    assert _estados(ejecucion) == ["PASS", "PASS", "PASS"]
    assert _observados(ejecucion) == ["aceptada", "rechazada", "rechazada"]


def test_cuentas_sinteticas_se_prueban_una_a_una(plataforma: Kernel) -> None:
    with LaboratorioHttp() as lab:
        token = _objetivo(plataforma, lab)
        ejecucion = _suite(plataforma, token, lab, "synthetic-accounts", cuentas=("a", "b"))

    assert _estados(ejecucion) == ["PASS"] * 4
    assert [r["cuenta"] for r in ejecucion["resultados"]] == ["a", "a", "b", "b"]
    assert ejecucion["solicitudes"] >= 4


def test_login_validation_agrupa_validacion_y_formato(plataforma: Kernel) -> None:
    with LaboratorioHttp() as lab:
        token = _objetivo(plataforma, lab)
        ejecucion = _suite(plataforma, token, lab, "login-validation")

    assert len(ejecucion["resultados"]) == 10
    assert _estados(ejecucion) == ["PASS"] * 10


def test_el_motor_no_sigue_redirecciones(plataforma: Kernel) -> None:
    with LaboratorioHttp() as lab:
        token = _objetivo(plataforma, lab)
        _suite(plataforma, token, lab, "credentials")
        visitadas = set(lab.rutas_visitadas)

    assert "/inicio" not in visitadas
    assert "/login" in visitadas


# ----- Procedimientos de seguridad -------------------------------------------------------------


def test_csrf_correcto_acepta_solo_el_token_real(plataforma: Kernel) -> None:
    with LaboratorioHttp() as lab:
        token = _objetivo(plataforma, lab)
        ejecucion = _procedimiento(plataforma, token, lab, "csrf", formulario="login")

    assert _estados(ejecucion) == ["PASS", "PASS", "PASS"]
    assert _observados(ejecucion) == ["rechazada", "rechazada", "aceptada"]


def test_csrf_permisivo_se_detecta_como_FAIL(plataforma: Kernel) -> None:
    escenario = Escenario(csrf_obligatorio=False)
    with LaboratorioHttp(escenario) as lab:
        token = _objetivo(plataforma, lab)
        ejecucion = _procedimiento(plataforma, token, lab, "csrf", formulario="login")

    por_id = {r["caso"]: r["resultado"] for r in ejecucion["resultados"]}
    assert por_id["csrf-envio-sin-token"] == "FAIL"
    assert por_id["csrf-token-incorrecto"] == "PASS"
    assert por_id["csrf-token-valido"] == "PASS"


def test_csrf_no_aplica_a_formularios_sin_token(plataforma: Kernel) -> None:
    with LaboratorioHttp() as lab:
        token = _objetivo(plataforma, lab)
        ejecucion = _procedimiento(plataforma, token, lab, "csrf", formulario="acceso")

    assert _estados(ejecucion) == ["SKIPPED"]


def test_limite_de_frecuencia_observa_el_bloqueo_del_servidor(plataforma: Kernel) -> None:
    with LaboratorioHttp(Escenario(umbral_bloqueo=3)) as lab:
        token = _objetivo(plataforma, lab)
        ejecucion = _procedimiento(plataforma, token, lab, "rate-limit", formulario="login")

    assert _estados(ejecucion) == ["PASS", "PASS", "PASS", "BLOCKED", "PASS"]
    bloqueada = ejecucion["resultados"][3]
    assert bloqueada["codigo_http"] == 429
    assert bloqueada["observado"] == "bloqueada"
    assert "tras 4 intentos" in ejecucion["resultados"][4]["motivo"]


def test_limite_de_frecuencia_sin_bloqueo_es_FAIL(plataforma: Kernel) -> None:
    with LaboratorioHttp() as lab:
        token = _objetivo(plataforma, lab)
        ejecucion = _procedimiento(plataforma, token, lab, "rate-limit", formulario="login")

    resumen = ejecucion["resultados"][-1]
    assert resumen["caso"] == "limite-frecuencia-resumen"
    assert resumen["resultado"] == "FAIL"
    assert "no se observó bloqueo" in resumen["motivo"]


def test_mfa_con_codigo_de_prueba_completa_los_dos_factores(plataforma: Kernel) -> None:
    with LaboratorioHttp() as lab:
        token = _objetivo(plataforma, lab)
        ejecucion = _procedimiento(plataforma, token, lab, "mfa", formulario="mfa")

    assert _estados(ejecucion) == ["PASS", "PASS", "PASS"]
    assert _observados(ejecucion) == ["aceptada", "rechazada", "aceptada"]
    assert [r["codigo_http"] for r in ejecucion["resultados"]] == [200, 200, 302]


def test_mfa_sin_codigo_de_prueba_no_abre_ejecucion(plataforma: Kernel) -> None:
    with LaboratorioHttp() as lab:
        token = _objetivo(plataforma, lab)
        with pytest.raises(ValidationError, match="no declara variable_mfa"):
            _procedimiento(plataforma, token, lab, "mfa", formulario="mfa", cuenta="b")
    assert _ejecuciones(plataforma) == 0


def test_cookies_de_sesion_se_analizan_sin_leer_su_valor(plataforma: Kernel) -> None:
    with LaboratorioHttp() as lab:
        token = _objetivo(plataforma, lab)
        ejecucion = _procedimiento(plataforma, token, lab, "sessions", formulario="login")

    por_id = {r["caso"]: r for r in ejecucion["resultados"]}
    assert por_id["sesion-cookie-1-httponly"]["resultado"] == "PASS"
    assert por_id["sesion-cookie-1-samesite"]["resultado"] == "PASS"
    assert por_id["sesion-cookie-1-secure"]["resultado"] == "SKIPPED"
    assert "sid=" not in repr(ejecucion)


def test_cookie_sin_httponly_se_detecta_como_FAIL(plataforma: Kernel) -> None:
    with LaboratorioHttp(Escenario(cookie_httponly=False)) as lab:
        token = _objetivo(plataforma, lab)
        ejecucion = _procedimiento(plataforma, token, lab, "sessions", formulario="login")

    por_id = {r["caso"]: r["resultado"] for r in ejecucion["resultados"]}
    assert por_id["sesion-cookie-1-httponly"] == "FAIL"


def test_respuestas_consistentes_pasan_la_comprobacion(plataforma: Kernel) -> None:
    with LaboratorioHttp() as lab:
        token = _objetivo(plataforma, lab)
        ejecucion = _procedimiento(plataforma, token, lab, "response-check", formulario="login")

    assert _estados(ejecucion) == ["PASS", "PASS", "PASS"]


def test_mensaje_que_revela_usuarios_se_detecta_como_FAIL(plataforma: Kernel) -> None:
    with LaboratorioHttp(Escenario(revelar_usuario=True)) as lab:
        token = _objetivo(plataforma, lab)
        ejecucion = _procedimiento(plataforma, token, lab, "response-check", formulario="login")

    por_id = {r["caso"]: r["resultado"] for r in ejecucion["resultados"]}
    assert por_id["consistencia-clasificacion"] == "PASS"
    assert por_id["consistencia-tamano-cuerpo"] == "FAIL"


# ----- Errores, límites y cancelación ----------------------------------------------------------


def test_error_del_servidor_se_registra_como_ERROR(plataforma: Kernel) -> None:
    with LaboratorioHttp(Escenario(fallar_500=True)) as lab:
        token = _objetivo(plataforma, lab)
        ejecucion = _suite(plataforma, token, lab, "validation")

    assert _estados(ejecucion) == ["ERROR"] * 6
    assert {r["codigo_http"] for r in ejecucion["resultados"]} == {500}
    assert all("HTTP 500" in r["motivo"] for r in ejecucion["resultados"])
    assert ejecucion["estado"] == "completada"


def test_tiempo_maximo_por_peticion_produce_ERROR(arrancar: Callable[..., Kernel]) -> None:
    kernel = arrancar(timeout_s=0.5)
    with LaboratorioHttp(Escenario(retardo_s=1.5)) as lab:
        token = _objetivo(kernel, lab)
        ejecucion = _suite(kernel, token, lab, "credentials")

    assert _estados(ejecucion) == ["ERROR"] * 3
    assert all("tiempo máximo" in r["motivo"] for r in ejecucion["resultados"])


def test_servidor_inalcanzable_produce_ERROR_de_conexion(plataforma: Kernel) -> None:
    with LaboratorioHttp() as lab:
        origen = lab.origen
    token = _admin(plataforma)
    plataforma.pruebas.registrar_objetivo(token, origen, confirmed=True)
    ejecucion = plataforma.pruebas.ejecutar_suite(
        token,
        suite="validation",
        objetivo=origen,
        formulario_id="login",
        cuentas=["a"],
        confirmed=True,
    )

    assert _estados(ejecucion) == ["ERROR"] * 6
    assert all("error de conexión" in r["motivo"] for r in ejecucion["resultados"])


def test_presupuesto_de_solicitudes_detiene_la_ejecucion(arrancar: Callable[..., Kernel]) -> None:
    kernel = arrancar(max_solicitudes=3)
    with LaboratorioHttp() as lab:
        token = _objetivo(kernel, lab)
        ejecucion = _suite(kernel, token, lab, "validation")

    assert ejecucion["solicitudes"] == 3
    assert _estados(ejecucion).count("PASS") == 1
    assert _estados(ejecucion).count("SKIPPED") == 5
    assert any("presupuesto" in r["motivo"] for r in ejecucion["resultados"])
    assert ejecucion["estado"] == "completada"


def test_concurrencia_limitada_y_resultados_en_orden(arrancar: Callable[..., Kernel]) -> None:
    kernel = arrancar(concurrencia=3)
    with LaboratorioHttp(Escenario(retardo_s=0.2)) as lab:
        token = _objetivo(kernel, lab)
        ejecucion = _suite(kernel, token, lab, "validation")
        maximo = lab.maximo_simultaneas

    assert [r["posicion"] for r in ejecucion["resultados"]] == [1, 2, 3, 4, 5, 6]
    assert _estados(ejecucion) == ["PASS"] * 6
    assert 2 <= maximo <= 3


def test_cancelacion_antes_de_empezar_no_envia_nada(plataforma: Kernel) -> None:
    evento = threading.Event()
    evento.set()
    with LaboratorioHttp() as lab:
        token = _objetivo(plataforma, lab)
        ejecucion = _suite(plataforma, token, lab, "validation", cancelacion=evento)
        peticiones = lab.peticiones

    assert ejecucion["estado"] == "cancelada"
    assert _estados(ejecucion) == ["SKIPPED"] * 6
    assert peticiones == 0


def test_cancelacion_durante_la_ejecucion_conserva_lo_ya_evaluado(
    plataforma: Kernel,
) -> None:
    evento = threading.Event()
    timer = threading.Timer(0.4, evento.set)
    with LaboratorioHttp(Escenario(retardo_s=0.3)) as lab:
        token = _objetivo(plataforma, lab)
        timer.start()
        ejecucion = _suite(plataforma, token, lab, "validation", cancelacion=evento)
    timer.cancel()

    estados = _estados(ejecucion)
    assert ejecucion["estado"] == "cancelada"
    assert len(estados) == 6
    assert estados.count("SKIPPED") >= 1
    assert estados.count("PASS") >= 1


# ----- Control de acceso y plan ----------------------------------------------------------------


def test_objetivo_no_registrado_se_rechaza_sin_abrir_ejecucion(plataforma: Kernel) -> None:
    token = _admin(plataforma)
    with LaboratorioHttp() as lab, pytest.raises(AuthorizationError, match="no está registrado"):
        _suite(plataforma, token, lab, "validation")
    assert _ejecuciones(plataforma) == 0


def test_ejecutar_sin_confirmacion_se_rechaza(plataforma: Kernel) -> None:
    token = _admin(plataforma)
    with LaboratorioHttp() as lab:
        plataforma.pruebas.registrar_objetivo(token, lab.origen, confirmed=True)
        with pytest.raises(AuthorizationError, match="confirmación"):
            plataforma.pruebas.ejecutar_suite(
                token,
                suite="validation",
                objetivo=lab.origen,
                formulario_id="login",
                cuentas=["a"],
                confirmed=False,
            )
    assert _ejecuciones(plataforma) == 0


def test_un_operador_puede_leer_pero_no_ejecutar(plataforma: Kernel) -> None:
    plataforma.security.accounts.create(OPERADOR, CLAVE_OPERADOR, roles=["operador"])
    token = plataforma.security.login(OPERADOR, CLAVE_OPERADOR)
    plataforma.security.reauthenticate(token, CLAVE_OPERADOR)

    assert len(plataforma.pruebas.formularios(token)) == 3
    with LaboratorioHttp() as lab, pytest.raises(AuthorizationError):
        plataforma.pruebas.registrar_objetivo(token, lab.origen, confirmed=True)


def test_cuenta_de_la_plataforma_no_se_usa_como_sintetica(plataforma: Kernel) -> None:
    plataforma.security.accounts.create("prueba-a", CLAVE_OPERADOR, roles=["operador"])
    token = _admin(plataforma)
    with LaboratorioHttp() as lab:
        plataforma.pruebas.registrar_objetivo(token, lab.origen, confirmed=True)
        with pytest.raises(ValidationError, match="cuenta de la plataforma"):
            _suite(plataforma, token, lab, "validation")
    assert _ejecuciones(plataforma) == 0


@pytest.mark.parametrize(
    ("suite", "formulario", "cuentas", "mensaje"),
    [
        ("inventada", "login", ("a",), "suite no conocida"),
        ("validation", "no-existe", ("a",), "formulario no encontrado"),
        ("validation", "login", ("fantasma",), "no configurada"),
        ("validation", "login", (), "al menos una cuenta"),
    ],
)
def test_un_plan_invalido_no_abre_ejecucion(
    plataforma: Kernel,
    suite: str,
    formulario: str,
    cuentas: tuple[str, ...],
    mensaje: str,
) -> None:
    with LaboratorioHttp() as lab:
        token = _objetivo(plataforma, lab)
        with pytest.raises(ValidationError, match=mensaje):
            _suite(plataforma, token, lab, suite, formulario=formulario, cuentas=cuentas)
    assert _ejecuciones(plataforma) == 0


# ----- Registro, informes y persistencia -------------------------------------------------------


def test_la_ejecucion_queda_registrada_y_se_puede_inspeccionar(plataforma: Kernel) -> None:
    with LaboratorioHttp() as lab:
        token = _objetivo(plataforma, lab)
        ejecucion = _suite(plataforma, token, lab, "credentials")

    historial = plataforma.pruebas.historial(token)
    detalle = plataforma.pruebas.inspeccionar(token, ejecucion["id"])
    assert historial[0]["id"] == ejecucion["id"]
    assert historial[0]["estado"] == "completada"
    assert detalle["estado"] == "completada"
    assert len(detalle["resultados"]) == 3
    assert detalle["resultados"][0]["cuenta"] == "a"


def test_informes_verificables_y_alteracion_detectada(plataforma: Kernel) -> None:
    token = _admin(plataforma)
    with LaboratorioHttp() as lab:
        plataforma.pruebas.registrar_objetivo(token, lab.origen, confirmed=True)
        ejecucion = _suite(plataforma, token, lab, "validation")

    exportes = [
        plataforma.pruebas.exportar(token, ejecucion["id"], f)
        for f in ("json", "csv", "html", "txt")
    ]
    assert all(e["sha256"] and e["tamano_bytes"] > 0 for e in exportes)
    assert {e["formato"] for e in exportes} == {"json", "csv", "html", "txt"}
    assert all(
        Path(e["ruta"]).is_file() and Path(e["ruta"]).is_relative_to(plataforma.context.reports_dir)
        for e in exportes
    )
    assert {e["estado"] for e in plataforma.pruebas.verificar_informes(token)} == {"correcto"}

    Path(exportes[0]["ruta"]).write_bytes(b"alterado")
    Path(exportes[1]["ruta"]).unlink()
    estados = {e["formato"]: e["estado"] for e in plataforma.pruebas.verificar_informes(token)}
    assert estados["json"] == "alterado"
    assert estados["csv"] == "faltante"
    assert estados["html"] == "correcto"


def test_informes_y_base_no_contienen_contrasenas(plataforma: Kernel) -> None:
    token = _admin(plataforma)
    with LaboratorioHttp() as lab:
        plataforma.pruebas.registrar_objetivo(token, lab.origen, confirmed=True)
        ejecucion = _suite(plataforma, token, lab, "credentials", cuentas=("a", "b"))
        exportes = [
            plataforma.pruebas.exportar(token, ejecucion["id"], f)
            for f in ("json", "csv", "html", "txt")
        ]

    contenido = b"".join(Path(e["ruta"]).read_bytes() for e in exportes)
    plataforma.stop()
    base = plataforma.context.storage_dir / "natxajo.db"
    contenido += base.read_bytes()
    for secreto in (CLAVE_A.encode(), CLAVE_B.encode()):
        assert secreto not in contenido


def test_la_auditoria_registra_cada_paso_sin_secretos(plataforma: Kernel) -> None:
    token = _admin(plataforma)
    with LaboratorioHttp() as lab:
        plataforma.pruebas.registrar_objetivo(token, lab.origen, confirmed=True)
        ejecucion = _suite(plataforma, token, lab, "validation")
        plataforma.pruebas.exportar(token, ejecucion["id"], "json")

    for tipo in (
        "pruebas.objetivo_registrado",
        "pruebas.ejecucion_iniciada",
        "pruebas.ejecucion_terminada",
        "pruebas.informe_exportado",
    ):
        eventos = plataforma.audit.events_of_type(tipo)
        assert eventos, tipo
        assert CLAVE_A not in repr(eventos)
    terminada = plataforma.audit.events_of_type("pruebas.ejecucion_terminada")[0]["payload"]
    assert terminada["estado"] == "completada"
    assert terminada["pass"] == 6
    assert terminada["requests"] == 12
    exportado = plataforma.audit.events_of_type("pruebas.informe_exportado")[0]["payload"]
    assert exportado["formato"] == "json"
    assert len(exportado["sha256"]) == 64


def test_la_base_impide_modificar_una_ejecucion_cerrada(plataforma: Kernel) -> None:
    token = _admin(plataforma)
    with LaboratorioHttp() as lab:
        plataforma.pruebas.registrar_objetivo(token, lab.origen, confirmed=True)
        ejecucion = _suite(plataforma, token, lab, "validation")

    base = plataforma.services.fetch(DATABASE)
    with pytest.raises(sqlite3.DatabaseError), base.transaction() as conexion:
        conexion.execute(
            "UPDATE http_results SET outcome = 'PASS' WHERE run_id = ?", (ejecucion["id"],)
        )
    with pytest.raises(sqlite3.DatabaseError), base.transaction() as conexion:
        conexion.execute("DELETE FROM http_runs WHERE id = ?", (ejecucion["id"],))
    with pytest.raises(sqlite3.DatabaseError), base.transaction() as conexion:
        conexion.execute(
            "UPDATE http_runs SET status = 'completada' WHERE id = ?", (ejecucion["id"],)
        )
    with pytest.raises(sqlite3.DatabaseError), base.transaction() as conexion:
        conexion.execute(
            "INSERT INTO http_results (run_id, position, case_id, form_id, form_type, account, outcome, "
            "expected, observed, http_status, duration_ms, reason) "
            "VALUES (?, 99, 'extra', 'login', 'usuario_contrasena', 'a', 'PASS', 'x', 'x', 200, 1, 'x')",
            (ejecucion["id"],),
        )


def test_no_se_exporta_una_ejecucion_en_curso(plataforma: Kernel) -> None:
    token = _admin(plataforma)
    plataforma.pruebas.registrar_objetivo(token, "http://127.0.0.1:9", confirmed=True)
    base = plataforma.services.fetch(DATABASE)
    with base.transaction() as conexion:
        RepositorioPruebas(base).abrir_ejecucion(
            conexion,
            run_id="11111111-1111-4111-8111-111111111111",
            suite="validation",
            origen="http://127.0.0.1:9",
            esquema_sha256="0" * 64,
            usuario=ADMIN_USER,
            iniciado_en="2026-11-27T00:00:00Z",
            casos=1,
        )
    with pytest.raises(ValidationError, match="en curso"):
        plataforma.pruebas.exportar(token, "11111111-1111-4111-8111-111111111111", "json")


def test_la_pausa_configurada_separa_las_peticiones(arrancar: Callable[..., Kernel]) -> None:
    kernel = arrancar(pausa_ms=100)
    with LaboratorioHttp() as lab:
        token = _objetivo(kernel, lab)
        inicio = time.perf_counter()
        ejecucion = _suite(kernel, token, lab, "validation")
        transcurrido = time.perf_counter() - inicio

    assert _estados(ejecucion) == ["PASS"] * 6
    # Seis casos con dos peticiones cada uno (token y envío): al menos 12 pausas de 100 ms.
    assert transcurrido >= 1.0
