"""Pruebas HTTP y formularios desde la terminal. Usa el mismo servicio que la CLI y la GUI.

La terminal pide los datos, muestra lo que devuelve el servicio y nada más. El servicio aplica el
guardián en cada operación (sesión, permiso, objetivo registrado, confirmación y reautenticación) y
registra el resultado. Antes de una operación crítica la terminal pide confirmación y, si la sesión
no está reciente, reautenticación; el servicio vuelve a comprobarlo.

Ayuda: escriba `?` seguido del número de una opción (por ejemplo `?6`) para ver qué hace.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, cast

from natxajo_auditor.core.contracts import (
    HTTP_EXPORT_PERMISSION,
    HTTP_READ_PERMISSION,
    HTTP_RUN_PERMISSION,
    HTTP_TARGET_PERMISSION,
)
from natxajo_auditor.core.exceptions import NatxajoError, SessionError, ValidationError
from natxajo_auditor.interfaces.terminal.console import Console, confirm

FORMATOS_INFORME: Final = ("json", "csv", "html", "txt")
LIMITE_HISTORIAL: Final = 20


@dataclass(frozen=True)
class _Opcion:
    clave: str
    etiqueta: str
    ayuda: str
    permiso: str
    accion: Callable[[Console], None]


# ----- Menú ------------------------------------------------------------------------------------


def pruebas_http(console: Console) -> None:
    """Submenú de pruebas HTTP. Vuelve al menú principal con 0."""
    _mostrar_menu(console)
    while True:
        eleccion = console.read("\nPruebas HTTP (m: menú, ?n: ayuda, 0: volver): ").strip().lower()
        if eleccion == "0":
            return
        if eleccion == "m":
            _mostrar_menu(console)
            continue
        if eleccion.startswith("?"):
            _mostrar_ayuda(console, eleccion[1:].strip())
            continue
        opcion = _OPCIONES.get(eleccion)
        if opcion is None:
            console.write("Opción no válida. Escriba m para ver el menú.")
            continue
        # Una sesión caducada sale del submenú y la terminal principal la trata como tal.
        console.kernel.security.sessions.validate(console.token)
        if not _permitida(console, opcion):
            console.write("Opción no disponible para su cuenta")
            continue
        try:
            opcion.accion(console)
        except SessionError:
            raise
        except NatxajoError as exc:
            console.write(f"Error: {exc}")


def _permitida(console: Console, opcion: _Opcion) -> bool:
    return console.kernel.security.authorizer.is_allowed(console.username, opcion.permiso)


def _mostrar_menu(console: Console) -> None:
    lineas = [
        "",
        "PRUEBAS HTTP Y FORMULARIOS",
        "  Solo objetivos registrados y cuentas sintéticas.",
    ]
    for opcion in _OPCIONES.values():
        if _permitida(console, opcion):
            lineas.append(f"{opcion.clave:>3}. {opcion.etiqueta}")
    lineas.append("  m. Mostrar menú")
    lineas.append("  0. Volver al menú principal")
    console.write("\n".join(lineas))


def _mostrar_ayuda(console: Console, clave: str) -> None:
    opcion = _OPCIONES.get(clave)
    if opcion is None:
        console.write("Indique el número de una opción, por ejemplo ?6.")
        return
    console.write(f"{opcion.clave}. {opcion.etiqueta}\n  {opcion.ayuda}")


# ----- Ayudas comunes --------------------------------------------------------------------------


def _pedir(console: Console, texto: str, *, defecto: str | None = None) -> str:
    valor = console.read(f"{texto}: ").strip()
    if valor:
        return valor
    if defecto is not None:
        return defecto
    raise ValidationError(f"falta el valor de «{texto}»")


def _tabla(filas: Sequence[Mapping[str, object]], claves: Sequence[str], vacio: str) -> str:
    if not filas:
        return vacio
    lineas = [" | ".join(claves)]
    for fila in filas:
        lineas.append(" | ".join(_celda(fila.get(clave)) for clave in claves))
    return "\n".join(lineas)


def _celda(valor: object) -> str:
    if valor is None or valor == "":
        return "-"
    if isinstance(valor, bool):
        return "sí" if valor else "no"
    return str(valor)


def _reautenticar_si_hace_falta(console: Console) -> None:
    seguridad = console.kernel.security
    sesion = seguridad.sessions.validate(console.token)
    if seguridad.sessions.recently_reauthenticated(sesion):
        return
    contrasena = console.read_secret("Contraseña para reautenticar: ")
    seguridad.reauthenticate(console.token, contrasena)
    console.write("Sesión reautenticada")


def _confirmar(console: Console, descripcion: str) -> bool:
    """Describe la operación, pide confirmación y reautentica. Sin confirmación no se hace nada."""
    console.write(descripcion)
    if not confirm(console):
        console.write("Operación cancelada")
        return False
    _reautenticar_si_hace_falta(console)
    return True


def _resumen_ejecucion(ejecucion: Mapping[str, object]) -> str:
    conteos = Counter(str(r["resultado"]) for r in _resultados(ejecucion))
    cabecera = (
        f"Ejecución {ejecucion['id']}: estado {ejecucion['estado']}, "
        f"solicitudes {ejecucion['solicitudes']}"
    )
    lineas = [cabecera]
    if ejecucion.get("motivo_cierre"):
        lineas.append(f"Motivo de cierre: {ejecucion['motivo_cierre']}")
    totales = " ".join(
        f"{nombre}={conteos.get(nombre, 0)}"
        for nombre in ("PASS", "FAIL", "BLOCKED", "ERROR", "SKIPPED")
    )
    lineas.append(f"Totales: {totales}")
    return "\n".join(lineas)


def _resultados(ejecucion: Mapping[str, object]) -> list[Mapping[str, object]]:
    return cast(list[Mapping[str, object]], ejecucion.get("resultados", []))


def _linea_resultado(resultado: Mapping[str, object]) -> str:
    return (
        f"[{resultado['resultado']}] {_celda(resultado['posicion']).rjust(3)} "
        f"{resultado['caso']} cuenta={_celda(resultado['cuenta'])} "
        f"observado={_celda(resultado['observado'])} "
        f"HTTP={_celda(resultado['codigo_http'])} :: {_celda(resultado['motivo'])}"
    )


# ----- Acciones de lectura ---------------------------------------------------------------------


def _formularios(console: Console) -> None:
    filas = console.kernel.pruebas.formularios(console.token)
    console.write(_tabla(filas, ("id", "tipo", "ruta", "csrf", "mfa"), "No hay formularios."))


def _cuentas(console: Console) -> None:
    filas = console.kernel.pruebas.cuentas(console.token)
    console.write(
        _tabla(
            filas,
            ("id", "usuario", "contrasena_en_entorno", "mfa_en_entorno"),
            "No hay cuentas sintéticas. Las contraseñas nunca se muestran.",
        )
    )


def _validar(console: Console) -> None:
    formulario = _pedir(console, "Formulario", defecto="login")
    controles = console.kernel.pruebas.validar(console.token, formulario)
    console.write(_tabla(controles, ("control", "estado", "detalle"), "Sin controles."))


def _objetivos(console: Console) -> None:
    filas = console.kernel.pruebas.objetivos(console.token)
    console.write(
        _tabla(
            filas,
            ("origen", "registrado_en", "registrado_por"),
            "No hay objetivos registrados: ninguna prueba puede enviarse todavía.",
        )
    )


def _historial(console: Console) -> None:
    filas = console.kernel.pruebas.historial(console.token, limite=LIMITE_HISTORIAL)
    console.write(
        _tabla(
            filas,
            ("id", "suite", "origen", "estado", "casos", "solicitudes", "iniciado_en"),
            "Sin ejecuciones registradas.",
        )
    )


def _resultados_de(console: Console) -> None:
    run_id = _pedir(console, "Identificador de la ejecución")
    ejecucion = console.kernel.pruebas.inspeccionar(console.token, run_id)
    lineas = [_resumen_ejecucion(ejecucion)]
    lineas.extend(_linea_resultado(r) for r in _resultados(ejecucion))
    console.write("\n".join(lineas))


def _verificar_informes(console: Console) -> None:
    filas = console.kernel.pruebas.verificar_informes(console.token)
    console.write(
        _tabla(
            filas,
            ("id", "run_id", "formato", "estado"),
            "No hay informes exportados.",
        )
    )


# ----- Acciones críticas (confirmación y reautenticación) --------------------------------------


def _registrar_objetivo(console: Console) -> None:
    origen = _pedir(console, "Origen a registrar (p. ej. https://app.ejemplo.test)")
    if not _confirmar(console, f"Se autorizará «{origen}» como objetivo de pruebas."):
        return
    registro = console.kernel.pruebas.registrar_objetivo(console.token, origen, confirmed=True)
    console.write(f"Objetivo registrado: {registro['origen']}")


def _ejecutar_suite(console: Console) -> None:
    catalogo = console.kernel.pruebas.catalogo(console.token)
    console.write("Suites: " + ", ".join(sorted(cast(dict[str, str], catalogo["suites"]))))
    suite = _pedir(console, "Suite")
    objetivo = _pedir(console, "Objetivo (origen registrado)")
    formulario = _pedir(console, "Formulario", defecto="login")
    cuentas = _cuentas_pedidas(console)
    descripcion = (
        f"Se enviarán solicitudes de la suite «{suite}» a {objetivo} con {len(cuentas)} "
        "cuenta(s) sintética(s)."
    )
    if not _confirmar(console, descripcion):
        return
    ejecucion = console.kernel.pruebas.ejecutar_suite(
        console.token,
        suite=suite,
        objetivo=objetivo,
        formulario_id=formulario,
        cuentas=cuentas,
        confirmed=True,
    )
    console.write(_resumen_ejecucion(ejecucion))


def _ejecutar_procedimiento(console: Console) -> None:
    catalogo = console.kernel.pruebas.catalogo(console.token)
    console.write(
        "Procedimientos: " + ", ".join(sorted(cast(dict[str, str], catalogo["procedimientos"])))
    )
    nombre = _pedir(console, "Procedimiento")
    objetivo = _pedir(console, "Objetivo (origen registrado)")
    formulario = _pedir(console, "Formulario", defecto="login")
    cuenta = _pedir(console, "Cuenta sintética")
    descripcion = f"Se ejecutará el procedimiento «{nombre}» contra {objetivo}."
    if not _confirmar(console, descripcion):
        return
    ejecucion = console.kernel.pruebas.ejecutar_procedimiento(
        console.token,
        nombre=nombre,
        objetivo=objetivo,
        formulario_id=formulario,
        cuenta=cuenta,
        confirmed=True,
    )
    console.write(_resumen_ejecucion(ejecucion))


def _cuentas_pedidas(console: Console) -> list[str]:
    texto = _pedir(console, "Cuentas sintéticas, separadas por comas")
    cuentas = [c.strip() for c in texto.split(",") if c.strip()]
    if not cuentas:
        raise ValidationError("indique al menos una cuenta sintética")
    return cuentas


def _exportar(console: Console) -> None:
    run_id = _pedir(console, "Identificador de la ejecución")
    formato = _pedir(console, f"Formato ({', '.join(FORMATOS_INFORME)})", defecto="json")
    informe = console.kernel.pruebas.exportar(console.token, run_id, formato)
    console.write(f"Informe exportado: {informe['ruta']}\nSHA-256: {informe['sha256']}")


def _recuperar(console: Console) -> None:
    descripcion = "Se cerrarán las ejecuciones que quedaron en curso. No se borra ningún resultado."
    if not _confirmar(console, descripcion):
        return
    recuperadas = console.kernel.pruebas.recuperar_interrumpidas(console.token, confirmed=True)
    console.write(
        _tabla(
            recuperadas,
            ("run_id", "resultados", "solicitudes"),
            "No hay ejecuciones interrumpidas.",
        )
    )


_OPCIONES: Final[dict[str, _Opcion]] = {
    opcion.clave: opcion
    for opcion in (
        _Opcion(
            "1",
            "Formularios configurados",
            "Lista los formularios declarados en formularios.json, con su tipo y ruta.",
            HTTP_READ_PERMISSION,
            _formularios,
        ),
        _Opcion(
            "2",
            "Cuentas sintéticas",
            "Lista las cuentas de prueba y si sus contraseñas están en el entorno. Nunca muestra "
            "las contraseñas.",
            HTTP_READ_PERMISSION,
            _cuentas,
        ),
        _Opcion(
            "3",
            "Validar un formulario",
            "Comprueba cuentas, variables de entorno, código MFA y token CSRF sin enviar nada.",
            HTTP_READ_PERMISSION,
            _validar,
        ),
        _Opcion(
            "4",
            "Objetivos registrados",
            "Lista los orígenes autorizados. Sin objetivo registrado no se envía ninguna prueba.",
            HTTP_READ_PERMISSION,
            _objetivos,
        ),
        _Opcion(
            "5",
            "Registrar un objetivo (confirma)",
            "Autoriza un origen para las pruebas. Pide confirmación y reautenticación.",
            HTTP_TARGET_PERMISSION,
            _registrar_objetivo,
        ),
        _Opcion(
            "6",
            "Ejecutar una suite (confirma)",
            "Envía las solicitudes de una suite a un objetivo registrado, con cuentas sintéticas.",
            HTTP_RUN_PERMISSION,
            _ejecutar_suite,
        ),
        _Opcion(
            "7",
            "Ejecutar un procedimiento de seguridad (confirma)",
            "Límite de intentos, CSRF, MFA, cookies, cabeceras, TLS, tiempos o consistencia.",
            HTTP_RUN_PERMISSION,
            _ejecutar_procedimiento,
        ),
        _Opcion(
            "8",
            "Historial de ejecuciones",
            "Últimas ejecuciones con su estado y su motivo de cierre.",
            HTTP_READ_PERMISSION,
            _historial,
        ),
        _Opcion(
            "9",
            "Resultados de una ejecución",
            "Muestra cada caso de una ejecución, con su resultado, código HTTP y motivo.",
            HTTP_READ_PERMISSION,
            _resultados_de,
        ),
        _Opcion(
            "10",
            "Exportar un informe",
            "Genera un informe en json, csv, html o txt, con su huella SHA-256.",
            HTTP_EXPORT_PERMISSION,
            _exportar,
        ),
        _Opcion(
            "11",
            "Verificar informes exportados",
            "Comprueba que cada informe sigue igual que cuando se exportó.",
            HTTP_READ_PERMISSION,
            _verificar_informes,
        ),
        _Opcion(
            "12",
            "Recuperar ejecuciones interrumpidas (confirma)",
            "Cierra las ejecuciones que quedaron en curso tras una parada. No borra resultados.",
            HTTP_RUN_PERMISSION,
            _recuperar,
        ),
    )
}
