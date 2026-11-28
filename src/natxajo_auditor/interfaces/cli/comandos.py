"""Manejadores de comandos de la CLI. Cada uno llama a un método del servicio de pruebas.

Ningún manejador decide permisos: el servicio aplica el guardián, la confirmación y la
reautenticación. Aquí solo se eligen valores por defecto (objetivo único, primera cuenta, última
ejecución cerrada) y se da forma al resultado. Los valores por defecto nunca amplían el alcance de
una operación crítica: un objetivo ambiguo o una cuenta sin configurar se rechazan.
"""

from __future__ import annotations

import argparse
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, cast

from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.interfaces.cli import salida
from natxajo_auditor.kernel.kernel import Kernel

CODIGO_OK: Final = 0
CODIGO_FALLOS: Final = 1
CODIGO_USO: Final = 2
CODIGO_AUTORIZACION: Final = 3
CODIGO_TECNICO: Final = 4

# Catálogos que la CLI necesita antes de iniciar sesión. Coinciden con los del motor (ver pruebas).
SUITES_FORMULARIOS: Final = ("validation", "format", "login-validation")
SUITES_CUENTAS: Final = ("credentials", "synthetic-accounts")
SUITES_TODAS: Final = (*SUITES_FORMULARIOS, *SUITES_CUENTAS)
FORMATOS: Final = ("json", "csv", "html", "txt")
LIMITE_HISTORIAL: Final = 20


@dataclass
class Contexto:
    kernel: Kernel
    token: str
    cancelacion: threading.Event


@dataclass(frozen=True)
class Salida:
    datos: Any
    texto: str
    codigo: int = CODIGO_OK


# ----- Formularios -----------------------------------------------------------------------------


def formularios_listar(ctx: Contexto, args: argparse.Namespace) -> Salida:
    datos = ctx.kernel.pruebas.formularios(ctx.token)
    texto = salida.tabla(
        ("id", "tipo", "ruta", "csrf", "mfa"),
        [(f["id"], f["tipo"], f["ruta"], f["csrf"], f["mfa"]) for f in datos],
    )
    return Salida(datos, texto)


def formulario_inspeccionar(ctx: Contexto, args: argparse.Namespace) -> Salida:
    datos = ctx.kernel.pruebas.formulario(ctx.token, args.formulario)
    return Salida(datos, salida.pares(datos))


def formulario_validar(ctx: Contexto, args: argparse.Namespace) -> Salida:
    controles = ctx.kernel.pruebas.validar(ctx.token, args.formulario)
    texto = salida.tabla(
        ("control", "estado", "detalle"),
        [(c["control"], c["estado"], c["detalle"]) for c in controles],
    )
    codigo = CODIGO_FALLOS if any(c["estado"] == "FAIL" for c in controles) else CODIGO_OK
    return Salida(controles, texto, codigo)


def formularios_probar(ctx: Contexto, args: argparse.Namespace) -> Salida:
    _exigir_suite(args.suite, SUITES_FORMULARIOS, "forms test")
    return _ejecutar_suite(ctx, args, args.suite, args.formulario or "login")


# ----- Autenticación ---------------------------------------------------------------------------


def auth_probar(ctx: Contexto, args: argparse.Namespace) -> Salida:
    _exigir_suite(args.suite, SUITES_CUENTAS, "auth test")
    return _ejecutar_suite(ctx, args, args.suite, args.formulario or "login")


def auth_politica(ctx: Contexto, args: argparse.Namespace) -> Salida:
    datos = ctx.kernel.pruebas.politica(ctx.token, args.formulario or "login")
    return Salida(datos, salida.pares(datos))


def auth_mfa(ctx: Contexto, args: argparse.Namespace) -> Salida:
    return _ejecutar_procedimiento(ctx, args, "mfa", args.formulario or "mfa")


def auth_sesiones(ctx: Contexto, args: argparse.Namespace) -> Salida:
    return _ejecutar_procedimiento(ctx, args, "sessions", args.formulario or "login")


# ----- Seguridad -------------------------------------------------------------------------------


def seguridad_limite(ctx: Contexto, args: argparse.Namespace) -> Salida:
    return _ejecutar_procedimiento(ctx, args, "rate-limit", args.formulario or "login")


def seguridad_csrf(ctx: Contexto, args: argparse.Namespace) -> Salida:
    return _ejecutar_procedimiento(ctx, args, "csrf", args.formulario or "login")


def seguridad_consistencia(ctx: Contexto, args: argparse.Namespace) -> Salida:
    return _ejecutar_procedimiento(ctx, args, "response-check", args.formulario or "login")


# ----- Solicitudes -----------------------------------------------------------------------------


def solicitudes_historial(ctx: Contexto, args: argparse.Namespace) -> Salida:
    datos = ctx.kernel.pruebas.historial(ctx.token, args.limite)
    texto = salida.tabla(
        (
            "id",
            "suite",
            "origen",
            "solicitado_por",
            "estado",
            "casos",
            "solicitudes",
            "iniciado_en",
        ),
        [
            (
                e["id"],
                e["suite"],
                e["origen"],
                e["solicitado_por"],
                e["estado"],
                e["casos"],
                e["solicitudes"],
                e["iniciado_en"],
            )
            for e in datos
        ],
    )
    return Salida(datos, texto)


def solicitudes_inspeccionar(ctx: Contexto, args: argparse.Namespace) -> Salida:
    run = args.run or _ultima_cerrada(ctx)
    ejecucion = ctx.kernel.pruebas.inspeccionar(ctx.token, run)
    resultados = cast(Sequence[Mapping[str, Any]], ejecucion["resultados"])
    texto = salida.resumen_ejecucion(ejecucion) + "\n\n" + salida.tabla_resultados(resultados)
    codigo = CODIGO_FALLOS if salida.hay_fallos(resultados) else CODIGO_OK
    return Salida(ejecucion, texto, codigo)


# ----- Informes --------------------------------------------------------------------------------


def informes_generar(ctx: Contexto, args: argparse.Namespace) -> Salida:
    run = args.run or _ultima_cerrada(ctx)
    exportados = [ctx.kernel.pruebas.exportar(ctx.token, run, formato) for formato in FORMATOS]
    texto = salida.tabla(
        ("formato", "tamaño_bytes", "sha256", "ruta"),
        [(e["formato"], e["tamano_bytes"], e["sha256"], e["ruta"]) for e in exportados],
    )
    return Salida(exportados, texto)


def informes_exportar(ctx: Contexto, args: argparse.Namespace) -> Salida:
    run = args.run or _ultima_cerrada(ctx)
    exportado = ctx.kernel.pruebas.exportar(ctx.token, run, args.formato)
    return Salida(exportado, salida.pares(exportado))


def informes_verificar(ctx: Contexto, args: argparse.Namespace) -> Salida:
    datos = ctx.kernel.pruebas.verificar_informes(ctx.token)
    texto = salida.tabla(
        ("estado", "formato", "ejecución", "creado_en", "ruta"),
        [(d["estado"], d["formato"], d["run_id"], d["creado_en"], d["ruta"]) for d in datos],
    )
    codigo = CODIGO_OK if all(d["estado"] == "correcto" for d in datos) else CODIGO_FALLOS
    return Salida(datos, texto or "No hay informes exportados.", codigo)


# ----- Catálogo y suites -----------------------------------------------------------------------


def catalogo_listar(ctx: Contexto, args: argparse.Namespace) -> Salida:
    catalogo = ctx.kernel.pruebas.catalogo(ctx.token)
    suites = cast(Mapping[str, str], catalogo["suites"])
    procedimientos = cast(Mapping[str, str], catalogo["procedimientos"])
    texto = (
        "Suites:\n"
        + salida.tabla(("suite", "descripción"), list(suites.items()))
        + "\n\nProcedimientos:\n"
        + salida.tabla(("procedimiento", "descripción"), list(procedimientos.items()))
    )
    return Salida({"suites": dict(suites), "procedimientos": dict(procedimientos)}, texto)


def suites_ejecutar(ctx: Contexto, args: argparse.Namespace) -> Salida:
    _exigir_suite(args.suite, SUITES_TODAS, "test suites run")
    return _ejecutar_suite(ctx, args, args.suite, args.formulario or "login")


# ----- Objetivos y cuentas ---------------------------------------------------------------------


def objetivos_listar(ctx: Contexto, args: argparse.Namespace) -> Salida:
    datos = ctx.kernel.pruebas.objetivos(ctx.token)
    texto = salida.tabla(
        ("origen", "registrado_en", "registrado_por"),
        [(o["origen"], o["registrado_en"], o["registrado_por"]) for o in datos],
    )
    return Salida(datos, texto or "No hay objetivos registrados.")


def objetivos_registrar(ctx: Contexto, args: argparse.Namespace) -> Salida:
    datos = ctx.kernel.pruebas.registrar_objetivo(
        ctx.token, args.origen, confirmed=bool(args.confirmar)
    )
    return Salida(datos, f"Objetivo registrado: {datos['origen']}")


def cuentas_listar(ctx: Contexto, args: argparse.Namespace) -> Salida:
    datos = ctx.kernel.pruebas.cuentas(ctx.token)
    texto = salida.tabla(
        ("id", "usuario", "correo", "contraseña_en_entorno", "mfa_en_entorno"),
        [
            (c["id"], c["usuario"], c["correo"], c["contrasena_en_entorno"], c["mfa_en_entorno"])
            for c in datos
        ],
    )
    return Salida(datos, texto or "No hay cuentas sintéticas configuradas.")


# ----- Ejecución compartida --------------------------------------------------------------------


def _ejecutar_suite(ctx: Contexto, args: argparse.Namespace, suite: str, formulario: str) -> Salida:
    ejecucion = ctx.kernel.pruebas.ejecutar_suite(
        ctx.token,
        suite=suite,
        objetivo=_objetivo(ctx, args.objetivo),
        formulario_id=formulario,
        cuentas=_cuentas(ctx, args.cuenta, todas=suite == "synthetic-accounts"),
        confirmed=bool(args.confirmar),
        cancelacion=ctx.cancelacion,
    )
    return _salida_ejecucion(ejecucion)


def _ejecutar_procedimiento(
    ctx: Contexto, args: argparse.Namespace, nombre: str, formulario: str
) -> Salida:
    if args.cuenta and len(args.cuenta) > 1:
        raise ValidationError("este procedimiento usa una sola cuenta: indique un único --cuenta")
    ejecucion = ctx.kernel.pruebas.ejecutar_procedimiento(
        ctx.token,
        nombre=nombre,
        objetivo=_objetivo(ctx, args.objetivo),
        formulario_id=formulario,
        cuenta=_cuentas(ctx, args.cuenta, todas=False)[0],
        confirmed=bool(args.confirmar),
        cancelacion=ctx.cancelacion,
    )
    return _salida_ejecucion(ejecucion)


def _salida_ejecucion(ejecucion: Mapping[str, Any]) -> Salida:
    resultados = cast(Sequence[Mapping[str, Any]], ejecucion["resultados"])
    texto = salida.resumen_ejecucion(ejecucion) + "\n\n" + salida.tabla_resultados(resultados)
    if ejecucion["estado"] == "cancelada":
        codigo = CODIGO_TECNICO
        texto += "\n\nLa ejecución se canceló: los resultados ya evaluados quedan registrados."
    elif salida.hay_fallos(resultados):
        codigo = CODIGO_FALLOS
    else:
        codigo = CODIGO_OK
    return Salida(dict(ejecucion), texto, codigo)


def _objetivo(ctx: Contexto, indicado: str | None) -> str:
    if indicado:
        return indicado
    registrados = ctx.kernel.pruebas.objetivos(ctx.token)
    if not registrados:
        raise ValidationError(
            "no hay objetivos registrados: use «natxajo targets add <origen> --confirmar»"
        )
    if len(registrados) > 1:
        raise ValidationError("hay varios objetivos registrados: indique --objetivo")
    return str(registrados[0]["origen"])


def _cuentas(ctx: Contexto, indicadas: Sequence[str] | None, *, todas: bool) -> list[str]:
    if indicadas:
        return list(indicadas)
    configuradas = [str(c["id"]) for c in ctx.kernel.pruebas.cuentas(ctx.token)]
    if not configuradas:
        raise ValidationError("no hay cuentas sintéticas configuradas")
    return configuradas if todas else configuradas[:1]


def _ultima_cerrada(ctx: Contexto) -> str:
    for ejecucion in ctx.kernel.pruebas.historial(ctx.token, LIMITE_HISTORIAL):
        if ejecucion["estado"] != "en_curso":
            return str(ejecucion["id"])
    raise ValidationError("no hay ejecuciones terminadas; ejecute una prueba primero")


def _exigir_suite(suite: str, permitidas: Sequence[str], comando: str) -> None:
    if suite not in permitidas:
        opciones = ", ".join(permitidas)
        raise ValidationError(f"«{comando}» acepta: {opciones}")
